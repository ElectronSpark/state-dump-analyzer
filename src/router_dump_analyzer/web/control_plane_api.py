"""Production HTTP control plane for sessions, review, and ingestion.

The routes in this module are intentionally independent of the legacy
single-input runtime routes.  They operate on a durable ``ControlPlane``
attached to ``application.state.control_plane`` and keep tenant identity out
of caller-controlled JSON.  The host application must install a
``ControlPlaneIdentityResolver`` backed by verified credentials.  The headers
select and audit the resolved identity; they do not authenticate it.
"""

# The boundary deliberately catches provider/store exceptions and translates
# the closed set in ``_raise_api_error``. Unknown exceptions are re-raised.
# ruff: noqa: BLE001

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from dataclasses import field as dataclass_field
from enum import Enum
from types import MappingProxyType
from typing import Any, NoReturn, Protocol
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Header,
    Query,
    Request,
    Response,
)
from fastapi import HTTPException as FastAPIHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_dump_analyzer.annotation_store import (
    MAX_AUTHOR_LENGTH,
    MAX_REFERENCE_REVISION_IDS,
    ManualCorrelationEdge,
    ReviewAnnotationKind,
    ReviewAuditRetentionMode,
    ReviewConflictError,
    ReviewIdempotencyConflictError,
    ReviewOverlayError,
    ReviewRetentionDisabledError,
    ReviewRetentionPolicy,
    ReviewScope,
    ReviewSubject,
    ReviewValidationError,
)
from router_dump_analyzer.annotation_store import (
    MAX_IDEMPOTENCY_KEY_LENGTH as MAX_REVIEW_IDEMPOTENCY_KEY_LENGTH,
)
from router_dump_analyzer.annotation_store import (
    MAX_IDENTIFIER_LENGTH as MAX_REVIEW_IDENTIFIER_LENGTH,
)
from router_dump_analyzer.control_plane import (
    ControlPlaneError,
    ControlPlaneScopeError,
    DatasetIntegrityError,
    HiddenSubjectResolutionError,
    SubjectResolutionError,
)
from router_dump_analyzer.ingestion_pipeline import (
    MAX_CONTENT_TYPE_LENGTH,
    MAX_FILENAME_LENGTH,
    MAX_IDEMPOTENCY_KEY_LENGTH,
    MAX_IMPORT_ID_LENGTH,
    MAX_IMPORT_METADATA_BYTES,
    MAX_NODE_HINT_LENGTH,
    CatalogExecutionProcessError,
    CatalogExecutionTimeoutError,
    ImportConflictError,
    ImportNotFoundError,
    ImportQuotaExceededError,
    ImportScope,
    IngestionPipelineError,
    IngestionStateRootPathError,
    PluginExecutionProcessError,
    PluginExecutionTimeoutError,
    validate_import_metadata,
)
from router_dump_analyzer.ingestion_pipeline import (
    MAX_SCOPE_ID_LENGTH as MAX_IMPORT_SCOPE_ID_LENGTH,
)
from router_dump_analyzer.operational_logging import (
    MAX_OPERATIONAL_COUNTER,
    OPERATIONAL_EVENT_CONTRACT,
    OperationalEventDiagnosticsSnapshot,
    emit_operational_event,
    operational_event_diagnostics_snapshot,
)
from router_dump_analyzer.public_text import (
    bounded_public_error_detail,
)
from router_dump_analyzer.session_store import (
    CatalogRetentionDisabledError,
    CatalogRetentionPolicy,
    IdempotencyConflict,
    SessionConflictError,
    SessionStoreDeadlineExceeded,
    SessionStoreError,
    StaleSessionVersion,
    validate_catalog_identifier,
    validate_catalog_label,
    validate_catalog_member_role,
    validate_catalog_metadata,
)
from router_dump_analyzer.value_core import (
    MAX_JSON_SAFE_INTEGER,
    CanonicalIntegerError,
    CanonicalIntegerErrorReason,
    parse_canonical_decimal_integer,
)
from router_dump_analyzer.web.service_api import control_plane_service_health

MAX_UPLOAD_SPOOL_MEMORY = 8 * 1024 * 1024
MAX_CONTROL_PLANE_JSON_BODY_BYTES = 1024 * 1024
MAX_PAGE_LIMIT = 5_000
CONTROL_PLANE_READ_ROLE = "control-plane:read"
CONTROL_PLANE_WRITE_ROLE = "control-plane:write"
CONTROL_PLANE_ADMIN_ROLE = "control-plane:admin"
MAX_RETENTION_AUDIT_LIMIT = 500
MAX_RETENTION_OPERATION_ID_LENGTH = 248
MAX_RETENTION_PROTECTED_IDS = 5_000
MAX_RETENTION_ACTOR_LENGTH = 256
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS = 1_024
_ACCESS_DENIAL_EVENT = "control_plane.access.denied"
_ACCESS_DENIAL_TENANT_KEY = secrets.token_bytes(32)
_MAX_ACCESS_DENIAL_SAMPLE_KEYS = 1_024
_DEFAULT_ACCESS_DENIAL_GLOBAL_BURST = 64
_DEFAULT_ACCESS_DENIAL_GLOBAL_REFILL_PER_SECOND = 1.0
_ACCESS_DENIAL_TENANT_CANDIDATES = 4
_PROCESS_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)
_ACCESS_DENIAL_RESPONSE_STATUSES = frozenset({400, 401, 403, 404})
_ACCESS_DENIAL_REQUEST_METHODS = frozenset(
    {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
)
_ACCESS_DENIAL_ROLES = frozenset(
    {
        CONTROL_PLANE_ADMIN_ROLE,
        CONTROL_PLANE_READ_ROLE,
        CONTROL_PLANE_WRITE_ROLE,
    }
)
_ACCESS_DENIAL_REPORTER_INSTALL_LOCK = threading.Lock()
_MISSING_ACCESS_DENIAL_REPORTER = object()


class ControlPlaneAccessPhase(str, Enum):
    """Closed ownership phase for one rejected control-plane request."""

    REQUEST_SOURCE = "request_source"
    IDENTITY_VERIFICATION = "identity_verification"
    IDENTITY_BINDING = "identity_binding"
    ROLE_AUTHORIZATION = "role_authorization"
    SCOPE_AUTHORIZATION = "scope_authorization"


class ControlPlaneAccessReason(str, Enum):
    """Closed, caller-independent reason vocabulary for access telemetry."""

    HOST_REJECTED = "host_rejected"
    ORIGIN_REJECTED = "origin_rejected"
    IDENTITY_VERIFICATION_FAILED = "identity_verification_failed"
    TENANT_REQUIRED = "tenant_required"
    TENANT_BINDING_MISMATCH = "tenant_binding_mismatch"
    PRINCIPAL_REQUIRED = "principal_required"
    PRINCIPAL_BINDING_MISMATCH = "principal_binding_mismatch"
    REQUIRED_ROLE_MISSING = "required_role_missing"
    PROJECT_SCOPE_DENIED = "project_scope_denied"
    WORKSPACE_SCOPE_DENIED = "workspace_scope_denied"
    PROJECT_CREATION_SCOPE_DENIED = "project_creation_scope_denied"
    WORKSPACE_CREATION_SCOPE_DENIED = "workspace_creation_scope_denied"


_ACCESS_DENIAL_REASONS_BY_PHASE: Mapping[
    ControlPlaneAccessPhase,
    frozenset[ControlPlaneAccessReason],
] = MappingProxyType(
    {
        ControlPlaneAccessPhase.REQUEST_SOURCE: frozenset(
            {
                ControlPlaneAccessReason.HOST_REJECTED,
                ControlPlaneAccessReason.ORIGIN_REJECTED,
            }
        ),
        ControlPlaneAccessPhase.IDENTITY_VERIFICATION: frozenset(
            {ControlPlaneAccessReason.IDENTITY_VERIFICATION_FAILED}
        ),
        ControlPlaneAccessPhase.IDENTITY_BINDING: frozenset(
            {
                ControlPlaneAccessReason.TENANT_REQUIRED,
                ControlPlaneAccessReason.TENANT_BINDING_MISMATCH,
                ControlPlaneAccessReason.PRINCIPAL_REQUIRED,
                ControlPlaneAccessReason.PRINCIPAL_BINDING_MISMATCH,
            }
        ),
        ControlPlaneAccessPhase.ROLE_AUTHORIZATION: frozenset(
            {ControlPlaneAccessReason.REQUIRED_ROLE_MISSING}
        ),
        ControlPlaneAccessPhase.SCOPE_AUTHORIZATION: frozenset(
            {
                ControlPlaneAccessReason.PROJECT_SCOPE_DENIED,
                ControlPlaneAccessReason.WORKSPACE_SCOPE_DENIED,
                ControlPlaneAccessReason.PROJECT_CREATION_SCOPE_DENIED,
                ControlPlaneAccessReason.WORKSPACE_CREATION_SCOPE_DENIED,
            }
        ),
    }
)


class _ControlPlaneAccessDenied(Exception):
    """Private typed decision carried unchanged to the common route wrapper."""

    __slots__ = (
        "concealed",
        "headers",
        "phase",
        "public_detail",
        "reason",
        "required_role",
        "status_code",
        "tenant_correlation",
    )

    def __init__(
        self,
        *,
        status_code: int,
        public_detail: str,
        phase: ControlPlaneAccessPhase,
        reason: ControlPlaneAccessReason,
        required_role: str | None = None,
        tenant_correlation: str | None = None,
        concealed: bool = False,
        headers: dict[str, str] | None = None,
    ) -> None:
        if type(phase) is not ControlPlaneAccessPhase:
            raise TypeError("access-denial phase must use the closed enum")
        if type(reason) is not ControlPlaneAccessReason:
            raise TypeError("access-denial reason must use the closed enum")
        if reason not in _ACCESS_DENIAL_REASONS_BY_PHASE[phase]:
            raise ValueError("access-denial reason does not belong to its phase")
        # Exception text is deliberately constant so an accidental private-log
        # path still cannot reveal a header, identity, scope, or URL.
        super().__init__("control-plane access was denied")
        self.status_code = status_code
        self.public_detail = public_detail
        self.phase = phase
        self.reason = reason
        self.required_role = required_role
        self.tenant_correlation = tenant_correlation
        self.concealed = concealed
        self.headers = headers


@dataclass(slots=True)
class _BoundedTenantMajority:
    """Constant-space conservative majority over trusted tenant digests."""

    total: int = 0
    counters: dict[str, int] = dataclass_field(default_factory=dict)

    def observe(self, correlation: str | None) -> None:
        self.total = min(self.total + 1, MAX_OPERATIONAL_COUNTER)
        if correlation is None:
            return
        existing = self.counters.get(correlation)
        if existing is not None:
            self.counters[correlation] = min(
                existing + 1,
                MAX_OPERATIONAL_COUNTER,
            )
            return
        if len(self.counters) < _ACCESS_DENIAL_TENANT_CANDIDATES:
            self.counters[correlation] = 1
            return
        for candidate in tuple(self.counters):
            remaining = self.counters[candidate] - 1
            if remaining:
                self.counters[candidate] = remaining
            else:
                del self.counters[candidate]

    def strict_majority(self) -> str | None:
        if not self.counters:
            return None
        candidate, lower_bound = max(
            self.counters.items(),
            key=lambda item: (item[1], item[0]),
        )
        return candidate if lower_bound * 2 > self.total else None

    def clear(self) -> None:
        self.total = 0
        self.counters.clear()

    def merge(self, other: _BoundedTenantMajority) -> None:
        """Conservatively merge a detached observation window in O(1) space."""

        self.total = min(self.total + other.total, MAX_OPERATIONAL_COUNTER)
        for correlation, count in other.counters.items():
            self.counters[correlation] = min(
                self.counters.get(correlation, 0) + count,
                MAX_OPERATIONAL_COUNTER,
            )
        while len(self.counters) > _ACCESS_DENIAL_TENANT_CANDIDATES:
            reduction = min(self.counters.values())
            for correlation in tuple(self.counters):
                remaining = self.counters[correlation] - reduction
                if remaining:
                    self.counters[correlation] = remaining
                else:
                    del self.counters[correlation]


@dataclass(slots=True)
class _AccessDenialSampleState:
    occurrences: int = 0
    suppressed_since_last: int = 0
    enqueue_failures_since_last: int = 0
    last_attempted_at: float = float("-inf")
    emission_in_flight: bool = False
    tenant_majority: _BoundedTenantMajority = dataclass_field(
        default_factory=_BoundedTenantMajority
    )


@dataclass(frozen=True, slots=True)
class ControlPlaneAccessTelemetrySnapshot:
    """Non-public counters for intentional sampling versus enqueue loss."""

    observed_denials: int
    emitted_events: int
    intentionally_suppressed: int
    enqueue_failures: int
    invalid_denials: int
    admitted_keys: int
    key_capacity: int
    overflow_observations: int
    overflow_emitted_events: int
    global_suppressed: int


class ControlPlaneAccessDenialReporter:
    """Bounded geometric/time sampler for access-denial operational events."""

    def __init__(
        self,
        *,
        emitter: Callable[..., bool] = emit_operational_event,
        monotonic: Callable[[], float] = time.monotonic,
        minimum_interval_seconds: float = 5.0,
        maximum_interval_seconds: float = 60.0,
        max_keys: int = _MAX_ACCESS_DENIAL_SAMPLE_KEYS,
        global_burst: int = _DEFAULT_ACCESS_DENIAL_GLOBAL_BURST,
        global_refill_per_second: float = (
            _DEFAULT_ACCESS_DENIAL_GLOBAL_REFILL_PER_SECOND
        ),
    ) -> None:
        if not callable(emitter) or not callable(monotonic):
            raise TypeError("access-denial reporter dependencies must be callable")
        if (
            type(minimum_interval_seconds) not in {int, float}
            or type(maximum_interval_seconds) not in {int, float}
            or not 0
            <= float(minimum_interval_seconds)
            <= float(maximum_interval_seconds)
            <= 3_600
        ):
            raise ValueError("access-denial sampling intervals are invalid")
        if type(max_keys) is not int or not 1 <= max_keys <= 4_096:
            raise ValueError("access-denial sample-key limit is invalid")
        if type(global_burst) is not int or not 1 <= global_burst <= 4_096:
            raise ValueError("access-denial global burst is invalid")
        if (
            type(global_refill_per_second) not in {int, float}
            or not math.isfinite(float(global_refill_per_second))
            or not 0 <= float(global_refill_per_second) <= 4_096
        ):
            raise ValueError("access-denial global refill rate is invalid")
        self._emitter = emitter
        self._monotonic = monotonic
        self._minimum_interval = float(minimum_interval_seconds)
        self._maximum_interval = float(maximum_interval_seconds)
        self._max_keys = max_keys
        self._global_burst = global_burst
        self._global_refill_per_second = float(global_refill_per_second)
        self._global_tokens = float(global_burst)
        self._global_last_refill_at: float | None = None
        self._lock = threading.Lock()
        self._states: dict[tuple[object, ...], _AccessDenialSampleState] = {}
        self._overflow_state = _AccessDenialSampleState()
        self._observed_denials = 0
        self._emitted_events = 0
        self._intentionally_suppressed = 0
        self._enqueue_failures = 0
        self._invalid_denials = 0
        self._overflow_observations = 0
        self._overflow_emitted_events = 0
        self._global_suppressed = 0

    @staticmethod
    def _increment(value: int) -> int:
        return min(value + 1, MAX_OPERATIONAL_COUNTER)

    @staticmethod
    def _add(*values: int) -> int:
        return min(sum(values), MAX_OPERATIONAL_COUNTER)

    def snapshot(self) -> ControlPlaneAccessTelemetrySnapshot:
        with self._lock:
            return ControlPlaneAccessTelemetrySnapshot(
                observed_denials=self._observed_denials,
                emitted_events=self._emitted_events,
                intentionally_suppressed=self._intentionally_suppressed,
                enqueue_failures=self._enqueue_failures,
                invalid_denials=self._invalid_denials,
                admitted_keys=len(self._states),
                key_capacity=self._max_keys,
                overflow_observations=self._overflow_observations,
                overflow_emitted_events=self._overflow_emitted_events,
                global_suppressed=self._global_suppressed,
            )

    @staticmethod
    def _valid_tenant_correlation(value: object) -> bool:
        return value is None or (
            type(value) is str
            and len(value) == 32
            and all(character in "0123456789abcdef" for character in value)
        )

    def _take_global_token_locked(self, now: float) -> bool:
        previous = self._global_last_refill_at
        if previous is None:
            self._global_last_refill_at = now
        elif now > previous:
            self._global_tokens = min(
                float(self._global_burst),
                self._global_tokens + (now - previous) * self._global_refill_per_second,
            )
            self._global_last_refill_at = now
        if self._global_tokens < 1.0:
            return False
        self._global_tokens -= 1.0
        return True

    @classmethod
    def _valid_dimensions(
        cls,
        denial: object,
        request_method: object,
        route_name: object,
        mutating: object,
    ) -> bool:
        """Validate every field before hashing or consuming sampler capacity."""

        if type(denial) is not _ControlPlaneAccessDenied:
            return False
        phase = denial.phase
        reason = denial.reason
        return (
            type(phase) is ControlPlaneAccessPhase
            and type(reason) is ControlPlaneAccessReason
            and reason in _ACCESS_DENIAL_REASONS_BY_PHASE[phase]
            and type(denial.status_code) is int
            and denial.status_code in _ACCESS_DENIAL_RESPONSE_STATUSES
            and type(request_method) is str
            and request_method in _ACCESS_DENIAL_REQUEST_METHODS
            and type(route_name) is str
            and 1 <= len(route_name) <= 128
            and all(
                character.isascii()
                and (character.isalnum() or character in {"_", "-", "."})
                for character in route_name
            )
            and type(mutating) is bool
            and type(denial.concealed) is bool
            and (
                denial.required_role is None
                or (
                    type(denial.required_role) is str
                    and denial.required_role in _ACCESS_DENIAL_ROLES
                )
            )
            and cls._valid_tenant_correlation(denial.tenant_correlation)
        )

    def report(
        self,
        *,
        denial: _ControlPlaneAccessDenied,
        request_method: str,
        route_name: str,
        mutating: bool,
    ) -> bool:
        """Observe one denial; never wait for a logging handler."""

        with self._lock:
            self._observed_denials = self._increment(self._observed_denials)
        try:
            valid_dimensions = self._valid_dimensions(
                denial,
                request_method,
                route_name,
                mutating,
            )
        except _PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            valid_dimensions = False
        if not valid_dimensions:
            with self._lock:
                self._invalid_denials = self._increment(self._invalid_denials)
            return False
        try:
            now = float(self._monotonic())
        except _PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            with self._lock:
                self._invalid_denials = self._increment(self._invalid_denials)
            return False
        if not math.isfinite(now):
            with self._lock:
                self._invalid_denials = self._increment(self._invalid_denials)
            return False
        with self._lock:
            key = (
                denial.phase,
                denial.reason,
                denial.status_code,
                request_method,
                route_name,
                mutating,
                denial.concealed,
                denial.required_role,
            )
            state = self._states.get(key)
            sampling_scope = "exact"
            if state is None:
                if len(self._states) < self._max_keys:
                    state = _AccessDenialSampleState()
                    self._states[key] = state
                else:
                    state = self._overflow_state
                    sampling_scope = "overflow"
                    self._overflow_observations = self._increment(
                        self._overflow_observations
                    )
            state.occurrences = self._increment(state.occurrences)
            state.tenant_majority.observe(denial.tenant_correlation)
            if state.emission_in_flight:
                state.suppressed_since_last = self._increment(
                    state.suppressed_since_last
                )
                self._intentionally_suppressed = self._increment(
                    self._intentionally_suppressed
                )
                return False
            since_attempt = now - state.last_attempted_at
            geometric = state.occurrences == 1 or (
                state.occurrences & (state.occurrences - 1) == 0
            )
            should_attempt = state.occurrences == 1 or (
                since_attempt >= self._minimum_interval
                and (geometric or since_attempt >= self._maximum_interval)
            )
            if not should_attempt:
                state.suppressed_since_last = self._increment(
                    state.suppressed_since_last
                )
                self._intentionally_suppressed = self._increment(
                    self._intentionally_suppressed
                )
                return False

            if not self._take_global_token_locked(now):
                state.suppressed_since_last = self._increment(
                    state.suppressed_since_last
                )
                self._intentionally_suppressed = self._increment(
                    self._intentionally_suppressed
                )
                self._global_suppressed = self._increment(self._global_suppressed)
                return False

            state.last_attempted_at = now
            state.emission_in_flight = True
            reserved_suppressed = state.suppressed_since_last
            reserved_enqueue_failures = state.enqueue_failures_since_last
            reserved_tenants = state.tenant_majority
            state.suppressed_since_last = 0
            state.enqueue_failures_since_last = 0
            state.tenant_majority = _BoundedTenantMajority()
            fields: dict[str, bool | int | str] = {
                "phase": denial.phase.value,
                "reason": denial.reason.value,
                "response_status": denial.status_code,
                "request_method": request_method,
                "route_name": route_name,
                "mutating": mutating,
                "concealed": denial.concealed,
                "occurrences": state.occurrences,
                "suppressed_since_last": reserved_suppressed,
                "enqueue_failures_since_last": reserved_enqueue_failures,
                "sampling_scope": sampling_scope,
            }
            if denial.required_role is not None:
                fields["required_role"] = denial.required_role
            tenant_correlation = reserved_tenants.strict_majority()
            if tenant_correlation is not None:
                fields["tenant_correlation"] = tenant_correlation
        try:
            accepted = bool(self._emitter(_ACCESS_DENIAL_EVENT, **fields))
        except _PROCESS_CONTROL_EXCEPTIONS:
            with self._lock:
                state.emission_in_flight = False
                state.suppressed_since_last = self._add(
                    state.suppressed_since_last,
                    reserved_suppressed,
                )
                state.enqueue_failures_since_last = self._add(
                    state.enqueue_failures_since_last,
                    reserved_enqueue_failures,
                )
                state.tenant_majority.merge(reserved_tenants)
            raise
        except BaseException:
            accepted = False
        with self._lock:
            state.emission_in_flight = False
            if accepted:
                self._emitted_events = self._increment(self._emitted_events)
                if sampling_scope == "overflow":
                    self._overflow_emitted_events = self._increment(
                        self._overflow_emitted_events
                    )
                return True
            self._enqueue_failures = self._increment(self._enqueue_failures)
            state.suppressed_since_last = self._add(
                state.suppressed_since_last,
                reserved_suppressed,
            )
            state.enqueue_failures_since_last = self._add(
                state.enqueue_failures_since_last,
                reserved_enqueue_failures,
                1,
            )
            state.tenant_majority.merge(reserved_tenants)
            return False


_DEFAULT_ACCESS_DENIAL_REPORTER = ControlPlaneAccessDenialReporter()


def _access_denial_reporter(application_state: Any) -> ControlPlaneAccessDenialReporter:
    """Resolve the app-scoped sampler without trusting arbitrary state objects."""

    try:
        reporter = getattr(
            application_state,
            "control_plane_access_denial_reporter",
            _MISSING_ACCESS_DENIAL_REPORTER,
        )
    except _PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return _DEFAULT_ACCESS_DENIAL_REPORTER
    if isinstance(reporter, ControlPlaneAccessDenialReporter):
        return reporter
    # Manual APIRouter mounts still receive an application-scoped sampler.
    # Factory-created applications install one eagerly, so this lock is only
    # a compatibility path and never participates in the report hot path.
    with _ACCESS_DENIAL_REPORTER_INSTALL_LOCK:
        try:
            reporter = getattr(
                application_state,
                "control_plane_access_denial_reporter",
                None,
            )
            if isinstance(reporter, ControlPlaneAccessDenialReporter):
                return reporter
            reporter = ControlPlaneAccessDenialReporter()
            setattr(
                application_state,
                "control_plane_access_denial_reporter",
                reporter,
            )
            return reporter
        except _PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _DEFAULT_ACCESS_DENIAL_REPORTER


def _resolved_tenant_correlation(tenant_id: str) -> str:
    """Return a restart-unstable digest of trusted resolved identity only."""

    payload = tenant_id.encode("utf-8", errors="surrogatepass")
    return hmac.new(
        _ACCESS_DENIAL_TENANT_KEY,
        payload,
        hashlib.sha256,
    ).hexdigest()[:32]


def _control_plane_access_denial(
    *,
    status_code: int,
    public_detail: str,
    phase: ControlPlaneAccessPhase,
    reason: ControlPlaneAccessReason,
    identity: ControlPlaneIdentity | None = None,
    required_role: str | None = None,
    concealed: bool = False,
    headers: dict[str, str] | None = None,
) -> _ControlPlaneAccessDenied:
    return _ControlPlaneAccessDenied(
        status_code=status_code,
        public_detail=public_detail,
        phase=phase,
        reason=reason,
        required_role=required_role,
        tenant_correlation=(
            _resolved_tenant_correlation(identity.tenant_id)
            if identity is not None
            else None
        ),
        concealed=concealed,
        headers=headers,
    )


def _deny_control_plane_access(
    *,
    status_code: int,
    public_detail: str,
    phase: ControlPlaneAccessPhase,
    reason: ControlPlaneAccessReason,
    identity: ControlPlaneIdentity | None = None,
    required_role: str | None = None,
    concealed: bool = False,
    headers: dict[str, str] | None = None,
) -> NoReturn:
    raise _control_plane_access_denial(
        status_code=status_code,
        public_detail=public_detail,
        phase=phase,
        reason=reason,
        identity=identity,
        required_role=required_role,
        concealed=concealed,
        headers=headers,
    )


class _ControlPlaneHTTPResponse(FastAPIHTTPException):
    """An HTTP response explicitly owned by this adapter."""

    def __init__(
        self,
        status_code: int,
        detail: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=status_code,
            detail=bounded_public_error_detail(
                detail,
                fallback="control-plane request was rejected",
                maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
            ),
            headers=headers,
        )


class _BoundedControlPlaneRoute(APIRoute):
    """Bound structured request bodies before FastAPI materializes JSON."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()
        is_raw_upload = self.endpoint.__name__ == "upload_import"

        async def bounded(request: Request) -> Any:
            try:
                _validate_control_plane_path_parameters(request.path_params)
                if not is_raw_upload and request.method.upper() in {
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                }:
                    announced = request.headers.get("content-length")
                    if announced is not None:
                        try:
                            announced_bytes = parse_canonical_decimal_integer(
                                announced,
                                "Content-Length",
                                minimum=0,
                            )
                        except CanonicalIntegerError as error:
                            raise _ControlPlaneHTTPResponse(
                                status_code=400,
                                detail=_canonical_integer_http_detail(
                                    error,
                                    grammar_detail=(
                                        "Content-Length must be a canonical decimal "
                                        "integer"
                                    ),
                                ),
                            ) from error
                        if announced_bytes > MAX_CONTROL_PLANE_JSON_BODY_BYTES:
                            raise _ControlPlaneHTTPResponse(
                                status_code=413,
                                detail="JSON request body is too large",
                            )
                    body = bytearray()
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > MAX_CONTROL_PLANE_JSON_BODY_BYTES:
                            raise _ControlPlaneHTTPResponse(
                                status_code=413,
                                detail="JSON request body is too large",
                            )
                    # Starlette's subsequent Request.body()/json() reads this
                    # cached value rather than consuming the receive channel again.
                    request._body = bytes(body)  # type: ignore[attr-defined]
                return await original(request)
            except _ControlPlaneAccessDenied as denial:
                reporter = _access_denial_reporter(request.app.state)
                try:
                    reporter.report(
                        denial=denial,
                        request_method=request.method.upper(),
                        route_name=self.name or self.endpoint.__name__,
                        mutating=_is_mutating_control_plane_request(request),
                    )
                except _PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException as telemetry_error:
                    # A deployment-supplied test/diagnostic reporter remains a
                    # best-effort side channel and cannot alter access control.
                    del telemetry_error
                raise _ControlPlaneHTTPResponse(
                    status_code=denial.status_code,
                    detail=denial.public_detail,
                    headers=denial.headers,
                ) from denial
            except RecursionError as error:
                raise _ControlPlaneHTTPResponse(
                    status_code=422,
                    detail="JSON request nesting is too deep",
                ) from error
            except Exception as error:
                _raise_api_error(error)

        return bounded


control_plane_router = APIRouter(
    prefix="/v1/control-plane",
    tags=["control-plane"],
    route_class=_BoundedControlPlaneRoute,
)


def _identity_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or "\x00" in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ControlPlaneIdentity:
    """Verified request identity supplied by deployment authentication."""

    tenant_id: str
    principal_id: str
    roles: frozenset[str]
    project_ids: frozenset[str] | None = None
    workspace_ids: frozenset[str] | None = None

    def __post_init__(self) -> None:
        _identity_text(self.tenant_id, "tenant_id")
        _identity_text(self.principal_id, "principal_id")
        if not isinstance(self.roles, frozenset) or not self.roles:
            raise ValueError("roles must be a non-empty frozenset")
        for role in self.roles:
            _identity_text(role, "role")
        for label, values in (
            ("project_ids", self.project_ids),
            ("workspace_ids", self.workspace_ids),
        ):
            if values is None:
                continue
            if not isinstance(values, frozenset):
                raise TypeError(f"{label} must be a frozenset or None")
            for value in values:
                _identity_text(value, label)


class ControlPlaneIdentityResolver(Protocol):
    """Resolve an identity from credentials verified outside this router."""

    def __call__(self, request: Request) -> ControlPlaneIdentity: ...


def _is_mutating_control_plane_request(request: Request) -> bool:
    method = request.method.upper()
    return method not in {"GET", "HEAD", "OPTIONS"} and not (
        method == "POST" and request.url.path.endswith("/correlation-report")
    )


def _normalized_authority(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    parsed = urlsplit(f"//{value}", allow_fragments=False)
    if (
        not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"{label} is invalid")
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError(f"{label} is invalid")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{label} is invalid") from error
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError(f"{label} is invalid")
    try:
        normalized_host = ipaddress.ip_address(hostname).compressed
    except ValueError:
        normalized_host = hostname.casefold()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    return normalized_host if port is None else f"{normalized_host}:{port}"


def _normalized_origin(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"{label} is invalid")
    authority = _normalized_authority(parsed.netloc, label)
    return f"{parsed.scheme.casefold()}://{authority}"


class TrustedHeaderIdentityResolver:
    """Explicit local-development adapter; never use as authentication.

    It is intentionally not installed by the router.  The local CLI may opt
    into it on a loopback listener, while production applications must install
    a resolver backed by verified credentials or trusted middleware.
    """

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str],
        allowed_origins: Iterable[str] | None = None,
    ) -> None:
        if isinstance(allowed_hosts, (str, bytes)):
            raise TypeError("allowed_hosts must be an iterable of authorities")
        if isinstance(allowed_origins, (str, bytes)):
            raise TypeError("allowed_origins must be an iterable of origins")
        hosts = frozenset(
            _normalized_authority(value, "allowed host") for value in allowed_hosts
        )
        if not hosts:
            raise ValueError("at least one allowed host is required")
        origins = frozenset(
            _normalized_origin(value, "allowed origin")
            for value in (
                allowed_origins
                if allowed_origins is not None
                else tuple(f"http://{host}" for host in hosts)
            )
        )
        if not origins:
            raise ValueError("at least one allowed origin is required")
        self._allowed_hosts = hosts
        self._allowed_origins = origins

    def _validate_request_source(self, request: Request) -> None:
        host_values = request.headers.getlist("host")
        if len(host_values) != 1:
            _deny_control_plane_access(
                status_code=400,
                public_detail="request host is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.HOST_REJECTED,
            )
        try:
            host = _normalized_authority(host_values[0], "Host")
        except ValueError as error:
            raise _control_plane_access_denial(
                status_code=400,
                public_detail="request host is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.HOST_REJECTED,
            ) from error
        if host not in self._allowed_hosts:
            _deny_control_plane_access(
                status_code=400,
                public_detail="request host is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.HOST_REJECTED,
            )

        if not _is_mutating_control_plane_request(request):
            return
        origin_values = request.headers.getlist("origin")
        if not origin_values:
            return
        if len(origin_values) != 1:
            _deny_control_plane_access(
                status_code=403,
                public_detail="request origin is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.ORIGIN_REJECTED,
            )
        try:
            origin = _normalized_origin(origin_values[0], "Origin")
        except ValueError as error:
            raise _control_plane_access_denial(
                status_code=403,
                public_detail="request origin is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.ORIGIN_REJECTED,
            ) from error
        if origin not in self._allowed_origins:
            _deny_control_plane_access(
                status_code=403,
                public_detail="request origin is not allowed",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.ORIGIN_REJECTED,
            )

    def __call__(self, request: Request) -> ControlPlaneIdentity:
        self._validate_request_source(request)
        tenant_header = request.headers.get("X-Tenant-ID")
        if tenant_header is None or not tenant_header.strip():
            _deny_control_plane_access(
                status_code=401,
                public_detail="control-plane identity could not be verified",
                phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
                reason=ControlPlaneAccessReason.TENANT_REQUIRED,
            )
        tenant_id = _identity_text(
            tenant_header,
            "X-Tenant-ID",
        )
        principal_id = request.headers.get("X-Principal-ID")
        if principal_id is None:
            principal_id = "local-read-only"
        return ControlPlaneIdentity(
            tenant_id=tenant_id,
            principal_id=_identity_text(
                principal_id,
                "X-Principal-ID",
            ),
            roles=frozenset(
                {
                    CONTROL_PLANE_ADMIN_ROLE,
                    CONTROL_PLANE_READ_ROLE,
                    CONTROL_PLANE_WRITE_ROLE,
                }
            ),
        )


def _resolved_identity(
    request: Request,
    *,
    required_role_override: str | None = None,
) -> ControlPlaneIdentity:
    cached = getattr(
        request.state,
        "router_dump_control_plane_identity",
        None,
    )
    if type(cached) is ControlPlaneIdentity:
        if (
            required_role_override is not None
            and required_role_override not in cached.roles
        ):
            _deny_control_plane_access(
                status_code=403,
                public_detail="request identity lacks the required role",
                phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
                reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
                identity=cached,
                required_role=required_role_override,
            )
        return cached
    resolver: Callable[[Request], object] | None = getattr(
        request.app.state,
        "control_plane_identity_resolver",
        None,
    )
    if resolver is None:
        raise _ControlPlaneHTTPResponse(
            status_code=503,
            detail="control-plane identity resolver is not configured",
        )
    if not callable(resolver):
        raise _ControlPlaneHTTPResponse(
            status_code=500,
            detail="control-plane identity resolver is invalid",
        )
    try:
        identity = resolver(request)
    except _ControlPlaneAccessDenied:
        raise
    except StarletteHTTPException as error:
        if error.status_code not in {401, 403}:
            # A host resolver owns identity verification, not adapter HTTP
            # responses.  Coerce even our private response subclass back to a
            # framework exception so the outer boundary treats non-auth
            # statuses as untrusted provider output and projects a bounded 500.
            raise FastAPIHTTPException(
                status_code=error.status_code,
                detail=error.detail,
                headers=error.headers,
            ) from error
        raise _control_plane_access_denial(
            status_code=error.status_code,
            public_detail=str(error.detail),
            phase=ControlPlaneAccessPhase.IDENTITY_VERIFICATION,
            reason=ControlPlaneAccessReason.IDENTITY_VERIFICATION_FAILED,
            headers=dict(error.headers) if error.headers is not None else None,
        ) from error
    except Exception as error:
        raise _control_plane_access_denial(
            status_code=401,
            public_detail="control-plane identity could not be verified",
            phase=ControlPlaneAccessPhase.IDENTITY_VERIFICATION,
            reason=ControlPlaneAccessReason.IDENTITY_VERIFICATION_FAILED,
        ) from error
    if type(identity) is not ControlPlaneIdentity:
        raise _ControlPlaneHTTPResponse(
            status_code=500,
            detail="control-plane identity resolver returned an invalid value",
        )

    tenant_header = request.headers.get("X-Tenant-ID")
    if tenant_header is None or tenant_header.strip() != identity.tenant_id:
        _deny_control_plane_access(
            status_code=403,
            public_detail="requested tenant is not authorized",
            phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
            reason=ControlPlaneAccessReason.TENANT_BINDING_MISMATCH,
            identity=identity,
        )
    principal_header = request.headers.get("X-Principal-ID")
    mutating = _is_mutating_control_plane_request(request)
    if mutating and (
        principal_header is None or principal_header.strip() != identity.principal_id
    ):
        _deny_control_plane_access(
            status_code=403,
            public_detail="request principal is not authorized",
            phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
            reason=ControlPlaneAccessReason.PRINCIPAL_BINDING_MISMATCH,
            identity=identity,
        )
    if (
        principal_header is not None
        and principal_header.strip() != identity.principal_id
    ):
        _deny_control_plane_access(
            status_code=403,
            public_detail="request principal is not authorized",
            phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
            reason=ControlPlaneAccessReason.PRINCIPAL_BINDING_MISMATCH,
            identity=identity,
        )
    is_retention_admin_request = "/retention/" in request.url.path
    required_role = required_role_override or (
        CONTROL_PLANE_ADMIN_ROLE
        if is_retention_admin_request
        else (CONTROL_PLANE_WRITE_ROLE if mutating else CONTROL_PLANE_READ_ROLE)
    )
    if required_role not in identity.roles:
        _deny_control_plane_access(
            status_code=403,
            public_detail="request identity lacks the required role",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
            identity=identity,
            required_role=required_role,
        )
    project_id = request.path_params.get("project_id")
    if (
        project_id is not None
        and identity.project_ids is not None
        and project_id not in identity.project_ids
    ):
        _deny_control_plane_access(
            status_code=404,
            public_detail="resource not found",
            phase=ControlPlaneAccessPhase.SCOPE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.PROJECT_SCOPE_DENIED,
            identity=identity,
            concealed=True,
        )
    workspace_id = request.path_params.get("workspace_id")
    if (
        workspace_id is not None
        and identity.workspace_ids is not None
        and workspace_id not in identity.workspace_ids
    ):
        _deny_control_plane_access(
            status_code=404,
            public_detail="resource not found",
            phase=ControlPlaneAccessPhase.SCOPE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.WORKSPACE_SCOPE_DENIED,
            identity=identity,
            concealed=True,
        )
    request.state.router_dump_control_plane_identity = identity
    return identity


def _control_plane(request: Request) -> Any:
    control_plane = getattr(request.app.state, "control_plane", None)
    if control_plane is None:
        raise _ControlPlaneHTTPResponse(
            status_code=503,
            detail="the durable control plane is not configured",
        )
    _resolved_identity(request)
    return control_plane


def _require_control_plane_admin(request: Request) -> ControlPlaneIdentity:
    """Require the exact administrative capability for maintenance APIs."""

    return _resolved_identity(
        request,
        required_role_override=CONTROL_PLANE_ADMIN_ROLE,
    )


def _tenant(value: str | None) -> str:
    if value is None or not value.strip():
        _deny_control_plane_access(
            status_code=401,
            public_detail="X-Tenant-ID is required",
            phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
            reason=ControlPlaneAccessReason.TENANT_REQUIRED,
        )
    return _catalog_identifier(value.strip(), "X-Tenant-ID")


def _principal(value: str | None) -> str:
    if value is None or not value.strip():
        _deny_control_plane_access(
            status_code=401,
            public_detail="X-Principal-ID is required for mutations",
            phase=ControlPlaneAccessPhase.IDENTITY_BINDING,
            reason=ControlPlaneAccessReason.PRINCIPAL_REQUIRED,
        )
    return _request_bounded_text(
        value.strip(),
        "X-Principal-ID",
        maximum=MAX_AUTHOR_LENGTH,
        reject_controls=True,
    )


def _visible_projects(
    control_plane: Any,
    identity: ControlPlaneIdentity,
    tenant_id: str,
    *,
    limit: int,
    offset: int,
) -> tuple[Any, ...]:
    if identity.project_ids is None:
        return control_plane.sessions.list_projects(
            tenant_id,
            limit=limit,
            offset=offset,
        )
    visible: list[Any] = []
    for project_id in sorted(identity.project_ids):
        try:
            visible.append(control_plane.sessions.get_project(tenant_id, project_id))
        except KeyError:
            continue
    return tuple(visible[offset : offset + limit])


def _visible_workspaces(
    control_plane: Any,
    identity: ControlPlaneIdentity,
    tenant_id: str,
    project_id: str,
    *,
    limit: int,
    offset: int,
) -> tuple[Any, ...]:
    project_id = _catalog_identifier(project_id, "project_id")
    if identity.workspace_ids is None:
        return control_plane.sessions.list_workspaces(
            tenant_id,
            project_id,
            limit=limit,
            offset=offset,
        )
    visible: list[Any] = []
    for workspace_id in sorted(identity.workspace_ids):
        try:
            workspace = control_plane.sessions.get_workspace(
                tenant_id,
                workspace_id,
            )
        except KeyError:
            continue
        if workspace.project_id == project_id:
            visible.append(workspace)
    return tuple(visible[offset : offset + limit])


def _body_object(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _ControlPlaneHTTPResponse(
            status_code=422, detail="request body must be an object"
        )
    return payload


def _request_validation_failure(detail: str) -> NoReturn:
    """Reject one malformed caller-owned value without exposing internals."""

    raise _ControlPlaneHTTPResponse(status_code=422, detail=detail)


def _catalog_identifier(value: object, field: str) -> str:
    try:
        return validate_catalog_identifier(value, field)
    except (TypeError, ValueError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} is invalid",
        ) from error


def _catalog_optional_identifier(
    value: object,
    field: str,
) -> str | None:
    if value is None:
        return None
    return _catalog_identifier(value, field)


def _catalog_label(value: object, field: str) -> str:
    try:
        return validate_catalog_label(value, field)
    except (TypeError, ValueError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} is invalid",
        ) from error


def _catalog_metadata(value: object, field: str) -> dict[str, Any]:
    if value is not None and not isinstance(value, Mapping):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} violates the bounded JSON contract",
        )
    try:
        return validate_catalog_metadata(value, field)
    except (RecursionError, TypeError, ValueError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} violates the bounded JSON contract",
        ) from error


def _catalog_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    return _catalog_identifier(value, "Idempotency-Key")


def _request_bounded_text(
    value: object,
    field: str,
    *,
    maximum: int,
    reject_whitespace: bool = False,
    reject_controls: bool = False,
    reject_surrounding_whitespace: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
        or (reject_whitespace and any(character.isspace() for character in value))
        or (
            reject_controls
            and any(ord(character) < 32 or ord(character) == 127 for character in value)
        )
        or (reject_surrounding_whitespace and value != value.strip())
    ):
        _request_validation_failure(f"{field} is invalid")
    return value


def _import_identifier(
    value: object,
    field: str,
    *,
    maximum: int = MAX_IMPORT_ID_LENGTH,
) -> str:
    return _request_bounded_text(
        value,
        field,
        maximum=maximum,
        reject_whitespace=True,
        reject_controls=True,
    )


def _review_identifier(value: object, field: str) -> str:
    return _request_bounded_text(
        value,
        field,
        maximum=MAX_REVIEW_IDENTIFIER_LENGTH,
        reject_controls=True,
    )


def _review_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    return _request_bounded_text(
        value,
        "Idempotency-Key",
        maximum=MAX_REVIEW_IDEMPOTENCY_KEY_LENGTH,
        reject_controls=True,
    )


_CATALOG_PATH_IDENTIFIERS = frozenset(
    {
        "member_id",
        "project_id",
        "session_id",
        "snapshot_id",
        "workspace_id",
    }
)


def _validate_control_plane_path_parameters(
    parameters: Mapping[str, object],
) -> None:
    """Validate every path identity before resolving a store or service."""

    for field, value in parameters.items():
        if field in _CATALOG_PATH_IDENTIFIERS:
            _catalog_identifier(value, field)
        elif field == "import_id":
            _import_identifier(value, field)
        elif field in {"annotation_id", "correlation_id"}:
            _review_identifier(value, field)


def _required_text(
    payload: dict[str, Any],
    field: str,
    *,
    allow_empty: bool = False,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must be a non-empty string",
        )
    return value


def _request_canonical_integer(
    value: object,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_SQLITE_INTEGER,
) -> int:
    """Parse one caller-owned integer before entering service/store code."""

    try:
        return parse_canonical_decimal_integer(
            value,
            field,
            minimum=minimum,
            maximum=maximum,
        )
    except CanonicalIntegerError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=_canonical_integer_http_detail(
                error,
                grammar_detail=f"{field} must be a canonical decimal integer",
            ),
        ) from error


def _canonical_integer_http_detail(
    error: CanonicalIntegerError,
    *,
    grammar_detail: str,
) -> str:
    """Translate a typed integer failure without parsing exception prose."""

    if error.reason is CanonicalIntegerErrorReason.GRAMMAR:
        return grammar_detail
    return str(error)


def _import_metadata_header(value: str | None) -> dict[str, Any]:
    if value is None:
        return {}
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, RecursionError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="X-Import-Metadata must contain a JSON object",
        ) from error
    if not isinstance(decoded, dict):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="X-Import-Metadata must contain a JSON object",
        )
    return decoded


def _iterable_strings(payload: dict[str, Any], field: str) -> tuple[str, ...]:
    value = payload.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must be an array of strings",
        )
    return tuple(value)


def _closed_object(
    payload: dict[str, Any],
    field: str,
    *,
    allowed_fields: frozenset[str],
) -> dict[str, Any]:
    value = payload.get(field, {})
    if not isinstance(value, dict):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must be an object",
        )
    unknown = sorted(set(value).difference(allowed_fields))
    if unknown:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=bounded_public_error_detail(
                f"{field} contains unsupported fields: {', '.join(unknown)}",
                fallback="control-plane request was rejected",
                maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
            ),
        )
    return value


def _retention_boolean(
    payload: dict[str, Any],
    field: str,
    *,
    default: bool,
) -> bool:
    value = payload.get(field, default)
    if type(value) is not bool:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must be a boolean",
        )
    return value


def _retention_integer(
    payload: dict[str, Any],
    field: str,
    *,
    default: int | None = None,
    minimum: int = 0,
    maximum: int = _MAX_SQLITE_INTEGER,
) -> int | None:
    value = payload.get(field, default)
    if value is None:
        return None
    try:
        parsed = parse_canonical_decimal_integer(
            value,
            field,
            minimum=minimum,
            maximum=maximum,
        )
    except CanonicalIntegerError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=_canonical_integer_http_detail(
                error,
                grammar_detail=f"{field} must be a canonical decimal integer",
            ),
        ) from error
    return parsed


def _retention_identifiers(
    payload: dict[str, Any],
    field: str,
) -> tuple[str, ...]:
    value = payload.get(field, [])
    if not isinstance(value, list):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must be an array of strings",
        )
    if len(value) > MAX_RETENTION_PROTECTED_IDS:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=(f"{field} supports at most {MAX_RETENTION_PROTECTED_IDS} values"),
        )
    identifiers = tuple(
        _catalog_identifier(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    )
    if len(identifiers) != len(set(identifiers)):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"{field} must not contain duplicates",
        )
    return identifiers


_CATALOG_RETENTION_FIELDS = frozenset(
    {
        "enabled",
        "fixture_before_ns",
        "idempotency_before_ns",
        "maximum_candidates",
        "preserve_latest_snapshot_per_session",
        "protected_fixture_ids",
        "protected_revision_ids",
        "protected_snapshot_ids",
        "revision_before_ns",
        "snapshot_before_ns",
    }
)
_REVIEW_RETENTION_FIELDS = frozenset(
    {
        "audit_before_sequence",
        "audit_mode",
        "enabled",
        "idempotency_before_ns",
        "maximum_candidates",
        "tombstone_before_ns",
    }
)


def _retention_policies(
    payload: dict[str, Any],
) -> tuple[CatalogRetentionPolicy, ReviewRetentionPolicy]:
    unknown = sorted(set(payload).difference({"catalog", "review"}))
    if unknown:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=bounded_public_error_detail(
                f"request contains unsupported fields: {', '.join(unknown)}",
                fallback="control-plane request was rejected",
                maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
            ),
        )
    catalog = _closed_object(
        payload,
        "catalog",
        allowed_fields=_CATALOG_RETENTION_FIELDS,
    )
    review = _closed_object(
        payload,
        "review",
        allowed_fields=_REVIEW_RETENTION_FIELDS,
    )
    audit_mode = review.get(
        "audit_mode",
        ReviewAuditRetentionMode.PRESERVE.value,
    )
    if not isinstance(audit_mode, str):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="audit_mode must be a string",
        )
    try:
        selected_audit_mode = ReviewAuditRetentionMode(audit_mode)
    except ValueError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="unsupported review audit retention mode",
        ) from error
    catalog_maximum = _retention_integer(
        catalog,
        "maximum_candidates",
        default=1_000,
        minimum=1,
        maximum=5_000,
    )
    review_maximum = _retention_integer(
        review,
        "maximum_candidates",
        default=1_000,
        minimum=1,
        maximum=5_000,
    )
    if catalog_maximum is None or review_maximum is None:
        raise AssertionError("retention candidate defaults must be integers")
    try:
        catalog_policy = CatalogRetentionPolicy(
            enabled=_retention_boolean(catalog, "enabled", default=False),
            idempotency_before_ns=_retention_integer(
                catalog,
                "idempotency_before_ns",
            ),
            snapshot_before_ns=_retention_integer(
                catalog,
                "snapshot_before_ns",
            ),
            revision_before_ns=_retention_integer(
                catalog,
                "revision_before_ns",
            ),
            fixture_before_ns=_retention_integer(
                catalog,
                "fixture_before_ns",
            ),
            preserve_latest_snapshot_per_session=_retention_boolean(
                catalog,
                "preserve_latest_snapshot_per_session",
                default=True,
            ),
            protected_fixture_ids=_retention_identifiers(
                catalog,
                "protected_fixture_ids",
            ),
            protected_revision_ids=_retention_identifiers(
                catalog,
                "protected_revision_ids",
            ),
            protected_snapshot_ids=_retention_identifiers(
                catalog,
                "protected_snapshot_ids",
            ),
            maximum_candidates=catalog_maximum,
        )
        review_policy = ReviewRetentionPolicy(
            enabled=_retention_boolean(review, "enabled", default=False),
            tombstone_before_ns=_retention_integer(
                review,
                "tombstone_before_ns",
            ),
            idempotency_before_ns=_retention_integer(
                review,
                "idempotency_before_ns",
            ),
            audit_mode=selected_audit_mode,
            audit_before_sequence=_retention_integer(
                review,
                "audit_before_sequence",
            ),
            maximum_candidates=review_maximum,
        )
    except Exception as error:
        _raise_api_error(error)
    return catalog_policy, review_policy


def _retention_operation_id(value: str | None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_RETENTION_OPERATION_ID_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _ControlPlaneHTTPResponse(
            status_code=428 if value is None else 422,
            detail=(
                "Idempotency-Key is required for retention execution"
                if value is None
                else "Idempotency-Key is invalid for retention execution"
            ),
        )
    return value


def _parse_if_match(value: str | None) -> int:
    if value is None:
        raise _ControlPlaneHTTPResponse(
            status_code=428,
            detail="If-Match with the current numeric version is required",
        )
    if len(value) < 3 or value[0] != '"' or value[-1] != '"':
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="If-Match must contain one strong canonical numeric ETag",
        )
    try:
        version = parse_canonical_decimal_integer(
            value[1:-1],
            "If-Match version",
            minimum=0,
            maximum=_MAX_SQLITE_INTEGER,
        )
    except CanonicalIntegerError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=_canonical_integer_http_detail(
                error,
                grammar_detail=(
                    "If-Match must contain one strong canonical numeric ETag"
                ),
            ),
        ) from error
    return version


def _etag(response: Response, version: int) -> None:
    response.headers["ETag"] = f'"{version}"'


_CORE_NS_WIRE_FIELDS = frozenset(
    {
        "absolute_timestamp_ns",
        "acknowledged_at_ns",
        "artifact_releases_acknowledged_at_ns",
        "captured_at_ns",
        "completed_at_ns",
        "created_at_ns",
        "deleted_at_ns",
        "end_ns",
        "evaluated_at_ns",
        "effective_now_ns",
        "expires_at_ns",
        "fixture_before_ns",
        "idempotency_before_ns",
        "last_claim_error_at_ns",
        "last_iteration_error_at_ns",
        "lease_expires_ns",
        "occurred_at_ns",
        "published_at_ns",
        "raw_timestamp_ns",
        "requested_now_ns",
        "revision_before_ns",
        "snapshot_before_ns",
        "start_ns",
        "time_ns",
        "timeline_end_ns",
        "timeline_start_ns",
        "timestamp_ns",
        "timestamp_uncertainty_ns",
        "tombstone_before_ns",
        "updated_at_ns",
    }
)
_OPAQUE_JSON_FIELDS = frozenset(
    {"attributes", "evidence", "metadata", "payload", "properties", "provenance"}
)


def _json_value(
    value: Any,
    *,
    key: str | None = None,
    opaque: bool = False,
) -> Any:
    """Return bounded-store records in a browser-safe JSON shape."""

    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            str(name): _json_value(
                item,
                key=str(name),
                opaque=opaque or str(name) in _OPAQUE_JSON_FIELDS,
            )
            for name, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_json_value(item, opaque=opaque) for item in value]
    if type(value) is int and not opaque and key in _CORE_NS_WIRE_FIELDS:
        return str(value)
    return value


def _review_json(value: Any) -> dict[str, Any]:
    projected = _json_value(value.to_dict())
    if not isinstance(projected, dict):
        raise TypeError("review record projection must be an object")
    return projected


@dataclass(frozen=True, slots=True)
class _ApiErrorPolicy:
    status_code: int
    public_detail: str
    expose_message: bool = False


# This is deliberately an exact, closed inventory of the exception classes
# translated by this HTTP boundary. Resolution follows the raised type's MRO,
# not declaration order, so a newly added subclass cannot be shadowed by a
# base-class branch. The contract test also walks every domain-error hierarchy
# and requires each concrete class to appear here explicitly.
_API_ERROR_POLICY_BY_CLASS: Mapping[type[Exception], _ApiErrorPolicy] = (
    MappingProxyType(
        {
            KeyError: _ApiErrorPolicy(404, "resource not found"),
            ImportNotFoundError: _ApiErrorPolicy(404, "resource not found"),
            HiddenSubjectResolutionError: _ApiErrorPolicy(
                404,
                "resource not found",
            ),
            StaleSessionVersion: _ApiErrorPolicy(
                409,
                "session version conflict",
                expose_message=True,
            ),
            SessionConflictError: _ApiErrorPolicy(
                409,
                "session request conflicts with durable state",
                expose_message=True,
            ),
            IdempotencyConflict: _ApiErrorPolicy(
                409,
                "idempotency conflict",
                expose_message=True,
            ),
            ReviewConflictError: _ApiErrorPolicy(
                409,
                "review request conflicts with durable state",
                expose_message=True,
            ),
            ReviewIdempotencyConflictError: _ApiErrorPolicy(
                409,
                "review idempotency conflict",
                expose_message=True,
            ),
            ImportConflictError: _ApiErrorPolicy(
                409,
                "import request conflicts with durable state",
                expose_message=True,
            ),
            ImportQuotaExceededError: _ApiErrorPolicy(
                409,
                "import quota was exceeded",
                expose_message=True,
            ),
            ReviewValidationError: _ApiErrorPolicy(
                422,
                "review request was rejected",
                expose_message=True,
            ),
            ControlPlaneScopeError: _ApiErrorPolicy(
                422,
                "control-plane request was rejected",
            ),
            SubjectResolutionError: _ApiErrorPolicy(
                422,
                "control-plane request was rejected",
            ),
            DatasetIntegrityError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            SessionStoreDeadlineExceeded: _ApiErrorPolicy(
                504,
                "catalog operation timed out",
            ),
            ControlPlaneError: _ApiErrorPolicy(
                422,
                "control-plane request was rejected",
            ),
            CatalogRetentionDisabledError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            SessionStoreError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            ReviewRetentionDisabledError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            ReviewOverlayError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            PluginExecutionTimeoutError: _ApiErrorPolicy(
                422,
                "ingestion request was rejected",
            ),
            CatalogExecutionTimeoutError: _ApiErrorPolicy(
                504,
                "catalog operation timed out",
            ),
            CatalogExecutionProcessError: _ApiErrorPolicy(
                502,
                "catalog operation failed",
            ),
            PluginExecutionProcessError: _ApiErrorPolicy(
                422,
                "ingestion request was rejected",
            ),
            IngestionStateRootPathError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            IngestionPipelineError: _ApiErrorPolicy(
                422,
                "ingestion request was rejected",
            ),
            # Bare built-ins are not a public validation contract. They can
            # originate in storage/path/integration code, so exposing their
            # text or classifying them as caller errors would fail open.
            ValueError: _ApiErrorPolicy(
                500,
                "internal control-plane operation failed",
            ),
            TypeError: _ApiErrorPolicy(
                500,
                "internal control-plane operation failed",
            ),
            # Host filesystem failures can carry absolute paths in both their
            # message and structured filename attributes. They are internal
            # storage failures, never caller-validation details.
            OSError: _ApiErrorPolicy(
                500,
                "durable control-plane storage failed",
            ),
            TimeoutError: _ApiErrorPolicy(504, "operation timed out"),
        }
    )
)

_API_ERROR_DOMAIN_ROOTS = (
    ControlPlaneError,
    SessionStoreError,
    ReviewOverlayError,
    IngestionPipelineError,
)


def _api_error_policy(error: Exception) -> _ApiErrorPolicy | None:
    """Resolve the most-specific declared policy independently of table order."""

    for error_class in type(error).__mro__:
        policy = _API_ERROR_POLICY_BY_CLASS.get(error_class)
        if policy is not None:
            return policy
    return None


def _bounded_public_error_detail(
    error: Exception,
    policy: _ApiErrorPolicy,
) -> str:
    """Return an exact declared public message, or the policy's safe fallback."""

    fallback = policy.public_detail
    # Message exposure is an exact-class capability. An undeclared subclass
    # may inherit an HTTP status via MRO, but it cannot inherit permission to
    # publish arbitrary exception text.
    if (
        not policy.expose_message
        or _API_ERROR_POLICY_BY_CLASS.get(type(error)) is not policy
    ):
        return fallback
    return bounded_public_error_detail(
        str(error),
        fallback=fallback,
        maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
    )


def _raise_api_error(error: Exception) -> NoReturn:
    if isinstance(error, _ControlPlaneAccessDenied):
        raise error
    if type(error) is _ControlPlaneHTTPResponse:
        raise error
    if isinstance(error, RequestValidationError):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="control-plane request validation failed",
        ) from error
    if isinstance(error, StarletteHTTPException):
        # `_raise_api_error` is reached from caught control-plane service/store
        # calls. Adapter-owned validation raises directly before this boundary;
        # a framework HTTP exception originating here is therefore untrusted
        # service output rather than an already-translated response.
        raise _ControlPlaneHTTPResponse(
            status_code=500,
            detail="internal control-plane operation failed",
        ) from error
    policy = _api_error_policy(error)
    if policy is not None:
        raise _ControlPlaneHTTPResponse(
            status_code=policy.status_code,
            detail=_bounded_public_error_detail(error, policy),
        ) from error
    raise error


def _scope(
    request: Request,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
) -> ReviewScope:
    tenant_id = _catalog_identifier(tenant_id, "tenant_id")
    project_id = _catalog_identifier(project_id, "project_id")
    workspace_id = _catalog_identifier(workspace_id, "workspace_id")
    try:
        requested_scope = ReviewScope(tenant_id, project_id, workspace_id)
    except ReviewValidationError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="control-plane scope is invalid",
        ) from error
    control_plane = _control_plane(request)
    try:
        workspace = control_plane.sessions.get_workspace(
            tenant_id,
            workspace_id,
        )
        if workspace.project_id != project_id:
            raise KeyError(workspace_id)
        return requested_scope
    except Exception as error:  # normalized at the HTTP boundary
        _raise_api_error(error)


def _import_scope(
    request: Request,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
) -> ImportScope:
    selected_tenant_id = _import_identifier(
        tenant_id,
        "tenant_id",
        maximum=MAX_IMPORT_SCOPE_ID_LENGTH,
    )
    selected_project_id = _import_identifier(
        project_id,
        "project_id",
        maximum=MAX_IMPORT_SCOPE_ID_LENGTH,
    )
    selected_workspace_id = _import_identifier(
        workspace_id,
        "workspace_id",
        maximum=MAX_IMPORT_SCOPE_ID_LENGTH,
    )
    selected = _scope(
        request,
        selected_tenant_id,
        selected_project_id,
        selected_workspace_id,
    )
    return ImportScope(
        selected.tenant_id,
        selected.project_id,
        selected.workspace_id,
    )


def _session_in_workspace(
    request: Request,
    tenant_id: str,
    workspace_id: str,
    session_id: str,
) -> Any:
    tenant_id = _catalog_identifier(tenant_id, "tenant_id")
    workspace_id = _catalog_identifier(workspace_id, "workspace_id")
    session_id = _catalog_identifier(session_id, "session_id")
    try:
        session = _control_plane(request).sessions.get_session(
            tenant_id,
            session_id,
        )
        if session.workspace_id != workspace_id:
            raise KeyError(session_id)
        return session
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/health")
def control_plane_health(
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Report durable queue health without tenant or analysis-session state."""

    response.headers["Cache-Control"] = "no-store"
    status = control_plane_service_health(request.app.state)
    return {
        "status": "ok" if status["healthy"] else "degraded",
        **status,
    }


def _diagnostic_counter(value: object) -> int | str:
    if type(value) is not int or not 0 <= value <= MAX_OPERATIONAL_COUNTER:
        raise ValueError("operational diagnostic counter is invalid")
    return str(value) if value > MAX_JSON_SAFE_INTEGER else value


def _operational_diagnostics_payload(
    operational: OperationalEventDiagnosticsSnapshot,
    access: ControlPlaneAccessTelemetrySnapshot,
) -> dict[str, Any]:
    if type(operational) is not OperationalEventDiagnosticsSnapshot:
        raise TypeError("operational diagnostics snapshot is invalid")
    if type(access) is not ControlPlaneAccessTelemetrySnapshot:
        raise TypeError("access diagnostics snapshot is invalid")
    if set(operational.event_classes) != set(OPERATIONAL_EVENT_CONTRACT):
        raise ValueError("operational event diagnostics are incomplete")
    channel = operational.channel
    event_classes = []
    for event in sorted(OPERATIONAL_EVENT_CONTRACT):
        counters = operational.event_classes[event]
        event_classes.append(
            {
                "event": event,
                "accepted_events": _diagnostic_counter(counters.accepted_events),
                "queue_full_drops": _diagnostic_counter(counters.queue_full_drops),
                "rejected_events": _diagnostic_counter(counters.rejected_events),
                "delivery_failures": _diagnostic_counter(counters.delivery_failures),
            }
        )
    healthy = (
        channel.dropped_events == 0
        and channel.delivery_failures == 0
        and access.enqueue_failures == 0
        and access.invalid_denials == 0
    )
    return {
        "schema": "rda.operational-diagnostics.v1",
        "status": "ok" if healthy else "degraded",
        "operational_events": {
            "accepted_events": _diagnostic_counter(channel.accepted_events),
            "dropped_events": _diagnostic_counter(channel.dropped_events),
            "delivery_failures": _diagnostic_counter(channel.delivery_failures),
            "queue_depth": _diagnostic_counter(channel.queue_depth),
            "queue_capacity": _diagnostic_counter(channel.queue_capacity),
            "worker_alive": bool(channel.worker_alive),
            "event_classes": event_classes,
        },
        "access_denial_sampling": {
            "observed_denials": _diagnostic_counter(access.observed_denials),
            "emitted_events": _diagnostic_counter(access.emitted_events),
            "intentionally_suppressed": _diagnostic_counter(
                access.intentionally_suppressed
            ),
            "enqueue_failures": _diagnostic_counter(access.enqueue_failures),
            "invalid_denials": _diagnostic_counter(access.invalid_denials),
            "admitted_keys": _diagnostic_counter(access.admitted_keys),
            "key_capacity": _diagnostic_counter(access.key_capacity),
            "overflow_observations": _diagnostic_counter(access.overflow_observations),
            "overflow_emitted_events": _diagnostic_counter(
                access.overflow_emitted_events
            ),
            "global_suppressed": _diagnostic_counter(access.global_suppressed),
        },
    }


@control_plane_router.get("/diagnostics/operational-events")
def operational_event_diagnostics(
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Return authenticated process counters without operational payloads."""

    _require_control_plane_admin(request)
    response.headers["Cache-Control"] = "no-store"
    try:
        operational = operational_event_diagnostics_snapshot()
        access = _access_denial_reporter(request.app.state).snapshot()
        return _operational_diagnostics_payload(operational, access)
    except _PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise _ControlPlaneHTTPResponse(
            status_code=503,
            detail="operational diagnostics are unavailable",
        ) from error


def _subjects(payload: dict[str, Any]) -> tuple[ReviewSubject, ...]:
    values = payload.get("subjects")
    if not isinstance(values, list):
        raise _ControlPlaneHTTPResponse(
            status_code=422, detail="subjects must be an array"
        )
    try:
        normalized: list[ReviewSubject] = []
        for value in values:
            if not isinstance(value, dict):
                raise _ControlPlaneHTTPResponse(
                    status_code=422,
                    detail="review subject must be an object",
                )
            candidate = dict(value)
            for field in ("start_ns", "end_ns"):
                raw = candidate.get(field)
                if raw is not None:
                    candidate[field] = _request_canonical_integer(
                        raw,
                        field,
                    )
            normalized.append(ReviewSubject.from_dict(candidate))
        return tuple(normalized)
    except Exception as error:
        _raise_api_error(error)


def _review_annotation_kind(value: str) -> ReviewAnnotationKind:
    try:
        return ReviewAnnotationKind(value)
    except ValueError as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="unsupported review annotation kind",
        ) from error


def _edges(payload: dict[str, Any]) -> tuple[ManualCorrelationEdge, ...]:
    values = payload.get("edges")
    if not isinstance(values, list) or any(
        not isinstance(value, dict) for value in values
    ):
        raise _ControlPlaneHTTPResponse(
            status_code=422, detail="edges must be an array"
        )
    try:
        return tuple(
            ManualCorrelationEdge(
                source_ordinal=value.get("source_ordinal"),
                target_ordinal=value.get("target_ordinal"),
                link_type=value.get("link_type"),
                directed=value.get("directed", True),
            )
            for value in values
        )
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/context")
def control_plane_context(
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    control_plane = _control_plane(request)
    identity = _resolved_identity(request)
    tenant_id = _tenant(x_tenant_id)
    projects = _visible_projects(
        control_plane,
        identity,
        tenant_id,
        limit=limit,
        offset=offset,
    )
    return {
        "enabled": True,
        "tenant_id": tenant_id,
        "principal_id": identity.principal_id,
        "can_admin": CONTROL_PLANE_ADMIN_ROLE in identity.roles,
        "can_write": CONTROL_PLANE_WRITE_ROLE in identity.roles,
        "limit": limit,
        "offset": offset,
        "next_offset": offset + len(projects) if len(projects) == limit else None,
        "projects": [_json_value(item) for item in projects],
    }


@control_plane_router.get("/projects")
def list_projects(
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    try:
        control_plane = _control_plane(request)
        identity = _resolved_identity(request)
        values = _visible_projects(
            control_plane,
            identity,
            _tenant(x_tenant_id),
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post("/projects", status_code=201)
def create_project(
    request: Request,
    payload: dict[str, Any],
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    control_plane = _control_plane(request)
    body = _body_object(payload)
    requested_project_id = _catalog_optional_identifier(
        body.get("project_id"),
        "project_id",
    )
    label = _catalog_label(body.get("label"), "project label")
    metadata = _catalog_metadata(body.get("metadata", {}), "project metadata")
    operation_key = _catalog_idempotency_key(idempotency_key)
    identity = _resolved_identity(request)
    if identity.project_ids is not None and (
        requested_project_id is None or requested_project_id not in identity.project_ids
    ):
        _deny_control_plane_access(
            status_code=403,
            public_detail="requested project creation is not authorized",
            phase=ControlPlaneAccessPhase.SCOPE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.PROJECT_CREATION_SCOPE_DENIED,
            identity=identity,
        )
    try:
        result = control_plane.sessions.create_project(
            _tenant(x_tenant_id),
            label,
            project_id=requested_project_id,
            metadata=metadata,
            idempotency_key=operation_key,
        )
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces")
def list_workspaces(
    project_id: str,
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    try:
        control_plane = _control_plane(request)
        identity = _resolved_identity(request)
        values = _visible_workspaces(
            control_plane,
            identity,
            _tenant(x_tenant_id),
            project_id,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces",
    status_code=201,
)
def create_workspace(
    project_id: str,
    request: Request,
    payload: dict[str, Any],
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    control_plane = _control_plane(request)
    body = _body_object(payload)
    requested_workspace_id = _catalog_optional_identifier(
        body.get("workspace_id"),
        "workspace_id",
    )
    label = _catalog_label(body.get("label"), "workspace label")
    metadata = _catalog_metadata(body.get("metadata", {}), "workspace metadata")
    operation_key = _catalog_idempotency_key(idempotency_key)
    identity = _resolved_identity(request)
    if identity.workspace_ids is not None and (
        requested_workspace_id is None
        or requested_workspace_id not in identity.workspace_ids
    ):
        _deny_control_plane_access(
            status_code=403,
            public_detail="requested workspace creation is not authorized",
            phase=ControlPlaneAccessPhase.SCOPE_AUTHORIZATION,
            reason=(ControlPlaneAccessReason.WORKSPACE_CREATION_SCOPE_DENIED),
            identity=identity,
        )
    try:
        result = control_plane.sessions.create_workspace(
            _tenant(x_tenant_id),
            _catalog_identifier(project_id, "project_id"),
            label,
            workspace_id=requested_workspace_id,
            metadata=metadata,
            idempotency_key=operation_key,
        )
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/retention/preview"
)
async def preview_workspace_retention(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """Return the bounded cross-store inventory without mutating any store."""

    _require_control_plane_admin(request)
    catalog_policy, review_policy = _retention_policies(_body_object(payload))
    tenant_id = _tenant(x_tenant_id)
    scope = _scope(request, tenant_id, project_id, workspace_id)
    try:
        # Retention inventory performs bounded synchronous SQLite/filesystem
        # reads.  Keep it off the event loop, but also out of Starlette's
        # shared sync-route limiter so concurrent previews cannot consume the
        # worker tokens used by health and other small synchronous routes.
        result = await asyncio.to_thread(
            _control_plane(request).retention_inventory,
            scope,
            catalog_policy=catalog_policy,
            review_policy=review_policy,
        )
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/retention/execute"
)
def execute_workspace_retention(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    """Execute one bounded, audited, workspace-scoped retention saga."""

    identity = _require_control_plane_admin(request)
    catalog_policy, review_policy = _retention_policies(_body_object(payload))
    operation_id = _retention_operation_id(idempotency_key)
    actor = _request_bounded_text(
        identity.principal_id,
        "retention actor",
        maximum=MAX_RETENTION_ACTOR_LENGTH,
        reject_controls=True,
        reject_surrounding_whitespace=True,
    )
    tenant_id = _tenant(x_tenant_id)
    scope = _scope(request, tenant_id, project_id, workspace_id)
    try:
        return _json_value(
            _control_plane(request).run_retention(
                scope,
                catalog_policy=catalog_policy,
                review_policy=review_policy,
                actor=actor,
                operation_id=operation_id,
            )
        )
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/retention/audit"
)
def list_workspace_retention_audit(
    project_id: str,
    workspace_id: str,
    request: Request,
    limit: int = Query(
        default=100,
        ge=1,
        le=MAX_RETENTION_AUDIT_LIMIT,
    ),
    catalog_after_sequence: int = Query(
        default=0,
        ge=0,
        le=MAX_JSON_SAFE_INTEGER,
    ),
    review_after_sequence: int = Query(
        default=0,
        ge=0,
        le=MAX_JSON_SAFE_INTEGER,
    ),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    """List bounded retention journals from all three durable stores."""

    _require_control_plane_admin(request)
    tenant_id = _tenant(x_tenant_id)
    ingestion_scope = _import_scope(
        request,
        tenant_id,
        project_id,
        workspace_id,
    )
    scope = ReviewScope(
        ingestion_scope.tenant_id,
        ingestion_scope.project_id,
        ingestion_scope.workspace_id,
    )
    control_plane = _control_plane(request)
    try:
        catalog = control_plane.sessions.list_retention_audit(
            tenant_id,
            workspace_id,
            after_sequence=catalog_after_sequence,
            limit=limit,
        )
        review = control_plane.annotations.list_retention_audit(
            scope,
            after_sequence=review_after_sequence,
            limit=limit,
        )
        ingestion = control_plane.ingestion.list_retention_audits(
            ingestion_scope,
            limit=limit,
        )
        return {
            "scope": _json_value(scope),
            "catalog": [_json_value(item) for item in catalog],
            "review": [_json_value(item) for item in review],
            "ingestion": [_json_value(item) for item in ingestion],
            "catalog_next_after_sequence": (
                catalog[-1].sequence if len(catalog) == limit else None
            ),
            "review_next_after_sequence": (
                review[-1].sequence if len(review) == limit else None
            ),
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces/{workspace_id}/fixtures")
def list_fixtures(
    project_id: str,
    workspace_id: str,
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        values = _control_plane(request).sessions.list_fixtures(
            tenant_id,
            workspace_id,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces/{workspace_id}/revisions")
def list_revisions(
    project_id: str,
    workspace_id: str,
    request: Request,
    node_id: str | None = Query(default=None),
    fixture_id: str | None = Query(default=None),
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    selected_node_id = _catalog_optional_identifier(node_id, "node_id")
    selected_fixture_id = _catalog_optional_identifier(fixture_id, "fixture_id")
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        values = _control_plane(request).sessions.list_revisions(
            tenant_id,
            workspace_id,
            node_id=selected_node_id,
            fixture_id=selected_fixture_id,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces/{workspace_id}/sessions")
def list_sessions(
    project_id: str,
    workspace_id: str,
    request: Request,
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        values = _control_plane(request).sessions.list_sessions(
            tenant_id,
            workspace_id,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions",
    status_code=201,
)
def create_session(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    body = _body_object(payload)
    label = _catalog_label(body.get("label"), "session label")
    selected_session_id = _catalog_optional_identifier(
        body.get("session_id"),
        "session_id",
    )
    metadata = _catalog_metadata(body.get("metadata", {}), "session metadata")
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        result = _control_plane(request).sessions.create_session(
            tenant_id,
            workspace_id,
            label,
            session_id=selected_session_id,
            metadata=metadata,
            idempotency_key=operation_key,
        )
        _etag(response, result.version)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}"
)
def get_session(
    project_id: str,
    workspace_id: str,
    session_id: str,
    request: Request,
    response: Response,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    result = _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        _etag(response, result.version)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.patch(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}"
)
def update_session(
    project_id: str,
    workspace_id: str,
    session_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    body = _body_object(payload)
    if not {"label", "metadata"} & body.keys():
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="session update requires label or metadata",
        )
    label = (
        _catalog_label(body.get("label"), "session label") if "label" in body else None
    )
    metadata = (
        _catalog_metadata(body.get("metadata"), "session metadata")
        if "metadata" in body
        else None
    )
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        result = _control_plane(request).sessions.update_session(
            tenant_id,
            session_id,
            expected_version=expected_version,
            label=label,
            metadata=metadata,
            replace_metadata="metadata" in body,
            idempotency_key=operation_key,
        )
        _etag(response, result.version)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.delete(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}"
)
def delete_session(
    project_id: str,
    workspace_id: str,
    session_id: str,
    request: Request,
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        result = _control_plane(request).sessions.delete_session(
            tenant_id,
            session_id,
            expected_version=expected_version,
            idempotency_key=operation_key,
        )
        response.headers["Cache-Control"] = "no-store"
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.put(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/"
    "{session_id}/members/{member_id}"
)
def put_session_member(
    project_id: str,
    workspace_id: str,
    session_id: str,
    member_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    body = _body_object(payload)
    fixture_id = _catalog_identifier(body.get("fixture_id"), "fixture_id")
    revision_id = _catalog_identifier(body.get("revision_id"), "revision_id")
    try:
        role = validate_catalog_member_role(body.get("role", "member"))
    except (TypeError, ValueError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422, detail="role is invalid"
        ) from error
    make_default = body.get("make_default", False)
    if type(make_default) is not bool:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="make_default must be a boolean",
        )
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        result = _control_plane(request).sessions.put_member(
            tenant_id,
            session_id,
            member_id,
            fixture_id=fixture_id,
            revision_id=revision_id,
            expected_version=expected_version,
            role=role,
            make_default=make_default,
            idempotency_key=operation_key,
        )
        if result.workspace_id != workspace_id:
            raise KeyError(session_id)
        _etag(response, result.version)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.delete(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/"
    "{session_id}/members/{member_id}"
)
def delete_session_member(
    project_id: str,
    workspace_id: str,
    session_id: str,
    member_id: str,
    request: Request,
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        result = _control_plane(request).sessions.delete_member(
            tenant_id,
            session_id,
            member_id,
            expected_version=expected_version,
            idempotency_key=operation_key,
        )
        if result.workspace_id != workspace_id:
            raise KeyError(session_id)
        _etag(response, result.version)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}/snapshots",
    status_code=201,
)
def snapshot_session(
    project_id: str,
    workspace_id: str,
    session_id: str,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    operation_key = _catalog_idempotency_key(idempotency_key)
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    _session_in_workspace(
        request,
        tenant_id,
        workspace_id,
        session_id,
    )
    try:
        result = _control_plane(request).sessions.snapshot_session(
            tenant_id,
            session_id,
            expected_version=expected_version,
            idempotency_key=operation_key,
        )
        if result.workspace_id != workspace_id:
            raise KeyError(session_id)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces/{workspace_id}/snapshots")
def list_session_snapshots(
    project_id: str,
    workspace_id: str,
    request: Request,
    session_id: str | None = Query(default=None),
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    selected_session_id = _catalog_optional_identifier(session_id, "session_id")
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        values = _control_plane(request).sessions.list_snapshots(
            tenant_id,
            workspace_id,
            session_id=selected_session_id,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_json_value(item) for item in values],
            "next_offset": offset + len(values) if len(values) == limit else None,
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/snapshots/{snapshot_id}"
)
def get_session_snapshot(
    project_id: str,
    workspace_id: str,
    snapshot_id: str,
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _tenant(x_tenant_id)
    _scope(request, tenant_id, project_id, workspace_id)
    try:
        result = _control_plane(request).sessions.get_snapshot(
            tenant_id,
            snapshot_id,
        )
        if result.workspace_id != workspace_id:
            raise KeyError(snapshot_id)
        return _json_value(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get("/projects/{project_id}/workspaces/{workspace_id}/imports")
def list_imports(
    project_id: str,
    workspace_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    before_created_at_ns: str | None = Query(default=None),
    before_import_id: str | None = Query(default=None),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    if (before_created_at_ns is None) != (before_import_id is None):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=(
                "before_created_at_ns and before_import_id must be supplied together"
            ),
        )
    selected_before_import_id = (
        None
        if before_import_id is None
        else _import_identifier(before_import_id, "before_import_id")
    )
    parsed_before_created_at_ns = (
        None
        if before_created_at_ns is None
        else _request_canonical_integer(
            before_created_at_ns,
            "before_created_at_ns",
        )
    )
    scope = _import_scope(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
    )
    try:
        values = _control_plane(request).ingestion.list_imports(
            scope,
            limit=limit,
            before_created_at_ns=parsed_before_created_at_ns,
            before_import_id=selected_before_import_id,
        )
        return {
            "items": [value.as_dict() for value in values],
            "next_cursor": (
                {
                    "before_created_at_ns": str(values[-1].created_at_ns),
                    "before_import_id": values[-1].import_id,
                }
                if len(values) == limit
                else None
            ),
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/imports",
    status_code=202,
)
async def upload_import(
    project_id: str,
    workspace_id: str,
    request: Request,
    original_name: str = Query(
        ...,
        min_length=1,
        max_length=MAX_FILENAME_LENGTH,
    ),
    auto_select: bool = Query(default=True),
    preferred_plugin_id: str | None = Query(default=None, max_length=128),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    x_node_hint: str | None = Header(
        default=None,
        alias="X-Node-Hint",
        max_length=MAX_NODE_HINT_LENGTH,
    ),
    x_import_metadata: str | None = Header(
        default=None,
        alias="X-Import-Metadata",
        max_length=MAX_IMPORT_METADATA_BYTES,
    ),
    content_type: str | None = Header(
        default=None,
        alias="Content-Type",
        max_length=MAX_CONTENT_TYPE_LENGTH,
    ),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
        max_length=MAX_IDEMPOTENCY_KEY_LENGTH,
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    selected_original_name = _request_bounded_text(
        original_name,
        "original_name",
        maximum=MAX_FILENAME_LENGTH,
    )
    selected_content_type = _request_bounded_text(
        content_type or "application/octet-stream",
        "Content-Type",
        maximum=MAX_CONTENT_TYPE_LENGTH,
    )
    selected_idempotency_key = (
        None
        if idempotency_key is None
        else _request_bounded_text(
            idempotency_key,
            "Idempotency-Key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
    )
    selected_preferred_plugin_id = (
        None
        if preferred_plugin_id is None
        else _import_identifier(
            preferred_plugin_id,
            "preferred_plugin_id",
            maximum=MAX_IMPORT_SCOPE_ID_LENGTH,
        )
    )
    selected_node_hint = (
        None
        if x_node_hint is None
        else _request_bounded_text(
            x_node_hint,
            "X-Node-Hint",
            maximum=MAX_NODE_HINT_LENGTH,
        )
    )
    try:
        import_metadata = validate_import_metadata(
            _import_metadata_header(x_import_metadata)
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="X-Import-Metadata violates the bounded JSON contract",
        ) from error
    except Exception as error:
        _raise_api_error(error)
    content_length = request.headers.get("content-length")
    announced: int | None = None
    if content_length is not None:
        try:
            announced = parse_canonical_decimal_integer(
                content_length,
                "Content-Length",
                minimum=0,
            )
        except CanonicalIntegerError as error:
            raise _ControlPlaneHTTPResponse(
                status_code=400,
                detail=_canonical_integer_http_detail(
                    error,
                    grammar_detail=(
                        "Content-Length must be a canonical decimal integer"
                    ),
                ),
            ) from error
    control_plane = _control_plane(request)
    if (
        announced is not None
        and announced > control_plane.ingestion.limits.max_upload_bytes
    ):
        raise _ControlPlaneHTTPResponse(status_code=413, detail="upload is too large")
    scope = _import_scope(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
    )
    # The object must remain open while ``to_thread`` consumes its iterator;
    # the explicit finally below closes it on every disconnect/error path.
    spool = tempfile.SpooledTemporaryFile(  # noqa: SIM115
        max_size=min(
            MAX_UPLOAD_SPOOL_MEMORY,
            control_plane.ingestion.limits.max_upload_bytes,
        ),
        mode="w+b",
    )
    byte_count = 0
    try:
        async for chunk in request.stream():
            byte_count += len(chunk)
            if byte_count > control_plane.ingestion.limits.max_upload_bytes:
                raise _ControlPlaneHTTPResponse(
                    status_code=413, detail="upload is too large"
                )
            # SpooledTemporaryFile rolls over to synchronous disk I/O.  Keep
            # that work away from the server event loop for large uploads.
            await asyncio.to_thread(spool.write, chunk)
        await asyncio.to_thread(spool.seek, 0)

        def chunks() -> Any:
            while block := spool.read(
                control_plane.ingestion.limits.upload_chunk_bytes
            ):
                yield block

        try:
            result = await asyncio.to_thread(
                control_plane.ingestion.submit_chunks,
                scope,
                chunks(),
                original_name=selected_original_name,
                content_type=selected_content_type,
                idempotency_key=selected_idempotency_key,
                auto_select=auto_select,
                preferred_plugin_id=selected_preferred_plugin_id,
                node_hint=selected_node_hint,
                metadata=import_metadata,
            )
            return result.as_dict()
        except Exception as error:
            _raise_api_error(error)
    finally:
        await asyncio.to_thread(spool.close)


def _selected_import(
    request: Request,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
    import_id: str,
) -> tuple[Any, ImportScope]:
    import_id = _import_identifier(import_id, "import_id")
    scope = _import_scope(
        request,
        tenant_id,
        project_id,
        workspace_id,
    )
    try:
        return _control_plane(request).ingestion.get_import(scope, import_id), scope
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}"
)
def get_import(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    result, _ = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    return result.as_dict()


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/candidates"
)
def import_candidates(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    try:
        values = _control_plane(request).ingestion.candidates(scope, import_id)
        return {"items": [item.as_dict() for item in values]}
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/events"
)
def import_events(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    after_sequence: str = Query(default="0"),
    limit: int = Query(default=200, ge=1, le=1_000),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    parsed_after_sequence = _request_canonical_integer(
        after_sequence,
        "after_sequence",
        maximum=MAX_JSON_SAFE_INTEGER,
    )
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    try:
        values = _control_plane(request).ingestion.events(
            scope,
            import_id,
            after_sequence=parsed_after_sequence,
            limit=limit,
        )
        return {"items": [item.as_dict() for item in values]}
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/events/stream"
)
async def stream_import_events(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    after_sequence: str = Query(default="0"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> StreamingResponse:
    parsed_after_sequence = _request_canonical_integer(
        after_sequence,
        "after_sequence",
        maximum=MAX_JSON_SAFE_INTEGER,
    )
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    control_plane = _control_plane(request)

    async def stream() -> Any:
        cursor = parsed_after_sequence
        while not await request.is_disconnected():
            events = await asyncio.to_thread(
                control_plane.ingestion.events,
                scope,
                import_id,
                after_sequence=cursor,
                limit=200,
            )
            for event in events:
                cursor = event.sequence
                yield (
                    f"id: {event.sequence}\n"
                    f"event: {event.event_type}\n"
                    f"data: {json.dumps(event.as_dict(), separators=(',', ':'))}\n\n"
                )
            descriptor = await asyncio.to_thread(
                control_plane.ingestion.get_import,
                scope,
                import_id,
            )
            if descriptor.state.terminal and not events:
                yield "event: end\ndata: {}\n\n"
                return
            if not events:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/selection"
)
def select_import_plugin(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    payload: dict[str, Any],
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    _principal(x_principal_id)
    if idempotency_key is None:
        raise _ControlPlaneHTTPResponse(
            status_code=428, detail="Idempotency-Key is required"
        )
    selected_idempotency_key = _request_bounded_text(
        idempotency_key,
        "Idempotency-Key",
        maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
    )
    body = _body_object(payload)
    probe_set_hash = _request_bounded_text(
        body.get("probe_set_hash"),
        "probe_set_hash",
        maximum=256,
    )
    plugin_id = _request_bounded_text(
        body.get("plugin_id"),
        "plugin_id",
        maximum=256,
    )
    plugin_version = _request_bounded_text(
        body.get("plugin_version"),
        "plugin_version",
        maximum=128,
    )
    package_hash = _request_bounded_text(
        body.get("package_hash"),
        "package_hash",
        maximum=256,
    )
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    try:
        result = _control_plane(request).ingestion.select_plugin(
            scope,
            import_id,
            probe_set_hash=probe_set_hash,
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            package_hash=package_hash,
            idempotency_key=selected_idempotency_key,
        )
        return result.as_dict()
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/resume"
)
def resume_import(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    _principal(x_principal_id)
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    try:
        return _control_plane(request).ingestion.resume(scope, import_id).as_dict()
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}/cancel"
)
def cancel_import(
    project_id: str,
    workspace_id: str,
    import_id: str,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    _, scope = _selected_import(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
        import_id,
    )
    try:
        return (
            _control_plane(request)
            .ingestion.cancel(
                scope,
                import_id,
                expected_version=expected_version,
            )
            .as_dict()
        )
    except Exception as error:
        _raise_api_error(error)


def _review_scope_from_path(
    request: Request,
    x_tenant_id: str | None,
    project_id: str,
    workspace_id: str,
) -> ReviewScope:
    return _scope(
        request,
        _tenant(x_tenant_id),
        project_id,
        workspace_id,
    )


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/annotations"
)
def list_annotations(
    project_id: str,
    workspace_id: str,
    request: Request,
    include_deleted: bool = Query(default=False),
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    expected_audit_watermark: str | None = Query(default=None),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    parsed_expected_watermark = (
        None
        if expected_audit_watermark is None
        else _request_canonical_integer(
            expected_audit_watermark,
            "expected_audit_watermark",
        )
    )
    if offset > 0 and parsed_expected_watermark is None:
        raise _ControlPlaneHTTPResponse(
            status_code=428,
            detail=(
                "expected_audit_watermark is required when continuing "
                "annotation pagination"
            ),
        )
    try:
        values, audit_watermark = _control_plane(
            request
        ).annotations.list_annotations_page(
            scope,
            include_deleted=include_deleted,
            limit=limit,
            offset=offset,
            expected_audit_watermark=parsed_expected_watermark,
        )
        return {
            "items": [_review_json(item) for item in values],
            "audit_watermark": str(audit_watermark),
        }
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/annotations",
    status_code=201,
)
def create_annotation(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    operation_key = _review_idempotency_key(idempotency_key)
    body = _body_object(payload)
    annotation_id = (
        None
        if body.get("annotation_id") is None
        else _review_identifier(body.get("annotation_id"), "annotation_id")
    )
    subjects = _subjects(body)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).create_annotation(
            scope,
            kind=_review_annotation_kind(_required_text(body, "kind")),
            subjects=subjects,
            author=actor,
            title=body.get("title", ""),
            body=body.get("body", ""),
            tags=_iterable_strings(body, "tags"),
            annotation_id=annotation_id,
            idempotency_key=operation_key,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/annotations/{annotation_id}"
)
def get_annotation(
    project_id: str,
    workspace_id: str,
    annotation_id: str,
    request: Request,
    response: Response,
    include_deleted: bool = Query(default=False),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).annotations.get_annotation(
            scope,
            annotation_id,
            include_deleted=include_deleted,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.patch(
    "/projects/{project_id}/workspaces/{workspace_id}/annotations/{annotation_id}"
)
def update_annotation(
    project_id: str,
    workspace_id: str,
    annotation_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    body = _body_object(payload)
    try:
        updates: dict[str, Any] = {}
        if "kind" in body:
            updates["kind"] = _review_annotation_kind(_required_text(body, "kind"))
        if "subjects" in body:
            updates["subjects"] = _subjects(body)
        for field in ("title", "body"):
            if field in body:
                if not isinstance(body[field], str):
                    raise _ControlPlaneHTTPResponse(
                        status_code=422,
                        detail=f"{field} must be a string",
                    )
                updates[field] = body[field]
        if "tags" in body:
            updates["tags"] = _iterable_strings(body, "tags")
        result = _control_plane(request).update_annotation(
            scope,
            annotation_id,
            expected_version=expected_version,
            actor=actor,
            **updates,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.delete(
    "/projects/{project_id}/workspaces/{workspace_id}/annotations/{annotation_id}"
)
def delete_annotation(
    project_id: str,
    workspace_id: str,
    annotation_id: str,
    request: Request,
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).delete_annotation(
            scope,
            annotation_id,
            expected_version=expected_version,
            actor=actor,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/correlations"
)
def list_correlations(
    project_id: str,
    workspace_id: str,
    request: Request,
    include_deleted: bool = Query(default=False),
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        values = _control_plane(request).annotations.list_correlations(
            scope,
            include_deleted=include_deleted,
            limit=limit,
            offset=offset,
        )
        return {"items": [_review_json(item) for item in values]}
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/correlations",
    status_code=201,
)
def create_correlation(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
    ),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    operation_key = _review_idempotency_key(idempotency_key)
    body = _body_object(payload)
    correlation_id = (
        None
        if body.get("correlation_id") is None
        else _review_identifier(body.get("correlation_id"), "correlation_id")
    )
    subjects = _subjects(body)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).create_correlation(
            scope,
            subjects=subjects,
            edges=_edges(body),
            author=actor,
            rationale=body.get("rationale", ""),
            tags=_iterable_strings(body, "tags"),
            confidence=body.get("confidence"),
            correlation_id=correlation_id,
            idempotency_key=operation_key,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/correlations/{correlation_id}"
)
def get_correlation(
    project_id: str,
    workspace_id: str,
    correlation_id: str,
    request: Request,
    response: Response,
    include_deleted: bool = Query(default=False),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).annotations.get_correlation(
            scope,
            correlation_id,
            include_deleted=include_deleted,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.patch(
    "/projects/{project_id}/workspaces/{workspace_id}/correlations/{correlation_id}"
)
def update_correlation(
    project_id: str,
    workspace_id: str,
    correlation_id: str,
    request: Request,
    payload: dict[str, Any],
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    body = _body_object(payload)
    try:
        updates: dict[str, Any] = {}
        if "subjects" in body:
            updates["subjects"] = _subjects(body)
        if "edges" in body:
            updates["edges"] = _edges(body)
        if "rationale" in body:
            if not isinstance(body["rationale"], str):
                raise _ControlPlaneHTTPResponse(
                    status_code=422,
                    detail="rationale must be a string",
                )
            updates["rationale"] = body["rationale"]
        if "tags" in body:
            updates["tags"] = _iterable_strings(body, "tags")
        if "confidence" in body:
            updates["confidence"] = body["confidence"]
        result = _control_plane(request).update_correlation(
            scope,
            correlation_id,
            expected_version=expected_version,
            actor=actor,
            **updates,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.delete(
    "/projects/{project_id}/workspaces/{workspace_id}/correlations/{correlation_id}"
)
def delete_correlation(
    project_id: str,
    workspace_id: str,
    correlation_id: str,
    request: Request,
    response: Response,
    if_match: str | None = Header(default=None, alias="If-Match"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    x_principal_id: str | None = Header(default=None, alias="X-Principal-ID"),
) -> dict[str, Any]:
    actor = _principal(x_principal_id)
    expected_version = _parse_if_match(if_match)
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        result = _control_plane(request).delete_correlation(
            scope,
            correlation_id,
            expected_version=expected_version,
            actor=actor,
        )
        _etag(response, result.version)
        return _review_json(result)
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.get(
    "/projects/{project_id}/workspaces/{workspace_id}/review-audit"
)
def review_audit(
    project_id: str,
    workspace_id: str,
    request: Request,
    after_sequence: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
    limit: int = Query(default=1_000, ge=1, le=MAX_PAGE_LIMIT),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        values = _control_plane(request).annotations.list_audit(
            scope,
            after_sequence=after_sequence,
            limit=limit,
        )
        return {"items": [_json_value(item) for item in values]}
    except Exception as error:
        _raise_api_error(error)


@control_plane_router.post(
    "/projects/{project_id}/workspaces/{workspace_id}/correlation-report"
)
def correlation_report(
    project_id: str,
    workspace_id: str,
    request: Request,
    payload: dict[str, Any],
    format: str = Query(default="json", pattern="^(json|markdown)$"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> Response:
    body = _body_object(payload)
    raw_revision_ids = body.get("revision_ids", [])
    if not isinstance(raw_revision_ids, list):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="revision_ids must be an array of strings",
        )
    control_plane = _control_plane(request)
    maximum_revision_ids = min(
        MAX_REFERENCE_REVISION_IDS,
        control_plane.limits.max_report_revisions,
    )
    if len(raw_revision_ids) > maximum_revision_ids:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=f"revision_ids supports at most {maximum_revision_ids} values",
        )
    revision_ids = tuple(
        _catalog_identifier(value, f"revision_ids[{index}]")
        for index, value in enumerate(raw_revision_ids)
    )
    session_id = _catalog_optional_identifier(body.get("session_id"), "session_id")
    snapshot_id = _catalog_optional_identifier(
        body.get("snapshot_id"),
        "snapshot_id",
    )
    selected_forms = sum(
        (
            bool(revision_ids),
            session_id is not None,
            snapshot_id is not None,
        )
    )
    if selected_forms > 1:
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail=("revision_ids, session_id, and snapshot_id are mutually exclusive"),
        )
    if len(revision_ids) != len(set(revision_ids)):
        raise _ControlPlaneHTTPResponse(
            status_code=422,
            detail="revision_ids must not contain duplicates",
        )
    scope = _review_scope_from_path(
        request,
        x_tenant_id,
        project_id,
        workspace_id,
    )
    try:
        report = control_plane.build_report(
            scope,
            revision_ids=revision_ids,
            session_id=session_id,
            snapshot_id=snapshot_id,
        )
    except Exception as error:
        _raise_api_error(error)
    headers = {
        "ETag": f'"sha256:{report.sha256}"',
        "Content-Disposition": (
            "attachment; filename=correlation-report."
            + ("md" if format == "markdown" else "json")
        ),
    }
    if format == "markdown":
        return PlainTextResponse(
            report.markdown,
            media_type="text/markdown",
            headers=headers,
        )
    return Response(
        content=report.canonical_json,
        media_type="application/json",
        headers=headers,
    )


__all__ = [
    "CONTROL_PLANE_ADMIN_ROLE",
    "CONTROL_PLANE_READ_ROLE",
    "CONTROL_PLANE_WRITE_ROLE",
    "ControlPlaneIdentity",
    "ControlPlaneIdentityResolver",
    "TrustedHeaderIdentityResolver",
    "control_plane_router",
]
