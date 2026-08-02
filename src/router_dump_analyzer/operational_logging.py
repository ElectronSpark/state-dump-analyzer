"""Bounded, non-blocking operational events for core service diagnostics.

Durable queue events and retention audits remain authoritative. This channel
is deliberately lossy: a slow or broken logging handler can consume only the
fixed-capacity background queue and can never block ingestion or retention.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from .public_text import (
    contains_probable_absolute_filesystem_path,
    contains_unsafe_invisible_text,
)

OPERATIONAL_LOG_SCHEMA: Final = "rda.operational.v1"
OPERATIONAL_LOGGER_NAME: Final = "router_dump_analyzer.operations"
MAX_OPERATIONAL_FIELDS: Final = 24
MAX_OPERATIONAL_FIELD_TEXT: Final = 256
MAX_OPERATIONAL_EVENT_BYTES: Final = 4 * 1024
DEFAULT_OPERATIONAL_QUEUE_SIZE: Final = 1_024
MAX_OPERATIONAL_COUNTER: Final = 2**63 - 1

# Libraries must not configure application logging, but an unconfigured
# ERROR record would otherwise be printed by Python's ``lastResort`` handler.
# One inert local handler suppresses that fallback while propagation still
# delivers records to any handler configured by the embedding application.
_MODULE_NULL_HANDLER: Final = logging.NullHandler()
logging.getLogger(OPERATIONAL_LOGGER_NAME).addHandler(_MODULE_NULL_HANDLER)


@dataclass(frozen=True, slots=True)
class _EventSpec:
    level: int
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class OperationalEventHealthSnapshot:
    """Aggregate-only state for the lossy operational event channel."""

    accepted_events: int
    dropped_events: int
    delivery_failures: int
    queue_depth: int
    queue_capacity: int
    worker_alive: bool


@dataclass(frozen=True, slots=True)
class OperationalEventClassHealthSnapshot:
    """Process-local counters for one declared event class.

    These diagnostics deliberately stay out of the anonymous HTTP health
    projection.  They let bounded producers distinguish their own intentional
    sampling from a real queue-capacity loss without changing the compatible
    aggregate health contract.
    """

    accepted_events: int
    queue_full_drops: int
    rejected_events: int
    delivery_failures: int


@dataclass(frozen=True, slots=True)
class OperationalEventDiagnosticsSnapshot:
    """Atomic counters for every declared operational event class.

    The mapping contains only closed contract names and bounded counters.  It
    intentionally carries no event fields, payload text, tenant identifiers,
    or queue contents, so an authenticated adapter can project it without
    crossing the operational-event privacy boundary.
    """

    channel: OperationalEventHealthSnapshot
    event_classes: Mapping[str, OperationalEventClassHealthSnapshot]


_ACCESS_DENIAL_PHASE_REASON: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "request_source": frozenset({"host_rejected", "origin_rejected"}),
        "identity_verification": frozenset({"identity_verification_failed"}),
        "identity_binding": frozenset(
            {
                "tenant_required",
                "tenant_binding_mismatch",
                "principal_required",
                "principal_binding_mismatch",
            }
        ),
        "role_authorization": frozenset({"required_role_missing"}),
        "scope_authorization": frozenset(
            {
                "project_scope_denied",
                "workspace_scope_denied",
                "project_creation_scope_denied",
                "workspace_creation_scope_denied",
            }
        ),
    }
)
_ACCESS_DENIAL_ROLES = frozenset(
    {
        "control-plane:read",
        "control-plane:write",
        "control-plane:admin",
    }
)
_ACCESS_DENIAL_SAMPLING_SCOPES = frozenset({"exact", "overflow"})


def _spec(
    level: int,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> _EventSpec:
    return _EventSpec(level, frozenset(required), frozenset(optional))


OPERATIONAL_EVENT_CONTRACT: Mapping[str, _EventSpec] = MappingProxyType(
    {
        "ingestion.catalog_call.started": _spec(
            logging.INFO,
            ("import_id", "stage", "operation_id", "attempt", "timeout_ms"),
        ),
        "ingestion.catalog_call.completed": _spec(
            logging.INFO,
            (
                "import_id",
                "stage",
                "operation_id",
                "attempt",
                "duration_ms",
                "next_state",
            ),
            ("event_count", "source_record_count", "resource_count"),
        ),
        "ingestion.catalog_call.discarded": _spec(
            logging.WARNING,
            (
                "import_id",
                "stage",
                "operation_id",
                "attempt",
                "duration_ms",
                "reason",
                "remote_acknowledged",
            ),
        ),
        "ingestion.attempt.failed": _spec(
            logging.WARNING,
            (
                "import_id",
                "stage",
                "attempt",
                "error_code",
                "retryable",
                "ambiguous_external_outcome",
            ),
            ("operation_id",),
        ),
        "ingestion.worker.failure_sampled": _spec(
            logging.WARNING,
            ("phase", "error_family", "consecutive"),
        ),
        "ingestion.worker.exited": _spec(
            logging.ERROR,
            ("error_family", "unexpected_worker_exits"),
        ),
        "retention.run.started": _spec(
            logging.INFO,
            (
                "run_id",
                "mode",
                "policy_enabled",
                "idempotent",
                "max_delete_batch",
                "max_scan_entries",
            ),
        ),
        "retention.preview.completed": _spec(
            logging.INFO,
            (
                "run_id",
                "eligible_imports",
                "content_blobs",
                "revision_datasets",
                "stale_partials",
                "work_items",
                "truncated",
                "duration_ms",
            ),
        ),
        "retention.plan.committed": _spec(
            logging.INFO,
            (
                "run_id",
                "audit_id",
                "eligible_imports",
                "work_items",
                "truncated",
            ),
        ),
        "retention.scan.truncated": _spec(
            logging.INFO,
            ("run_id", "source", "limit", "observed_at_least"),
        ),
        "retention.cleanup.started": _spec(
            logging.INFO,
            (
                "run_id",
                "audit_id",
                "total_items",
                "completed_items",
                "pending_items",
                "resumed",
            ),
        ),
        "retention.cleanup.batch_completed": _spec(
            logging.DEBUG,
            (
                "run_id",
                "audit_id",
                "batch_index",
                "attempted_items",
                "checkpointed_items",
                "deleted_items",
                "skipped_items",
                "failed_items",
                "deleted_bytes",
                "remaining_items",
                "duration_ms",
            ),
        ),
        "retention.run.completed": _spec(
            logging.INFO,
            (
                "run_id",
                "audit_id",
                "deleted_imports",
                "deleted_files",
                "deleted_bytes",
                "deletion_failures",
                "truncated",
                "duration_ms",
            ),
        ),
        "retention.run.replayed": _spec(
            logging.INFO,
            ("run_id", "audit_id", "outcome"),
        ),
        "retention.run.failed": _spec(
            logging.ERROR,
            ("run_id", "phase", "error_family", "mutation_started"),
            ("audit_id",),
        ),
        "control_plane.access.denied": _spec(
            logging.WARNING,
            (
                "phase",
                "reason",
                "response_status",
                "request_method",
                "route_name",
                "mutating",
                "concealed",
                "occurrences",
                "suppressed_since_last",
                "enqueue_failures_since_last",
                "sampling_scope",
            ),
            ("required_role", "tenant_correlation"),
        ),
    }
)


def _valid_field_name(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 64
        and all(
            character.isascii() and (character.isalnum() or character == "_")
            for character in value
        )
    )


def _validated_fields(
    event: str,
    values: Mapping[str, Any],
) -> tuple[int, dict[str, bool | int | str]]:
    spec = OPERATIONAL_EVENT_CONTRACT[event]
    if not spec.required.issubset(values) or not set(values).issubset(
        spec.required | spec.optional
    ):
        raise ValueError("operational event fields do not match the contract")
    if len(values) > MAX_OPERATIONAL_FIELDS:
        raise ValueError("operational event has too many fields")
    fields: dict[str, bool | int | str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not _valid_field_name(key):
            raise ValueError("operational event field name is invalid")
        if type(value) is bool:
            fields[key] = value
        elif type(value) is int:
            if not 0 <= value <= MAX_OPERATIONAL_COUNTER:
                raise ValueError("operational event integer is invalid")
            fields[key] = value
        elif isinstance(value, str):
            if (
                not value
                or len(value) > MAX_OPERATIONAL_FIELD_TEXT
                or contains_unsafe_invisible_text(value)
                or contains_probable_absolute_filesystem_path(value)
            ):
                raise ValueError("operational event text is invalid")
            fields[key] = value
        else:
            raise ValueError("operational event value type is invalid")
    if event == "control_plane.access.denied":
        phase = fields["phase"]
        reason = fields["reason"]
        if (
            type(phase) is not str
            or type(reason) is not str
            or reason not in _ACCESS_DENIAL_PHASE_REASON.get(phase, ())
        ):
            raise ValueError("access-denial phase/reason vocabulary is invalid")
        if fields["sampling_scope"] not in _ACCESS_DENIAL_SAMPLING_SCOPES:
            raise ValueError("access-denial sampling scope is invalid")
        if fields["response_status"] not in {400, 401, 403, 404}:
            raise ValueError("access-denial response status is invalid")
        required_role = fields.get("required_role")
        if required_role is not None and required_role not in _ACCESS_DENIAL_ROLES:
            raise ValueError("access-denial required role is invalid")
        tenant_correlation = fields.get("tenant_correlation")
        if tenant_correlation is not None and (
            type(tenant_correlation) is not str
            or len(tenant_correlation) != 32
            or any(
                character not in "0123456789abcdef" for character in tenant_correlation
            )
        ):
            raise ValueError("access-denial tenant correlation is invalid")
    encoded = json.dumps(
        {"schema": OPERATIONAL_LOG_SCHEMA, "event": event, "fields": fields},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_OPERATIONAL_EVENT_BYTES:
        raise ValueError("operational event exceeds its byte budget")
    return spec.level, fields


class OperationalEventEmitter:
    """Best-effort fixed-capacity handoff to the standard logging stack."""

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        max_queue_size: int = DEFAULT_OPERATIONAL_QUEUE_SIZE,
    ) -> None:
        if (
            type(max_queue_size) is not int
            or not 1 <= max_queue_size <= MAX_OPERATIONAL_COUNTER
        ):
            raise ValueError("max_queue_size must be a positive integer")
        self._logger = logger or logging.getLogger(OPERATIONAL_LOGGER_NAME)
        self._queue: queue.Queue[tuple[int, str, dict[str, bool | int | str]]] = (
            queue.Queue(maxsize=max_queue_size)
        )
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._accepted_events = 0
        self._dropped_events = 0
        self._delivery_failures = 0
        self._accepted_by_event = {event: 0 for event in OPERATIONAL_EVENT_CONTRACT}
        self._queue_full_drops_by_event = {
            event: 0 for event in OPERATIONAL_EVENT_CONTRACT
        }
        self._rejected_by_event = {event: 0 for event in OPERATIONAL_EVENT_CONTRACT}
        self._delivery_failures_by_event = {
            event: 0 for event in OPERATIONAL_EVENT_CONTRACT
        }

    @property
    def accepted_events(self) -> int:
        with self._lock:
            return self._accepted_events

    @property
    def dropped_events(self) -> int:
        with self._lock:
            return self._dropped_events

    @property
    def delivery_failures(self) -> int:
        with self._lock:
            return self._delivery_failures

    def _record_drop(self, event: str | None, *, queue_full: bool) -> None:
        with self._lock:
            self._dropped_events = min(
                self._dropped_events + 1,
                MAX_OPERATIONAL_COUNTER,
            )
            if event is not None and event in OPERATIONAL_EVENT_CONTRACT:
                counters = (
                    self._queue_full_drops_by_event
                    if queue_full
                    else self._rejected_by_event
                )
                counters[event] = min(
                    counters[event] + 1,
                    MAX_OPERATIONAL_COUNTER,
                )

    def _record_accept_locked(self, event: str) -> None:
        """Commit producer acceptance before a worker can record delivery."""

        self._accepted_events = min(
            self._accepted_events + 1,
            MAX_OPERATIONAL_COUNTER,
        )
        self._accepted_by_event[event] = min(
            self._accepted_by_event[event] + 1,
            MAX_OPERATIONAL_COUNTER,
        )

    def event_class_health_snapshot(
        self,
        event: str,
    ) -> OperationalEventClassHealthSnapshot:
        """Return loss counters for one closed event class."""

        if event not in OPERATIONAL_EVENT_CONTRACT:
            raise ValueError("operational event name is not declared")
        with self._lock:
            return self._event_class_health_snapshot_locked(event)

    def _event_class_health_snapshot_locked(
        self,
        event: str,
    ) -> OperationalEventClassHealthSnapshot:
        return OperationalEventClassHealthSnapshot(
            accepted_events=self._accepted_by_event[event],
            queue_full_drops=self._queue_full_drops_by_event[event],
            rejected_events=self._rejected_by_event[event],
            delivery_failures=self._delivery_failures_by_event[event],
        )

    def diagnostics_snapshot(self) -> OperationalEventDiagnosticsSnapshot:
        """Return one lock-consistent snapshot of all declared event classes."""

        with self._lock:
            channel = self._health_snapshot_locked()
            event_classes = {
                event: self._event_class_health_snapshot_locked(event)
                for event in OPERATIONAL_EVENT_CONTRACT
            }
        return OperationalEventDiagnosticsSnapshot(
            channel=channel, event_classes=MappingProxyType(event_classes)
        )

    def health_snapshot(self) -> OperationalEventHealthSnapshot:
        """Return bounded counters without event content or caller identity."""

        with self._lock:
            return self._health_snapshot_locked()

    def _health_snapshot_locked(self) -> OperationalEventHealthSnapshot:
        worker = self._worker
        return OperationalEventHealthSnapshot(
            accepted_events=self._accepted_events,
            dropped_events=self._dropped_events,
            delivery_failures=self._delivery_failures,
            queue_depth=self._queue.qsize(),
            queue_capacity=self._queue.maxsize,
            worker_alive=worker is not None and worker.is_alive(),
        )

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            worker = threading.Thread(
                target=self._run,
                name="rda-operational-logger",
                daemon=True,
            )
            worker.start()
            self._worker = worker

    def _run(self) -> None:
        while True:
            level, event, fields = self._queue.get()
            try:
                self._logger.log(
                    level,
                    event,
                    extra={
                        "rda_schema": OPERATIONAL_LOG_SCHEMA,
                        "rda_event": event,
                        "rda_fields": fields,
                    },
                )
            except BaseException:  # noqa: BLE001 - logging is an isolation boundary.
                with self._lock:
                    self._delivery_failures = min(
                        self._delivery_failures + 1,
                        MAX_OPERATIONAL_COUNTER,
                    )
                    self._delivery_failures_by_event[event] = min(
                        self._delivery_failures_by_event[event] + 1,
                        MAX_OPERATIONAL_COUNTER,
                    )
            finally:
                self._queue.task_done()

    def emit(self, event: str, /, **fields: Any) -> bool:
        """Validate and enqueue one event without waiting for a handler."""

        try:
            if event not in OPERATIONAL_EVENT_CONTRACT:
                raise ValueError("operational event name is not declared")
            level, normalized = _validated_fields(event, fields)
        except Exception:  # noqa: BLE001 - telemetry must stay best effort.
            self._record_drop(
                event if event in OPERATIONAL_EVENT_CONTRACT else None,
                queue_full=False,
            )
            return False
        try:
            self._ensure_worker()
            with self._lock:
                self._queue.put_nowait((level, event, normalized))
                self._record_accept_locked(event)
            return True
        except queue.Full:
            self._record_drop(event, queue_full=True)
            return False
        except Exception:  # noqa: BLE001 - telemetry must stay best effort.
            self._record_drop(event, queue_full=False)
            return False

    def flush(self, *, timeout: float = 1.0) -> bool:
        """Wait boundedly for accepted events; intended for tests/shutdown."""

        if type(timeout) not in {int, float} or not 0 <= float(timeout) <= 60:
            raise ValueError("timeout must be between zero and 60 seconds")
        deadline = time.monotonic() + float(timeout)
        while self._queue.unfinished_tasks:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.001)
        return True


_DEFAULT_EMITTER = OperationalEventEmitter()


def emit_operational_event(event: str, /, **fields: Any) -> bool:
    """Emit through the process-global bounded operational channel."""

    return _DEFAULT_EMITTER.emit(event, **fields)


def flush_operational_events(*, timeout: float = 1.0) -> bool:
    return _DEFAULT_EMITTER.flush(timeout=timeout)


def operational_event_health_snapshot() -> OperationalEventHealthSnapshot:
    """Expose aggregate process-channel health without logging payloads."""

    return _DEFAULT_EMITTER.health_snapshot()


def operational_event_class_health_snapshot(
    event: str,
) -> OperationalEventClassHealthSnapshot:
    """Return process-local counters without expanding public health output."""

    return _DEFAULT_EMITTER.event_class_health_snapshot(event)


def operational_event_diagnostics_snapshot() -> OperationalEventDiagnosticsSnapshot:
    """Return atomic per-class counters without event or caller payloads."""

    return _DEFAULT_EMITTER.diagnostics_snapshot()


__all__ = [
    "MAX_OPERATIONAL_COUNTER",
    "MAX_OPERATIONAL_EVENT_BYTES",
    "OPERATIONAL_EVENT_CONTRACT",
    "OPERATIONAL_LOGGER_NAME",
    "OPERATIONAL_LOG_SCHEMA",
    "OperationalEventClassHealthSnapshot",
    "OperationalEventDiagnosticsSnapshot",
    "OperationalEventEmitter",
    "OperationalEventHealthSnapshot",
    "emit_operational_event",
    "flush_operational_events",
    "operational_event_class_health_snapshot",
    "operational_event_diagnostics_snapshot",
    "operational_event_health_snapshot",
]
