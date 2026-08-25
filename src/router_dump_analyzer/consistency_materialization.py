"""Plan-bound, fail-closed materialization of revision consistency findings.

This module deliberately does not build a revision world or publish a dataset.
It is the deterministic boundary between those two stages: callers supply an
already frozen execution plan, its exact plan-bound router, an immutable world,
and the artifact identities admitted to the revision.
"""

from __future__ import annotations

import json
from base64 import b64decode
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum, StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Any, Final
from uuid import UUID

from .canonical import (
    canonical_json,
    normalized_opaque_value_json,
    strict_canonical_json,
    strict_canonical_json_bytes,
)
from .capability_executor import PluginCapabilityOutputError
from .capability_router import (
    CapabilityProviderRef,
    CapabilityRouteSelector,
    PlanBoundCapabilityRouter,
)
from .plugin_api import (
    MAX_CAPTURE_RANGE_SCOPE_LENGTH,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    AbsoluteTimeSelector,
    CaptureRange,
    ClockAlignmentPolicy,
    ConsistencyFinding,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    Evidence,
    FindingResult,
    KeyAtom,
    PluginCapability,
    PluginDiagnostic,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionWatermark,
    RelationDirection,
    RelationshipView,
    RelativeToWatermarkSelector,
    ResolvedNodeBasis,
    ResourceKey,
    ResourceStateView,
    TemporalSelectorKind,
    WatermarkScope,
    WorldBasis,
    WorldBasisKind,
)
from .plugin_composition import REVISION_CONSISTENCY_ROLE
from .plugin_execution_plan import (
    PluginExecutionPin,
    PluginExecutionPlan,
    primary_parser_execution_pin,
    snapshot_plugin_execution_plan,
    validate_execution_identity,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .revision_world import _canonical_resource_identity
from .value_core import parse_canonical_decimal_integer

CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION: Final[str] = (
    "router_dump_analyzer.consistency_materialization.v1"
)
CONSISTENCY_MATERIALIZATION_COUNT_FIELDS: Final[tuple[str, ...]] = (
    "provider_count",
    "finding_count",
    "diagnostic_count",
    "emitted_finding_count",
    "emitted_diagnostic_count",
    "duplicate_findings_discarded",
    "duplicate_diagnostics_discarded",
    "world_reads",
)
CONSISTENCY_MATERIALIZATION_ENVELOPE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "status",
        "plan_digest",
        "basis",
        "basis_digest",
        "providers",
        *CONSISTENCY_MATERIALIZATION_COUNT_FIELDS,
    }
)
_MATERIALIZED_FINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "rule_id",
        "severity",
        "result",
        "summary",
        "resources",
        "resource_references",
        "provenance",
        "quality",
        "basis",
        "evidence",
        "details",
        "producer",
        "execution_plan_digest",
        "finding_id",
    }
)
_MATERIALIZED_DIAGNOSTIC_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "stage",
        "severity",
        "code",
        "message",
        "recoverable",
        "evidence",
        "details",
        "origin",
        "producer",
        "diagnostic_id",
    }
)
_MATERIALIZED_PROVIDER_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "member_id",
        "node_id",
        "basis_revision_id",
        "plan_digest",
        "instance_id",
        "plugin_id",
        "plugin_version",
        "registered_execution_identity",
        "configuration_digest",
        "schema_digest",
        "package_hash",
        "capability",
        "roles",
    }
)
_JSON_SAFE_INTEGER_MAX: Final[int] = (1 << 53) - 1


def _is_lowercase_sha256_digest(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _is_lowercase_package_digest(value: object) -> bool:
    if type(value) is not str:
        return False
    prefixes = (
        "sha256:",
        "manifest-sha256:",
        "module-sha256:",
        "package-sha256:",
    )
    for prefix in prefixes:
        if value.startswith(prefix):
            digest = value[len(prefix) :]
            return len(digest) == 64 and all(
                character in "0123456789abcdef" for character in digest
            )
    return False


def _exact_storage_record(
    value: object,
    fields: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    if type(value) is not dict or len(value) != len(fields):
        raise ValueError(f"{label} must use its exact canonical fields")
    if any(type(key) is not str or key not in fields for key in value):
        raise ValueError(f"{label} must use its exact canonical fields")
    return value


def _storage_text(
    value: object,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or (not allow_empty and not value)
        or "\x00" in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_materialized_provider_projection(
    value: object,
    label: str,
) -> Mapping[str, Any]:
    record = _exact_storage_record(value, _MATERIALIZED_PROVIDER_FIELDS, label)
    member_id = validate_execution_identity(
        record["member_id"],
        f"{label}.member_id",
    )
    basis_revision_id = validate_execution_identity(
        record["basis_revision_id"],
        f"{label}.basis_revision_id",
    )
    if member_id != basis_revision_id:
        raise ValueError(f"{label} member does not match its basis revision")
    validate_execution_identity(record["node_id"], f"{label}.node_id")
    validate_execution_identity(record["instance_id"], f"{label}.instance_id")
    validate_execution_identity(record["plugin_id"], f"{label}.plugin_id")
    validate_execution_identity(
        record["plugin_version"],
        f"{label}.plugin_version",
        maximum=128,
    )
    for field in (
        "plan_digest",
        "registered_execution_identity",
        "configuration_digest",
        "schema_digest",
    ):
        if not _is_lowercase_sha256_digest(record[field]):
            raise ValueError(f"{label}.{field} is invalid")
    if not _is_lowercase_package_digest(record["package_hash"]):
        raise ValueError(f"{label}.package_hash is invalid")
    if record["capability"] != PluginCapability.CONSISTENCY_CHECK.value:
        raise ValueError(f"{label}.capability is invalid")
    roles = record["roles"]
    if type(roles) is not list or len(roles) > 128:
        raise ValueError(f"{label}.roles is invalid")
    validated_roles = [
        validate_execution_identity(role, f"{label}.roles[{index}]")
        for index, role in enumerate(roles)
    ]
    if len(validated_roles) != len(set(validated_roles)):
        raise ValueError(f"{label}.roles contains duplicates")
    if not {"primary_parser", REVISION_CONSISTENCY_ROLE}.intersection(
        validated_roles
    ):
        raise ValueError(f"{label}.roles does not select consistency materialization")
    return record


def _validate_materialized_record_identity(
    record: Mapping[str, Any],
    *,
    identity_field: str,
    label: str,
) -> None:
    identifier = record[identity_field]
    if not _is_lowercase_sha256_digest(identifier):
        raise ValueError(f"{label} digest is invalid")
    payload = dict(record)
    payload.pop(identity_field)
    expected = "sha256:" + sha256(strict_canonical_json_bytes(payload)).hexdigest()
    if identifier != expected:
        raise ValueError(f"{label} digest does not match its record")


def _storage_timestamp(value: object, label: str, *, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise ValueError(f"{label} must be a canonical signed-64 string or null")
    try:
        parsed = parse_canonical_decimal_integer(
            value,
            label,
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
    except ValueError as error:
        raise ValueError(
            f"{label} must be a canonical signed-64 string or null"
        ) from error
    return parsed


def _validate_storage_json(
    value: object,
    label: str,
    *,
    depth: int = 0,
    units: list[int] | None = None,
) -> None:
    current_units = [0] if units is None else units
    if depth > 16:
        raise ValueError(f"{label} exceeds the storage depth limit")
    current_units[0] += 1
    if current_units[0] > 4_096:
        raise ValueError(f"{label} exceeds the storage value-unit limit")
    value_type = type(value)
    if value is None or value_type is bool:
        return
    if value_type is int:
        if value.bit_length() > 4_096:
            raise ValueError(f"{label} contains an oversized integer")
        return
    if value_type is float:
        if not isfinite(value):
            raise ValueError(f"{label} contains a non-finite number")
        return
    if value_type is str:
        if len(value) > 65_536:
            raise ValueError(f"{label} contains oversized text")
        return
    if value_type is list:
        if len(value) > 1_024:
            raise ValueError(f"{label} contains too many items")
        for item in value:
            _validate_storage_json(
                item,
                label,
                depth=depth + 1,
                units=current_units,
            )
        return
    if value_type is dict:
        if len(value) > 1_024:
            raise ValueError(f"{label} contains too many items")
        for key, item in value.items():
            _storage_text(key, f"{label} key", 256)
            _validate_storage_json(
                item,
                label,
                depth=depth + 1,
                units=current_units,
            )
        return
    raise ValueError(f"{label} contains an unsupported storage value")


_STORAGE_EVIDENCE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "artifact_id",
        "locator",
        "raw_timestamp_ns",
        "clock_domain",
        "excerpt_sha256",
    }
)


def _evidence_from_storage(
    value: object,
    label: str,
    *,
    artifact_ids: frozenset[UUID],
) -> Evidence:
    record = _exact_storage_record(value, _STORAGE_EVIDENCE_FIELDS, label)
    try:
        artifact_id = UUID(_storage_text(record["artifact_id"], label, 36))
    except ValueError as error:
        raise ValueError(f"{label}.artifact_id is invalid") from error
    if str(artifact_id) != record["artifact_id"]:
        raise ValueError(f"{label}.artifact_id is invalid")
    if artifact_id not in artifact_ids:
        raise ValueError(f"{label}.artifact_id is outside the revision inventory")
    clock_domain = record["clock_domain"]
    if clock_domain is not None:
        clock_domain = _storage_text(clock_domain, f"{label}.clock_domain", 256)
    excerpt_sha256 = record["excerpt_sha256"]
    if excerpt_sha256 is not None and (
        type(excerpt_sha256) is not str
        or len(excerpt_sha256) != 64
        or any(character not in "0123456789abcdef" for character in excerpt_sha256)
    ):
        raise ValueError(f"{label}.excerpt_sha256 is invalid")
    evidence = Evidence(
        artifact_id=artifact_id,
        locator=_storage_text(record["locator"], f"{label}.locator", 4_096),
        raw_timestamp_ns=_storage_timestamp(
            record["raw_timestamp_ns"],
            f"{label}.raw_timestamp_ns",
        ),
        clock_domain=clock_domain,
        excerpt_sha256=excerpt_sha256,
    )
    if strict_canonical_json(
        _evidence_projection(
            evidence,
            artifact_ids=artifact_ids,
            label=label,
        )
    ) != strict_canonical_json(dict(record)):
        raise ValueError(f"{label} is not canonical")
    return evidence


def _evidence_tuple_from_storage(
    value: object,
    label: str,
    *,
    artifact_ids: frozenset[UUID],
    maximum: int,
    aggregate_count: list[int] | None = None,
) -> tuple[Evidence, ...]:
    if type(value) is not list:
        raise ValueError(f"{label} must be an exact array")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds the configured evidence limit")
    if aggregate_count is not None:
        aggregate_count[0] += len(value)
        if aggregate_count[0] > maximum:
            raise ValueError(
                "materialized consistency evidence exceeds the aggregate limit"
            )
    return tuple(
        _evidence_from_storage(
            item,
            f"{label}[{index}]",
            artifact_ids=artifact_ids,
        )
        for index, item in enumerate(value)
    )


class ConsistencyMaterializationError(RuntimeError):
    """A selected consistency provider could not be materialized safely."""


class ConsistencyMaterializationStatus(StrEnum):
    COMPLETE = "complete"
    NOT_APPLICABLE = "not_applicable"


def legacy_consistency_materialization_envelope(
    *,
    plan_digest: str | None,
    finding_count: int,
) -> dict[str, Any]:
    """Return the one public envelope for a pre-materialization revision."""

    if plan_digest is not None and not _is_lowercase_sha256_digest(plan_digest):
        raise ValueError("plan_digest must be a sha256-prefixed digest or None")
    if (
        type(finding_count) is not int
        or not 0 <= finding_count <= _JSON_SAFE_INTEGER_MAX
    ):
        raise ValueError("finding_count must be a JSON-safe non-negative integer")
    return {
        "schema_version": CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
        "status": "not_materialized",
        "plan_digest": plan_digest,
        "basis": None,
        "basis_digest": None,
        "providers": None,
        "provider_count": None,
        "finding_count": finding_count,
        "diagnostic_count": None,
        "emitted_finding_count": None,
        "emitted_diagnostic_count": None,
        "duplicate_findings_discarded": None,
        "duplicate_diagnostics_discarded": None,
        "world_reads": None,
    }


@dataclass(frozen=True, slots=True)
class ConsistencyMaterializationLimits:
    """Revision-wide limits layered on top of per-provider executor limits."""

    max_providers: int = 32
    max_findings: int = 10_000
    max_diagnostics: int = 2_000
    max_resource_references: int = 100_000
    max_evidence_references: int = 100_000
    max_world_reads: int = 100_000
    max_artifact_ids: int = 100_000
    max_capture_ranges: int = 100_000
    max_basis_value_units: int = 2_000_000
    max_serialized_bytes: int = 16 * 1024 * 1024
    max_node_resolutions: int = 100_000

    def __post_init__(self) -> None:
        for name in (
            "max_providers",
            "max_findings",
            "max_diagnostics",
            "max_resource_references",
            "max_evidence_references",
            "max_world_reads",
            "max_artifact_ids",
            "max_capture_ranges",
            "max_node_resolutions",
            "max_basis_value_units",
            "max_serialized_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 1_000_000_000:
                raise ValueError(f"{name} must be an integer between 1 and 1000000000")


def _validate_materialized_artifact_ids(
    artifact_ids: object,
    limits: ConsistencyMaterializationLimits,
) -> frozenset[UUID]:
    if type(limits) is not ConsistencyMaterializationLimits:
        raise TypeError("limits must be an exact ConsistencyMaterializationLimits")
    if type(artifact_ids) is not frozenset:
        raise TypeError("artifact_ids must be a frozenset of exact UUID values")
    if len(artifact_ids) > limits.max_artifact_ids:
        raise ValueError("artifact_ids exceed the configured artifact limit")
    if any(type(item) is not UUID for item in artifact_ids):
        raise TypeError("artifact_ids must be a frozenset of exact UUID values")
    return artifact_ids


@dataclass(frozen=True, slots=True)
class ConsistencyMaterializationSummary:
    passed: int
    failed: int
    unknown: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.passed, self.failed, self.unknown)
        ):
            raise ValueError("consistency summary counts must be non-negative integers")

    def client_projection(self) -> dict[str, int]:
        return {
            "pass": self.passed,
            "fail": self.failed,
            "unknown": self.unknown,
        }


@dataclass(frozen=True, slots=True)
class MaterializedConsistencyFinding:
    """One immutable canonical client record plus its exact producer."""

    finding_id: str
    provider: CapabilityProviderRef
    canonical_record: str

    def __post_init__(self) -> None:
        if not _is_lowercase_sha256_digest(self.finding_id):
            raise ValueError("finding_id must be a sha256-prefixed digest")
        if type(self.provider) is not CapabilityProviderRef:
            raise TypeError("provider must be an exact CapabilityProviderRef")
        if type(self.canonical_record) is not str:
            raise TypeError("canonical_record must be an exact string")
        try:
            record = json.loads(self.canonical_record)
        except (TypeError, ValueError) as error:
            raise ValueError("canonical_record must contain JSON") from error
        payload = dict(record) if type(record) is dict else {}
        payload.pop("finding_id", None)
        expected_identity = (
            "sha256:" + sha256(strict_canonical_json_bytes(payload)).hexdigest()
        )
        if (
            type(record) is not dict
            or record.get("finding_id") != self.finding_id
            or self.finding_id != expected_identity
            or strict_canonical_json(record) != self.canonical_record
        ):
            raise ValueError("canonical_record is not the canonical finding record")

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class MaterializedConsistencyDiagnostic:
    """One recoverable diagnostic retained with exact producer provenance."""

    diagnostic_id: str
    provider: CapabilityProviderRef
    diagnostic: PluginDiagnostic
    canonical_record: str

    def __post_init__(self) -> None:
        if not _is_lowercase_sha256_digest(self.diagnostic_id):
            raise ValueError("diagnostic_id must be a sha256-prefixed digest")
        if type(self.provider) is not CapabilityProviderRef:
            raise TypeError("provider must be an exact CapabilityProviderRef")
        if type(self.diagnostic) is not PluginDiagnostic:
            raise TypeError("diagnostic must be an exact PluginDiagnostic")
        if type(self.canonical_record) is not str:
            raise TypeError("canonical_record must be an exact string")
        try:
            record = json.loads(self.canonical_record)
        except (TypeError, ValueError) as error:
            raise ValueError("canonical_record must contain JSON") from error
        payload = dict(record) if type(record) is dict else {}
        payload.pop("diagnostic_id", None)
        expected_identity = (
            "sha256:" + sha256(strict_canonical_json_bytes(payload)).hexdigest()
        )
        if (
            type(record) is not dict
            or record.get("diagnostic_id") != self.diagnostic_id
            or self.diagnostic_id != expected_identity
            or strict_canonical_json(record) != self.canonical_record
        ):
            raise ValueError("canonical_record is not the canonical diagnostic record")

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class ConsistencyMaterializationResult:
    status: ConsistencyMaterializationStatus
    plan_digest: str
    providers: tuple[CapabilityProviderRef, ...]
    findings: tuple[MaterializedConsistencyFinding, ...]
    diagnostics: tuple[MaterializedConsistencyDiagnostic, ...]
    summary: ConsistencyMaterializationSummary
    emitted_findings: int
    emitted_diagnostics: int
    duplicate_findings_discarded: int
    duplicate_diagnostics_discarded: int
    world_reads: int
    canonical_basis: str | None
    basis_digest: str | None

    def __post_init__(self) -> None:
        if type(self.status) is not ConsistencyMaterializationStatus:
            raise TypeError("status must be an exact ConsistencyMaterializationStatus")
        if not _is_lowercase_sha256_digest(self.plan_digest):
            raise ValueError("plan_digest must be a sha256-prefixed digest")
        for name, values, expected in (
            ("providers", self.providers, CapabilityProviderRef),
            ("findings", self.findings, MaterializedConsistencyFinding),
            ("diagnostics", self.diagnostics, MaterializedConsistencyDiagnostic),
        ):
            if type(values) is not tuple or any(
                type(item) is not expected for item in values
            ):
                raise TypeError(f"{name} must contain exact {expected.__name__} values")
        if type(self.summary) is not ConsistencyMaterializationSummary:
            raise TypeError(
                "summary must be an exact ConsistencyMaterializationSummary"
            )
        for name in (
            "emitted_findings",
            "emitted_diagnostics",
            "duplicate_findings_discarded",
            "duplicate_diagnostics_discarded",
            "world_reads",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.status is ConsistencyMaterializationStatus.NOT_APPLICABLE and (
            self.providers or self.findings or self.diagnostics
        ):
            raise ValueError("not_applicable materialization cannot contain output")
        if self.status is ConsistencyMaterializationStatus.NOT_APPLICABLE:
            if self.canonical_basis is not None or self.basis_digest is not None:
                raise ValueError("not_applicable materialization cannot carry a basis")
        else:
            if (
                type(self.canonical_basis) is not str
                or type(self.basis_digest) is not str
            ):
                raise ValueError("complete materialization requires a canonical basis")
            try:
                basis = json.loads(self.canonical_basis)
            except (TypeError, ValueError) as error:
                raise ValueError("canonical_basis must contain JSON") from error
            expected = (
                "sha256:" + sha256(self.canonical_basis.encode("utf-8")).hexdigest()
            )
            if (
                type(basis) is not dict
                or strict_canonical_json(basis) != self.canonical_basis
                or self.basis_digest != expected
            ):
                raise ValueError("canonical_basis or basis_digest is invalid")

    @property
    def plugin_diagnostics(self) -> tuple[PluginDiagnostic, ...]:
        return tuple(item.diagnostic for item in self.diagnostics)

    def client_findings(self) -> list[dict[str, Any]]:
        return [item.client_projection() for item in self.findings]

    def client_diagnostics(self) -> list[dict[str, Any]]:
        return [item.client_projection() for item in self.diagnostics]

    def metadata_projection(self) -> dict[str, Any]:
        return {
            "schema_version": CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
            "status": self.status.value,
            "plan_digest": self.plan_digest,
            "basis": (
                json.loads(self.canonical_basis)
                if self.canonical_basis is not None
                else None
            ),
            "basis_digest": self.basis_digest,
            "providers": [_provider_projection(item) for item in self.providers],
            "provider_count": len(self.providers),
            "finding_count": len(self.findings),
            "diagnostic_count": len(self.diagnostics),
            "emitted_finding_count": self.emitted_findings,
            "emitted_diagnostic_count": self.emitted_diagnostics,
            "duplicate_findings_discarded": self.duplicate_findings_discarded,
            "duplicate_diagnostics_discarded": self.duplicate_diagnostics_discarded,
            "world_reads": self.world_reads,
        }

    def dataset_fragment(self) -> dict[str, Any]:
        """Return detached fields for the later ingestion publication stage."""

        return {
            "findings": self.client_findings(),
            "consistency_diagnostics": self.client_diagnostics(),
            "consistency_materialization": self.metadata_projection(),
            "consistency_summary": self.summary.client_projection(),
        }


def _published_consistency_storage_projection(
    result: ConsistencyMaterializationResult,
) -> dict[str, Any]:
    """Represent every serialized copy added by ingestion publication.

    Consistency diagnostics intentionally appear in both the dedicated field
    and the generic diagnostic stream.  Budgeting only the canonical provider
    record once would therefore understate the durable contribution by nearly
    half for diagnostic-heavy revisions.  This projection mirrors every
    published copy plus the materialization and summary envelopes.
    """

    fragment = result.dataset_fragment()
    diagnostics = fragment["consistency_diagnostics"]
    return {
        "_ingestion": {
            "mode": "core-ingestion-v3",
            "plugin_execution_plan_digest": result.plan_digest,
            "consistency_materialization_status": result.status.value,
        },
        "inventory": {"mode": "core-ingestion-v3"},
        "findings": fragment["findings"],
        "consistency_diagnostics": diagnostics,
        "consistency_materialization": fragment["consistency_materialization"],
        "diagnostics": diagnostics,
        "summary": {"consistency": fragment["consistency_summary"]},
    }


def _require_published_consistency_storage_budget(
    result: ConsistencyMaterializationResult,
    maximum_bytes: int,
) -> None:
    # Ingestion publishes with the established escaped ``canonical_json``
    # profile. Budget the exact same bytes: non-ASCII text expands to JSON
    # escapes there and would otherwise pass a smaller UTF-8-oriented limit.
    serialized = canonical_json(
        _published_consistency_storage_projection(result)
    ).encode("utf-8")
    if len(serialized) > maximum_bytes:
        raise ConsistencyMaterializationError(
            "consistency output exceeded the aggregate byte limit"
        )


class _AggregateWorld:
    """Charge all providers against one revision-wide world-read budget."""

    def __init__(
        self,
        world: ReadOnlyWorld,
        *,
        basis: WorldBasis,
        perspective_ref: Any,
        maximum_reads: int,
    ) -> None:
        self._world = world
        self._basis = basis
        self._perspective_ref = perspective_ref
        self._maximum = maximum_reads
        self._remaining = maximum_reads

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> Any:
        return self._perspective_ref

    @property
    def reads_used(self) -> int:
        return self._maximum - self._remaining

    def _charge(self) -> None:
        if self._remaining <= 0:
            raise ConsistencyMaterializationError(
                "consistency providers exceeded the aggregate world-read limit"
            )
        self._remaining -= 1

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self._charge()
        return self._world.state_of(resource)

    def _bounded_iter[Item](
        self,
        producer: Callable[[int], Iterable[Item]],
        requested_limit: int | None,
    ) -> Iterable[Item]:
        if requested_limit is not None and (
            type(requested_limit) is not int or requested_limit < 0
        ):
            raise ValueError("world read limit must be a non-negative integer")
        remaining = self._remaining
        allowed = remaining
        if requested_limit is not None:
            allowed = min(allowed, requested_limit)
        cap_limited = requested_limit is None or requested_limit >= remaining
        # When the wrapper's aggregate cap is the limiting factor, ask the
        # underlying bounded world for one sentinel item.  A compliant world
        # otherwise returns a clean EOF at exactly ``allowed`` and could make a
        # truncated consistency scan look complete.  An explicit smaller
        # caller limit remains ordinary pagination and is not probed.
        producer_limit = (
            allowed + 1 if cap_limited and requested_limit != 0 else allowed
        )
        iterator = iter(producer(producer_limit))
        count = 0
        try:
            for item in iterator:
                if count >= allowed:
                    message = (
                        "consistency providers exceeded the aggregate world-read limit"
                        if cap_limited
                        else "world provider exceeded the aggregate bounded read request"
                    )
                    raise ConsistencyMaterializationError(message)
                self._charge()
                count += 1
                yield item
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]:
        return self._bounded_iter(
            lambda bounded: self._world.iter_states(
                layers=layers,
                kinds=kinds,
                limit=bounded,
            ),
            limit,
        )

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        return self._bounded_iter(
            lambda bounded: self._world.related(
                resource,
                direction=direction,
                relation_types=relation_types,
                limit=bounded,
            ),
            limit,
        )

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        return self._bounded_iter(
            lambda bounded: self._world.iter_relationships(
                relation_types=relation_types,
                layers=layers,
                limit=bounded,
            ),
            limit,
        )


def _artifact_id_set(
    artifact_ids: Collection[UUID],
    *,
    maximum: int,
) -> frozenset[UUID]:
    if type(artifact_ids) not in (tuple, list, set, frozenset):
        raise TypeError("artifact_ids must be a built-in bounded collection")
    if len(artifact_ids) > maximum:
        raise ConsistencyMaterializationError(
            "revision artifact identities exceeded the configured limit"
        )
    if any(type(item) is not UUID for item in artifact_ids):
        raise TypeError("artifact_ids must contain exact UUID values")
    return frozenset(UUID(bytes=item.bytes) for item in artifact_ids)


class _ProjectionByteBudget:
    """Incremental allocation proxy for one client-value projection."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.used = 0

    def charge(self, amount: int) -> None:
        if type(amount) is not int or amount < 0:
            raise ConsistencyMaterializationError(
                "consistency projection produced an invalid byte charge"
            )
        if amount > self.maximum - self.used:
            raise ConsistencyMaterializationError(
                "consistency projection exceeded the aggregate byte limit"
            )
        self.used += amount


def _client_value(
    value: Any,
    *,
    label: str,
    depth: int = 0,
    units: list[int] | None = None,
    active: set[int] | None = None,
    stringify_integers: bool = False,
    maximum_units: int = 4_096,
    maximum_sequence_items: int = 1_024,
    byte_budget: _ProjectionByteBudget | None = None,
    accept_json_arrays: bool = False,
) -> Any:
    current_units = units if units is not None else [0]
    current_active = active if active is not None else set()
    current_units[0] += 1
    if current_units[0] > maximum_units:
        raise ConsistencyMaterializationError(
            f"{label} exceeds {maximum_units} value units"
        )
    if depth > 16:
        raise ConsistencyMaterializationError(f"{label} exceeds 16 container levels")
    value_type = type(value)
    if value is None or value_type is bool:
        if byte_budget is not None:
            byte_budget.charge(4 if value is None or value is True else 5)
        return value
    if isinstance(value, Enum):
        if byte_budget is not None:
            byte_budget.charge(len(json.dumps(value.value).encode("utf-8")))
        return value.value
    if value_type is int:
        if value.bit_length() > 4_096:
            raise ConsistencyMaterializationError(
                f"{label} contains an integer exceeding 4096 bits"
            )
        if stringify_integers:
            if byte_budget is not None:
                byte_budget.charge(len(str(value)) + 2)
            return str(value)
        if -_JSON_SAFE_INTEGER_MAX <= value <= _JSON_SAFE_INTEGER_MAX:
            if byte_budget is not None:
                byte_budget.charge(len(str(value)))
            return value
        if byte_budget is not None:
            byte_budget.charge(len(str(value)) + 64)
        return {"type": "integer", "encoding": "decimal", "value": str(value)}
    if value_type is float:
        if not isfinite(value):
            raise ConsistencyMaterializationError(
                f"{label} contains a non-finite float"
            )
        if byte_budget is not None:
            byte_budget.charge(len(repr(value)))
        return value
    if value_type is str:
        if len(value) > 65_536:
            raise ConsistencyMaterializationError(f"{label} contains oversized text")
        if byte_budget is not None:
            byte_budget.charge(len(json.dumps(value).encode("utf-8")))
        return value
    if value_type is bytes:
        if len(value) > 65_536:
            raise ConsistencyMaterializationError(f"{label} contains oversized bytes")
        if byte_budget is not None:
            byte_budget.charge((len(value) * 2) + 64)
        return {"type": "bytes", "encoding": "hex", "value": value.hex()}
    if value_type is UUID:
        if byte_budget is not None:
            byte_budget.charge(38)
        return str(value)
    if value_type is tuple or (accept_json_arrays and value_type is list):
        if len(value) > maximum_sequence_items:
            raise ConsistencyMaterializationError(f"{label} contains too many items")
        if byte_budget is not None:
            byte_budget.charge(2 + len(value))
        identity = id(value)
        if identity in current_active:
            raise ConsistencyMaterializationError(f"{label} contains a reference cycle")
        current_active.add(identity)
        try:
            return [
                _client_value(
                    item,
                    label=label,
                    depth=depth + 1,
                    units=current_units,
                    active=current_active,
                    stringify_integers=stringify_integers,
                    maximum_units=maximum_units,
                    maximum_sequence_items=maximum_sequence_items,
                    byte_budget=byte_budget,
                    accept_json_arrays=accept_json_arrays,
                )
                for item in value
            ]
        finally:
            current_active.remove(identity)
    if value_type in (dict, MappingProxyType):
        if len(value) > 1_024:
            raise ConsistencyMaterializationError(f"{label} contains too many items")
        if byte_budget is not None:
            byte_budget.charge(2 + len(value))
        identity = id(value)
        if identity in current_active:
            raise ConsistencyMaterializationError(f"{label} contains a reference cycle")
        current_active.add(identity)
        try:
            result: dict[str, Any] = {}
            for key, item in value.items():
                if (
                    type(key) is not str
                    or not key
                    or len(key) > 256
                    or "\x00" in key
                ):
                    raise ConsistencyMaterializationError(
                        f"{label} mappings require bounded non-empty string keys"
                    )
                if byte_budget is not None:
                    byte_budget.charge(len(json.dumps(key).encode("utf-8")) + 1)
                result[key] = _client_value(
                    item,
                    label=label,
                    depth=depth + 1,
                    units=current_units,
                    active=current_active,
                    stringify_integers=stringify_integers,
                    maximum_units=maximum_units,
                    maximum_sequence_items=maximum_sequence_items,
                    byte_budget=byte_budget,
                    accept_json_arrays=accept_json_arrays,
                )
            return result
        finally:
            current_active.remove(identity)
    if is_dataclass(value) and not isinstance(value, type):
        descriptors = fields(value)
        if byte_budget is not None:
            byte_budget.charge(
                2
                + len(descriptors)
                + sum(
                    len(json.dumps(descriptor.name).encode("utf-8")) + 1
                    for descriptor in descriptors
                )
            )
        identity = id(value)
        if identity in current_active:
            raise ConsistencyMaterializationError(f"{label} contains a reference cycle")
        current_active.add(identity)
        try:
            return {
                descriptor.name: _client_value(
                    getattr(value, descriptor.name),
                    label=label,
                    depth=depth + 1,
                    units=current_units,
                    active=current_active,
                    stringify_integers=stringify_integers,
                    maximum_units=maximum_units,
                maximum_sequence_items=maximum_sequence_items,
                byte_budget=byte_budget,
                accept_json_arrays=accept_json_arrays,
            )
                for descriptor in descriptors
            }
        finally:
            current_active.remove(identity)
    raise ConsistencyMaterializationError(
        f"{label} contains unsupported type {value_type.__name__}"
    )


def _resource_projection(resource: ResourceKey) -> dict[str, Any]:
    if type(resource) is not ResourceKey:
        raise ConsistencyMaterializationError(
            "consistency finding resources must be exact ResourceKey values"
        )
    identifier, identity = _canonical_resource_identity(resource)
    return {"resource_id": identifier, "typed_resource_key": identity}


def _evidence_projection(
    evidence: Evidence,
    *,
    artifact_ids: frozenset[UUID],
    label: str,
) -> dict[str, Any]:
    if type(evidence) is not Evidence:
        raise ConsistencyMaterializationError(f"{label} must be an exact Evidence")
    if type(evidence.artifact_id) is not UUID:
        raise ConsistencyMaterializationError(f"{label}.artifact_id must be a UUID")
    if evidence.artifact_id not in artifact_ids:
        raise ConsistencyMaterializationError(
            f"{label} references an artifact outside the revision"
        )
    if (
        type(evidence.locator) is not str
        or not evidence.locator
        or len(evidence.locator) > 4_096
        or "\x00" in evidence.locator
    ):
        raise ConsistencyMaterializationError(
            f"{label}.locator must contain 1 to 4096 safe characters"
        )
    if evidence.raw_timestamp_ns is not None and (
        type(evidence.raw_timestamp_ns) is not int
        or not MIN_TIMESTAMP_NS <= evidence.raw_timestamp_ns <= MAX_TIMESTAMP_NS
    ):
        raise ConsistencyMaterializationError(
            f"{label}.raw_timestamp_ns must be a signed 64-bit integer or null"
        )
    if evidence.clock_domain is not None and (
        type(evidence.clock_domain) is not str
        or not evidence.clock_domain
        or len(evidence.clock_domain) > 256
        or "\x00" in evidence.clock_domain
    ):
        raise ConsistencyMaterializationError(
            f"{label}.clock_domain must contain 1 to 256 safe characters or null"
        )
    if evidence.excerpt_sha256 is not None and (
        type(evidence.excerpt_sha256) is not str
        or len(evidence.excerpt_sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in evidence.excerpt_sha256
        )
    ):
        raise ConsistencyMaterializationError(
            f"{label}.excerpt_sha256 must be a 64-digit hexadecimal digest or null"
        )
    return {
        "artifact_id": str(evidence.artifact_id),
        "locator": evidence.locator,
        "raw_timestamp_ns": (
            str(evidence.raw_timestamp_ns)
            if evidence.raw_timestamp_ns is not None
            else None
        ),
        "clock_domain": evidence.clock_domain,
        "excerpt_sha256": (
            evidence.excerpt_sha256.lower()
            if evidence.excerpt_sha256 is not None
            else None
        ),
    }


def _basis_evidence(basis: WorldBasis) -> Iterable[Evidence]:
    for capture in basis.capture_ranges:
        yield from capture.evidence
    for resolution in basis.node_resolutions:
        yield from resolution.evidence
    if basis.watermark is not None:
        yield from basis.watermark.evidence


def _basis_with_canonical_storage_evidence(basis: WorldBasis) -> WorldBasis:
    """Normalize evidence digests before generic dataclass projection.

    Standalone finding and diagnostic evidence already travels through
    ``_evidence_projection``.  Evidence nested in a ``WorldBasis`` otherwise
    reaches the generic dataclass projector directly, so normalize the one
    admitted case-insensitive field here to preserve reader/writer symmetry.
    """

    def normalized(values: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        return tuple(
            replace(
                item,
                excerpt_sha256=(
                    item.excerpt_sha256.lower()
                    if item.excerpt_sha256 is not None
                    else None
                ),
            )
            for item in values
        )

    watermark = basis.watermark
    return replace(
        basis,
        capture_ranges=tuple(
            replace(item, evidence=normalized(item.evidence))
            for item in basis.capture_ranges
        ),
        node_resolutions=tuple(
            replace(item, evidence=normalized(item.evidence))
            for item in basis.node_resolutions
        ),
        watermark=(
            replace(watermark, evidence=normalized(watermark.evidence))
            if watermark is not None
            else None
        ),
    )


def _validate_basis_containers(
    basis: WorldBasis,
    *,
    maximum_capture_ranges: int,
    maximum_node_resolutions: int,
    maximum_evidence: int,
) -> int:
    """Validate the complete basis vocabulary before generic projection."""

    if type(basis) is not WorldBasis:
        raise ConsistencyMaterializationError(
            "revision world basis must be an exact WorldBasis"
        )

    def optional_time(value: object, label: str) -> None:
        if value is not None and (
            type(value) is not int
            or not MIN_TIMESTAMP_NS <= value <= MAX_TIMESTAMP_NS
        ):
            raise ConsistencyMaterializationError(
                f"{label} must be a signed 64-bit integer or None"
            )

    def optional_text(value: object, label: str, maximum: int) -> None:
        if value is not None and (
            type(value) is not str
            or not value
            or len(value) > maximum
            or "\x00" in value
        ):
            raise ConsistencyMaterializationError(
                f"{label} must contain 1 to {maximum} characters or be None"
            )

    def validate_scope(value: object, label: str) -> None:
        if type(value) is not WatermarkScope:
            raise ConsistencyMaterializationError(
                f"{label} must be an exact WatermarkScope"
            )
        if (
            type(value.node_id) is not str
            or not value.node_id
            or len(value.node_id) > 256
            or "\x00" in value.node_id
            or type(value.status_perspective_id) is not str
            or not value.status_perspective_id
            or len(value.status_perspective_id) > 128
            or "\x00" in value.status_perspective_id
            or (
                value.topology_projection_id is not None
                and (
                    type(value.topology_projection_id) is not str
                    or not value.topology_projection_id
                    or len(value.topology_projection_id) > 128
                    or "\x00" in value.topology_projection_id
                )
            )
        ):
            raise ConsistencyMaterializationError(f"{label} is invalid")
        try:
            WatermarkScope.__post_init__(value)
        except (TypeError, ValueError) as error:
            raise ConsistencyMaterializationError(f"{label} is invalid") from error

    if (
        type(basis.kind) is not WorldBasisKind
        or type(basis.provenance) is not Provenance
        or type(basis.quality) is not Quality
    ):
        raise ConsistencyMaterializationError(
            "revision world basis metadata is invalid"
        )
    optional_time(basis.requested_time_ns, "world basis requested_time_ns")
    optional_time(basis.resolved_at_min_ns, "world basis resolved_at_min_ns")
    optional_time(basis.resolved_at_max_ns, "world basis resolved_at_max_ns")
    if (basis.resolved_at_min_ns is None) != (basis.resolved_at_max_ns is None):
        raise ConsistencyMaterializationError(
            "revision world basis resolved bounds must both be present or absent"
        )
    if (
        basis.resolved_at_min_ns is not None
        and basis.resolved_at_max_ns is not None
        and basis.resolved_at_min_ns > basis.resolved_at_max_ns
    ):
        raise ConsistencyMaterializationError(
            "revision world basis resolved bounds are reversed"
        )
    optional_text(basis.clock_domain, "world basis clock_domain", 256)
    optional_text(basis.unresolved_reason, "world basis unresolved_reason", 8_192)

    selector = basis.selector
    if selector is not None:
        try:
            if type(selector) is AbsoluteTimeSelector:
                optional_time(selector.time_ns, "world basis selector time_ns")
                if (
                    type(selector.clock_domain) is not str
                    or not selector.clock_domain
                    or len(selector.clock_domain) > 256
                    or "\x00" in selector.clock_domain
                    or type(selector.clock_policy) is not ClockAlignmentPolicy
                    or type(selector.kind) is not TemporalSelectorKind
                    or selector.kind is not TemporalSelectorKind.ABSOLUTE_TIME
                ):
                    raise ConsistencyMaterializationError(
                        "revision world basis selector is invalid"
                    )
                AbsoluteTimeSelector.__post_init__(selector)
            elif type(selector) is RelativeToWatermarkSelector:
                optional_time(selector.offset_ns, "world basis selector offset_ns")
                if (
                    selector.offset_ns > 0
                    or type(selector.clock_policy) is not ClockAlignmentPolicy
                    or type(selector.kind) is not TemporalSelectorKind
                    or selector.kind is not TemporalSelectorKind.RELATIVE_TO_WATERMARK
                ):
                    raise ConsistencyMaterializationError(
                        "revision world basis selector is invalid"
                    )
                validate_scope(selector.scope, "world basis selector scope")
                RelativeToWatermarkSelector.__post_init__(selector)
            else:
                raise ConsistencyMaterializationError(
                    "revision world basis selector is invalid"
                )
        except ConsistencyMaterializationError:
            raise
        except (TypeError, ValueError) as error:
            raise ConsistencyMaterializationError(
                "revision world basis selector is invalid"
            ) from error

    if (
        type(basis.capture_ranges) is not tuple
        or len(basis.capture_ranges) > maximum_capture_ranges
    ):
        raise ConsistencyMaterializationError(
            "revision world basis exceeded the configured capture-range limit"
        )
    if (
        type(basis.node_resolutions) is not tuple
        or len(basis.node_resolutions) > maximum_node_resolutions
    ):
        raise ConsistencyMaterializationError(
            "revision world basis exceeded the configured node-resolution limit"
        )

    evidence_count = 0

    def validate_evidence(values: object, label: str) -> None:
        nonlocal evidence_count
        if type(values) is not tuple:
            raise ConsistencyMaterializationError(f"{label} must be an exact tuple")
        evidence_count += len(values)
        if evidence_count > maximum_evidence:
            raise ConsistencyMaterializationError(
                "revision world basis evidence exceeded the aggregate limit"
            )
        if any(type(item) is not Evidence for item in values):
            raise ConsistencyMaterializationError(
                f"{label} must contain exact Evidence values"
            )

    for index, capture in enumerate(basis.capture_ranges):
        if type(capture) is not CaptureRange:
            raise ConsistencyMaterializationError(
                f"revision world basis capture_ranges[{index}] is invalid"
            )
        if (
            type(capture.scope) is not str
            or not capture.scope
            or len(capture.scope) > MAX_CAPTURE_RANGE_SCOPE_LENGTH
            or "\x00" in capture.scope
        ):
            raise ConsistencyMaterializationError(
                f"revision world basis capture_ranges[{index}].scope is invalid"
            )
        optional_time(
            capture.observed_at_min_ns,
            f"revision world basis capture_ranges[{index}].observed_at_min_ns",
        )
        optional_time(
            capture.observed_at_max_ns,
            f"revision world basis capture_ranges[{index}].observed_at_max_ns",
        )
        if (
            capture.observed_at_min_ns is not None
            and capture.observed_at_max_ns is not None
            and capture.observed_at_min_ns > capture.observed_at_max_ns
        ):
            raise ConsistencyMaterializationError(
                f"revision world basis capture_ranges[{index}] bounds are reversed"
            )
        optional_text(
            capture.clock_domain,
            f"revision world basis capture_ranges[{index}].clock_domain",
            256,
        )
        validate_evidence(
            capture.evidence,
            f"revision world basis capture_ranges[{index}].evidence",
        )
    for index, resolution in enumerate(basis.node_resolutions):
        if type(resolution) is not ResolvedNodeBasis:
            raise ConsistencyMaterializationError(
                f"revision world basis node_resolutions[{index}] is invalid"
            )
        if type(resolution.quality) is not Quality:
            raise ConsistencyMaterializationError(
                f"revision world basis node_resolutions[{index}].quality is invalid"
            )
        if (
            type(resolution.node_id) is not str
            or not resolution.node_id
            or len(resolution.node_id) > 256
            or "\x00" in resolution.node_id
        ):
            raise ConsistencyMaterializationError(
                f"revision world basis node_resolutions[{index}].node_id is invalid"
            )
        optional_text(
            resolution.local_clock_domain,
            f"revision world basis node_resolutions[{index}].local_clock_domain",
            256,
        )
        optional_text(
            resolution.mapping_method,
            f"revision world basis node_resolutions[{index}].mapping_method",
            256,
        )
        optional_text(
            resolution.reason_code,
            f"revision world basis node_resolutions[{index}].reason_code",
            128,
        )
        for field_name in (
            "local_min_ns",
            "local_max_ns",
            "absolute_min_ns",
            "absolute_max_ns",
        ):
            optional_time(
                getattr(resolution, field_name),
                f"revision world basis node_resolutions[{index}].{field_name}",
            )
        validate_evidence(
            resolution.evidence,
            f"revision world basis node_resolutions[{index}].evidence",
        )
        try:
            ResolvedNodeBasis.__post_init__(resolution)
        except (TypeError, ValueError) as error:
            raise ConsistencyMaterializationError(
                f"revision world basis node_resolutions[{index}] is invalid"
            ) from error
    if basis.watermark is not None:
        if type(basis.watermark) is not ReconstructionWatermark:
            raise ConsistencyMaterializationError(
                "revision world basis watermark is invalid"
            )
        watermark = basis.watermark
        validate_scope(watermark.scope, "revision world basis watermark scope")
        if (
            type(watermark.clock_domain) is not str
            or not watermark.clock_domain
            or len(watermark.clock_domain) > 256
            or "\x00" in watermark.clock_domain
            or type(watermark.provenance) is not Provenance
            or type(watermark.quality) is not Quality
        ):
            raise ConsistencyMaterializationError(
                "revision world basis watermark metadata is invalid"
            )
        optional_time(
            watermark.local_time_ns,
            "revision world basis watermark local_time_ns",
        )
        optional_time(
            watermark.absolute_min_ns,
            "revision world basis watermark absolute_min_ns",
        )
        optional_time(
            watermark.absolute_max_ns,
            "revision world basis watermark absolute_max_ns",
        )
        optional_text(
            watermark.mapping_method,
            "revision world basis watermark mapping_method",
            256,
        )
        validate_evidence(
            watermark.evidence,
            "revision world basis watermark.evidence",
        )
        try:
            ReconstructionWatermark.__post_init__(watermark)
        except (TypeError, ValueError) as error:
            raise ConsistencyMaterializationError(
                "revision world basis watermark is invalid"
            ) from error
    return evidence_count


def _provider_projection(provider: CapabilityProviderRef) -> dict[str, Any]:
    pin = provider.pin
    return {
        "member_id": provider.member_id,
        "node_id": provider.node_id,
        "basis_revision_id": provider.basis_revision_id,
        "plan_digest": provider.plan_digest,
        "instance_id": pin.instance_id,
        "plugin_id": pin.plugin_id,
        "plugin_version": pin.plugin_version,
        "registered_execution_identity": pin.registered_execution_identity,
        "configuration_digest": pin.configuration_digest,
        "schema_digest": pin.schema_digest,
        "package_hash": pin.artifact.package_hash,
        "capability": provider.capability.value,
        "roles": list(pin.roles),
    }


def _selected_pins(plan: PluginExecutionPlan) -> tuple[PluginExecutionPin, ...]:
    primary = primary_parser_execution_pin(plan)
    capability = PluginCapability.CONSISTENCY_CHECK.value
    selected: list[PluginExecutionPin] = []
    if capability in primary.capabilities:
        selected.append(primary)
    auxiliaries: list[PluginExecutionPin] = []
    for pin in plan.plugins:
        if pin.instance_id == primary.instance_id:
            continue
        selected_role = REVISION_CONSISTENCY_ROLE in pin.roles
        declares_capability = capability in pin.capabilities
        if selected_role and not declares_capability:
            raise ConsistencyMaterializationError(
                "revision_consistency auxiliary does not declare consistency_check"
            )
        if selected_role and declares_capability:
            auxiliaries.append(pin)
    auxiliaries.sort(
        key=lambda pin: (pin.instance_id, pin.registered_execution_identity)
    )
    selected.extend(auxiliaries)
    return tuple(selected)


def revision_consistency_selected_pins(
    plan: PluginExecutionPlan,
) -> tuple[PluginExecutionPin, ...]:
    """Return detached pins selected for automatic revision materialization."""

    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    return _selected_pins(snapshot_plugin_execution_plan(plan))


def _not_applicable_result(
    plan: PluginExecutionPlan,
) -> ConsistencyMaterializationResult:
    return ConsistencyMaterializationResult(
        status=ConsistencyMaterializationStatus.NOT_APPLICABLE,
        plan_digest=plan.plan_digest,
        providers=(),
        findings=(),
        diagnostics=(),
        summary=ConsistencyMaterializationSummary(0, 0, 0),
        emitted_findings=0,
        emitted_diagnostics=0,
        duplicate_findings_discarded=0,
        duplicate_diagnostics_discarded=0,
        world_reads=0,
        canonical_basis=None,
        basis_digest=None,
    )


def not_applicable_consistency_materialization(
    plan: PluginExecutionPlan,
) -> ConsistencyMaterializationResult:
    """Return a plan-bound result without constructing a router or world.

    The helper fails closed if the plan selects any consistency provider. A
    coordinator can therefore select pins first and use this path only for an
    empty selection, without binding provider state.
    """

    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    detached_plan = snapshot_plugin_execution_plan(plan)
    if _selected_pins(detached_plan):
        raise ConsistencyMaterializationError(
            "not_applicable consistency materialization requires no selected provider"
        )
    return _not_applicable_result(detached_plan)


def _diagnostic_projection(
    diagnostic: PluginDiagnostic,
    *,
    provider: CapabilityProviderRef,
    artifact_ids: frozenset[UUID],
) -> tuple[dict[str, Any], int]:
    if type(diagnostic) is not PluginDiagnostic:
        raise ConsistencyMaterializationError(
            "consistency diagnostics must be exact PluginDiagnostic values"
        )
    if (
        type(diagnostic.stage) is not DiagnosticStage
        or type(diagnostic.severity) is not DiagnosticSeverity
        or type(diagnostic.origin) is not DiagnosticOrigin
        or type(diagnostic.recoverable) is not bool
        or type(diagnostic.code) is not str
        or not diagnostic.code
        or len(diagnostic.code) > 256
        or "\x00" in diagnostic.code
        or type(diagnostic.message) is not str
        or not diagnostic.message
        or len(diagnostic.message) > 8_192
        or "\x00" in diagnostic.message
        or type(diagnostic.evidence) is not tuple
    ):
        raise ConsistencyMaterializationError(
            "consistency diagnostic changed after capability validation"
        )
    evidence = [
        _evidence_projection(
            item,
            artifact_ids=artifact_ids,
            label=f"consistency diagnostic evidence[{index}]",
        )
        for index, item in enumerate(diagnostic.evidence)
    ]
    record = {
        "stage": diagnostic.stage.value,
        "severity": diagnostic.severity.value,
        "code": diagnostic.code,
        "message": diagnostic.message,
        "recoverable": diagnostic.recoverable,
        "evidence": evidence,
        "details": _client_value(diagnostic.details, label="diagnostic details"),
        "origin": diagnostic.origin.value,
        "producer": _provider_projection(provider),
    }
    return record, len(evidence)


def _finding_projection(
    finding: ConsistencyFinding,
    *,
    provider: CapabilityProviderRef,
    plan_digest: str,
    basis: WorldBasis,
    basis_projection: dict[str, Any],
    artifact_ids: frozenset[UUID],
) -> tuple[dict[str, Any], int, int]:
    if type(finding) is not ConsistencyFinding:
        raise ConsistencyMaterializationError(
            "consistency outputs must be exact ConsistencyFinding values"
        )
    if (
        type(finding.rule_id) is not str
        or not finding.rule_id
        or len(finding.rule_id) > 256
        or "\x00" in finding.rule_id
        or type(finding.severity) is not DiagnosticSeverity
        or type(finding.result) is not FindingResult
        or type(finding.summary) is not str
        or not finding.summary
        or len(finding.summary) > 8_192
        or "\x00" in finding.summary
        or type(finding.resources) is not tuple
        or type(finding.provenance) is not Provenance
        or type(finding.quality) is not Quality
        or type(finding.basis) is not WorldBasis
        or type(finding.evidence) is not tuple
    ):
        raise ConsistencyMaterializationError(
            "consistency finding changed after capability validation"
        )
    try:
        basis_matches = finding.basis == basis
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise ConsistencyMaterializationError(
            "consistency finding basis could not be compared"
        ) from error
    if not basis_matches:
        raise ConsistencyMaterializationError(
            "consistency finding basis does not match the revision world basis"
        )
    resources = [_resource_projection(item) for item in finding.resources]
    evidence = [
        _evidence_projection(
            item,
            artifact_ids=artifact_ids,
            label=f"consistency finding evidence[{index}]",
        )
        for index, item in enumerate(finding.evidence)
    ]
    record: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "result": finding.result.value,
        "summary": finding.summary,
        "resources": [item["resource_id"] for item in resources],
        "resource_references": resources,
        "provenance": finding.provenance.value,
        "quality": finding.quality.value,
        "basis": basis_projection,
        "evidence": evidence,
        "details": _client_value(finding.details, label="finding details"),
        "producer": _provider_projection(provider),
        "execution_plan_digest": plan_digest,
    }
    digest = "sha256:" + sha256(strict_canonical_json_bytes(record)).hexdigest()
    record["finding_id"] = digest
    return record, len(resources), len(evidence)


def _optional_storage_text(
    value: object,
    label: str,
    maximum: int,
) -> str | None:
    return None if value is None else _storage_text(value, label, maximum)


def _scope_from_storage(value: object, label: str) -> WatermarkScope:
    record = _exact_storage_record(
        value,
        frozenset(
            {"node_id", "status_perspective_id", "topology_projection_id"}
        ),
        label,
    )
    return WatermarkScope(
        node_id=_storage_text(record["node_id"], f"{label}.node_id", 256),
        status_perspective_id=_storage_text(
            record["status_perspective_id"],
            f"{label}.status_perspective_id",
            128,
        ),
        topology_projection_id=_optional_storage_text(
            record["topology_projection_id"],
            f"{label}.topology_projection_id",
            128,
        ),
    )


def _validate_materialized_consistency_basis(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits,
    aggregate_evidence_count: list[int] | None = None,
) -> str:
    selected_limits = limits
    fields = frozenset(
        {
            "kind",
            "requested_time_ns",
            "resolved_at_min_ns",
            "resolved_at_max_ns",
            "capture_ranges",
            "provenance",
            "quality",
            "clock_domain",
            "selector",
            "node_resolutions",
            "watermark",
            "unresolved_reason",
        }
    )
    record = _exact_storage_record(value, fields, "materialized world basis")
    raw_ranges = record["capture_ranges"]
    if (
        type(raw_ranges) is not list
        or len(raw_ranges) > selected_limits.max_capture_ranges
    ):
        raise ValueError("materialized world basis capture_ranges must be an array")
    captures: list[CaptureRange] = []
    for index, raw_capture in enumerate(raw_ranges):
        label = f"materialized world basis capture_ranges[{index}]"
        capture = _exact_storage_record(
            raw_capture,
            frozenset(
                {
                    "scope",
                    "observed_at_min_ns",
                    "observed_at_max_ns",
                    "evidence",
                    "clock_domain",
                }
            ),
            label,
        )
        captures.append(
            CaptureRange(
                scope=_storage_text(
                    capture["scope"],
                    f"{label}.scope",
                    MAX_CAPTURE_RANGE_SCOPE_LENGTH,
                ),
                observed_at_min_ns=_storage_timestamp(
                    capture["observed_at_min_ns"],
                    f"{label}.observed_at_min_ns",
                ),
                observed_at_max_ns=_storage_timestamp(
                    capture["observed_at_max_ns"],
                    f"{label}.observed_at_max_ns",
                ),
                evidence=_evidence_tuple_from_storage(
                    capture["evidence"],
                    f"{label}.evidence",
                    artifact_ids=artifact_ids,
                    maximum=selected_limits.max_evidence_references,
                    aggregate_count=aggregate_evidence_count,
                ),
                clock_domain=_optional_storage_text(
                    capture["clock_domain"],
                    f"{label}.clock_domain",
                    256,
                ),
            )
        )

    raw_resolutions = record["node_resolutions"]
    if (
        type(raw_resolutions) is not list
        or len(raw_resolutions) > selected_limits.max_node_resolutions
    ):
        raise ValueError("materialized world basis node_resolutions must be an array")
    resolutions: list[ResolvedNodeBasis] = []
    resolution_fields = frozenset(
        {
            "node_id",
            "local_clock_domain",
            "local_min_ns",
            "local_max_ns",
            "absolute_min_ns",
            "absolute_max_ns",
            "mapping_method",
            "quality",
            "reason_code",
            "evidence",
        }
    )
    for index, raw_resolution in enumerate(raw_resolutions):
        label = f"materialized world basis node_resolutions[{index}]"
        resolution = _exact_storage_record(
            raw_resolution,
            resolution_fields,
            label,
        )
        resolutions.append(
            ResolvedNodeBasis(
                node_id=_storage_text(
                    resolution["node_id"], f"{label}.node_id", 256
                ),
                local_clock_domain=_optional_storage_text(
                    resolution["local_clock_domain"],
                    f"{label}.local_clock_domain",
                    256,
                ),
                local_min_ns=_storage_timestamp(
                    resolution["local_min_ns"], f"{label}.local_min_ns"
                ),
                local_max_ns=_storage_timestamp(
                    resolution["local_max_ns"], f"{label}.local_max_ns"
                ),
                absolute_min_ns=_storage_timestamp(
                    resolution["absolute_min_ns"], f"{label}.absolute_min_ns"
                ),
                absolute_max_ns=_storage_timestamp(
                    resolution["absolute_max_ns"], f"{label}.absolute_max_ns"
                ),
                mapping_method=_optional_storage_text(
                    resolution["mapping_method"],
                    f"{label}.mapping_method",
                    256,
                ),
                quality=Quality(resolution["quality"]),
                reason_code=_optional_storage_text(
                    resolution["reason_code"], f"{label}.reason_code", 128
                ),
                evidence=_evidence_tuple_from_storage(
                    resolution["evidence"],
                    f"{label}.evidence",
                    artifact_ids=artifact_ids,
                    maximum=selected_limits.max_evidence_references,
                    aggregate_count=aggregate_evidence_count,
                ),
            )
        )

    raw_selector = record["selector"]
    selector: AbsoluteTimeSelector | RelativeToWatermarkSelector | None
    if raw_selector is None:
        selector = None
    elif isinstance(raw_selector, Mapping) and raw_selector.get("kind") == (
        TemporalSelectorKind.ABSOLUTE_TIME.value
    ):
        selector_record = _exact_storage_record(
            raw_selector,
            frozenset({"time_ns", "clock_domain", "clock_policy", "kind"}),
            "materialized world basis selector",
        )
        selector = AbsoluteTimeSelector(
            time_ns=_storage_timestamp(
                selector_record["time_ns"],
                "materialized world basis selector.time_ns",
                optional=False,
            ),
            clock_domain=_storage_text(
                selector_record["clock_domain"],
                "materialized world basis selector.clock_domain",
                256,
            ),
            clock_policy=ClockAlignmentPolicy(selector_record["clock_policy"]),
        )
    elif isinstance(raw_selector, Mapping) and raw_selector.get("kind") == (
        TemporalSelectorKind.RELATIVE_TO_WATERMARK.value
    ):
        selector_record = _exact_storage_record(
            raw_selector,
            frozenset({"offset_ns", "scope", "clock_policy", "kind"}),
            "materialized world basis selector",
        )
        selector = RelativeToWatermarkSelector(
            offset_ns=_storage_timestamp(
                selector_record["offset_ns"],
                "materialized world basis selector.offset_ns",
                optional=False,
            ),
            scope=_scope_from_storage(
                selector_record["scope"],
                "materialized world basis selector.scope",
            ),
            clock_policy=ClockAlignmentPolicy(selector_record["clock_policy"]),
        )
    else:
        raise ValueError("materialized world basis selector is invalid")

    raw_watermark = record["watermark"]
    if raw_watermark is None:
        watermark = None
    else:
        watermark_record = _exact_storage_record(
            raw_watermark,
            frozenset(
                {
                    "scope",
                    "local_time_ns",
                    "clock_domain",
                    "provenance",
                    "quality",
                    "absolute_min_ns",
                    "absolute_max_ns",
                    "mapping_method",
                    "evidence",
                }
            ),
            "materialized world basis watermark",
        )
        watermark = ReconstructionWatermark(
            scope=_scope_from_storage(
                watermark_record["scope"],
                "materialized world basis watermark.scope",
            ),
            local_time_ns=_storage_timestamp(
                watermark_record["local_time_ns"],
                "materialized world basis watermark.local_time_ns",
                optional=False,
            ),
            clock_domain=_storage_text(
                watermark_record["clock_domain"],
                "materialized world basis watermark.clock_domain",
                256,
            ),
            provenance=Provenance(watermark_record["provenance"]),
            quality=Quality(watermark_record["quality"]),
            absolute_min_ns=_storage_timestamp(
                watermark_record["absolute_min_ns"],
                "materialized world basis watermark.absolute_min_ns",
            ),
            absolute_max_ns=_storage_timestamp(
                watermark_record["absolute_max_ns"],
                "materialized world basis watermark.absolute_max_ns",
            ),
            mapping_method=_optional_storage_text(
                watermark_record["mapping_method"],
                "materialized world basis watermark.mapping_method",
                256,
            ),
            evidence=_evidence_tuple_from_storage(
                watermark_record["evidence"],
                "materialized world basis watermark.evidence",
                artifact_ids=artifact_ids,
                maximum=selected_limits.max_evidence_references,
                aggregate_count=aggregate_evidence_count,
            ),
        )

    basis = WorldBasis(
        kind=WorldBasisKind(record["kind"]),
        requested_time_ns=_storage_timestamp(
            record["requested_time_ns"],
            "materialized world basis requested_time_ns",
        ),
        resolved_at_min_ns=_storage_timestamp(
            record["resolved_at_min_ns"],
            "materialized world basis resolved_at_min_ns",
        ),
        resolved_at_max_ns=_storage_timestamp(
            record["resolved_at_max_ns"],
            "materialized world basis resolved_at_max_ns",
        ),
        capture_ranges=tuple(captures),
        provenance=Provenance(record["provenance"]),
        quality=Quality(record["quality"]),
        clock_domain=_optional_storage_text(
            record["clock_domain"],
            "materialized world basis clock_domain",
            256,
        ),
        selector=selector,
        node_resolutions=tuple(resolutions),
        watermark=watermark,
        unresolved_reason=_optional_storage_text(
            record["unresolved_reason"],
            "materialized world basis unresolved_reason",
            8_192,
        ),
    )
    _validate_basis_containers(
        basis,
        maximum_capture_ranges=selected_limits.max_capture_ranges,
        maximum_node_resolutions=selected_limits.max_node_resolutions,
        maximum_evidence=selected_limits.max_evidence_references,
    )
    projected = _client_value(
        basis,
        label="materialized world basis",
        stringify_integers=True,
        maximum_units=selected_limits.max_basis_value_units,
        maximum_sequence_items=max(
            selected_limits.max_capture_ranges,
            selected_limits.max_node_resolutions,
            selected_limits.max_evidence_references,
        ),
    )
    canonical = strict_canonical_json(dict(record))
    if strict_canonical_json(projected) != canonical:
        raise ValueError("materialized world basis is not canonical")
    return canonical


def validate_materialized_consistency_basis(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits | None = None,
    aggregate_evidence_count: list[int] | None = None,
) -> str:
    """Validate and return the canonical JSON for one stored WorldBasis."""

    selected_limits = limits or ConsistencyMaterializationLimits()
    admitted_artifact_ids = _validate_materialized_artifact_ids(
        artifact_ids,
        selected_limits,
    )
    return _validate_materialized_consistency_basis(
        value,
        artifact_ids=admitted_artifact_ids,
        limits=selected_limits,
        aggregate_evidence_count=aggregate_evidence_count,
    )


def _validate_materialized_resource_reference(
    value: object,
    label: str,
) -> str:
    record = _exact_storage_record(
        value,
        frozenset({"resource_id", "typed_resource_key"}),
        label,
    )
    resource_id = _storage_text(record["resource_id"], f"{label}.resource_id", 4_096)
    identity = _exact_storage_record(
        record["typed_resource_key"],
        frozenset({"namespace", "node", "layer", "kind", "parts"}),
        f"{label}.typed_resource_key",
    )
    identity_text = {
        field: _storage_text(
            identity[field],
            f"{label}.typed_resource_key.{field}",
            256,
        )
        for field in ("namespace", "node", "layer", "kind")
    }
    parts = identity["parts"]
    if type(parts) is not list or not 1 <= len(parts) <= 32:
        raise ValueError(f"{label}.typed_resource_key.parts is invalid")
    names: set[str] = set()
    decoded_parts: list[tuple[str, Any]] = []

    def decode_key_value(normalized: Mapping[str, Any]) -> Any:
        value_type = normalized["type"]
        if value_type == "integer":
            return int(normalized["value"], 10)
        if value_type == "string":
            return normalized["value"]
        if value_type == "bytes":
            return b64decode(normalized["value"], validate=True)
        if value_type == "uuid":
            return UUID(normalized["value"])
        if value_type == "tuple":
            return tuple(decode_key_value(item) for item in normalized["items"])
        if value_type == "key_atom":
            return KeyAtom(
                normalized["type_tag"],
                decode_key_value(normalized["value"]),
            )
        raise ValueError(f"{label}.typed_resource_key contains a non-KeyValue tag")

    for index, raw_part in enumerate(parts):
        part = _exact_storage_record(
            raw_part,
            frozenset({"name", "value"}),
            f"{label}.typed_resource_key.parts[{index}]",
        )
        name = _storage_text(part["name"], f"{label}.part.name", 256)
        if name in names:
            raise ValueError(f"{label}.typed_resource_key part names must be unique")
        names.add(name)
        normalized = normalized_opaque_value_json(part["value"])
        if canonical_json(normalized) != canonical_json(part["value"]):
            raise ValueError(f"{label}.typed_resource_key value is not canonical")
        decoded_parts.append((name, decode_key_value(normalized)))
    resource_key = ResourceKey(
        namespace=identity_text["namespace"],
        node=identity_text["node"],
        layer=identity_text["layer"],
        kind=identity_text["kind"],
        parts=tuple(decoded_parts),
    )
    expected_id, expected_identity = _canonical_resource_identity(resource_key)
    if resource_id != expected_id:
        raise ValueError(f"{label}.resource_id does not match its typed key")
    if canonical_json(expected_identity) != canonical_json(dict(identity)):
        raise ValueError(f"{label}.typed_resource_key is not canonical")
    return resource_id


def _validate_materialized_consistency_finding(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits,
    aggregate_resource_count: list[int] | None = None,
    aggregate_evidence_count: list[int] | None = None,
) -> None:
    selected_limits = limits
    record = _exact_storage_record(
        value,
        _MATERIALIZED_FINDING_FIELDS,
        "materialized consistency finding",
    )
    if not _is_lowercase_sha256_digest(record["finding_id"]) or not (
        _is_lowercase_sha256_digest(record["execution_plan_digest"])
    ):
        raise ValueError("materialized consistency finding digest is invalid")
    _storage_text(record["rule_id"], "consistency finding rule_id", 256)
    DiagnosticSeverity(record["severity"])
    FindingResult(record["result"])
    _storage_text(record["summary"], "consistency finding summary", 8_192)
    Provenance(record["provenance"])
    Quality(record["quality"])
    if (
        type(record["resource_references"]) is not list
        or len(record["resource_references"])
        > selected_limits.max_resource_references
    ):
        raise ValueError("consistency finding resource_references must be an array")
    if aggregate_resource_count is not None:
        aggregate_resource_count[0] += len(record["resource_references"])
        if aggregate_resource_count[0] > selected_limits.max_resource_references:
            raise ValueError(
                "materialized consistency resource references exceed the aggregate limit"
            )
    resources = record["resources"]
    if (
        type(resources) is not list
        or len(resources) > selected_limits.max_resource_references
        or len(resources) != len(record["resource_references"])
    ):
        raise ValueError(
            "consistency finding resources do not match resource_references"
        )
    reference_ids = [
        _validate_materialized_resource_reference(
            item,
            f"consistency finding resource_references[{index}]",
        )
        for index, item in enumerate(record["resource_references"])
    ]
    if (
        any(type(item) is not str for item in resources)
        or resources != reference_ids
    ):
        raise ValueError(
            "consistency finding resources do not match resource_references"
        )
    _validate_materialized_consistency_basis(
        record["basis"],
        artifact_ids=artifact_ids,
        limits=selected_limits,
    )
    _evidence_tuple_from_storage(
        record["evidence"],
        "consistency finding evidence",
        artifact_ids=artifact_ids,
        maximum=selected_limits.max_evidence_references,
        aggregate_count=aggregate_evidence_count,
    )
    if type(record["details"]) is not dict:
        raise ValueError("consistency finding details must be an exact object")
    _validate_storage_json(record["details"], "consistency finding details")
    projected_details = _client_value(
        record["details"],
        label="consistency finding details",
        accept_json_arrays=True,
    )
    if strict_canonical_json(projected_details) != strict_canonical_json(
        record["details"]
    ):
        raise ValueError("consistency finding details are not canonical")
    _validate_materialized_provider_projection(
        record["producer"],
        "consistency finding producer",
    )
    _validate_materialized_record_identity(
        record,
        identity_field="finding_id",
        label="materialized consistency finding",
    )


def validate_materialized_consistency_finding(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits | None = None,
    aggregate_resource_count: list[int] | None = None,
    aggregate_evidence_count: list[int] | None = None,
) -> None:
    """Reject a partial or non-canonical persisted consistency finding."""

    selected_limits = limits or ConsistencyMaterializationLimits()
    admitted_artifact_ids = _validate_materialized_artifact_ids(
        artifact_ids,
        selected_limits,
    )
    _validate_materialized_consistency_finding(
        value,
        artifact_ids=admitted_artifact_ids,
        limits=selected_limits,
        aggregate_resource_count=aggregate_resource_count,
        aggregate_evidence_count=aggregate_evidence_count,
    )


def _validate_materialized_consistency_diagnostic(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits,
    aggregate_evidence_count: list[int] | None = None,
) -> None:
    selected_limits = limits
    record = _exact_storage_record(
        value,
        _MATERIALIZED_DIAGNOSTIC_FIELDS,
        "materialized consistency diagnostic",
    )
    if not _is_lowercase_sha256_digest(record["diagnostic_id"]):
        raise ValueError("materialized consistency diagnostic digest is invalid")
    DiagnosticStage(record["stage"])
    DiagnosticSeverity(record["severity"])
    _storage_text(record["code"], "consistency diagnostic code", 256)
    _storage_text(
        record["message"],
        "consistency diagnostic message",
        8_192,
    )
    if type(record["recoverable"]) is not bool or not record["recoverable"]:
        raise ValueError("materialized consistency diagnostic must be recoverable")
    if DiagnosticOrigin(record["origin"]) is not DiagnosticOrigin.PLUGIN:
        raise ValueError("materialized consistency diagnostic origin is invalid")
    _evidence_tuple_from_storage(
        record["evidence"],
        "consistency diagnostic evidence",
        artifact_ids=artifact_ids,
        maximum=selected_limits.max_evidence_references,
        aggregate_count=aggregate_evidence_count,
    )
    if type(record["details"]) is not dict:
        raise ValueError("consistency diagnostic details must be an exact object")
    _validate_storage_json(record["details"], "consistency diagnostic details")
    projected_details = _client_value(
        record["details"],
        label="consistency diagnostic details",
        accept_json_arrays=True,
    )
    if strict_canonical_json(projected_details) != strict_canonical_json(
        record["details"]
    ):
        raise ValueError("consistency diagnostic details are not canonical")
    _validate_materialized_provider_projection(
        record["producer"],
        "consistency diagnostic producer",
    )
    _validate_materialized_record_identity(
        record,
        identity_field="diagnostic_id",
        label="materialized consistency diagnostic",
    )


def validate_materialized_consistency_diagnostic(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    limits: ConsistencyMaterializationLimits | None = None,
    aggregate_evidence_count: list[int] | None = None,
) -> None:
    """Reject a partial or non-canonical persisted consistency diagnostic."""

    selected_limits = limits or ConsistencyMaterializationLimits()
    admitted_artifact_ids = _validate_materialized_artifact_ids(
        artifact_ids,
        selected_limits,
    )
    _validate_materialized_consistency_diagnostic(
        value,
        artifact_ids=admitted_artifact_ids,
        limits=selected_limits,
        aggregate_evidence_count=aggregate_evidence_count,
    )


def validate_consistency_materialization_envelope(value: object) -> None:
    """Require the complete closed v1 durable materialization envelope."""

    record = _exact_storage_record(
        value,
        CONSISTENCY_MATERIALIZATION_ENVELOPE_FIELDS,
        "consistency materialization",
    )
    if record["schema_version"] != CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION:
        raise ValueError("consistency materialization schema is unsupported")
    if type(record["status"]) is not str or record["status"] not in {
        ConsistencyMaterializationStatus.COMPLETE.value,
        ConsistencyMaterializationStatus.NOT_APPLICABLE.value,
    }:
        raise ValueError("consistency materialization status is invalid")
    if not _is_lowercase_sha256_digest(record["plan_digest"]):
        raise ValueError("consistency materialization plan digest is invalid")
    if record["basis"] is not None and type(record["basis"]) is not dict:
        raise ValueError("consistency materialization basis is invalid")
    if record["basis_digest"] is not None and not _is_lowercase_sha256_digest(
        record["basis_digest"]
    ):
        raise ValueError("consistency materialization basis digest is invalid")
    if type(record["providers"]) is not list:
        raise ValueError("consistency materialization providers are invalid")
    for field in CONSISTENCY_MATERIALIZATION_COUNT_FIELDS:
        count = record[field]
        if type(count) is not int or not 0 <= count <= _JSON_SAFE_INTEGER_MAX:
            raise ValueError(f"consistency materialization {field} is invalid")


def materialize_revision_consistency(
    *,
    plan: PluginExecutionPlan,
    router: PlanBoundCapabilityRouter,
    world: ReadOnlyWorld,
    artifact_ids: Collection[UUID],
    limits: ConsistencyMaterializationLimits | None = None,
) -> ConsistencyMaterializationResult:
    """Invoke the plan-selected providers and return deterministic output.

    The primary parser participates automatically when it declares
    ``CONSISTENCY_CHECK``. Auxiliary pins participate only when they carry the
    reserved ``revision_consistency`` role. Limits count emitted values before
    duplicate elimination, so repetition cannot bypass a quota.
    """

    selected_limits = limits or ConsistencyMaterializationLimits()
    if type(selected_limits) is not ConsistencyMaterializationLimits:
        raise TypeError("limits must be an exact ConsistencyMaterializationLimits")
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    if type(router) is not PlanBoundCapabilityRouter:
        raise TypeError("router must be an exact PlanBoundCapabilityRouter")
    try:
        detached_plan = snapshot_plugin_execution_plan(plan)
        if router.plan != detached_plan:
            raise ConsistencyMaterializationError(
                "capability router is not bound to the supplied execution plan"
            )
        if router.member_id != detached_plan.basis_revision_id:
            raise ConsistencyMaterializationError(
                "capability router member does not match the execution-plan "
                "basis revision"
            )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except ConsistencyMaterializationError:
        raise
    except BaseException as error:
        raise ConsistencyMaterializationError(
            "consistency materialization inputs could not be validated"
        ) from error
    selected = _selected_pins(detached_plan)
    if len(selected) > selected_limits.max_providers:
        raise ConsistencyMaterializationError(
            "consistency provider count exceeded the configured limit"
        )
    if not selected:
        result = _not_applicable_result(detached_plan)
        _require_published_consistency_storage_budget(
            result,
            selected_limits.max_serialized_bytes,
        )
        return result

    try:
        admitted_artifacts = _artifact_id_set(
            artifact_ids,
            maximum=selected_limits.max_artifact_ids,
        )
        basis = world.basis
        perspective_ref = world.perspective_ref
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except ConsistencyMaterializationError:
        raise
    except BaseException as error:
        raise ConsistencyMaterializationError(
            "consistency materialization world could not be validated"
        ) from error
    if type(basis) is not WorldBasis:
        raise ConsistencyMaterializationError(
            "revision world basis must be an exact WorldBasis"
        )
    try:
        basis_evidence_count = _validate_basis_containers(
            basis,
            maximum_capture_ranges=selected_limits.max_capture_ranges,
            maximum_node_resolutions=selected_limits.max_node_resolutions,
            maximum_evidence=selected_limits.max_evidence_references,
        )
        for index, item in enumerate(_basis_evidence(basis)):
            _evidence_projection(
                item,
                artifact_ids=admitted_artifacts,
                label=f"world basis evidence[{index}]",
            )
        basis_projection_budget = _ProjectionByteBudget(
            selected_limits.max_serialized_bytes
        )
        basis_projection = _client_value(
            _basis_with_canonical_storage_evidence(basis),
            label="world basis",
            stringify_integers=True,
            maximum_units=selected_limits.max_basis_value_units,
            maximum_sequence_items=max(
                selected_limits.max_capture_ranges,
                selected_limits.max_node_resolutions,
                selected_limits.max_evidence_references,
            ),
            byte_budget=basis_projection_budget,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except ConsistencyMaterializationError:
        raise
    except BaseException as error:
        raise ConsistencyMaterializationError(
            "revision world basis could not be projected"
        ) from error
    assert type(basis_projection) is dict
    canonical_basis = strict_canonical_json(basis_projection)
    canonical_basis_bytes = len(canonical_basis.encode("utf-8"))
    basis_digest = "sha256:" + sha256(canonical_basis.encode("utf-8")).hexdigest()

    aggregate_world = _AggregateWorld(
        world,
        basis=basis,
        perspective_ref=perspective_ref,
        maximum_reads=selected_limits.max_world_reads,
    )
    findings_by_id: dict[str, MaterializedConsistencyFinding] = {}
    diagnostics_by_id: dict[str, MaterializedConsistencyDiagnostic] = {}
    providers: list[CapabilityProviderRef] = []
    emitted_findings = 0
    emitted_diagnostics = 0
    resource_references = 0
    evidence_references = basis_evidence_count
    serialized_bytes = canonical_basis_bytes
    if serialized_bytes > selected_limits.max_serialized_bytes:
        raise ConsistencyMaterializationError(
            "consistency basis exceeded the aggregate byte limit"
        )

    for pin in selected:
        role = (
            "primary_parser"
            if "primary_parser" in pin.roles
            else REVISION_CONSISTENCY_ROLE
        )
        try:
            route = router.resolve(
                CapabilityRouteSelector(
                    PluginCapability.CONSISTENCY_CHECK,
                    role=role,
                    instance_id=pin.instance_id,
                )
            )
            invocation = route.check_consistency(aggregate_world)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PluginCapabilityOutputError as error:
            if str(error) == (
                "consistency finding basis does not match the revision world basis"
            ):
                raise ConsistencyMaterializationError(str(error)) from error
            raise ConsistencyMaterializationError(
                "selected consistency provider failed"
            ) from error
        except BaseException as error:
            raise ConsistencyMaterializationError(
                "selected consistency provider failed"
            ) from error
        provider = invocation.provider
        if (
            provider.plan_digest != detached_plan.plan_digest
            or provider.pin != pin
            or provider.capability is not PluginCapability.CONSISTENCY_CHECK
        ):
            raise ConsistencyMaterializationError(
                "consistency invocation returned stale provider provenance"
            )
        providers.append(provider)

        for finding in invocation.result.findings:
            emitted_findings += 1
            if emitted_findings > selected_limits.max_findings:
                raise ConsistencyMaterializationError(
                    "consistency findings exceeded the aggregate limit"
                )
            # Every retained finding repeats the complete authoritative basis.
            # Reject before constructing/serializing that record when even the
            # basis alone cannot fit in the remaining revision-wide budget.
            if (
                canonical_basis_bytes
                > selected_limits.max_serialized_bytes - serialized_bytes
            ):
                raise ConsistencyMaterializationError(
                    "consistency output exceeded the aggregate byte limit"
                )
            try:
                record, resources_count, evidence_count = _finding_projection(
                    finding,
                    provider=provider,
                    plan_digest=detached_plan.plan_digest,
                    basis=basis,
                    basis_projection=basis_projection,
                    artifact_ids=admitted_artifacts,
                )
                canonical_record = strict_canonical_json(record)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except ConsistencyMaterializationError:
                raise
            except BaseException as error:
                raise ConsistencyMaterializationError(
                    "consistency finding could not be projected"
                ) from error
            resource_references += resources_count
            evidence_references += evidence_count
            serialized_bytes += len(canonical_record.encode("utf-8"))
            if resource_references > selected_limits.max_resource_references:
                raise ConsistencyMaterializationError(
                    "consistency resource references exceeded the aggregate limit"
                )
            if evidence_references > selected_limits.max_evidence_references:
                raise ConsistencyMaterializationError(
                    "consistency evidence references exceeded the aggregate limit"
                )
            if serialized_bytes > selected_limits.max_serialized_bytes:
                raise ConsistencyMaterializationError(
                    "consistency output exceeded the aggregate byte limit"
                )
            finding_id = record["finding_id"]
            assert type(finding_id) is str
            materialized = MaterializedConsistencyFinding(
                finding_id=finding_id,
                provider=provider,
                canonical_record=canonical_record,
            )
            previous = findings_by_id.get(finding_id)
            if previous is not None and previous.canonical_record != canonical_record:
                raise ConsistencyMaterializationError(
                    "consistency finding identity collision"
                )
            findings_by_id.setdefault(finding_id, materialized)

        for diagnostic in invocation.result.diagnostics:
            emitted_diagnostics += 1
            if emitted_diagnostics > selected_limits.max_diagnostics:
                raise ConsistencyMaterializationError(
                    "consistency diagnostics exceeded the aggregate limit"
                )
            try:
                record, evidence_count = _diagnostic_projection(
                    diagnostic,
                    provider=provider,
                    artifact_ids=admitted_artifacts,
                )
                canonical_payload = strict_canonical_json(record)
                diagnostic_id = (
                    "sha256:" + sha256(canonical_payload.encode("utf-8")).hexdigest()
                )
                record["diagnostic_id"] = diagnostic_id
                canonical_record = strict_canonical_json(record)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except ConsistencyMaterializationError:
                raise
            except BaseException as error:
                raise ConsistencyMaterializationError(
                    "consistency diagnostic could not be projected"
                ) from error
            evidence_references += evidence_count
            serialized_bytes += len(canonical_record.encode("utf-8"))
            if evidence_references > selected_limits.max_evidence_references:
                raise ConsistencyMaterializationError(
                    "consistency evidence references exceeded the aggregate limit"
                )
            if serialized_bytes > selected_limits.max_serialized_bytes:
                raise ConsistencyMaterializationError(
                    "consistency output exceeded the aggregate byte limit"
                )
            materialized_diagnostic = MaterializedConsistencyDiagnostic(
                diagnostic_id=diagnostic_id,
                provider=provider,
                diagnostic=diagnostic,
                canonical_record=canonical_record,
            )
            previous = diagnostics_by_id.get(diagnostic_id)
            if previous is not None and previous.canonical_record != canonical_record:
                raise ConsistencyMaterializationError(
                    "consistency diagnostic identity collision"
                )
            diagnostics_by_id.setdefault(diagnostic_id, materialized_diagnostic)

    findings = tuple(findings_by_id[key] for key in sorted(findings_by_id))
    diagnostics = tuple(diagnostics_by_id[key] for key in sorted(diagnostics_by_id))
    counts = {result: 0 for result in FindingResult}
    for item in findings:
        projection = item.client_projection()
        counts[FindingResult(projection["result"])] += 1
    result = ConsistencyMaterializationResult(
        status=ConsistencyMaterializationStatus.COMPLETE,
        plan_digest=detached_plan.plan_digest,
        providers=tuple(providers),
        findings=findings,
        diagnostics=diagnostics,
        summary=ConsistencyMaterializationSummary(
            passed=counts[FindingResult.PASS],
            failed=counts[FindingResult.FAIL],
            unknown=counts[FindingResult.UNKNOWN],
        ),
        emitted_findings=emitted_findings,
        emitted_diagnostics=emitted_diagnostics,
        duplicate_findings_discarded=emitted_findings - len(findings),
        duplicate_diagnostics_discarded=emitted_diagnostics - len(diagnostics),
        world_reads=aggregate_world.reads_used,
        canonical_basis=canonical_basis,
        basis_digest=basis_digest,
    )
    _require_published_consistency_storage_budget(
        result,
        selected_limits.max_serialized_bytes,
    )
    return result


__all__ = [
    "CONSISTENCY_MATERIALIZATION_COUNT_FIELDS",
    "CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION",
    "ConsistencyMaterializationError",
    "ConsistencyMaterializationLimits",
    "ConsistencyMaterializationResult",
    "ConsistencyMaterializationStatus",
    "ConsistencyMaterializationSummary",
    "MaterializedConsistencyDiagnostic",
    "MaterializedConsistencyFinding",
    "legacy_consistency_materialization_envelope",
    "materialize_revision_consistency",
    "not_applicable_consistency_materialization",
    "revision_consistency_selected_pins",
    "validate_consistency_materialization_envelope",
    "validate_materialized_consistency_basis",
    "validate_materialized_consistency_diagnostic",
    "validate_materialized_consistency_finding",
]
