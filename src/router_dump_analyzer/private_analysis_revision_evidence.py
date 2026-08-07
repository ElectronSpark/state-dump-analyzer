"""Deterministic client-safe evidence projection for trusted revisions.

The adapter intentionally sits between the durable catalog/data loader and the
private-analysis tool service.  It accepts already verified descriptors and a
normalized dataset, selects each revision's time independently, and freezes a
request-bound evidence corpus before any model runner can execute.

This module performs no catalog lookup, authorization, plug-in invocation, or
model work. It can freeze either the existing client-safe views or the already
normalized plug-in-owned values selected by an independently authorized
full-fidelity policy; it never interprets those proprietary values.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any

from .cancellation import check_cancellation_probe, cooperatively_sorted
from .contract_validation import validate_bounded_json_value
from .normalized_data import (
    EventRedactionPolicy,
    NormalizedDataCancellationProbeError,
    NormalizedDataCancellationProbeResultError,
    NormalizedDataCancellationRequested,
    event_redaction_policy,
    redact_event_for_client,
    redact_resource_for_client,
    redact_resource_view,
    resource_id,
)
from .plugin_execution_plan import (
    plugin_execution_pin_dict,
    primary_parser_execution_pin,
)
from .private_analysis.contracts import (
    PrivateAnalysisClockMode,
    PrivateAnalysisRequest,
)
from .private_analysis.disclosure import PrivateAnalysisEvidenceClass
from .private_analysis.evidence import (
    MAX_EVIDENCE_PAYLOAD_ATOM_CHARACTERS,
    MAX_EVIDENCE_PAYLOAD_CONTAINER_ITEMS,
    MAX_EVIDENCE_PAYLOAD_DEPTH,
    MAX_EVIDENCE_PAYLOAD_UNITS,
    CoreEvidenceProducer,
    EvidenceAuthority,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeBasis,
    EvidenceTimeRange,
    evidence_locator_digest,
    evidence_payload_digest,
    validate_evidence_token,
)
from .private_analysis.evidence_corpus import (
    DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES,
    DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES,
    MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES,
    MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES,
    PrivateAnalysisEvidenceCorpus,
    PrivateAnalysisEvidenceEntry,
)
from .private_analysis_binding import (
    PrivateAnalysisEvidenceBindingError,
    bind_private_analysis_plugin_producer,
    bind_private_analysis_revision,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)
from .source_record_core import project_source_record_for_log
from .value_core import MAX_JSON_SAFE_INTEGER, parse_canonical_decimal_integer

_SIGNED_NS_MIN = -(1 << 63)
_SIGNED_NS_MAX = (1 << 63) - 1

_REVISION_METADATA_SCHEMA = "router_dump_analyzer.client_safe.revision_metadata.v2"
_PLUGIN_SCHEMA_METADATA_SCHEMA = "router_dump_analyzer.client_safe.plugin_schema.v1"
_SOURCE_RECORD_SCHEMA = "router_dump_analyzer.client_safe.source_record.v1"
_EVENT_SCHEMA = "router_dump_analyzer.client_safe.normalized_event.v1"
_RESOURCE_IDENTITY_SCHEMA = "router_dump_analyzer.client_safe.resource_identity.v1"
_RESOURCE_STATE_SCHEMA = "router_dump_analyzer.client_safe.resource_state_interval.v1"
_RELATIONSHIP_SCHEMA = "router_dump_analyzer.client_safe.relationship_interval.v1"
_PROPRIETARY_SOURCE_RECORD_SCHEMA = "router_dump_analyzer.proprietary.source_record.v1"
_PROPRIETARY_EVENT_SCHEMA = "router_dump_analyzer.proprietary.normalized_event.v1"
_PROPRIETARY_RESOURCE_IDENTITY_SCHEMA = (
    "router_dump_analyzer.proprietary.resource_identity.v1"
)
_PROPRIETARY_RESOURCE_STATE_SCHEMA = (
    "router_dump_analyzer.proprietary.resource_state_interval.v1"
)
_PROPRIETARY_RELATIONSHIP_SCHEMA = (
    "router_dump_analyzer.proprietary.relationship_interval.v1"
)


class PrivateAnalysisRevisionEvidenceError(ValueError):
    """Trusted revision evidence cannot be projected without ambiguity."""


class PrivateAnalysisRevisionEvidenceCancelled(
    PrivateAnalysisRevisionEvidenceError
):
    """Evidence freezing stopped for a cancelled or expired durable run."""


@dataclass(slots=True)
class _EvidenceEntryAccumulator:
    """Bound canonical payload storage before the corpus duplicates indexes."""

    maximum_entries: int
    maximum_payload_bytes: int
    entries: list[PrivateAnalysisEvidenceEntry]
    payload_bytes: int = 0

    def __len__(self) -> int:
        return len(self.entries)

    def append(self, entry: PrivateAnalysisEvidenceEntry) -> None:
        if len(self.entries) >= self.maximum_entries:
            raise PrivateAnalysisRevisionEvidenceError(
                "private-analysis revision evidence exceeds the configured "
                "corpus entry limit"
            )
        next_bytes = self.payload_bytes + entry.payload_bytes
        if next_bytes > self.maximum_payload_bytes:
            raise PrivateAnalysisRevisionEvidenceError(
                "private-analysis revision evidence exceeds the configured "
                "corpus payload byte limit"
            )
        self.entries.append(entry)
        self.payload_bytes = next_bytes


_check_cancellation = partial(
    check_cancellation_probe,
    cancelled_error=lambda: PrivateAnalysisRevisionEvidenceCancelled(
        "private-analysis evidence freezing was cancelled"
    ),
    unavailable_error=lambda: PrivateAnalysisRevisionEvidenceError(
        "private-analysis cancellation state is unavailable"
    ),
    invalid_result_error=lambda: PrivateAnalysisRevisionEvidenceError(
        "private-analysis cancellation probe returned an invalid value"
    ),
)


@dataclass(frozen=True, slots=True)
class TrustedPrivateAnalysisRevision:
    """One loader-verified revision supplied to the pure evidence adapter.

    ``dataset`` is intentionally retained by reference: the durable loader may
    already hold a very large immutable mapping.  The builder never mutates or
    deep-copies it; each selected client-safe payload is frozen immediately by
    :class:`PrivateAnalysisEvidenceEntry`.
    """

    workspace: WorkspaceDescriptor
    fixture: FixtureDescriptor
    revision: AnalysisRevisionDescriptor
    dataset: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.workspace) is not WorkspaceDescriptor:
            raise TypeError("workspace must be WorkspaceDescriptor")
        if type(self.fixture) is not FixtureDescriptor:
            raise TypeError("fixture must be FixtureDescriptor")
        if type(self.revision) is not AnalysisRevisionDescriptor:
            raise TypeError("revision must be AnalysisRevisionDescriptor")
        if not isinstance(self.dataset, Mapping):
            raise TypeError("dataset must be a mapping")
        # Validate the catalog relationship now, without retaining a second
        # detached copy of a potentially large normalized dataset.
        bind_private_analysis_revision(
            self.workspace,
            self.fixture,
            self.revision,
        )


@dataclass(frozen=True, slots=True)
class _TimelineClock:
    basis: EvidenceTimeBasis
    clock_domain: str | None = None


def _ns(value: object, label: str, *, minimum: int = _SIGNED_NS_MIN) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            label,
            minimum=minimum,
            maximum=_SIGNED_NS_MAX,
        )
    except ValueError as error:
        raise PrivateAnalysisRevisionEvidenceError(
            f"{label} must be a canonical decimal nanosecond value between "
            f"{minimum} and {_SIGNED_NS_MAX}"
        ) from error


def _optional_ns(
    value: object,
    label: str,
    *,
    minimum: int = _SIGNED_NS_MIN,
) -> int | None:
    if value is None:
        return None
    return _ns(value, label, minimum=minimum)


def _dataset_sequence(
    dataset: Mapping[str, Any],
    field: str,
    *,
    cancellation_probe: Callable[[], bool] | None = None,
) -> Sequence[Mapping[str, Any]]:
    supplied = dataset.get(field, ())
    if not isinstance(supplied, (list, tuple)):
        raise PrivateAnalysisRevisionEvidenceError(
            f"normalized dataset {field} must be a sequence"
        )
    for ordinal, item in enumerate(supplied):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        if not isinstance(item, Mapping):
            raise PrivateAnalysisRevisionEvidenceError(
                f"normalized dataset {field} must contain mappings"
            )
    return supplied


def validate_private_analysis_timeline_metadata(
    dataset: Mapping[str, Any],
) -> tuple[int, int, EvidenceTimeBasis, str | None]:
    """Validate and return the exact declared normalized timeline domain."""

    ingestion = dataset.get("_ingestion")
    if not isinstance(ingestion, Mapping):
        raise PrivateAnalysisRevisionEvidenceError(
            "normalized dataset lacks trusted _ingestion metadata"
        )
    raw_basis = ingestion.get("timeline_time_basis")
    if raw_basis is None:
        basis = EvidenceTimeBasis.REVISION_START_RELATIVE_NS
    else:
        try:
            basis = EvidenceTimeBasis(raw_basis)
        except (TypeError, ValueError) as error:
            raise PrivateAnalysisRevisionEvidenceError(
                "timeline_time_basis is unsupported"
            ) from error
    if basis not in {
        EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
        EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
        EvidenceTimeBasis.SOURCE_CLOCK_NS,
    }:
        raise PrivateAnalysisRevisionEvidenceError(
            "timeline_time_basis cannot identify temporal revision evidence"
        )
    declared_clock_domain = ingestion.get("timeline_clock_domain")
    clock_domain: str | None = None
    if declared_clock_domain is not None:
        try:
            clock_domain = validate_evidence_token(
                declared_clock_domain,
                "timeline_clock_domain",
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise PrivateAnalysisRevisionEvidenceError(
                "timeline_clock_domain must be a bounded path-safe token"
            ) from error
    if basis is EvidenceTimeBasis.SOURCE_CLOCK_NS:
        if clock_domain is None:
            raise PrivateAnalysisRevisionEvidenceError(
                "source-clock timeline requires timeline_clock_domain"
            )
    elif clock_domain is not None:
        raise PrivateAnalysisRevisionEvidenceError(
            "timeline_clock_domain is valid only for a source-clock timeline"
        )
    minimum = 0 if basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _SIGNED_NS_MIN
    start = _ns(
        ingestion.get("timeline_start_ns"),
        "timeline_start_ns",
        minimum=minimum,
    )
    end = _ns(
        ingestion.get("timeline_end_ns"),
        "timeline_end_ns",
        minimum=minimum,
    )
    if end < start:
        raise PrivateAnalysisRevisionEvidenceError(
            "normalized dataset timeline end precedes its start"
        )
    if (
        basis is EvidenceTimeBasis.REVISION_START_RELATIVE_NS
        and end - start > _SIGNED_NS_MAX
    ):
        raise PrivateAnalysisRevisionEvidenceError(
            "revision-relative timeline span exceeds signed 64-bit nanoseconds"
        )
    return start, end, basis, clock_domain


def _timeline_bounds(
    dataset: Mapping[str, Any],
) -> tuple[int, int, _TimelineClock]:
    start, end, basis, clock_domain = validate_private_analysis_timeline_metadata(
        dataset
    )
    return start, end, _TimelineClock(basis, clock_domain)


def private_analysis_revision_cutoff_ns(
    request: PrivateAnalysisRequest,
    revision_binding: EvidenceRevisionBinding,
    *,
    timeline_start_ns: int,
    timeline_end_ns: int,
    timeline_basis: EvidenceTimeBasis,
) -> int:
    """Resolve one request clock against one revision without clamping."""

    if type(request) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    if type(revision_binding) is not EvidenceRevisionBinding:
        raise TypeError("revision_binding must be EvidenceRevisionBinding")
    if revision_binding not in request.revisions:
        raise PrivateAnalysisEvidenceBindingError(
            "revision is not a member of the private-analysis request"
        )
    temporal_bases = {
        EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
        EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
        EvidenceTimeBasis.SOURCE_CLOCK_NS,
    }
    minimum = (
        0 if timeline_basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _SIGNED_NS_MIN
    )
    if (
        type(timeline_basis) is not EvidenceTimeBasis
        or timeline_basis not in temporal_bases
        or type(timeline_start_ns) is not int
        or type(timeline_end_ns) is not int
        or not minimum <= timeline_start_ns <= _SIGNED_NS_MAX
        or not minimum <= timeline_end_ns <= _SIGNED_NS_MAX
        or timeline_end_ns < timeline_start_ns
    ):
        raise PrivateAnalysisRevisionEvidenceError(
            "revision timeline bounds are invalid"
        )
    if request.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION:
        cutoff = timeline_end_ns
    elif request.clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS:
        if timeline_basis is not EvidenceTimeBasis.ABSOLUTE_UNIX_NS:
            raise PrivateAnalysisRevisionEvidenceError(
                "absolute private-analysis time requires a revision timeline "
                "proven as absolute Unix nanoseconds"
            )
        assert request.selected_time_ns is not None
        cutoff = request.selected_time_ns
    elif request.clock_mode is PrivateAnalysisClockMode.REVISION_END_RELATIVE_NS:
        assert request.selected_time_ns is not None
        cutoff = timeline_end_ns + request.selected_time_ns
        if not _SIGNED_NS_MIN <= cutoff <= _SIGNED_NS_MAX:
            raise PrivateAnalysisRevisionEvidenceError(
                "revision-relative selected time exceeds signed 64-bit nanoseconds"
            )
    else:  # pragma: no cover - sealed request enum
        raise PrivateAnalysisRevisionEvidenceError(
            "private-analysis request uses an unsupported clock mode"
        )
    if not timeline_start_ns <= cutoff <= timeline_end_ns:
        raise PrivateAnalysisRevisionEvidenceError(
            "selected time is outside the revision timeline"
        )
    return cutoff


def _interval_at(
    item: Mapping[str, Any],
    cutoff_ns: int,
    *,
    allow_unknown_start: bool,
    subject: str,
) -> tuple[bool, int | None]:
    start = _optional_ns(item.get("valid_from_ns"), "valid_from_ns")
    end = _optional_ns(item.get("valid_to_ns"), "valid_to_ns")
    if start is not None and end is not None and end < start:
        raise PrivateAnalysisRevisionEvidenceError(
            "normalized validity interval ends before it starts"
        )
    if end is not None and cutoff_ns >= end:
        return False, start
    if start is not None:
        return cutoff_ns >= start, start
    if allow_unknown_start:
        return True, None
    raise PrivateAnalysisRevisionEvidenceError(
        f"historical private analysis cannot place {subject} with an unknown "
        "validity start"
    )


def _selected_interval_time(
    clock: _TimelineClock,
    start_ns: int | None,
    cutoff_ns: int,
) -> EvidenceTimeRange:
    if start_ns is None:
        return EvidenceTimeRange.unknown()
    return _time_interval(clock, start_ns, cutoff_ns)


_PROVENANCE = {
    "observed": EvidenceFactProvenance.OBSERVED,
    "event_derived": EvidenceFactProvenance.LOG_DERIVED,
    "reconstructed": EvidenceFactProvenance.STATE_RECONSTRUCTED,
    "correlated": EvidenceFactProvenance.RELATIONSHIP_INFERRED,
    "plugin_default": EvidenceFactProvenance.SNAPSHOT_OBSERVED,
}


def _fact_provenance(
    value: object,
    *,
    default: EvidenceFactProvenance,
) -> EvidenceFactProvenance:
    if value is None:
        return default
    if type(value) is not str or value not in _PROVENANCE:
        raise PrivateAnalysisRevisionEvidenceError(
            "normalized evidence has an unsupported provenance value"
        )
    return _PROVENANCE[value]


def _projected_time_coordinate(clock: _TimelineClock, value: int) -> int:
    # A revision-start-relative value is already an offset from revision
    # start. ``timeline_start_ns`` is the lower bound of that coordinate
    # domain, not a second origin to subtract during evidence projection.
    if not _SIGNED_NS_MIN <= value <= _SIGNED_NS_MAX:
        raise PrivateAnalysisRevisionEvidenceError(
            "projected evidence time exceeds signed 64-bit nanoseconds"
        )
    return value


def _time_point(
    clock: _TimelineClock,
    timestamp_ns: int,
    uncertainty_ns: int | None = None,
) -> EvidenceTimeRange:
    coordinate = _projected_time_coordinate(clock, timestamp_ns)
    uncertainty = uncertainty_ns or 0
    if (
        coordinate - uncertainty < _SIGNED_NS_MIN
        or coordinate + uncertainty > _SIGNED_NS_MAX
    ):
        raise PrivateAnalysisRevisionEvidenceError(
            "projected evidence uncertainty exceeds signed 64-bit nanoseconds"
        )
    return EvidenceTimeRange(
        clock.basis,
        start_ns=coordinate,
        end_ns=coordinate,
        uncertainty_ns=uncertainty_ns,
        clock_domain=clock.clock_domain,
    )


def _time_interval(
    clock: _TimelineClock,
    start_ns: int,
    end_ns: int,
) -> EvidenceTimeRange:
    return EvidenceTimeRange(
        clock.basis,
        start_ns=_projected_time_coordinate(clock, start_ns),
        end_ns=_projected_time_coordinate(clock, end_ns),
        clock_domain=clock.clock_domain,
    )


def _selected_observation_time(
    request: PrivateAnalysisRequest,
    *,
    clock: _TimelineClock,
    timestamp_ns: int | None,
    uncertainty_ns: int | None,
    cutoff_ns: int,
    subject: str,
) -> EvidenceTimeRange | None:
    """Select a retained observation without inventing a missing timestamp.

    An unknown timestamp is usable for a latest-snapshot review because the
    retained item is part of that revision.  It cannot be placed on an
    earlier reconstruction, so historical requests fail instead of silently
    omitting or misdating the fact.
    """

    if timestamp_ns is None:
        if uncertainty_ns is not None:
            raise PrivateAnalysisRevisionEvidenceError(
                f"{subject} with an unknown timestamp cannot carry uncertainty"
            )
        if request.clock_mode is not PrivateAnalysisClockMode.LATEST_PER_REVISION:
            raise PrivateAnalysisRevisionEvidenceError(
                f"historical private analysis cannot place {subject} with an "
                "unknown timestamp"
            )
        return EvidenceTimeRange.unknown()
    uncertainty = uncertainty_ns or 0
    if (
        timestamp_ns - uncertainty < _SIGNED_NS_MIN
        or timestamp_ns + uncertainty > _SIGNED_NS_MAX
    ):
        raise PrivateAnalysisRevisionEvidenceError(
            f"{subject} uncertainty interval exceeds signed 64-bit nanoseconds"
        )
    if timestamp_ns - uncertainty > cutoff_ns:
        return None
    return _time_point(clock, timestamp_ns, uncertainty_ns)


def _entry(
    *,
    scope: EvidenceScope,
    revision_binding: EvidenceRevisionBinding,
    producer: EvidenceProducer,
    kind: EvidenceKind,
    subject_kind: str,
    locator_identity: dict[str, object],
    payload_schema: str,
    payload: dict[str, object],
    provenance: EvidenceFactProvenance,
    time_range: EvidenceTimeRange,
    evidence_class: PrivateAnalysisEvidenceClass = (
        PrivateAnalysisEvidenceClass.CLIENT_SAFE
    ),
    cancellation_probe: Callable[[], bool] | None,
) -> PrivateAnalysisEvidenceEntry:
    _check_cancellation(cancellation_probe)
    locator_digest = evidence_locator_digest(subject_kind, locator_identity)
    _check_cancellation(cancellation_probe)
    projected_payload = _json_safe_evidence_payload(payload)
    content_digest = evidence_payload_digest(payload_schema, projected_payload)
    _check_cancellation(cancellation_probe)
    reference = EvidenceReference(
        scope=scope,
        revision=revision_binding,
        producer=producer,
        kind=kind,
        subject_kind=subject_kind,
        locator_digest=locator_digest,
        evidence_class=evidence_class,
        payload_schema=payload_schema,
        fact_provenance=provenance,
        time_range=time_range,
        content_digest=content_digest,
    )
    _check_cancellation(cancellation_probe)
    entry = PrivateAnalysisEvidenceEntry(reference, projected_payload)
    _check_cancellation(cancellation_probe)
    return entry


def _json_safe_evidence_payload(
    payload: dict[str, object],
) -> dict[str, object]:
    """Preserve exact large integers as canonical decimal strings.

    Normalized datasets intentionally retain signed 64-bit timestamps and
    plug-in-owned opaque integers. Evidence envelopes are portable JSON and
    therefore cap numeric tokens at IEEE-754's exact integer range. The
    independently typed time range keeps timestamp semantics; payload values
    outside that range cross this boundary as exact decimal strings.
    """

    # Detach and bound the plug-in-owned tree before projection.  Besides
    # preventing mutation races, this preserves the evidence contract's
    # deterministic cycle/depth/container failures instead of letting a
    # recursive projection surface RecursionError.
    snapshot = validate_bounded_json_value(
        payload,
        "evidence payload projection",
        maximum_depth=MAX_EVIDENCE_PAYLOAD_DEPTH,
        maximum_container_items=MAX_EVIDENCE_PAYLOAD_CONTAINER_ITEMS,
        maximum_units=MAX_EVIDENCE_PAYLOAD_UNITS,
        maximum_atom_units=MAX_EVIDENCE_PAYLOAD_ATOM_CHARACTERS,
        maximum_integer_bits=4_096,
        exact_types=True,
        allow_exact_tuples=False,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError("evidence payload projection must be an exact JSON object")

    def project(value: object) -> object:
        if type(value) is int and not (
            -MAX_JSON_SAFE_INTEGER <= value <= MAX_JSON_SAFE_INTEGER
        ):
            return str(value)
        if type(value) is list:
            return [project(item) for item in value]
        if type(value) is dict:
            return {key: project(item) for key, item in value.items()}
        return value

    projected = project(snapshot)
    assert type(projected) is dict
    return projected


def _core_producer() -> EvidenceProducer:
    return EvidenceProducer(
        authority=EvidenceAuthority.CORE_CORROBORATION,
        producer_id=CoreEvidenceProducer.REVISION_METADATA_V1.value,
    )


def _descriptors(
    dataset: Mapping[str, Any],
    *,
    cancellation_probe: Callable[[], bool] | None = None,
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for descriptor in _dataset_sequence(
        dataset,
        "kind_descriptors",
        cancellation_probe=cancellation_probe,
    ):
        kind = descriptor.get("kind")
        if type(kind) is str and kind:
            result[kind] = descriptor
    return result


def _resource_identity_projection(
    record: Mapping[str, Any],
    *,
    identifier: str,
    kind_name: str,
) -> dict[str, object]:
    """Project timeless identity without copying the latest summary state."""

    projection: dict[str, object] = {
        "resource_id": identifier,
        "kind": kind_name,
        "layer": record.get("layer", "unknown"),
        "label": record.get("label", identifier),
        "key": dict(record.get("key", {})),
    }
    if record.get("presentation_tags") is not None:
        projection["presentation_tags"] = record["presentation_tags"]
    return projection


def _interval_projection(
    interval: Mapping[str, Any],
    *,
    cutoff_ns: int,
) -> dict[str, Any]:
    """Hide a future interval boundary from an as-of reconstruction."""

    projection = dict(interval)
    end = _optional_ns(interval.get("valid_to_ns"), "valid_to_ns")
    if end is None or end > cutoff_ns:
        projection["valid_to_ns"] = None
    return projection


def _project_revision(
    request: PrivateAnalysisRequest,
    supplied: TrustedPrivateAnalysisRevision,
    *,
    plugin_evidence_class: PrivateAnalysisEvidenceClass,
    entries: _EvidenceEntryAccumulator,
    maximum_entries: int,
    cancellation_probe: Callable[[], bool] | None,
) -> None:
    _check_cancellation(cancellation_probe)
    scope, binding = bind_private_analysis_revision(
        supplied.workspace,
        supplied.fixture,
        supplied.revision,
    )
    if scope != request.scope or binding not in request.revisions:
        raise PrivateAnalysisEvidenceBindingError(
            "trusted revision is not bound to the private-analysis request"
        )
    plan = supplied.revision.execution_plan
    if plan is None:  # bind_private_analysis_revision already rejects this
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires an immutable execution plan"
        )
    primary = primary_parser_execution_pin(plan)
    plugin_producer = bind_private_analysis_plugin_producer(
        supplied.revision,
        plugin_instance_id=primary.instance_id,
        role="primary_parser",
    )
    core_producer = _core_producer()
    dataset = supplied.dataset
    client_event_policy: EventRedactionPolicy | None = None
    mandatory_entries = 1 + len(plan.plugins)
    if len(entries) + mandatory_entries > maximum_entries:
        raise PrivateAnalysisRevisionEvidenceError(
            "private-analysis revision evidence exceeds the configured "
            "corpus entry limit"
        )
    timeline_start, timeline_end, timeline_clock = _timeline_bounds(dataset)
    cutoff = private_analysis_revision_cutoff_ns(
        request,
        binding,
        timeline_start_ns=timeline_start,
        timeline_end_ns=timeline_end,
        timeline_basis=timeline_clock.basis,
    )

    def require_capacity() -> None:
        if len(entries) >= maximum_entries:
            raise PrivateAnalysisRevisionEvidenceError(
                "private-analysis revision evidence exceeds the configured "
                "corpus entry limit"
            )

    revision_payload: dict[str, object] = {
        "fixture_id": binding.fixture_id,
        "node_id": binding.node_id,
        "revision_id": binding.revision_id,
        "plan_basis_revision_id": binding.plan_basis_revision_id,
        "execution_plan_digest": binding.execution_plan_digest,
        "timeline_start_ns": str(timeline_start),
        "timeline_end_ns": str(timeline_end),
        "timeline_time_basis": timeline_clock.basis.value,
        "timeline_clock_domain": timeline_clock.clock_domain,
        "selected_cutoff_ns": str(cutoff),
        "selected_evidence_coordinate_ns": str(
            _projected_time_coordinate(timeline_clock, cutoff)
        ),
        "clock_mode": request.clock_mode.value,
    }
    require_capacity()
    entries.append(
        _entry(
            scope=scope,
            revision_binding=binding,
            producer=core_producer,
            kind=EvidenceKind.REVISION_METADATA,
            subject_kind="revision_metadata",
            locator_identity={"revision_id": binding.revision_id},
            payload_schema=_REVISION_METADATA_SCHEMA,
            payload=revision_payload,
            provenance=EvidenceFactProvenance.NOT_APPLICABLE,
            time_range=EvidenceTimeRange.not_applicable(),
            cancellation_probe=cancellation_probe,
        )
    )

    for pin_ordinal, pin in enumerate(plan.plugins):
        if pin_ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        require_capacity()
        pin_wire = plugin_execution_pin_dict(pin)
        plugin_payload: dict[str, object] = {
            "instance_id": pin_wire["instance_id"],
            "plugin_id": pin_wire["plugin_id"],
            "plugin_version": pin_wire["plugin_version"],
            "core_api_version": pin_wire["core_api_version"],
            "configuration_digest": pin_wire["configuration_digest"],
            "schema_digest": pin_wire["schema_digest"],
            "registered_execution_identity": pin_wire[
                "registered_execution_identity"
            ],
            "schema_versions": pin_wire["schema_versions"],
            "capabilities": pin_wire["capabilities"],
            "roles": pin_wire["roles"],
            "package_hash": pin_wire["artifact"]["package_hash"],  # type: ignore[index]
        }
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=core_producer,
                kind=EvidenceKind.PLUGIN_SCHEMA,
                subject_kind="plugin_execution_pin",
                locator_identity={"plugin_instance_id": pin.instance_id},
                payload_schema=_PLUGIN_SCHEMA_METADATA_SCHEMA,
                payload=plugin_payload,
                provenance=EvidenceFactProvenance.NOT_APPLICABLE,
                time_range=EvidenceTimeRange.not_applicable(),
                cancellation_probe=cancellation_probe,
            )
        )

    for ordinal, record in enumerate(
        _dataset_sequence(
            dataset,
            "source_records",
            cancellation_probe=cancellation_probe,
        )
    ):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        timestamp = _optional_ns(
            record.get("timestamp_ns"),
            "source record timestamp_ns",
        )
        uncertainty = _optional_ns(
            record.get("timestamp_uncertainty_ns"),
            "source record timestamp_uncertainty_ns",
            minimum=0,
        )
        time_range = _selected_observation_time(
            request,
            clock=timeline_clock,
            timestamp_ns=timestamp,
            uncertainty_ns=uncertainty,
            cutoff_ns=cutoff,
            subject="source record",
        )
        if time_range is None:
            continue
        locator = record.get("source_record_uid")
        if type(locator) is not str or not locator:
            raise PrivateAnalysisRevisionEvidenceError(
                "normalized source record lacks a stable identifier"
            )
        require_capacity()
        _check_cancellation(cancellation_probe)
        if plugin_evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY:
            payload_schema = _PROPRIETARY_SOURCE_RECORD_SCHEMA
            payload = {str(key): value for key, value in record.items()}
        else:
            payload_schema = _SOURCE_RECORD_SCHEMA
            projected = project_source_record_for_log(dict(record))
            payload = {str(key): value for key, value in projected.items()}
        _check_cancellation(cancellation_probe)
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=plugin_producer,
                kind=EvidenceKind.SOURCE_RECORD,
                subject_kind="normalized_source_record",
                locator_identity={
                    "source_record_uid": locator,
                    "ordinal": ordinal,
                },
                payload_schema=payload_schema,
                payload=payload,
                provenance=EvidenceFactProvenance.OBSERVED,
                time_range=time_range,
                evidence_class=plugin_evidence_class,
                cancellation_probe=cancellation_probe,
            )
        )

    for ordinal, event in enumerate(
        _dataset_sequence(
            dataset,
            "events",
            cancellation_probe=cancellation_probe,
        )
    ):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        timestamp = _optional_ns(event.get("timestamp_ns"), "event timestamp_ns")
        uncertainty = _optional_ns(
            event.get("timestamp_uncertainty_ns"),
            "event timestamp_uncertainty_ns",
            minimum=0,
        )
        time_range = _selected_observation_time(
            request,
            clock=timeline_clock,
            timestamp_ns=timestamp,
            uncertainty_ns=uncertainty,
            cutoff_ns=cutoff,
            subject="event",
        )
        if time_range is None:
            continue
        locator = event.get("event_uid", event.get("event_id"))
        if type(locator) is not str or not locator:
            raise PrivateAnalysisRevisionEvidenceError(
                "normalized event lacks a stable identifier"
            )
        require_capacity()
        _check_cancellation(cancellation_probe)
        if plugin_evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY:
            payload_schema = _PROPRIETARY_EVENT_SCHEMA
            payload = {str(key): value for key, value in event.items()}
        else:
            payload_schema = _EVENT_SCHEMA
            if client_event_policy is None:
                try:
                    client_event_policy = event_redaction_policy(
                        dataset,
                        cancellation_probe=cancellation_probe,
                    )
                except NormalizedDataCancellationRequested as error:
                    raise PrivateAnalysisRevisionEvidenceCancelled(
                        "private-analysis evidence freezing was cancelled"
                    ) from error
                except NormalizedDataCancellationProbeResultError as error:
                    raise PrivateAnalysisRevisionEvidenceError(
                        "private-analysis cancellation probe returned an invalid value"
                    ) from error
                except NormalizedDataCancellationProbeError as error:
                    raise PrivateAnalysisRevisionEvidenceError(
                        "private-analysis cancellation state is unavailable"
                    ) from error
            payload = {
                str(key): value
                for key, value in redact_event_for_client(
                    event,
                    dataset,
                    policy=client_event_policy,
                ).items()
            }
        _check_cancellation(cancellation_probe)
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=plugin_producer,
                kind=EvidenceKind.EVENT,
                subject_kind="normalized_event",
                locator_identity={"event_uid": locator, "ordinal": ordinal},
                payload_schema=payload_schema,
                payload=payload,
                provenance=_fact_provenance(
                    event.get("provenance"),
                    default=EvidenceFactProvenance.LOG_DERIVED,
                ),
                time_range=time_range,
                evidence_class=plugin_evidence_class,
                cancellation_probe=cancellation_probe,
            )
        )

    resource_records = _dataset_sequence(
        dataset,
        "resources",
        cancellation_probe=cancellation_probe,
    )
    lifecycle_intervals = _dataset_sequence(
        dataset,
        "lifecycle_intervals",
        cancellation_probe=cancellation_probe,
    )
    active_resource_ids: set[str] = set()
    for ordinal, interval in enumerate(lifecycle_intervals):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        active, _start = _interval_at(
            interval,
            cutoff,
            allow_unknown_start=(
                request.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION
            ),
            subject="resource lifecycle interval",
        )
        if not active:
            continue
        lifecycle_resource = interval.get("resource")
        if type(lifecycle_resource) is str:
            active_resource_ids.add(lifecycle_resource)

    if active_resource_ids:
        # Once a lifecycle interval proves some resource may be selected,
        # resource/descriptors work cannot produce a valid entry unless one
        # slot remains. Keep this after the lifecycle scan so an already-full
        # corpus does not fail speculatively when no resource is active.
        require_capacity()
    resources: dict[str, Mapping[str, Any]] = {}
    seen_resource_ids: set[str] = set()
    for ordinal, record in enumerate(resource_records):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        identifier = resource_id(record)
        if identifier in seen_resource_ids:
            raise PrivateAnalysisRevisionEvidenceError(
                "normalized dataset contains duplicate resource identifiers"
            )
        seen_resource_ids.add(identifier)
        if identifier in active_resource_ids:
            resources[identifier] = record
    active_resource_ids.intersection_update(resources)
    descriptors = (
        _descriptors(dataset, cancellation_probe=cancellation_probe)
        if active_resource_ids
        else {}
    )

    ordered_active_resource_ids = cooperatively_sorted(
        active_resource_ids,
        lambda: _check_cancellation(cancellation_probe),
    )
    for ordinal, identifier in enumerate(ordered_active_resource_ids):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        require_capacity()
        record = resources[identifier]
        kind_name = str(record.get("kind", "UNKNOWN"))
        _check_cancellation(cancellation_probe)
        identity_projection = _resource_identity_projection(
            record,
            identifier=identifier,
            kind_name=kind_name,
        )
        if plugin_evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY:
            payload_schema = _PROPRIETARY_RESOURCE_IDENTITY_SCHEMA
            payload = identity_projection
        else:
            payload_schema = _RESOURCE_IDENTITY_SCHEMA
            client_projection = redact_resource_for_client(
                identity_projection,
                descriptors.get(kind_name),
            )
            client_projection.pop("state", None)
            payload = {
                str(key): value
                for key, value in client_projection.items()
            }
        _check_cancellation(cancellation_probe)
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=plugin_producer,
                kind=EvidenceKind.RESOURCE_IDENTITY,
                subject_kind="normalized_resource",
                locator_identity={"resource_id": identifier},
                payload_schema=payload_schema,
                payload=payload,
                provenance=EvidenceFactProvenance.SNAPSHOT_OBSERVED,
                time_range=_time_point(timeline_clock, cutoff),
                evidence_class=plugin_evidence_class,
                cancellation_probe=cancellation_probe,
            )
        )

    state_intervals = _dataset_sequence(
        dataset,
        "state_intervals",
        cancellation_probe=cancellation_probe,
    )
    for ordinal, interval in enumerate(state_intervals):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        state_resource = interval.get("resource")
        if type(state_resource) is not str or state_resource not in active_resource_ids:
            continue
        active, interval_start = _interval_at(
            interval,
            cutoff,
            allow_unknown_start=(
                request.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION
            ),
            subject="resource state interval",
        )
        if not active:
            continue
        require_capacity()
        identifier = state_resource
        record = resources[identifier]
        kind_name = str(record.get("kind", "UNKNOWN"))
        _check_cancellation(cancellation_probe)
        selected = _interval_projection(interval, cutoff_ns=cutoff)
        view: dict[str, Any] = {
            **selected,
            "resource_id": identifier,
            "kind": kind_name,
            "layer": record.get("layer", "unknown"),
            "label": record.get("label", identifier),
            "exists": True,
            "state": dict(selected.get("properties", {})),
            "key": dict(record.get("key", {})),
            "resource": _resource_identity_projection(
                record,
                identifier=identifier,
                kind_name=kind_name,
            ),
        }
        if plugin_evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY:
            payload_schema = _PROPRIETARY_RESOURCE_STATE_SCHEMA
            payload = {
                "resource": _resource_identity_projection(
                    record,
                    identifier=identifier,
                    kind_name=kind_name,
                ),
                "state_interval": dict(selected),
            }
        else:
            payload_schema = _RESOURCE_STATE_SCHEMA
            payload = {
                str(key): value
                for key, value in redact_resource_view(
                    view,
                    descriptors.get(kind_name),
                ).items()
            }
        _check_cancellation(cancellation_probe)
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=plugin_producer,
                kind=EvidenceKind.RESOURCE_STATE_INTERVAL,
                subject_kind="normalized_resource_state",
                locator_identity={
                    "resource_id": identifier,
                    "valid_from_ns": (
                        None if interval_start is None else str(interval_start)
                    ),
                    "ordinal": ordinal,
                },
                payload_schema=payload_schema,
                payload=payload,
                provenance=_fact_provenance(
                    interval.get("provenance"),
                    default=EvidenceFactProvenance.STATE_RECONSTRUCTED,
                ),
                time_range=_selected_interval_time(
                    timeline_clock,
                    interval_start,
                    cutoff,
                ),
                evidence_class=plugin_evidence_class,
                cancellation_probe=cancellation_probe,
            )
        )

    relationship_intervals = _dataset_sequence(
        dataset,
        "relationship_intervals",
        cancellation_probe=cancellation_probe,
    )
    for ordinal, interval in enumerate(relationship_intervals):
        if ordinal % 256 == 0:
            _check_cancellation(cancellation_probe)
        source = interval.get("source")
        target = interval.get("target")
        if (
            type(source) is not str
            or type(target) is not str
            or source not in active_resource_ids
            or target not in active_resource_ids
            or interval.get("present") is not True
        ):
            continue
        active, interval_start = _interval_at(
            interval,
            cutoff,
            allow_unknown_start=(
                request.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION
            ),
            subject="relationship interval",
        )
        if not active:
            continue
        require_capacity()
        _check_cancellation(cancellation_probe)
        selected = _interval_projection(interval, cutoff_ns=cutoff)
        relation_type = selected.get(
            "relation_type",
            selected.get("type", "related_to"),
        )
        if type(relation_type) is not str or not relation_type:
            raise PrivateAnalysisRevisionEvidenceError(
                "normalized relationship lacks a stable relation type"
            )
        if plugin_evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY:
            payload_schema = _PROPRIETARY_RELATIONSHIP_SCHEMA
            payload = {str(key): value for key, value in selected.items()}
        else:
            payload_schema = _RELATIONSHIP_SCHEMA
            payload = {
                "source": source,
                "target": target,
                "relation_type": relation_type,
                "present": True,
                "valid_from_ns": selected.get("valid_from_ns"),
                "valid_to_ns": selected.get("valid_to_ns"),
                "observed_at_min_ns": selected.get("observed_at_min_ns"),
                "observed_at_max_ns": selected.get("observed_at_max_ns"),
                "provenance": selected.get("provenance"),
                "quality": selected.get("quality"),
            }
        _check_cancellation(cancellation_probe)
        # Exact JSON objects may contain null but never an absent/raw plug-in
        # attributes container.  Keep the stable core envelope only.
        entries.append(
            _entry(
                scope=scope,
                revision_binding=binding,
                producer=plugin_producer,
                kind=EvidenceKind.RELATIONSHIP_INTERVAL,
                subject_kind="normalized_relationship",
                locator_identity={
                    "source": source,
                    "target": target,
                    "relation_type": relation_type,
                    "valid_from_ns": (
                        None if interval_start is None else str(interval_start)
                    ),
                    "ordinal": ordinal,
                },
                payload_schema=payload_schema,
                payload=payload,
                provenance=_fact_provenance(
                    interval.get("provenance"),
                    default=EvidenceFactProvenance.RELATIONSHIP_INFERRED,
                ),
                time_range=_selected_interval_time(
                    timeline_clock,
                    interval_start,
                    cutoff,
                ),
                evidence_class=plugin_evidence_class,
                cancellation_probe=cancellation_probe,
            )
        )


def build_private_analysis_revision_evidence_corpus(
    request: PrivateAnalysisRequest,
    revisions: tuple[TrustedPrivateAnalysisRevision, ...],
    *,
    maximum_entries: int = DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES,
    maximum_payload_bytes: int = (
        DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
    ),
    plugin_evidence_class: PrivateAnalysisEvidenceClass = (
        PrivateAnalysisEvidenceClass.CLIENT_SAFE
    ),
    cancellation_probe: Callable[[], bool] | None = None,
) -> PrivateAnalysisEvidenceCorpus:
    """Freeze the exact request's generic revision evidence into one corpus."""

    if type(request) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    if type(revisions) is not tuple:
        raise TypeError("revisions must be a tuple")
    if (
        type(maximum_entries) is not int
        or not 1 <= maximum_entries <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES
    ):
        raise ValueError(
            "maximum_entries must be between 1 and "
            f"{MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES}"
        )
    if type(plugin_evidence_class) is not PrivateAnalysisEvidenceClass:
        raise TypeError("plugin_evidence_class must be PrivateAnalysisEvidenceClass")
    if (
        type(maximum_payload_bytes) is not int
        or not 1
        <= maximum_payload_bytes
        <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
    ):
        raise ValueError(
            "maximum_payload_bytes must be between 1 and "
            f"{MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES}"
        )
    if cancellation_probe is not None and not callable(cancellation_probe):
        raise TypeError("cancellation_probe must be callable or None")
    _check_cancellation(cancellation_probe)
    if plugin_evidence_class not in (
        PrivateAnalysisEvidenceClass.CLIENT_SAFE,
        PrivateAnalysisEvidenceClass.PROPRIETARY,
    ):
        raise ValueError("plugin_evidence_class must be client_safe or proprietary")
    if any(type(item) is not TrustedPrivateAnalysisRevision for item in revisions):
        raise TypeError("revisions must contain TrustedPrivateAnalysisRevision values")
    supplied_by_binding: dict[object, TrustedPrivateAnalysisRevision] = {}
    for ordinal, supplied in enumerate(revisions):
        if ordinal % 16 == 0:
            _check_cancellation(cancellation_probe)
        scope, binding = bind_private_analysis_revision(
            supplied.workspace,
            supplied.fixture,
            supplied.revision,
        )
        if scope != request.scope:
            raise PrivateAnalysisEvidenceBindingError(
                "trusted revision scope does not match the request"
            )
        if binding in supplied_by_binding:
            raise PrivateAnalysisEvidenceBindingError(
                "trusted revision inputs must be unique"
            )
        supplied_by_binding[binding] = supplied
    if frozenset(supplied_by_binding) != frozenset(request.revisions):
        raise PrivateAnalysisEvidenceBindingError(
            "trusted revisions must exactly match the request revision set"
        )

    entries = _EvidenceEntryAccumulator(
        maximum_entries=maximum_entries,
        maximum_payload_bytes=maximum_payload_bytes,
        entries=[],
    )
    for ordinal, binding in enumerate(request.revisions):
        if ordinal % 16 == 0:
            _check_cancellation(cancellation_probe)
        _project_revision(
            request,
            supplied_by_binding[binding],
            plugin_evidence_class=plugin_evidence_class,
            entries=entries,
            maximum_entries=maximum_entries,
            cancellation_probe=cancellation_probe,
        )
    _check_cancellation(cancellation_probe)
    return PrivateAnalysisEvidenceCorpus._from_trusted_entries(
        tuple(entries.entries),
        maximum_entries=maximum_entries,
        maximum_payload_bytes=maximum_payload_bytes,
        construction_checkpoint=lambda: _check_cancellation(cancellation_probe),
    )


__all__ = [
    "PrivateAnalysisRevisionEvidenceCancelled",
    "PrivateAnalysisRevisionEvidenceError",
    "TrustedPrivateAnalysisRevision",
    "build_private_analysis_revision_evidence_corpus",
    "private_analysis_revision_cutoff_ns",
    "validate_private_analysis_timeline_metadata",
]
