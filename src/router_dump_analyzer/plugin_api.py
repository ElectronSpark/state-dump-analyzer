"""Versioned, implementation-neutral contracts for analyzer plugins.

The core owns decoding, storage, temporal semantics, and validation. Plugins
translate platform/version-specific status and event fields into these records.
Production workers validate and batch every yielded value at the IPC boundary.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import BinaryIO, Iterable, Mapping, Protocol, Sequence
from uuid import UUID


CORE_PLUGIN_API_VERSION = "1.0"
FORWARDING_IR_VERSION = "1.0"
PLUGIN_ENTRY_POINT_GROUP = "router_dump_analyzer.plugins"

type Scalar = None | bool | int | float | str | bytes | UUID
type Value = Scalar | tuple[Value, ...] | Mapping[str, Value]
type Properties = Mapping[str, Value]
type KeyScalar = int | str | bytes | UUID
type KeyValue = KeyScalar | tuple[KeyValue, ...]


class Provenance(StrEnum):
    """How a fact was obtained; independent of confidence in that fact."""

    OBSERVED = "observed"
    EVENT_DERIVED = "event_derived"
    RECONSTRUCTED = "reconstructed"
    CORRELATED = "correlated"
    PLUGIN_DEFAULT = "plugin_default"


class Quality(StrEnum):
    """How strongly the available evidence determines a fact."""

    EXACT = "exact"
    BEST_EFFORT = "best_effort"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class MutationOperation(StrEnum):
    UPSERT = "upsert"
    DELETE = "delete"
    UNKNOWN = "unknown"


class ResourceEffect(StrEnum):
    """Core-derived effect of a mutation against the immediately prior world."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


class ForwardingOperation(StrEnum):
    UPSERT = "upsert"
    DELETE = "delete"


class RelationshipOperation(StrEnum):
    ADD = "add"
    REMOVE = "remove"
    UNKNOWN = "unknown"


class ReconstructionSupport(StrEnum):
    """Manifest default only; individual outputs still carry their own quality."""

    EXACT = "exact"
    BEST_EFFORT = "best_effort"
    UNSUPPORTED = "unsupported"


class FindingResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class RelationDirection(StrEnum):
    OUTGOING = "outgoing"
    INCOMING = "incoming"
    BOTH = "both"


class DashboardAggregation(StrEnum):
    COUNT = "count"
    COUNT_DISTINCT = "count_distinct"
    SUM = "sum"
    AVERAGE = "average"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"


class DashboardFilterOperator(StrEnum):
    EQ = "eq"
    NOT_EQ = "not_eq"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    CONTAINS = "contains"


class DashboardValueFormat(StrEnum):
    AUTO = "auto"
    TEXT = "text"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STATUS = "status"
    RESOURCE = "resource"


class DashboardSortDirection(StrEnum):
    ASCENDING = "ascending"
    DESCENDING = "descending"


class DiagnosticSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DiagnosticOrigin(StrEnum):
    CORE_DECODER = "core_decoder"
    PLUGIN = "plugin"


class DiagnosticStage(StrEnum):
    PROBE = "probe"
    LOCATE = "locate"
    STATUS_PARSE = "status_parse"
    TRACE_DECODE = "trace_decode"
    TRACE_MAP = "trace_map"
    APPLY = "apply"
    REVERT = "revert"
    CORRELATE = "correlate"
    CONSISTENCY = "consistency"
    FORWARDING = "forwarding"


class WorldBasisKind(StrEnum):
    OBSERVED_CAPTURE_VECTOR = "observed_capture_vector"
    RECONSTRUCTED_TIME = "reconstructed_time"


@dataclass(frozen=True, slots=True)
class PluginManifest:
    plugin_id: str
    plugin_version: str
    core_api_version: str
    supported_platforms: tuple[str, ...]
    supported_software_versions: str
    capabilities: frozenset[str]
    reconstruction_default: ReconstructionSupport
    forwarding_ir_versions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PropertyDescriptor:
    name: str
    label: str
    value_type: str
    searchable: bool = False
    indexed: bool = False
    sensitive: bool = False


class IconRenderMode(StrEnum):
    """How the core should paint a plug-in-provided SVG path."""

    STROKE = "stroke"
    FILL = "fill"


_SVG_PATH_PATTERN = re.compile(r"^[MmZzLlHhVvCcSsQqTtAa0-9eE,.+\-\s]+$")
_DASHBOARD_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DASHBOARD_FIELD_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$"
)
_COLOR_PATTERN = re.compile(r"^#[0-9A-Fa-f]{6}$")


def _validate_dashboard_id(value: str, label: str) -> None:
    if not value or len(value) > 128 or _DASHBOARD_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{label} must be a lowercase dotted, dashed, or underscored identifier"
        )


def _validate_dashboard_field(value: str, label: str) -> None:
    if (
        not value
        or len(value) > 256
        or _DASHBOARD_FIELD_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(f"{label} must be a dotted field path")


@dataclass(frozen=True, slots=True)
class ResourceIconDescriptor:
    """Safe icon geometry supplied by a plug-in resource-kind descriptor."""

    path: str
    view_box: tuple[float, float, float, float] = (0.0, 0.0, 24.0, 24.0)
    render_mode: IconRenderMode = IconRenderMode.STROKE
    stroke_width: float = 1.8

    def __post_init__(self) -> None:
        if (
            not self.path
            or len(self.path) > 4096
            or _SVG_PATH_PATTERN.fullmatch(self.path) is None
        ):
            raise ValueError("icon path must contain only SVG path geometry")
        try:
            IconRenderMode(self.render_mode)
        except (TypeError, ValueError) as error:
            raise ValueError("icon render_mode must be stroke or fill") from error
        values = tuple(float(value) for value in self.view_box)
        if (
            len(values) != 4
            or any(not math.isfinite(value) for value in values)
            or values[2] <= 0
            or values[3] <= 0
        ):
            raise ValueError("icon view_box must contain four finite values with positive size")
        width = float(self.stroke_width)
        if not math.isfinite(width) or not 0.25 <= width <= 8:
            raise ValueError("icon stroke_width must be between 0.25 and 8")


@dataclass(frozen=True, slots=True)
class ResourceKindDescriptor:
    kind: str
    label: str
    key_fields: tuple[str, ...]
    properties: tuple[PropertyDescriptor, ...]
    default_timeline_fields: tuple[str, ...] = ()
    display_name_fields: tuple[str, ...] = ()
    default_table_fields: tuple[str, ...] = ()
    condition_field: str | None = None
    presentation_tags: tuple[str, ...] = ()
    icon: ResourceIconDescriptor | None = None


@dataclass(frozen=True, slots=True)
class DashboardFilterDescriptor:
    """Safe declarative predicate over one generic resource-state row."""

    field: str
    operator: DashboardFilterOperator
    value: Value = True

    def __post_init__(self) -> None:
        _validate_dashboard_field(self.field, "dashboard filter field")
        try:
            operator = DashboardFilterOperator(self.operator)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported dashboard filter operator") from error
        if operator in {DashboardFilterOperator.IN, DashboardFilterOperator.NOT_IN}:
            if not isinstance(self.value, tuple):
                raise ValueError("dashboard in/not_in filters require a tuple value")
        if operator is DashboardFilterOperator.EXISTS and not isinstance(
            self.value, bool
        ):
            raise ValueError("dashboard exists filters require a boolean value")


@dataclass(frozen=True, slots=True)
class DashboardStatisticDescriptor:
    """One common aggregate calculated by the core over resource-state rows."""

    statistic_id: str
    label: str
    aggregation: DashboardAggregation
    resource_kinds: tuple[str, ...] = ()
    field: str | None = None
    filters: tuple[DashboardFilterDescriptor, ...] = ()
    unit: str | None = None
    precision: int = 0
    include_absent: bool = False

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.statistic_id, "dashboard statistic_id")
        try:
            aggregation = DashboardAggregation(self.aggregation)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported dashboard aggregation") from error
        if aggregation is not DashboardAggregation.COUNT and self.field is None:
            raise ValueError("non-count dashboard statistics require a field")
        if self.field is not None:
            _validate_dashboard_field(self.field, "dashboard statistic field")
        if not 0 <= self.precision <= 6:
            raise ValueError("dashboard statistic precision must be between 0 and 6")


@dataclass(frozen=True, slots=True)
class DashboardColumnDescriptor:
    """One safe field projection in a common resource table."""

    field: str
    label: str
    value_format: DashboardValueFormat = DashboardValueFormat.AUTO

    def __post_init__(self) -> None:
        _validate_dashboard_field(self.field, "dashboard table column field")
        try:
            DashboardValueFormat(self.value_format)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported dashboard column value_format") from error


@dataclass(frozen=True, slots=True)
class DashboardTableDescriptor:
    """A reusable point-in-time table over plugin-selected resource kinds."""

    table_id: str
    title: str
    resource_kinds: tuple[str, ...]
    columns: tuple[DashboardColumnDescriptor, ...]
    include_absent: bool = False
    max_rows: int = 50
    sort_field: str | None = None
    sort_direction: DashboardSortDirection = DashboardSortDirection.ASCENDING
    empty_message: str = "No matching resources at this time."

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.table_id, "dashboard table_id")
        if not self.columns:
            raise ValueError("dashboard tables require at least one column")
        if not 1 <= self.max_rows <= 500:
            raise ValueError("dashboard table max_rows must be between 1 and 500")
        if self.sort_field is not None:
            _validate_dashboard_field(self.sort_field, "dashboard table sort_field")
        try:
            DashboardSortDirection(self.sort_direction)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported dashboard table sort_direction") from error


@dataclass(frozen=True, slots=True)
class DashboardDescriptor:
    """Plugin-owned modular dashboard rendered with core statistics and tables."""

    dashboard_id: str
    title: str
    description: str
    statistics: tuple[DashboardStatisticDescriptor, ...] = ()
    tables: tuple[DashboardTableDescriptor, ...] = ()
    default_open: bool = False
    collapsible: bool = True
    default_expanded: bool = True
    movable: bool = True

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.dashboard_id, "dashboard_id")
        if not self.statistics and not self.tables:
            raise ValueError("dashboard requires at least one statistic or table")
        widget_ids = [item.statistic_id for item in self.statistics] + [
            item.table_id for item in self.tables
        ]
        if len(widget_ids) != len(set(widget_ids)):
            raise ValueError("dashboard widget identifiers must be unique")
        if not self.collapsible and not self.default_expanded:
            raise ValueError("a non-collapsible dashboard must be expanded by default")


@dataclass(frozen=True, slots=True)
class RelationshipTypeDescriptor:
    """A plug-in-owned semantic edge type rendered generically by the core."""

    relation_type: str
    label: str
    directed: bool
    structural: bool


@dataclass(frozen=True, slots=True)
class CausalLinkTypeDescriptor:
    """A plug-in-owned event-correlation type rendered generically by the core."""

    link_type: str
    label: str
    directed: bool = True


@dataclass(frozen=True, slots=True)
class SourceRecordTypeDescriptor:
    """Plug-in presentation for one core-retained timestamped input stream."""

    source_type: str
    label: str
    description: str = ""
    color: str = "#66b8ff"

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.source_type, "source_type")
        if not self.label or len(self.label) > 120:
            raise ValueError("source record label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("source record description must be at most 500 characters")
        if _COLOR_PATTERN.fullmatch(self.color) is None:
            raise ValueError("source record color must be a six-digit CSS hex color")


@dataclass(frozen=True, slots=True)
class RecordLanePreset:
    """Optional plug-in vocabulary for a core-rendered regex source lane."""

    lane_id: str
    label: str
    pattern: str
    source_types: tuple[str, ...] = ()
    unmatched_only: bool = False
    case_sensitive: bool = False
    default_enabled: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.lane_id, "record lane_id")
        if not self.label or len(self.label) > 120:
            raise ValueError("record lane label must contain 1 to 120 characters")
        if not self.pattern or len(self.pattern) > 160:
            raise ValueError("record lane pattern must contain 1 to 160 characters")
        if "(?" in self.pattern or re.search(r"\\[1-9]", self.pattern):
            raise ValueError("record lane pattern uses unsupported regex features")
        try:
            re.compile(self.pattern)
        except re.error as error:
            raise ValueError(f"invalid record lane pattern: {error.msg}") from error
        if len(self.description) > 500:
            raise ValueError("record lane description must be at most 500 characters")


@dataclass(frozen=True, slots=True)
class PluginSchema:
    """All semantic types a plug-in may emit for one analysis revision.

    Plug-ins may derive additional resources, temporal relationships, and event
    correlations when the source material needs them.  The core validates emitted
    values against this schema but does not invent or interpret domain types.
    """

    resource_kinds: tuple[ResourceKindDescriptor, ...]
    relationship_types: tuple[RelationshipTypeDescriptor, ...]
    causal_link_types: tuple[CausalLinkTypeDescriptor, ...] = ()
    dashboards: tuple[DashboardDescriptor, ...] = ()
    source_record_types: tuple[SourceRecordTypeDescriptor, ...] = ()
    record_lane_presets: tuple[RecordLanePreset, ...] = ()

    def __post_init__(self) -> None:
        dashboard_ids = [dashboard.dashboard_id for dashboard in self.dashboards]
        if len(dashboard_ids) != len(set(dashboard_ids)):
            raise ValueError("plugin dashboard identifiers must be unique")
        resource_kinds = {descriptor.kind for descriptor in self.resource_kinds}
        referenced_kinds = {
            kind
            for dashboard in self.dashboards
            for widget in (*dashboard.statistics, *dashboard.tables)
            for kind in widget.resource_kinds
        }
        if unknown := referenced_kinds - resource_kinds:
            raise ValueError(
                "plugin dashboards reference unknown resource kinds: "
                + ", ".join(sorted(unknown))
            )
        source_types = [descriptor.source_type for descriptor in self.source_record_types]
        if len(source_types) != len(set(source_types)):
            raise ValueError("plugin source record types must be unique")
        lane_ids = [preset.lane_id for preset in self.record_lane_presets]
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("plugin record lane preset identifiers must be unique")
        referenced_source_types = {
            source_type
            for preset in self.record_lane_presets
            for source_type in preset.source_types
        }
        if unknown := referenced_source_types - set(source_types):
            raise ValueError(
                "plugin record lane presets reference unknown source types: "
                + ", ".join(sorted(unknown))
            )


@dataclass(frozen=True, slots=True)
class ArtifactInfo:
    artifact_id: UUID
    logical_path: PurePosixPath
    parent_artifact_id: UUID | None
    media_type: str
    compressed_size: int | None
    uncompressed_size: int | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class DumpInventory:
    node_hint: str | None
    artifacts: tuple[ArtifactInfo, ...]
    metadata: Properties = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    confidence: float
    reasons: tuple[str, ...]
    detected_platform: str | None = None
    detected_software_version: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeReport:
    result: ProbeResult | None
    diagnostics: tuple[PluginDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class InputSpec:
    """One logical parser input, possibly assembled from multiple artifacts."""

    artifact_ids: tuple[UUID, ...]
    role: str
    node: str
    layer: str
    parser_id: str
    logical_root: PurePosixPath | None = None
    options: Properties = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResourceKey:
    """Typed identity; ``parts`` are canonical and ordered by the plugin."""

    namespace: str
    node: str
    layer: str
    kind: str
    parts: tuple[tuple[str, KeyValue], ...]

    def __post_init__(self) -> None:
        names = tuple(name for name, _value in self.parts)
        if len(set(names)) != len(names):
            raise ValueError("resource key part names must be unique")

        def reject_boolean(value: KeyValue) -> None:
            if isinstance(value, bool):
                raise ValueError("Boolean resource-key parts are forbidden; use a tagged integer or string")
            if isinstance(value, tuple):
                for item in value:
                    reject_boolean(item)

        for _name, value in self.parts:
            reject_boolean(value)


@dataclass(frozen=True, slots=True)
class Evidence:
    artifact_id: UUID
    locator: str
    raw_timestamp_ns: int | None
    clock_domain: str | None
    excerpt_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """A generic retained input record, optionally linked to normalization.

    The core assigns and indexes the source record identifier and owns
    timestamps and pagination. Plug-ins assign source type semantics, decode
    the message, and may link it to a normalized domain event without
    discarding unmatched input.
    """

    source_record_uid: bytes
    timestamp_ns: int | None
    timestamp_uncertainty_ns: int | None
    source_type: str
    source_name: str
    record_name: str
    message: str
    layer: str | None
    attributes: Properties = field(default_factory=dict)
    matched_event_uid: bytes | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class PluginDiagnostic:
    stage: DiagnosticStage
    severity: DiagnosticSeverity
    code: str
    message: str
    recoverable: bool
    evidence: tuple[Evidence, ...] = ()
    details: Properties = field(default_factory=dict)
    origin: DiagnosticOrigin = DiagnosticOrigin.PLUGIN


@dataclass(frozen=True, slots=True)
class UnknownField:
    name: str
    reason_code: str
    message: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class PropertyPatch:
    """Complete state or patch with distinct null, removal, and unknown values.

    A key in ``set_values`` with value ``None`` means explicit null. A key in
    ``remove_fields`` means known absent. ``unknown_fields`` means the evidence
    cannot determine the value. When ``complete`` is false, unmentioned fields
    are untouched rather than removed.
    """

    set_values: Properties = field(default_factory=dict)
    remove_fields: tuple[str, ...] = ()
    unknown_fields: tuple[UnknownField, ...] = ()
    field_quality: Mapping[str, Quality] = field(default_factory=dict)
    field_provenance: Mapping[str, Provenance] = field(default_factory=dict)
    complete: bool = False

    def __post_init__(self) -> None:
        set_names = set(self.set_values)
        remove_names = set(self.remove_fields)
        unknown_names = {unknown.name for unknown in self.unknown_fields}
        if len(remove_names) != len(self.remove_fields):
            raise ValueError("remove_fields contains duplicate names")
        if len(unknown_names) != len(self.unknown_fields):
            raise ValueError("unknown_fields contains duplicate names")
        overlap = (set_names & remove_names) | (set_names & unknown_names) | (
            remove_names & unknown_names
        )
        if overlap:
            raise ValueError(
                "a property cannot be set, removed, and/or unknown together: "
                + ", ".join(sorted(overlap))
            )
        mentioned = set_names | remove_names | unknown_names
        metadata_names = set(self.field_quality) | set(self.field_provenance)
        if unrelated := metadata_names - mentioned:
            raise ValueError(
                "field metadata refers to unmentioned properties: "
                + ", ".join(sorted(unrelated))
            )


@dataclass(frozen=True, slots=True)
class SnapshotObservation:
    resource: ResourceKey
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    state: PropertyPatch
    provenance: Provenance
    quality: Quality
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class RelationshipObservation:
    """One observed relationship; omission never proves that another edge is absent."""

    source: ResourceKey
    target: ResourceKey
    relation_type: str
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    present: bool | None
    attributes: PropertyPatch
    provenance: Provenance
    quality: Quality
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class RelationshipCollectionObservation:
    """Completeness marker for a streamed relationship collection.

    Only a marker with ``complete=True`` allows the core to infer that an
    unlisted edge of ``relation_type`` is absent for this owner/direction.
    """

    owner: ResourceKey
    direction: RelationDirection
    relation_type: str
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    complete: bool
    provenance: Provenance
    quality: Quality
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class SourceRecordRef:
    """Core-assigned source identity retained through domain mapping."""

    source_id: str
    message_ordinal: int
    trace_uid: str | None = None
    stream_uid: str | None = None
    packet_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class DomainEvent:
    event_uid: bytes
    timestamp_ns: int | None
    timestamp_uncertainty_ns: int | None
    source_sequence: int
    event_type: str
    action: str | None
    outcome: Outcome
    attributes: Properties
    subjects: tuple[ResourceKey, ...]
    provenance: Provenance
    quality: Quality
    source: SourceRecordRef
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class StateMutation:
    resource: ResourceKey
    operation: MutationOperation
    before: PropertyPatch | None
    after: PropertyPatch | None
    effective_time_ns: int | None
    time_uncertainty_ns: int | None
    cause_event_uid: bytes | None
    provenance: Provenance
    quality: Quality
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RelationshipMutation:
    source: ResourceKey
    target: ResourceKey
    relation_type: str
    operation: RelationshipOperation
    attributes: PropertyPatch
    effective_time_ns: int | None
    time_uncertainty_ns: int | None
    cause_event_uid: bytes | None
    provenance: Provenance
    quality: Quality
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CausalLink:
    source_event_uid: bytes
    target_event_uid: bytes
    link_type: str
    confidence: float
    provenance: Provenance
    quality: Quality
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class UnknownChange:
    change_kind: str
    reason_code: str
    message: str
    affected_resources: tuple[ResourceKey, ...] = ()
    affected_fields: tuple[str, ...] = ()
    relation_type: str | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class ReconstructionCoverage:
    scope: str
    exact_outputs: int
    best_effort_outputs: int
    ambiguous_outputs: int
    unknown_outputs: int


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """One atomic plug-in result applied against the event's pre-change world.

    Atomicity lets a plug-in create a parent, its required children, and their
    relationships without exposing a transient invalid world.  An empty change
    set is a valid result, including for failed or idempotent domain events.
    """

    state: tuple[StateMutation, ...] = ()
    relationships: tuple[RelationshipMutation, ...] = ()
    causal_links: tuple[CausalLink, ...] = ()
    unknowns: tuple[UnknownChange, ...] = ()
    diagnostics: tuple[PluginDiagnostic, ...] = ()
    coverage: tuple[ReconstructionCoverage, ...] = ()


@dataclass(frozen=True, slots=True)
class ClockAnchor:
    left_clock_domain: str
    left_raw_ns: int
    right_clock_domain: str
    right_raw_ns: int
    uncertainty_ns: int
    method: str
    provenance: Provenance
    quality: Quality
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class ConsistencyFinding:
    rule_id: str
    severity: DiagnosticSeverity
    result: FindingResult
    summary: str
    resources: tuple[ResourceKey, ...]
    provenance: Provenance
    quality: Quality
    basis: WorldBasis
    evidence: tuple[Evidence, ...]
    details: Properties = field(default_factory=dict)


# The core decoder converts native bt2 messages into these dependency-free
# records. Plugins interpret their domain payloads and never import bt2 directly.
@dataclass(frozen=True, slots=True)
class CtfEventRecord:
    trace_uid: str
    stream_uid: str
    packet_sequence: int | None
    message_ordinal: int
    event_name: str
    timestamp_ns: int | None
    timestamp_uncertainty_ns: int | None
    clock_domain: str | None
    payload: Properties
    common_context: Properties = field(default_factory=dict)
    specific_context: Properties = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CtfStreamBoundary:
    trace_uid: str
    stream_uid: str
    started: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CtfPacketBoundary:
    trace_uid: str
    stream_uid: str
    packet_sequence: int | None
    started: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CtfDiscardedEvents:
    trace_uid: str
    stream_uid: str
    count: int | None
    message_ordinal: int
    begin_timestamp_ns: int | None
    end_timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CtfDiscardedPackets:
    trace_uid: str
    stream_uid: str
    count: int | None
    message_ordinal: int
    begin_timestamp_ns: int | None
    end_timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class CtfStreamActivityBoundary:
    trace_uid: str
    stream_uid: str
    began: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ()


type CtfMessage = (
    CtfEventRecord
    | CtfStreamBoundary
    | CtfPacketBoundary
    | CtfDiscardedEvents
    | CtfDiscardedPackets
    | CtfStreamActivityBoundary
)


class ArtifactReader(Protocol):
    """Read-only, quota-enforced access to inventoried artifacts."""

    def open_binary(self, artifact_id: UUID) -> BinaryIO: ...

    def materialize_private_path(self, artifact_id: UUID) -> str: ...

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str: ...


class TraceDecoder(Protocol):
    """Core-owned generic decoder; this object is not passed to plugins."""

    def iter_ctf(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[CtfMessage | PluginDiagnostic]: ...


@dataclass(frozen=True, slots=True)
class CaptureRange:
    scope: str
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class WorldBasis:
    kind: WorldBasisKind
    requested_time_ns: int | None
    resolved_at_min_ns: int | None
    resolved_at_max_ns: int | None
    capture_ranges: tuple[CaptureRange, ...]
    provenance: Provenance
    quality: Quality


@dataclass(frozen=True, slots=True)
class ResourceStateView:
    resource: ResourceKey
    exists: bool | None
    properties: Properties
    provenance: Provenance
    quality: Quality
    valid_from_ns: int | None
    valid_to_ns: int | None
    observed_at_min_ns: int | None = None
    observed_at_max_ns: int | None = None
    field_quality: Mapping[str, Quality] = field(default_factory=dict)
    unknown_fields: tuple[UnknownField, ...] = ()
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RelationshipView:
    source: ResourceKey
    target: ResourceKey
    relation_type: str
    attributes: Properties
    provenance: Provenance
    quality: Quality
    valid_from_ns: int | None
    valid_to_ns: int | None
    evidence: tuple[Evidence, ...] = ()


class ReadOnlyWorld(Protocol):
    @property
    def basis(self) -> WorldBasis: ...

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None: ...

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]: ...

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]: ...

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]: ...


@dataclass(frozen=True, slots=True)
class CorrelationWindow:
    start_ns: int | None
    end_ns: int | None
    max_events: int
    max_world_reads: int = 128


@dataclass(frozen=True, slots=True)
class CorrelationQuery:
    start_ns: int | None
    end_ns: int | None
    max_events: int
    event_types: frozenset[str] | None = None
    layers: frozenset[str] | None = None
    subject: ResourceKey | None = None
    correlation_keys: Properties = field(default_factory=dict)
    cursor: str | None = None


@dataclass(frozen=True, slots=True)
class EventBatch:
    events: tuple[DomainEvent, ...]
    next_cursor: str | None
    truncated: bool
    watermark_ns: int | None


class CorrelationReader(Protocol):
    """Window-bound indexed access; the core enforces one cumulative budget.

    Requested ranges are clamped to the associated ``CorrelationWindow`` and
    all calls together stop after ``max_events``. A plugin cannot widen the
    reader by passing ``None`` bounds.
    """

    @property
    def remaining_event_budget(self) -> int: ...

    @property
    def remaining_world_budget(self) -> int: ...

    def iter_event_batches(
        self,
        query: CorrelationQuery,
    ) -> Iterable[EventBatch]: ...

    def world_at(self, timestamp_ns: int) -> ReadOnlyWorld:
        """Return a world inside the bound window; reject out-of-window reads."""
        ...


@dataclass(frozen=True, slots=True)
class ForwardingMember:
    target: ResourceKey
    role: str | None = None
    weight: int | None = None
    priority: int | None = None
    eligible: bool | None = None


@dataclass(frozen=True, slots=True)
class FibEntry:
    key: ResourceKey
    vrf: ResourceKey
    prefix: str
    selection_rank: tuple[int, ...]
    selected: bool | None
    multipath_group: str | None
    next_hop_group: ResourceKey | None
    direct_interface: ResourceKey | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class NextHopGroup:
    key: ResourceKey
    members: tuple[ForwardingMember, ...]
    hash_policy: str | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class NextHop:
    key: ResourceKey
    address: str | None
    interface: ResourceKey | None
    adjacency: ResourceKey | None
    tunnel: ResourceKey | None
    recursive_target: ResourceKey | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class FailoverGroup:
    key: ResourceKey
    primary: ResourceKey | None
    backup: ResourceKey | None
    selected: ResourceKey | None
    revertive: bool | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class Adjacency:
    key: ResourceKey
    vrf: ResourceKey
    address: str
    interface: ResourceKey | None
    resolved: bool | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class TunnelAction:
    key: ResourceKey
    action_type: str
    next_object: ResourceKey | None
    parameters: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()


@dataclass(frozen=True, slots=True)
class InterfaceForwardingState:
    key: ResourceKey
    admin_up: bool | None
    oper_up: bool | None
    addresses: tuple[str, ...]
    attributes: Properties


@dataclass(frozen=True, slots=True)
class VrfForwardingState:
    key: ResourceKey
    name: str
    active: bool | None
    attributes: Properties


type ForwardingRecord = (
    FibEntry
    | NextHopGroup
    | NextHop
    | FailoverGroup
    | Adjacency
    | TunnelAction
    | InterfaceForwardingState
    | VrfForwardingState
)


@dataclass(frozen=True, slots=True)
class ForwardingMutation:
    operation: ForwardingOperation
    key: ResourceKey
    record: ForwardingRecord | None
    effective_time_ns: int | None
    time_uncertainty_ns: int | None
    cause_event_uid: bytes | None
    provenance: Provenance
    quality: Quality
    basis: WorldBasis
    evidence: tuple[Evidence, ...] = ()
    ir_version: str = FORWARDING_IR_VERSION

    def __post_init__(self) -> None:
        if self.operation is ForwardingOperation.UPSERT:
            if self.record is None:
                raise ValueError("forwarding upsert requires a record")
            if self.record.key != self.key:
                raise ValueError("forwarding upsert record key does not match mutation key")
        elif self.record is not None:
            raise ValueError("forwarding delete must not include a record")


class AnalyzerPlugin(Protocol):
    """Platform/version plugin discovered through Python entry points."""

    manifest: PluginManifest

    def describe(self) -> PluginSchema: ...

    def probe(self, inventory: DumpInventory) -> ProbeReport: ...

    def locate_inputs(
        self,
        inventory: DumpInventory,
    ) -> Iterable[InputSpec | PluginDiagnostic]: ...

    def parse_status(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[
        SnapshotObservation
        | RelationshipObservation
        | RelationshipCollectionObservation
        | PluginDiagnostic
    ]: ...

    def parse_ctf(
        self,
        spec: InputSpec,
        messages: Iterable[CtfMessage],
    ) -> Iterable[DomainEvent | PluginDiagnostic]: ...

    def parse_text_trace(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[DomainEvent | PluginDiagnostic]: ...

    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet: ...

    def revert(
        self,
        event: DomainEvent,
        world_after: ReadOnlyWorld,
    ) -> ChangeSet: ...

    def correlate(
        self,
        reader: CorrelationReader,
        window: CorrelationWindow,
    ) -> Iterable[
        CausalLink | RelationshipMutation | ClockAnchor | PluginDiagnostic
    ]: ...

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> Iterable[ConsistencyFinding | PluginDiagnostic]: ...

    def project_forwarding(
        self,
        ir_version: str,
        changes: ChangeSet | None,
        world: ReadOnlyWorld,
    ) -> Iterable[ForwardingMutation | PluginDiagnostic]: ...
