from .canonical import MAX_TYPED_ATOM_PAYLOAD_UNITS as MAX_TYPED_ATOM_PAYLOAD_UNITS, validate_named_typed_parts as validate_named_typed_parts
from .contract_validation import bounded_string as bounded_string, coerce_enum as coerce_enum, strict_boolean as strict_boolean, strict_integer as strict_integer, typed_tuple as typed_tuple, validate_bounded_json_value as validate_bounded_json_value, validity_bounds as validity_bounds
from .public_text import contains_filesystem_identity_path as contains_filesystem_identity_path, contains_unsafe_identifier_text as contains_unsafe_identifier_text, has_visible_identity_anchor as has_visible_identity_anchor
from .temporal_core import MAX_TEMPORAL_NS as MAX_TEMPORAL_NS, MIN_TEMPORAL_NS as MIN_TEMPORAL_NS
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import BinaryIO, Protocol
from uuid import UUID

CORE_PLUGIN_API_VERSION: str
FORWARDING_IR_VERSION: str
PLUGIN_ENTRY_POINT_GROUP: str
MIN_TIMESTAMP_NS = MIN_TEMPORAL_NS
MAX_TIMESTAMP_NS = MAX_TEMPORAL_NS
MAX_PROBE_REASONS: int
MAX_PROBE_REASON_LENGTH: int
MAX_PROBE_DETECTED_TEXT_LENGTH: int
MAX_PROBE_DIAGNOSTICS: int
MAX_DIAGNOSTIC_CODE_LENGTH: int
MAX_DIAGNOSTIC_MESSAGE_LENGTH: int
MAX_DIAGNOSTIC_EVIDENCE_ITEMS: int
MAX_EVIDENCE_LOCATOR_LENGTH: int
MAX_EVIDENCE_CLOCK_DOMAIN_LENGTH: int
MAX_DIAGNOSTIC_DETAILS_DEPTH: int
MAX_DIAGNOSTIC_DETAILS_CONTAINER_ITEMS: int
MAX_DIAGNOSTIC_DETAILS_UNITS: int
MAX_DIAGNOSTIC_DETAILS_ATOM_UNITS: int
MAX_DIAGNOSTIC_DETAILS_INTEGER_BITS: int
type Scalar = None | bool | int | float | str | bytes | UUID
type Value = Scalar | tuple[Value, ...] | Mapping[str, Value]
type Properties = Mapping[str, Value]
type KeyScalar = int | str | bytes | UUID

@dataclass(frozen=True, slots=True)
class KeyAtom:
    type_tag: str
    value: KeyScalar
    def __post_init__(self) -> None: ...
type KeyValue = KeyScalar | KeyAtom | tuple[KeyValue, ...]

class Provenance(StrEnum):
    OBSERVED = 'observed'
    EVENT_DERIVED = 'event_derived'
    RECONSTRUCTED = 'reconstructed'
    CORRELATED = 'correlated'
    PLUGIN_DEFAULT = 'plugin_default'

class Quality(StrEnum):
    EXACT = 'exact'
    BEST_EFFORT = 'best_effort'
    AMBIGUOUS = 'ambiguous'
    UNKNOWN = 'unknown'

class Outcome(StrEnum):
    SUCCESS = 'success'
    FAILURE = 'failure'
    UNKNOWN = 'unknown'

class ProbeMatchKind(StrEnum):
    EXACT = 'exact'
    COMPATIBLE = 'compatible'
    NONE = 'none'

class PluginCapability(StrEnum):
    STATUS_PARSE = 'status_parse'
    CTF_PARSE = 'ctf_parse'
    TEXT_TRACE_PARSE = 'text_trace_parse'
    EVENT_REDUCTION = 'event_reduction'
    EVENT_REVERSION = 'event_reversion'
    CORRELATION = 'correlation'
    CONSISTENCY_CHECK = 'consistency_check'
    TOPOLOGY_PROJECTION = 'topology_projection'
    FORWARDING_PROJECTION = 'forwarding_projection'
    FORWARDING_TRACE = 'forwarding_trace'
    EVIDENCE_ANALYSIS = 'evidence_analysis'

class InputParserKind(StrEnum):
    STATUS = 'status'
    CTF = 'ctf'
    TEXT_TRACE = 'text_trace'

REQUIRED_PLUGIN_HOOKS: tuple[str, ...]
PLUGIN_CAPABILITY_HOOKS: Mapping[PluginCapability, tuple[str, ...]]
INPUT_PARSER_HOOKS: Mapping[InputParserKind, str]
INPUT_PARSER_CAPABILITIES: Mapping[InputParserKind, PluginCapability]

class ConditionClass(StrEnum):
    HEALTHY = 'healthy'
    DEGRADED = 'degraded'
    ERROR = 'error'
    ABSENT = 'absent'
    UNKNOWN = 'unknown'

class MutationOperation(StrEnum):
    UPSERT = 'upsert'
    DELETE = 'delete'
    UNKNOWN = 'unknown'

class ResourceEffect(StrEnum):
    CREATED = 'created'
    MODIFIED = 'modified'
    DELETED = 'deleted'
    UNCHANGED = 'unchanged'
    UNKNOWN = 'unknown'

class ForwardingOperation(StrEnum):
    UPSERT = 'upsert'
    DELETE = 'delete'

class PathGroupMode(StrEnum):
    SINGLE_ACTIVE = 'single_active'
    ALL_ACTIVE = 'all_active'
    UNSPECIFIED = 'unspecified'

class ForwardingMemberActivity(StrEnum):
    ACTIVE = 'active'
    STANDBY = 'standby'
    INACTIVE = 'inactive'
    UNUSABLE = 'unusable'
    UNKNOWN = 'unknown'

class ForwardingMemberSelection(StrEnum):
    SELECTED = 'selected'
    NOT_SELECTED = 'not_selected'
    UNKNOWN = 'unknown'

class ForwardingConstraintKind(StrEnum):
    EXCLUDE_EXACT_SCOPE = 'exclude_exact_scope'

class ForwardingPolicyVerdict(StrEnum):
    PERMITTED = 'permitted'
    BLOCKED = 'blocked'
    NOT_APPLICABLE = 'not_applicable'
    UNKNOWN = 'unknown'

class ForwardingPacketDisposition(StrEnum):
    CONTINUE = 'continue'
    DELIVER = 'deliver'
    DROP = 'drop'
    PUNT = 'punt'
    REPLICATE = 'replicate'
    UNKNOWN = 'unknown'

class ForwardingTransitionOrigin(StrEnum):
    NODE_PLUGIN = 'node_plugin'
    USER_FORCED = 'user_forced'

class ConnectorMatchPolicyKind(StrEnum):
    EXACT_TOKEN = 'exact_token'
    LINKER = 'linker'

class FederationMatchState(StrEnum):
    MATCHED = 'matched'
    AMBIGUOUS = 'ambiguous'
    UNRESOLVED = 'unresolved'
    CONFLICT = 'conflict'

class RoutePresentationRole(StrEnum):
    PRINCIPAL = 'principal'
    OVERLAY = 'overlay'
    ANNOTATION = 'annotation'

class RoutePresentationScope(StrEnum):
    PATH = 'path'
    STEP = 'step'
    SPAN = 'span'
    RESOURCE = 'resource'

class RoutePresentationStyle(StrEnum):
    PATH = 'path'
    BAND = 'band'
    BADGE = 'badge'
    CALLOUT = 'callout'

class RelationshipOperation(StrEnum):
    ADD = 'add'
    REMOVE = 'remove'
    UNKNOWN = 'unknown'

class ReconstructionSupport(StrEnum):
    EXACT = 'exact'
    BEST_EFFORT = 'best_effort'
    UNSUPPORTED = 'unsupported'

class FindingResult(StrEnum):
    PASS = 'pass'
    FAIL = 'fail'
    UNKNOWN = 'unknown'

class RelationDirection(StrEnum):
    OUTGOING = 'outgoing'
    INCOMING = 'incoming'
    BOTH = 'both'

class DashboardAggregation(StrEnum):
    COUNT = 'count'
    COUNT_DISTINCT = 'count_distinct'
    SUM = 'sum'
    AVERAGE = 'average'
    MINIMUM = 'minimum'
    MAXIMUM = 'maximum'

class DashboardFilterOperator(StrEnum):
    EQ = 'eq'
    NOT_EQ = 'not_eq'
    IN = 'in'
    NOT_IN = 'not_in'
    EXISTS = 'exists'
    CONTAINS = 'contains'

class DashboardValueFormat(StrEnum):
    AUTO = 'auto'
    TEXT = 'text'
    NUMBER = 'number'
    BOOLEAN = 'boolean'
    STATUS = 'status'
    RESOURCE = 'resource'

class DashboardSortDirection(StrEnum):
    ASCENDING = 'ascending'
    DESCENDING = 'descending'

class DiagnosticSeverity(StrEnum):
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'

class DiagnosticOrigin(StrEnum):
    CORE_DECODER = 'core_decoder'
    PLUGIN = 'plugin'

class DiagnosticStage(StrEnum):
    PROBE = 'probe'
    LOCATE = 'locate'
    STATUS_PARSE = 'status_parse'
    TRACE_DECODE = 'trace_decode'
    TRACE_MAP = 'trace_map'
    APPLY = 'apply'
    REVERT = 'revert'
    CORRELATE = 'correlate'
    CONSISTENCY = 'consistency'
    FORWARDING = 'forwarding'

class WorldBasisKind(StrEnum):
    OBSERVED_CAPTURE_VECTOR = 'observed_capture_vector'
    RECONSTRUCTED_TIME = 'reconstructed_time'
    ABSOLUTE_TIME = 'absolute_time'
    RELATIVE_CAPTURE_VECTOR = 'relative_capture_vector'

class TemporalSelectorKind(StrEnum):
    ABSOLUTE_TIME = 'absolute_time'
    RELATIVE_TO_WATERMARK = 'relative_to_watermark'

class ClockAlignmentPolicy(StrEnum):
    STRICT = 'strict'
    BEST_EFFORT = 'best_effort'

class StatusPerspectiveRole(StrEnum):
    INTENDED = 'intended'
    PROGRAMMED = 'programmed'
    OBSERVED = 'observed'
    OTHER = 'other'

class TopologyUsability(StrEnum):
    USABLE = 'usable'
    UNUSABLE = 'unusable'
    DEGRADED = 'degraded'
    UNKNOWN = 'unknown'

class TopologyTwoParticipantShape(StrEnum):
    DOMAIN_NODE = 'domain_node'
    COMPACT_EDGE = 'compact_edge'

class TopologyDomainRole(StrEnum):
    EXTERNAL = 'external'

class InterNodeRouteTraceRole(StrEnum):
    INCLUDE = 'include'
    OVERLAY = 'overlay'
    CONFLICT = 'conflict'

class StatusSourceCombinationPolicy(StrEnum):
    ALL_REQUIRED_USABLE = 'all_required_usable'
    ANY_DECLARED_USABLE = 'any_declared_usable'

@dataclass(frozen=True, slots=True)
class TopologyExternalClassification:
    role: TopologyDomainRole
    coverage_complete: bool
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyPluginSemanticsDescriptor:
    role: TopologyDomainRole | str | None = ...
    coverage_complete: bool | None = ...
    def __post_init__(self) -> None: ...
    @property
    def external_classification(self) -> TopologyExternalClassification | None: ...

@dataclass(frozen=True, slots=True)
class InterNodeLinkPresentation:
    route_trace: InterNodeRouteTraceRole = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class WatermarkScope:
    node_id: str
    status_perspective_id: str
    topology_projection_id: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class AbsoluteTimeSelector:
    time_ns: int
    clock_domain: str
    clock_policy: ClockAlignmentPolicy = ...
    kind: TemporalSelectorKind = field(default=TemporalSelectorKind.ABSOLUTE_TIME, init=False)
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class RelativeToWatermarkSelector:
    offset_ns: int
    scope: WatermarkScope
    clock_policy: ClockAlignmentPolicy = ...
    kind: TemporalSelectorKind = field(default=TemporalSelectorKind.RELATIVE_TO_WATERMARK, init=False)
    def __post_init__(self) -> None: ...
type TemporalSelector = AbsoluteTimeSelector | RelativeToWatermarkSelector

class TimelineTimeBasis(StrEnum):
    ABSOLUTE_UNIX_NS = 'absolute_unix_ns'
    REVISION_START_RELATIVE_NS = 'revision_start_relative_ns'
    SOURCE_CLOCK_NS = 'source_clock_ns'

@dataclass(frozen=True, slots=True)
class PluginManifest:
    plugin_id: str
    plugin_version: str
    core_api_version: str
    supported_platforms: tuple[str, ...]
    supported_software_versions: str
    capabilities: frozenset[PluginCapability | str]
    reconstruction_default: ReconstructionSupport
    forwarding_ir_versions: tuple[str, ...] = ...
    timeline_time_basis: TimelineTimeBasis = ...
    timeline_clock_domain: str | None = ...
    def __post_init__(self) -> None: ...
    def supports(self, capability: PluginCapability | str) -> bool: ...

@dataclass(frozen=True, slots=True)
class PropertyDescriptor:
    name: str
    label: str
    value_type: str
    searchable: bool = ...
    indexed: bool = ...
    sensitive: bool = ...
    client_visible: bool = ...
    def __post_init__(self) -> None: ...

class IconRenderMode(StrEnum):
    STROKE = 'stroke'
    FILL = 'fill'

@dataclass(frozen=True, slots=True)
class ResourceIconDescriptor:
    path: str
    view_box: tuple[float, float, float, float] = ...
    render_mode: IconRenderMode = ...
    stroke_width: float = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResourceKindDescriptor:
    kind: str
    label: str
    key_fields: tuple[str, ...]
    properties: tuple[PropertyDescriptor, ...]
    default_timeline_fields: tuple[str, ...] = ...
    display_name_fields: tuple[str, ...] = ...
    default_table_fields: tuple[str, ...] = ...
    condition_field: str | None = ...
    presentation_tags: tuple[str, ...] = ...
    icon: ResourceIconDescriptor | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class DashboardFilterDescriptor:
    field: str
    operator: DashboardFilterOperator
    value: Value = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class DashboardStatisticDescriptor:
    statistic_id: str
    label: str
    aggregation: DashboardAggregation
    resource_kinds: tuple[str, ...] = ...
    field: str | None = ...
    filters: tuple[DashboardFilterDescriptor, ...] = ...
    unit: str | None = ...
    precision: int = ...
    include_absent: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class DashboardColumnDescriptor:
    field: str
    label: str
    value_format: DashboardValueFormat = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class DashboardTableDescriptor:
    table_id: str
    title: str
    resource_kinds: tuple[str, ...]
    columns: tuple[DashboardColumnDescriptor, ...]
    include_absent: bool = ...
    max_rows: int = ...
    sort_field: str | None = ...
    sort_direction: DashboardSortDirection = ...
    empty_message: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResourceTableRelationLevelDescriptor:
    label: str
    relation_types: tuple[str, ...]
    target_kinds: tuple[str, ...] = ...
    direction: RelationDirection = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResourceTableViewDescriptor:
    view_id: str
    label: str
    description: str
    root_kinds: tuple[str, ...]
    levels: tuple[ResourceTableRelationLevelDescriptor, ...]
    columns: tuple[DashboardColumnDescriptor, ...] = ...
    default_selected: bool = ...
    include_absent: bool = ...
    default_expanded_depth: int = ...
    max_roots: int = ...
    max_children_per_node: int = ...
    max_nodes: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class DashboardDescriptor:
    dashboard_id: str
    title: str
    description: str
    statistics: tuple[DashboardStatisticDescriptor, ...] = ...
    tables: tuple[DashboardTableDescriptor, ...] = ...
    default_open: bool = ...
    collapsible: bool = ...
    default_expanded: bool = ...
    movable: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class RelationshipTypeDescriptor:
    relation_type: str
    label: str
    directed: bool
    structural: bool
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class CausalLinkTypeDescriptor:
    link_type: str
    label: str
    directed: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class SourceRecordGroupDescriptor:
    group_id: str
    label: str
    description: str = ...
    default_included: bool = ...
    copy_action_label: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class SourceRecordTypeDescriptor:
    source_type: str
    label: str
    description: str = ...
    color: str = ...
    stream_group: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class StatusPerspectiveDescriptor:
    perspective_id: str
    label: str
    layer_id: str
    role: StatusPerspectiveRole
    description: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class StatusPerspectiveRef:
    perspective_id: str
    plugin_instance_id: str | None = ...
    schema_digest: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ConnectorMatchPolicyDescriptor:
    policy_id: str
    claim_contract_id: str
    kind: ConnectorMatchPolicyKind
    argument_names: tuple[str, ...]
    linker_plugin_id: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyProjectionDescriptor:
    projection_id: str
    label: str
    supported_status_perspective_ids: tuple[str, ...]
    description: str = ...
    default_status_perspective_id: str | None = ...
    status_source_combination_policy: StatusSourceCombinationPolicy = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class RecordLanePreset:
    lane_id: str
    label: str
    pattern: str
    source_types: tuple[str, ...] = ...
    unmatched_only: bool = ...
    case_sensitive: bool = ...
    default_enabled: bool = ...
    description: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PluginSchema:
    resource_kinds: tuple[ResourceKindDescriptor, ...]
    relationship_types: tuple[RelationshipTypeDescriptor, ...]
    causal_link_types: tuple[CausalLinkTypeDescriptor, ...] = ...
    dashboards: tuple[DashboardDescriptor, ...] = ...
    resource_table_views: tuple[ResourceTableViewDescriptor, ...] = ...
    source_record_groups: tuple[SourceRecordGroupDescriptor, ...] = ...
    source_record_types: tuple[SourceRecordTypeDescriptor, ...] = ...
    record_lane_presets: tuple[RecordLanePreset, ...] = ...
    status_perspectives: tuple[StatusPerspectiveDescriptor, ...] = ...
    topology_projections: tuple[TopologyProjectionDescriptor, ...] = ...
    connector_match_policies: tuple[ConnectorMatchPolicyDescriptor, ...] = ...
    def __post_init__(self) -> None: ...

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
    detected_platform: str | None = ...
    detected_software_version: str | None = ...
    match_kind: ProbeMatchKind = ...
    def __post_init__(self) -> None: ...

def validate_probe_result(value: object) -> ProbeResult: ...

@dataclass(frozen=True, slots=True)
class ProbeReport:
    result: ProbeResult | None
    diagnostics: tuple[PluginDiagnostic, ...] = ...

@dataclass(frozen=True, slots=True)
class InputSpec:
    artifact_ids: tuple[UUID, ...]
    role: str
    node: str
    layer: str
    parser_id: str
    logical_root: PurePosixPath | None = ...
    options: Properties = field(default_factory=dict)
    parser_kind: InputParserKind | None = ...
    def __post_init__(self) -> None: ...
    @property
    def dispatch_hook(self) -> str | None: ...
    @property
    def required_capability(self) -> PluginCapability | None: ...

@dataclass(frozen=True, slots=True)
class ResourceKey:
    namespace: str
    node: str
    layer: str
    kind: str
    parts: tuple[tuple[str, KeyValue], ...]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class Evidence:
    artifact_id: UUID
    locator: str
    raw_timestamp_ns: int | None
    clock_domain: str | None
    excerpt_sha256: str | None = ...

@dataclass(frozen=True, slots=True)
class SourceRecord:
    source_record_uid: bytes
    timestamp_ns: int | None
    timestamp_uncertainty_ns: int | None
    source_type: str
    source_name: str
    record_name: str
    message: str
    layer: str | None
    attributes: Properties = field(default_factory=dict)
    matched_event_uid: bytes | None = ...
    evidence: tuple[Evidence, ...] = ...
    copy_text: str | None = ...
    matched_event_uids: tuple[bytes, ...] = ...

@dataclass(frozen=True, slots=True)
class SourceRecordEmission:
    timestamp_ns: int | None
    timestamp_uncertainty_ns: int | None
    source_type: str
    source_name: str
    record_name: str
    message: str
    layer: str | None
    attributes: Properties = field(default_factory=dict)
    matched_event_uid: bytes | None = ...
    evidence: tuple[Evidence, ...] = ...
    copy_text: str | None = ...
    matched_event_uids: tuple[bytes, ...] = ...

@dataclass(frozen=True, slots=True)
class PluginDiagnostic:
    stage: DiagnosticStage
    severity: DiagnosticSeverity
    code: str
    message: str
    recoverable: bool
    evidence: tuple[Evidence, ...] = ...
    details: Properties = field(default_factory=dict)
    origin: DiagnosticOrigin = ...

def validate_plugin_diagnostic(value: object, *, label: str = 'diagnostic', expected_origin: DiagnosticOrigin | None = None, expected_stage: DiagnosticStage | None = None, artifact_ids: Collection[UUID] | None = None, maximum_evidence_items: int = ...) -> PluginDiagnostic: ...
def validate_probe_report(value: object, *, artifact_ids: Collection[UUID] | None = None, maximum_diagnostics: int = ..., maximum_evidence_items: int = ...) -> ProbeReport: ...

@dataclass(frozen=True, slots=True)
class UnknownField:
    name: str
    reason_code: str
    message: str
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class PropertyPatch:
    set_values: Properties = field(default_factory=dict)
    remove_fields: tuple[str, ...] = ...
    unknown_fields: tuple[UnknownField, ...] = ...
    field_quality: Mapping[str, Quality] = field(default_factory=dict)
    field_provenance: Mapping[str, Provenance] = field(default_factory=dict)
    complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class SnapshotObservation:
    resource: ResourceKey
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    state: PropertyPatch
    provenance: Provenance
    quality: Quality
    evidence: Evidence
    condition: Value = ...
    condition_class: ConditionClass = ...
    perspective_ref: StatusPerspectiveRef | None = ...

@dataclass(frozen=True, slots=True)
class RelationshipObservation:
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
    perspective_ref: StatusPerspectiveRef | None = ...

@dataclass(frozen=True, slots=True)
class RelationshipCollectionObservation:
    owner: ResourceKey
    direction: RelationDirection
    relation_type: str
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    complete: bool
    provenance: Provenance
    quality: Quality
    evidence: Evidence
    perspective_ref: StatusPerspectiveRef | None = ...

@dataclass(frozen=True, slots=True)
class SourceRecordRef:
    source_id: str
    message_ordinal: int
    trace_uid: str | None = ...
    stream_uid: str | None = ...
    packet_sequence: int | None = ...

def derive_event_uid(plugin_id: str, parser_id: str, source: SourceRecordRef, local_discriminator: KeyScalar | None = None) -> bytes: ...

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
    def __post_init__(self) -> None: ...

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
    evidence: tuple[Evidence, ...] = ...
    condition: Value = ...
    condition_class: ConditionClass = ...
    perspective_ref: StatusPerspectiveRef | None = ...

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
    evidence: tuple[Evidence, ...] = ...
    perspective_ref: StatusPerspectiveRef | None = ...

@dataclass(frozen=True, slots=True)
class CausalLink:
    source_event_uid: bytes
    target_event_uid: bytes
    link_type: str
    confidence: float
    provenance: Provenance
    quality: Quality
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class UnknownChange:
    change_kind: str
    reason_code: str
    message: str
    affected_resources: tuple[ResourceKey, ...] = ...
    affected_fields: tuple[str, ...] = ...
    relation_type: str | None = ...
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class ReconstructionCoverage:
    scope: str
    exact_outputs: int
    best_effort_outputs: int
    ambiguous_outputs: int
    unknown_outputs: int

@dataclass(frozen=True, slots=True)
class ChangeSet:
    state: tuple[StateMutation, ...] = ...
    relationships: tuple[RelationshipMutation, ...] = ...
    causal_links: tuple[CausalLink, ...] = ...
    unknowns: tuple[UnknownChange, ...] = ...
    diagnostics: tuple[PluginDiagnostic, ...] = ...
    coverage: tuple[ReconstructionCoverage, ...] = ...

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
    evidence: tuple[Evidence, ...] = ...

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
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class CtfStreamBoundary:
    trace_uid: str
    stream_uid: str
    started: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class CtfPacketBoundary:
    trace_uid: str
    stream_uid: str
    packet_sequence: int | None
    started: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class CtfDiscardedEvents:
    trace_uid: str
    stream_uid: str
    count: int | None
    message_ordinal: int
    begin_timestamp_ns: int | None
    end_timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class CtfDiscardedPackets:
    trace_uid: str
    stream_uid: str
    count: int | None
    message_ordinal: int
    begin_timestamp_ns: int | None
    end_timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ...

@dataclass(frozen=True, slots=True)
class CtfStreamActivityBoundary:
    trace_uid: str
    stream_uid: str
    began: bool
    message_ordinal: int
    timestamp_ns: int | None
    clock_domain: str | None
    evidence: tuple[Evidence, ...] = ...
type CtfMessage = CtfEventRecord | CtfStreamBoundary | CtfPacketBoundary | CtfDiscardedEvents | CtfDiscardedPackets | CtfStreamActivityBoundary

class ArtifactReader(Protocol):
    def open_binary(self, artifact_id: UUID) -> BinaryIO: ...
    def materialize_private_path(self, artifact_id: UUID) -> str: ...
    def materialize_private_tree(self, artifact_ids: Sequence[UUID], logical_root: PurePosixPath | None = None) -> str: ...

class TraceDecoder(Protocol):
    def iter_ctf(self, reader: ArtifactReader, spec: InputSpec) -> Iterable[CtfMessage | PluginDiagnostic]: ...

@dataclass(frozen=True, slots=True)
class CaptureRange:
    scope: str
    observed_at_min_ns: int | None
    observed_at_max_ns: int | None
    evidence: tuple[Evidence, ...] = ...
    clock_domain: str | None = ...

@dataclass(frozen=True, slots=True)
class ReconstructionWatermark:
    scope: WatermarkScope
    local_time_ns: int
    clock_domain: str
    provenance: Provenance
    quality: Quality
    absolute_min_ns: int | None = ...
    absolute_max_ns: int | None = ...
    mapping_method: str | None = ...
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResolvedNodeBasis:
    node_id: str
    local_clock_domain: str | None
    local_min_ns: int | None
    local_max_ns: int | None
    absolute_min_ns: int | None
    absolute_max_ns: int | None
    mapping_method: str | None
    quality: Quality
    reason_code: str | None = ...
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class WorldBasis:
    kind: WorldBasisKind
    requested_time_ns: int | None
    resolved_at_min_ns: int | None
    resolved_at_max_ns: int | None
    capture_ranges: tuple[CaptureRange, ...]
    provenance: Provenance
    quality: Quality
    clock_domain: str | None = ...
    selector: TemporalSelector | None = ...
    node_resolutions: tuple[ResolvedNodeBasis, ...] = ...
    watermark: ReconstructionWatermark | None = ...
    unresolved_reason: str | None = ...

@dataclass(frozen=True, slots=True)
class ResourceStateView:
    resource: ResourceKey
    exists: bool | None
    properties: Properties
    provenance: Provenance
    quality: Quality
    valid_from_ns: int | None
    valid_to_ns: int | None
    observed_at_min_ns: int | None = ...
    observed_at_max_ns: int | None = ...
    field_quality: Mapping[str, Quality] = field(default_factory=dict)
    unknown_fields: tuple[UnknownField, ...] = ...
    evidence: tuple[Evidence, ...] = ...
    perspective_ref: StatusPerspectiveRef | None = ...

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
    evidence: tuple[Evidence, ...] = ...
    perspective_ref: StatusPerspectiveRef | None = ...

@dataclass(frozen=True, slots=True)
class TopologyProjectionRequest:
    projection_id: str
    status_perspective_id: str
    max_records: int = ...
    max_world_reads: int = ...
    seed_resources: tuple[ResourceKey, ...] = ...
    max_claims: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyMatchReference:
    matcher_id: str
    arguments: Properties
    resolved_candidates: tuple[ResourceKey, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyEndpointReference:
    resource: ResourceKey | None = ...
    match: TopologyMatchReference | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyResourcePresentation:
    two_participant_shape: TopologyTwoParticipantShape = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyResourceRecord:
    resource: ResourceKey
    role: str | None = ...
    presentation: TopologyResourcePresentation = field(default_factory=TopologyResourcePresentation)
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyEndpointRecord:
    endpoint_id: str
    target: TopologyEndpointReference
    role: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyLinkRecord:
    link_id: str
    source: TopologyEndpointReference
    target: TopologyEndpointReference
    directed: bool = ...
    def __post_init__(self) -> None: ...
type TopologyProjectionPayload = TopologyResourceRecord | TopologyEndpointRecord | TopologyLinkRecord

@dataclass(frozen=True, slots=True)
class TopologyProjectionRecord:
    projection_id: str
    status_perspective_id: str
    payload: TopologyProjectionPayload
    usability: TopologyUsability
    source_resources: tuple[ResourceKey, ...]
    provenance: Provenance
    quality: Quality
    exists: bool | None = ...
    properties: Properties = field(default_factory=dict)
    unknown_fields: tuple[UnknownField, ...] = ...
    valid_from_ns: int | None = ...
    valid_to_ns: int | None = ...
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class GlobalResourceRef:
    member_id: str
    revision_id: str
    plugin_instance_id: str
    resource: ResourceKey
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ConnectorClaim:
    claim_id: str
    endpoint: ResourceKey
    claim_contract_id: str
    match_policy_id: str
    arguments: tuple[tuple[str, KeyValue], ...]
    provenance: Provenance
    quality: Quality
    status_perspective: StatusPerspectiveRef | None = ...
    role: str | None = ...
    valid_from_ns: int | None = ...
    valid_to_ns: int | None = ...
    evidence: tuple[Evidence, ...] = ...
    link_type: str = ...
    presentation: InterNodeLinkPresentation = field(default_factory=InterNodeLinkPresentation)
    def __post_init__(self) -> None: ...
type TopologyProjectionOutput = TopologyProjectionRecord | ConnectorClaim | PluginDiagnostic

@dataclass(frozen=True, slots=True)
class FederatedConnectorClaim:
    endpoint: GlobalResourceRef
    claim: ConnectorClaim
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class FederationMatchCandidate:
    claim_id: str
    endpoint: GlobalResourceRef
    quality: Quality
    confidence: float | None = ...
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class FederationLinkResult:
    result_id: str
    match_policy_id: str
    source: FederatedConnectorClaim
    state: FederationMatchState
    candidates: tuple[FederationMatchCandidate, ...]
    provenance: Provenance
    quality: Quality
    link_type: str | None = ...
    directed: bool = ...
    properties: Properties = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class FederationLinkRequest:
    policy: ConnectorMatchPolicyDescriptor
    claims: tuple[FederatedConnectorClaim, ...]
    max_results: int = ...
    max_candidates_per_result: int = ...
    def __post_init__(self) -> None: ...

class FederationLinkerPlugin(Protocol):
    linker_plugin_id: str
    linker_plugin_version: str
    def describe_match_policies(self) -> tuple[ConnectorMatchPolicyDescriptor, ...]: ...
    def link(self, request: FederationLinkRequest) -> Iterable[FederationLinkResult | PluginDiagnostic]: ...

class ReadOnlyWorld(Protocol):
    @property
    def basis(self) -> WorldBasis: ...
    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None: ...
    def state_of(self, resource: ResourceKey) -> ResourceStateView | None: ...
    def iter_states(self, layers: frozenset[str] | None = None, kinds: frozenset[str] | None = None, limit: int | None = None) -> Iterable[ResourceStateView]: ...
    def related(self, resource: ResourceKey, direction: RelationDirection = ..., relation_types: frozenset[str] | None = None, limit: int | None = None) -> Iterable[RelationshipView]: ...
    def iter_relationships(self, relation_types: frozenset[str] | None = None, layers: frozenset[str] | None = None, limit: int | None = None) -> Iterable[RelationshipView]: ...

@dataclass(frozen=True, slots=True)
class CorrelationWindow:
    start_ns: int | None
    end_ns: int | None
    max_events: int
    max_world_reads: int = ...

@dataclass(frozen=True, slots=True)
class CorrelationQuery:
    start_ns: int | None
    end_ns: int | None
    max_events: int
    event_types: frozenset[str] | None = ...
    layers: frozenset[str] | None = ...
    subject: ResourceKey | None = ...
    correlation_keys: Properties = field(default_factory=dict)
    cursor: str | None = ...

@dataclass(frozen=True, slots=True)
class EventBatch:
    events: tuple[DomainEvent, ...]
    next_cursor: str | None
    truncated: bool
    watermark_ns: int | None

class CorrelationReader(Protocol):
    @property
    def remaining_event_budget(self) -> int: ...
    @property
    def remaining_world_budget(self) -> int: ...
    def iter_event_batches(self, query: CorrelationQuery) -> Iterable[EventBatch]: ...
    def world_at(self, timestamp_ns: int) -> ReadOnlyWorld: ...

class EvidenceAnalysisKind(StrEnum):
    ROUTE_TRACE = 'route_trace'
    TRACE_CORRELATION = 'trace_correlation'
    EVIDENCE_CORRELATION = 'evidence_correlation'
    EVIDENCE_INTERPRETATION = 'evidence_interpretation'

class _EvidenceAnalysisThawBudget:
    units: int
    active: set[int]
    def __init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class EvidenceAnalysisFact:
    reference_digest: str
    evidence_kind: str
    subject_kind: str
    node_id: str
    revision_id: str
    payload_schema: str
    fact_provenance: str
    time_basis: str
    time_start_ns: int | None
    time_end_ns: int | None
    time_clock_domain: str | None
    payload: Properties
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class EvidenceAnalysisRequest:
    invocation_id: str
    analysis_kind: EvidenceAnalysisKind
    facts: tuple[EvidenceAnalysisFact, ...]
    parameters: Properties = field(default_factory=dict)
    max_observations: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class EvidenceAnalysisObservation:
    observation_id: str
    category: str
    summary: str
    cited_reference_digests: tuple[str, ...]
    quality: Quality
    details: Properties = field(default_factory=dict)
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class RoutePresentationDescriptor:
    presentation_id: str
    role: RoutePresentationRole
    scope: RoutePresentationScope
    style: RoutePresentationStyle
    label: str
    topology_references: tuple[TopologyEndpointReference, ...]
    anchor_resources: tuple[ResourceKey, ...] = ...
    facts: Properties = field(default_factory=dict)
    description: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingProjectionRequest:
    ir_version: str
    status_perspective: StatusPerspectiveRef
    changes: ChangeSet | None = ...
    max_records: int = ...
    max_world_reads: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResolutionContribution:
    phase: str
    text: str
    quality: Quality
    resource_references: tuple[ResourceKey, ...] = ...
    topology_references: tuple[TopologyEndpointReference, ...] = ...
    evidence: tuple[Evidence, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingSizeObservation:
    basis_contract_id: str
    size_bytes: int
    complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingMtuConstraint:
    basis_contract_id: str
    limit_bytes: int
    resource: ResourceKey | None = ...
    complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingPacketLayer:
    layer_id: str
    contract_id: str
    label: str = field(compare=False, hash=False)
    fields: tuple[tuple[str, KeyValue], ...] = ...
    size_bytes: int | None = ...
    complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingPacketState:
    layers: tuple[ForwardingPacketLayer, ...]
    size: ForwardingSizeObservation | None = ...
    complete: bool = ...
    def __post_init__(self) -> None: ...
    @property
    def identity_complete(self) -> bool: ...

@dataclass(frozen=True, slots=True)
class ForwardingPacketTransition:
    transition_id: str
    step_id: str
    before: ForwardingPacketState
    after: ForwardingPacketState
    action_contract_id: str
    action_label: str
    disposition: ForwardingPacketDisposition
    origin: ForwardingTransitionOrigin
    actor_id: str
    mtu: ForwardingMtuConstraint | None = ...
    forced_rule_id: str | None = ...
    contributions: tuple[ResolutionContribution, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingSteeringRule:
    rule_id: str
    target_step_id: str
    action_contract_id: str
    reason: str
    priority: int = ...
    expected_before: ForwardingPacketState | None = ...
    selected_candidate: ResourceKey | None = ...
    packet_after: ForwardingPacketState | None = ...
    disposition: ForwardingPacketDisposition | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingStepRequest:
    step_id: str
    member_id: str
    status_perspective: StatusPerspectiveRef
    forwarding_object: ResourceKey
    packet_state: ForwardingPacketState
    lookup_context: tuple[tuple[str, KeyValue], ...] = ...
    ingress_resource: ResourceKey | None = ...
    steering_rules: tuple[ForwardingSteeringRule, ...] = ...
    max_candidates: int = ...
    ir_version: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingStepResult:
    step_id: str
    transition: ForwardingPacketTransition
    selected_candidate: ResourceKey | None
    next_forwarding_object: ResourceKey | None
    next_lookup_context: tuple[tuple[str, KeyValue], ...] = ...
    recursive: bool = ...
    terminal: bool = ...
    quality: Quality = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingPolicyScope:
    contract_id: str
    arguments: tuple[tuple[str, KeyValue], ...]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingCandidateConstraint:
    constraint_id: str
    kind: ForwardingConstraintKind
    candidate_scope: ForwardingPolicyScope
    traffic_classes: frozenset[str] = ...
    contributions: tuple[ResolutionContribution, ...] = ...
    def __post_init__(self) -> None: ...
    def applies_to(self, traffic_class: str | None) -> bool | None: ...

@dataclass(frozen=True, slots=True)
class ForwardingPolicyDecision:
    candidate: ResourceKey
    constraint: ForwardingCandidateConstraint
    verdict: ForwardingPolicyVerdict
    traffic_class: str | None
    ingress_scopes: frozenset[ForwardingPolicyScope]
    ingress_scopes_complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingTraversalStateKey:
    member_id: str
    status_perspective: StatusPerspectiveRef
    forwarding_object: ResourceKey
    forwarding_domain: ResourceKey | None = ...
    ingress_resource: ResourceKey | None = ...
    lookup_context: tuple[tuple[str, KeyValue], ...] = ...
    packet_context: tuple[tuple[str, KeyValue], ...] = ...
    packet_state: ForwardingPacketState | None = ...
    policy_scopes: frozenset[ForwardingPolicyScope] = ...
    policy_scopes_complete: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingCycleReport:
    first_seen_step: int
    repeated_at_step: int
    cycle_states: tuple[ForwardingTraversalStateKey, ...]
    contributions: tuple[ResolutionContribution, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ForwardingMember:
    target: ResourceKey
    role: str | None = ...
    weight: int | None = ...
    priority: int | None = ...
    eligible: bool | None = ...
    activity: ForwardingMemberActivity | None = ...
    selection: ForwardingMemberSelection | None = ...
    contributions: tuple[ResolutionContribution, ...] = ...
    policy_constraints: tuple[ForwardingCandidateConstraint, ...] = ...
    def __post_init__(self) -> None: ...

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
    unresolved_dependencies: tuple[ResourceKey, ...] = ...
    presentations: tuple[RoutePresentationDescriptor, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class NextHopGroup:
    key: ResourceKey
    members: tuple[ForwardingMember, ...]
    hash_policy: str | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ...
    mode: PathGroupMode | None = ...
    contributions: tuple[ResolutionContribution, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class NextHop:
    key: ResourceKey
    address: str | None
    interface: ResourceKey | None
    adjacency: ResourceKey | None
    tunnel: ResourceKey | None
    recursive_target: ResourceKey | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ...

@dataclass(frozen=True, slots=True)
class FailoverGroup:
    key: ResourceKey
    primary: ResourceKey | None
    backup: ResourceKey | None
    selected: ResourceKey | None
    revertive: bool | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ...

@dataclass(frozen=True, slots=True)
class Adjacency:
    key: ResourceKey
    vrf: ResourceKey
    address: str
    interface: ResourceKey | None
    resolved: bool | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ...

@dataclass(frozen=True, slots=True)
class TunnelAction:
    key: ResourceKey
    action_type: str
    next_object: ResourceKey | None
    parameters: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ...
    presentations: tuple[RoutePresentationDescriptor, ...] = ...
    def __post_init__(self) -> None: ...

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
type ForwardingRecord = FibEntry | NextHopGroup | NextHop | FailoverGroup | Adjacency | TunnelAction | InterfaceForwardingState | VrfForwardingState

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
    evidence: tuple[Evidence, ...] = ...
    ir_version: str = ...
    def __post_init__(self) -> None: ...
type StatusParseOutput = SnapshotObservation | RelationshipObservation | RelationshipCollectionObservation | SourceRecordEmission | PluginDiagnostic
type TraceParseOutput = DomainEvent | SourceRecordEmission | PluginDiagnostic

class AnalyzerPluginBase:
    manifest: PluginManifest
    def describe(self) -> PluginSchema: ...
    def probe(self, inventory: DumpInventory) -> ProbeReport: ...
    def locate_inputs(self, inventory: DumpInventory) -> Iterable[InputSpec | PluginDiagnostic]: ...
    def parse_status(self, reader: ArtifactReader, spec: InputSpec) -> Iterable[StatusParseOutput]: ...
    def parse_ctf(self, spec: InputSpec, messages: Iterable[CtfMessage]) -> Iterable[TraceParseOutput]: ...
    def parse_text_trace(self, reader: ArtifactReader, spec: InputSpec) -> Iterable[TraceParseOutput]: ...
    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet: ...
    def revert(self, event: DomainEvent, world_after: ReadOnlyWorld) -> ChangeSet: ...
    def correlate(self, reader: CorrelationReader, window: CorrelationWindow) -> Iterable[CausalLink | RelationshipMutation | ClockAnchor | PluginDiagnostic]: ...
    def check_consistency(self, world: ReadOnlyWorld) -> Iterable[ConsistencyFinding | PluginDiagnostic]: ...
    def project_topology(self, request: TopologyProjectionRequest, world: ReadOnlyWorld) -> Iterable[TopologyProjectionOutput]: ...
    def project_forwarding(self, request: ForwardingProjectionRequest, world: ReadOnlyWorld) -> Iterable[ForwardingMutation | PluginDiagnostic]: ...
    def resolve_forwarding_step(self, request: ForwardingStepRequest, world: ReadOnlyWorld) -> ForwardingStepResult | PluginDiagnostic: ...
    def analyze_evidence(self, request: EvidenceAnalysisRequest) -> Iterable[EvidenceAnalysisObservation | PluginDiagnostic]: ...

class AnalyzerPlugin(Protocol):
    manifest: PluginManifest
    def describe(self) -> PluginSchema: ...
    def probe(self, inventory: DumpInventory) -> ProbeReport: ...
    def locate_inputs(self, inventory: DumpInventory) -> Iterable[InputSpec | PluginDiagnostic]: ...
    def parse_status(self, reader: ArtifactReader, spec: InputSpec) -> Iterable[StatusParseOutput]: ...
    def parse_ctf(self, spec: InputSpec, messages: Iterable[CtfMessage]) -> Iterable[TraceParseOutput]: ...
    def parse_text_trace(self, reader: ArtifactReader, spec: InputSpec) -> Iterable[TraceParseOutput]: ...
    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet: ...
    def revert(self, event: DomainEvent, world_after: ReadOnlyWorld) -> ChangeSet: ...
    def correlate(self, reader: CorrelationReader, window: CorrelationWindow) -> Iterable[CausalLink | RelationshipMutation | ClockAnchor | PluginDiagnostic]: ...
    def check_consistency(self, world: ReadOnlyWorld) -> Iterable[ConsistencyFinding | PluginDiagnostic]: ...
    def project_topology(self, request: TopologyProjectionRequest, world: ReadOnlyWorld) -> Iterable[TopologyProjectionOutput]: ...
    def project_forwarding(self, request: ForwardingProjectionRequest, world: ReadOnlyWorld) -> Iterable[ForwardingMutation | PluginDiagnostic]: ...
    def resolve_forwarding_step(self, request: ForwardingStepRequest, world: ReadOnlyWorld) -> ForwardingStepResult | PluginDiagnostic: ...
    def analyze_evidence(self, request: EvidenceAnalysisRequest) -> Iterable[EvidenceAnalysisObservation | PluginDiagnostic]: ...
