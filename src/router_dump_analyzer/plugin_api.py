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
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Iterable, Mapping, Protocol, Sequence
from uuid import UUID


CORE_PLUGIN_API_VERSION = "1.0"
FORWARDING_IR_VERSION = "1.0"
PLUGIN_ENTRY_POINT_GROUP = "router_dump_analyzer.plugins"

type Scalar = None | bool | int | float | str | bytes | UUID
type Value = Scalar | tuple[Value, ...] | Mapping[str, Value]
type Properties = Mapping[str, Value]
type KeyScalar = int | str | bytes | UUID


_STANDARD_KEY_ATOM_TAGS = frozenset(
    {"opaque_int", "opaque_uint", "ipv4", "ipv6", "uuid", "bytes"}
)
_PLUGIN_KEY_ATOM_TAG_PATTERN = re.compile(
    r"^plugin:[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*:"
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
)
_KEY_ATOM_MAX_TAG_LENGTH = 128
_KEY_ATOM_MAX_PAYLOAD_LENGTH = 4096


@dataclass(frozen=True, slots=True)
class KeyAtom:
    """One explicitly typed atom in an otherwise opaque resource key.

    Existing ``int``, ``str``, ``bytes``, and ``UUID`` key scalars remain
    valid.  Use a tagged atom when the same scalar representation can carry
    different plug-in semantics, such as a numeric IPv4 address versus an
    opaque hardware identifier, or UUID/IPv6 bytes versus generic bytes.

    The standard tags are ``opaque_int``, ``opaque_uint``, ``ipv4``, ``ipv6``,
    ``uuid``, and ``bytes``.  Plug-ins may add bounded tags in the form
    ``plugin:<plugin-id>:<local-tag>``; the core preserves but never interprets
    those tags.
    """

    type_tag: str
    value: KeyScalar

    def __post_init__(self) -> None:
        if (
            not isinstance(self.type_tag, str)
            or not self.type_tag
            or len(self.type_tag) > _KEY_ATOM_MAX_TAG_LENGTH
            or (
                self.type_tag not in _STANDARD_KEY_ATOM_TAGS
                and _PLUGIN_KEY_ATOM_TAG_PATTERN.fullmatch(self.type_tag) is None
            )
        ):
            raise ValueError(
                "key atom type_tag must be a supported standard tag or "
                "plugin:<plugin-id>:<local-tag>"
            )

        value = self.value
        if isinstance(value, bool):
            raise ValueError("Boolean key-atom payloads are forbidden")

        if self.type_tag in {"opaque_int", "opaque_uint", "ipv4"}:
            if type(value) is not int:
                raise ValueError(
                    f"key atom {self.type_tag} payload must be an integer"
                )
            if self.type_tag == "opaque_uint" and value < 0:
                raise ValueError("key atom opaque_uint payload must be non-negative")
            if self.type_tag == "ipv4" and not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(
                    "key atom ipv4 payload must be between 0 and 2^32 - 1"
                )
            return

        if self.type_tag in {"ipv6", "uuid"}:
            if not isinstance(value, bytes) or len(value) != 16:
                raise ValueError(
                    f"key atom {self.type_tag} payload must be exactly 16 bytes"
                )
            return

        if self.type_tag == "bytes":
            if not isinstance(value, bytes):
                raise ValueError("key atom bytes payload must be bytes")
            if len(value) > _KEY_ATOM_MAX_PAYLOAD_LENGTH:
                raise ValueError("key atom bytes payload exceeds 4096 bytes")
            return

        if not isinstance(value, (int, str, bytes, UUID)):
            raise ValueError(
                "plugin-namespaced key atom payload must be int, str, bytes, or UUID"
            )
        if isinstance(value, (str, bytes)) and len(value) > _KEY_ATOM_MAX_PAYLOAD_LENGTH:
            raise ValueError("plugin-namespaced key atom payload exceeds 4096 units")


type KeyValue = KeyScalar | KeyAtom | tuple[KeyValue, ...]


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


class ProbeMatchKind(StrEnum):
    """Plug-in-owned compatibility decision for one probed artifact set."""

    EXACT = "exact"
    COMPATIBLE = "compatible"
    NONE = "none"


class PluginCapability(StrEnum):
    """Standard optional behavior advertised by a node/device plug-in.

    Discovery, ``describe()``, ``probe()``, and ``locate_inputs()`` are part of
    every plug-in.  These values advertise the optional hooks that the plug-in
    actually implements.  A manifest may retain a non-standard string for a
    legacy or deployment-specific extension, but new plug-ins should use these
    enum members.
    """

    STATUS_PARSE = "status_parse"
    CTF_PARSE = "ctf_parse"
    TEXT_TRACE_PARSE = "text_trace_parse"
    EVENT_REDUCTION = "event_reduction"
    EVENT_REVERSION = "event_reversion"
    CORRELATION = "correlation"
    CONSISTENCY_CHECK = "consistency_check"
    TOPOLOGY_PROJECTION = "topology_projection"
    FORWARDING_PROJECTION = "forwarding_projection"


class InputParserKind(StrEnum):
    """Core dispatch target for one plug-in-declared logical input."""

    STATUS = "status"
    CTF = "ctf"
    TEXT_TRACE = "text_trace"


REQUIRED_PLUGIN_HOOKS = (
    "describe",
    "probe",
    "locate_inputs",
)

PLUGIN_CAPABILITY_HOOKS: Mapping[PluginCapability, tuple[str, ...]] = (
    MappingProxyType(
        {
            PluginCapability.STATUS_PARSE: ("parse_status",),
            PluginCapability.CTF_PARSE: ("parse_ctf",),
            PluginCapability.TEXT_TRACE_PARSE: ("parse_text_trace",),
            PluginCapability.EVENT_REDUCTION: ("apply",),
            PluginCapability.EVENT_REVERSION: ("revert",),
            PluginCapability.CORRELATION: ("correlate",),
            PluginCapability.CONSISTENCY_CHECK: ("check_consistency",),
            PluginCapability.TOPOLOGY_PROJECTION: ("project_topology",),
            PluginCapability.FORWARDING_PROJECTION: ("project_forwarding",),
        }
    )
)

INPUT_PARSER_HOOKS: Mapping[InputParserKind, str] = MappingProxyType(
    {
        InputParserKind.STATUS: "parse_status",
        InputParserKind.CTF: "parse_ctf",
        InputParserKind.TEXT_TRACE: "parse_text_trace",
    }
)

INPUT_PARSER_CAPABILITIES: Mapping[InputParserKind, PluginCapability] = (
    MappingProxyType(
        {
            InputParserKind.STATUS: PluginCapability.STATUS_PARSE,
            InputParserKind.CTF: PluginCapability.CTF_PARSE,
            InputParserKind.TEXT_TRACE: PluginCapability.TEXT_TRACE_PARSE,
        }
    )
)


class ConditionClass(StrEnum):
    """Plug-in-normalized presentation class; never inferred from status text."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    ABSENT = "absent"
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


class PathGroupMode(StrEnum):
    """Plug-in-declared forwarding semantics for one candidate group."""

    SINGLE_ACTIVE = "single_active"
    ALL_ACTIVE = "all_active"
    UNSPECIFIED = "unspecified"


class ForwardingMemberActivity(StrEnum):
    """Whether one member currently participates in packet forwarding."""

    ACTIVE = "active"
    STANDBY = "standby"
    INACTIVE = "inactive"
    UNUSABLE = "unusable"
    UNKNOWN = "unknown"


class ForwardingMemberSelection(StrEnum):
    """The plug-in's explicit selection decision for one group member."""

    SELECTED = "selected"
    NOT_SELECTED = "not_selected"
    UNKNOWN = "unknown"


class ForwardingConstraintKind(StrEnum):
    """Core-evaluable behavior of one plug-in-declared candidate constraint.

    The core understands only the comparison operation.  The protocol or
    platform meaning of the compared scope remains owned by the plug-in.
    """

    EXCLUDE_EXACT_SCOPE = "exclude_exact_scope"


class ForwardingPolicyVerdict(StrEnum):
    """Result of evaluating one candidate constraint for one traffic class."""

    PERMITTED = "permitted"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ConnectorMatchPolicyKind(StrEnum):
    """Who is permitted to interpret a connector claim's typed arguments."""

    EXACT_TOKEN = "exact_token"
    LINKER = "linker"


class FederationMatchState(StrEnum):
    """Resolution state for one bounded cross-node connector match."""

    MATCHED = "matched"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    CONFLICT = "conflict"


class RoutePresentationRole(StrEnum):
    """How a declarative presentation relates to the resolved forwarding path."""

    PRINCIPAL = "principal"
    OVERLAY = "overlay"
    ANNOTATION = "annotation"


class RoutePresentationScope(StrEnum):
    """The portion of a resolved path to which a presentation applies."""

    PATH = "path"
    STEP = "step"
    SPAN = "span"
    RESOURCE = "resource"


class RoutePresentationStyle(StrEnum):
    """Safe render primitives that the core maps through its own theme."""

    PATH = "path"
    BAND = "band"
    BADGE = "badge"
    CALLOUT = "callout"


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
    ABSOLUTE_TIME = "absolute_time"
    RELATIVE_CAPTURE_VECTOR = "relative_capture_vector"


class TemporalSelectorKind(StrEnum):
    ABSOLUTE_TIME = "absolute_time"
    RELATIVE_TO_WATERMARK = "relative_to_watermark"


class ClockAlignmentPolicy(StrEnum):
    STRICT = "strict"
    BEST_EFFORT = "best_effort"


class StatusPerspectiveRole(StrEnum):
    """Plugin-owned intent of a status view; never an implicit truth ranking."""

    INTENDED = "intended"
    PROGRAMMED = "programmed"
    OBSERVED = "observed"
    OTHER = "other"


class TopologyUsability(StrEnum):
    USABLE = "usable"
    UNUSABLE = "unusable"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class TopologyTwoParticipantShape(StrEnum):
    """Safe plug-in preference for presenting a two-participant domain.

    This is presentation metadata only.  It never changes the domain resource,
    its attachment links, or their temporal identity.  The core still validates
    complete, conflict-free membership before honoring ``COMPACT_EDGE``.
    """

    DOMAIN_NODE = "domain_node"
    COMPACT_EDGE = "compact_edge"


class StatusSourceCombinationPolicy(StrEnum):
    """Plugin-declared operator for combining topology status sources."""

    ALL_REQUIRED_USABLE = "all_required_usable"
    ANY_DECLARED_USABLE = "any_declared_usable"


@dataclass(frozen=True, slots=True)
class WatermarkScope:
    """Exact status stream whose latest complete point anchors a relative query."""

    node_id: str
    status_perspective_id: str
    topology_projection_id: str | None = None

    def __post_init__(self) -> None:
        if not self.node_id or len(self.node_id) > 256:
            raise ValueError("watermark node_id must contain 1 to 256 characters")
        if not self.status_perspective_id or len(self.status_perspective_id) > 128:
            raise ValueError(
                "watermark status_perspective_id must contain 1 to 128 characters"
            )
        if self.topology_projection_id is not None and (
            not self.topology_projection_id
            or len(self.topology_projection_id) > 128
        ):
            raise ValueError(
                "watermark topology_projection_id must contain 1 to 128 characters"
            )


@dataclass(frozen=True, slots=True)
class AbsoluteTimeSelector:
    """Request one absolute instant and map it into every selected node clock."""

    time_ns: int
    clock_domain: str
    clock_policy: ClockAlignmentPolicy = ClockAlignmentPolicy.STRICT
    kind: TemporalSelectorKind = field(
        default=TemporalSelectorKind.ABSOLUTE_TIME,
        init=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.time_ns, int) or isinstance(self.time_ns, bool):
            raise ValueError("absolute time_ns must be an integer, not a boolean")
        if not self.clock_domain or len(self.clock_domain) > 256:
            raise ValueError("absolute clock_domain must contain 1 to 256 characters")
        try:
            ClockAlignmentPolicy(self.clock_policy)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported absolute clock alignment policy") from error


@dataclass(frozen=True, slots=True)
class RelativeToWatermarkSelector:
    """Request a historical offset from one scoped complete watermark."""

    offset_ns: int
    scope: WatermarkScope
    clock_policy: ClockAlignmentPolicy = ClockAlignmentPolicy.STRICT
    kind: TemporalSelectorKind = field(
        default=TemporalSelectorKind.RELATIVE_TO_WATERMARK,
        init=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.offset_ns, int) or isinstance(self.offset_ns, bool):
            raise ValueError("relative offset_ns must be an integer, not a boolean")
        if self.offset_ns > 0:
            raise ValueError("relative offset_ns must be zero or negative")
        try:
            ClockAlignmentPolicy(self.clock_policy)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported relative clock alignment policy") from error


type TemporalSelector = AbsoluteTimeSelector | RelativeToWatermarkSelector


@dataclass(frozen=True, slots=True)
class PluginManifest:
    plugin_id: str
    plugin_version: str
    core_api_version: str
    supported_platforms: tuple[str, ...]
    supported_software_versions: str
    capabilities: frozenset[PluginCapability | str]
    reconstruction_default: ReconstructionSupport
    forwarding_ir_versions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        normalized: set[PluginCapability | str] = set()
        for capability in self.capabilities:
            if not isinstance(capability, str):
                raise ValueError(
                    "plugin capabilities must be strings or PluginCapability values"
                )
            try:
                normalized.add(PluginCapability(capability))
            except ValueError:
                if (
                    not capability
                    or len(capability) > 128
                    or _OPAQUE_ID_PATTERN.fullmatch(capability) is None
                ):
                    raise ValueError(
                        "custom plugin capabilities must be non-empty opaque identifiers"
                    ) from None
                normalized.add(capability)
        object.__setattr__(self, "capabilities", frozenset(normalized))

    def supports(self, capability: PluginCapability | str) -> bool:
        """Return whether the manifest advertises one standard or custom capability."""

        candidate = (
            capability.value
            if isinstance(capability, PluginCapability)
            else capability
        )
        return any(
            (item.value if isinstance(item, PluginCapability) else item) == candidate
            for item in self.capabilities
        )


@dataclass(frozen=True, slots=True)
class PropertyDescriptor:
    name: str
    label: str
    value_type: str
    searchable: bool = False
    indexed: bool = False
    sensitive: bool = False

    def __post_init__(self) -> None:
        _validate_dashboard_field(self.name, "property name")
        if not self.label or len(self.label) > 120:
            raise ValueError("property label must contain 1 to 120 characters")
        _validate_opaque_id(self.value_type, "property value_type")
        for field_name, value in (
            ("searchable", self.searchable),
            ("indexed", self.indexed),
            ("sensitive", self.sensitive),
        ):
            if not isinstance(value, bool):
                raise ValueError(f"property {field_name} must be a boolean")


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
_OPAQUE_ID_PATTERN = re.compile(r"^[^\s\x00-\x1f\x7f]+$")


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


def _validate_opaque_id(value: str, label: str) -> None:
    """Validate only transport safety and bounds; callers must not parse the ID."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or _OPAQUE_ID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(
            f"{label} must be a non-empty opaque identifier without whitespace or control characters"
        )


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

    def __post_init__(self) -> None:
        _validate_opaque_id(self.kind, "resource kind")
        if not self.label or len(self.label) > 120:
            raise ValueError("resource kind label must contain 1 to 120 characters")
        if len(self.key_fields) != len(set(self.key_fields)):
            raise ValueError("resource kind key fields must be unique")
        for field_name in self.key_fields:
            _validate_dashboard_field(field_name, "resource kind key field")
        if any(
            not isinstance(descriptor, PropertyDescriptor)
            for descriptor in self.properties
        ):
            raise ValueError(
                "resource kind properties must contain PropertyDescriptor values"
            )
        property_names = [descriptor.name for descriptor in self.properties]
        if len(property_names) != len(set(property_names)):
            raise ValueError("resource kind property names must be unique")
        for label, fields in (
            ("default timeline", self.default_timeline_fields),
            ("display name", self.display_name_fields),
            ("default table", self.default_table_fields),
        ):
            if len(fields) != len(set(fields)):
                raise ValueError(f"resource kind {label} fields must be unique")
            for field_name in fields:
                _validate_dashboard_field(
                    field_name,
                    f"resource kind {label} field",
                )
        if self.condition_field is not None:
            _validate_dashboard_field(
                self.condition_field,
                "resource kind condition field",
            )
        if len(self.presentation_tags) != len(set(self.presentation_tags)):
            raise ValueError("resource kind presentation tags must be unique")
        for tag in self.presentation_tags:
            _validate_opaque_id(tag, "resource kind presentation tag")
        if self.icon is not None and not isinstance(
            self.icon,
            ResourceIconDescriptor,
        ):
            raise ValueError(
                "resource kind icon must be a ResourceIconDescriptor or None"
            )


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
class ResourceTableRelationLevelDescriptor:
    """One bounded relationship hop in a plug-in-declared resource table tree."""

    label: str
    relation_types: tuple[str, ...]
    target_kinds: tuple[str, ...] = ()
    direction: RelationDirection = RelationDirection.OUTGOING

    def __post_init__(self) -> None:
        if not self.label or len(self.label) > 120:
            raise ValueError("resource table relation label must contain 1 to 120 characters")
        if not self.relation_types:
            raise ValueError("resource table relation levels require at least one relationship type")
        if len(self.relation_types) != len(set(self.relation_types)):
            raise ValueError("resource table relation types must be unique within a level")
        for relation_type in self.relation_types:
            _validate_dashboard_id(relation_type, "resource table relationship type")
        if len(self.target_kinds) != len(set(self.target_kinds)):
            raise ValueError("resource table target kinds must be unique within a level")
        try:
            RelationDirection(self.direction)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported resource table relationship direction") from error


@dataclass(frozen=True, slots=True)
class ResourceTableViewDescriptor:
    """Generic point-in-time resource tree whose semantics remain plug-in-owned."""

    view_id: str
    label: str
    description: str
    root_kinds: tuple[str, ...]
    levels: tuple[ResourceTableRelationLevelDescriptor, ...]
    columns: tuple[DashboardColumnDescriptor, ...] = ()
    default_selected: bool = False
    include_absent: bool = False
    default_expanded_depth: int = 1
    max_roots: int = 100
    max_children_per_node: int = 16
    max_nodes: int = 5_000

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.view_id, "resource table view_id")
        if not self.label or len(self.label) > 120:
            raise ValueError("resource table view label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("resource table view description must be at most 500 characters")
        if not self.root_kinds:
            raise ValueError("resource table views require at least one root kind")
        if len(self.root_kinds) != len(set(self.root_kinds)):
            raise ValueError("resource table root kinds must be unique")
        if not 1 <= len(self.levels) <= 3:
            raise ValueError("resource table views require between one and three relationship levels")
        if not 0 <= self.default_expanded_depth <= len(self.levels):
            raise ValueError("resource table default_expanded_depth exceeds the relationship depth")
        if not 1 <= self.max_roots <= 500:
            raise ValueError("resource table max_roots must be between 1 and 500")
        if not 1 <= self.max_children_per_node <= 100:
            raise ValueError("resource table max_children_per_node must be between 1 and 100")
        if (
            not isinstance(self.max_nodes, int)
            or isinstance(self.max_nodes, bool)
            or not 1 <= self.max_nodes <= 5_000
        ):
            raise ValueError("resource table max_nodes must be between 1 and 5000")
        column_fields = [column.field for column in self.columns]
        if len(column_fields) != len(set(column_fields)):
            raise ValueError("resource table view columns must be unique")


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

    def __post_init__(self) -> None:
        _validate_opaque_id(self.relation_type, "relationship type")
        if not self.label or len(self.label) > 120:
            raise ValueError("relationship label must contain 1 to 120 characters")
        if not isinstance(self.directed, bool):
            raise ValueError("relationship directed must be a boolean")
        if not isinstance(self.structural, bool):
            raise ValueError("relationship structural must be a boolean")


@dataclass(frozen=True, slots=True)
class CausalLinkTypeDescriptor:
    """A plug-in-owned event-correlation type rendered generically by the core."""

    link_type: str
    label: str
    directed: bool = True

    def __post_init__(self) -> None:
        _validate_opaque_id(self.link_type, "causal link type")
        if not self.label or len(self.label) > 120:
            raise ValueError("causal link label must contain 1 to 120 characters")
        if not isinstance(self.directed, bool):
            raise ValueError("causal link directed must be a boolean")


@dataclass(frozen=True, slots=True)
class SourceRecordGroupDescriptor:
    """Plug-in-owned grouping for retained source-record stream controls.

    Group identifiers are opaque to the core.  The core validates references
    from source-record types and renders the supplied label and description.
    A source type that declares no group remains valid; presentation surfaces
    may expose it through an implicit group scoped to that source type.
    """

    group_id: str
    label: str
    description: str = ""
    default_included: bool = False

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.group_id, "source record group_id")
        if not self.label or len(self.label) > 120:
            raise ValueError("source record group label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("source record group description must be at most 500 characters")
        if not isinstance(self.default_included, bool):
            raise ValueError("source record group default_included must be a boolean")


@dataclass(frozen=True, slots=True)
class SourceRecordTypeDescriptor:
    """Plug-in presentation for one core-retained timestamped input stream.

    ``stream_group`` is optional plug-in-owned presentation vocabulary.  When
    present it references ``PluginSchema.source_record_groups``.  The core
    validates and transports it without assigning domain meaning to the group
    identifier.
    """

    source_type: str
    label: str
    description: str = ""
    color: str = "#66b8ff"
    stream_group: str | None = None

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.source_type, "source_type")
        if not self.label or len(self.label) > 120:
            raise ValueError("source record label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("source record description must be at most 500 characters")
        if _COLOR_PATTERN.fullmatch(self.color) is None:
            raise ValueError("source record color must be a six-digit CSS hex color")
        if self.stream_group is not None:
            _validate_dashboard_id(
                self.stream_group,
                "source record stream_group",
            )


@dataclass(frozen=True, slots=True)
class StatusPerspectiveDescriptor:
    """One independently reconstructed layer-local status interpretation."""

    perspective_id: str
    label: str
    layer_id: str
    role: StatusPerspectiveRole
    description: str = ""

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.perspective_id, "status perspective_id")
        _validate_dashboard_id(self.layer_id, "status layer_id")
        if not self.label or len(self.label) > 120:
            raise ValueError("status perspective label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("status perspective description must be at most 500 characters")
        try:
            StatusPerspectiveRole(self.role)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported status perspective role") from error


_SCHEMA_DIGEST_PATTERN = re.compile(
    r"^(?:[a-z][a-z0-9._-]{0,31}:)?[0-9a-f]{16,128}$"
)


@dataclass(frozen=True, slots=True)
class StatusPerspectiveRef:
    """A local perspective optionally qualified by core-owned identities.

    A plug-in may emit only ``perspective_id``.  Once the core knows the
    selected installation and immutable schema, it can attach
    ``plugin_instance_id`` and ``schema_digest`` so equal local IDs from
    different plug-ins or schema revisions cannot be conflated.
    """

    perspective_id: str
    plugin_instance_id: str | None = None
    schema_digest: str | None = None

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.perspective_id, "status perspective reference ID")
        if self.plugin_instance_id is not None:
            _validate_opaque_id(
                self.plugin_instance_id,
                "status perspective plugin_instance_id",
            )
        if self.schema_digest is not None and (
            not isinstance(self.schema_digest, str)
            or _SCHEMA_DIGEST_PATTERN.fullmatch(self.schema_digest) is None
        ):
            raise ValueError(
                "status perspective schema_digest must be lowercase hexadecimal "
                "with an optional lowercase algorithm prefix"
            )


@dataclass(frozen=True, slots=True)
class ConnectorMatchPolicyDescriptor:
    """Declare whether connector arguments permit equality matching or need a linker.

    ``EXACT_TOKEN`` authorizes the core to compare the complete ordered argument
    tuple for equality.  Any normalization, aliasing, reciprocity rule, or other
    semantic interpretation requires ``LINKER`` and the named allowlisted linker
    plug-in.
    """

    policy_id: str
    claim_contract_id: str
    kind: ConnectorMatchPolicyKind
    argument_names: tuple[str, ...]
    linker_plugin_id: str | None = None

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.policy_id, "connector match policy_id")
        _validate_dashboard_id(
            self.claim_contract_id,
            "connector claim_contract_id",
        )
        try:
            kind = ConnectorMatchPolicyKind(self.kind)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported connector match policy kind") from error
        if not isinstance(self.argument_names, tuple):
            raise ValueError("connector match argument_names must be a tuple")
        if not 1 <= len(self.argument_names) <= 32:
            raise ValueError(
                "connector match policies require 1 to 32 argument names"
            )
        if len(self.argument_names) != len(set(self.argument_names)):
            raise ValueError("connector match argument names must be unique")
        for name in self.argument_names:
            _validate_dashboard_field(name, "connector match argument name")
        if kind is ConnectorMatchPolicyKind.EXACT_TOKEN:
            if self.linker_plugin_id is not None:
                raise ValueError(
                    "exact-token connector match policies must not name a linker"
                )
        elif self.linker_plugin_id is None:
            raise ValueError("linker connector match policies require a linker_plugin_id")
        if self.linker_plugin_id is not None:
            _validate_dashboard_id(
                self.linker_plugin_id,
                "connector match linker_plugin_id",
            )


@dataclass(frozen=True, slots=True)
class TopologyProjectionDescriptor:
    """Plugin-owned topology semantics with explicitly selectable status views."""

    projection_id: str
    label: str
    supported_status_perspective_ids: tuple[str, ...]
    description: str = ""
    default_status_perspective_id: str | None = None
    status_source_combination_policy: StatusSourceCombinationPolicy = (
        StatusSourceCombinationPolicy.ALL_REQUIRED_USABLE
    )

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.projection_id, "topology projection_id")
        if not self.label or len(self.label) > 120:
            raise ValueError("topology projection label must contain 1 to 120 characters")
        if len(self.description) > 500:
            raise ValueError("topology projection description must be at most 500 characters")
        if not self.supported_status_perspective_ids:
            raise ValueError(
                "topology projections require at least one supported status perspective"
            )
        if len(self.supported_status_perspective_ids) != len(
            set(self.supported_status_perspective_ids)
        ):
            raise ValueError(
                "topology projection status perspective identifiers must be unique"
            )
        for perspective_id in self.supported_status_perspective_ids:
            _validate_dashboard_id(
                perspective_id,
                "topology status perspective identifier",
            )
        if (
            self.default_status_perspective_id is not None
            and self.default_status_perspective_id
            not in self.supported_status_perspective_ids
        ):
            raise ValueError(
                "topology default status perspective must be one of the supported perspectives"
            )
        try:
            StatusSourceCombinationPolicy(self.status_source_combination_policy)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported topology status source combination policy") from error


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
    resource_table_views: tuple[ResourceTableViewDescriptor, ...] = ()
    source_record_groups: tuple[SourceRecordGroupDescriptor, ...] = ()
    source_record_types: tuple[SourceRecordTypeDescriptor, ...] = ()
    record_lane_presets: tuple[RecordLanePreset, ...] = ()
    status_perspectives: tuple[StatusPerspectiveDescriptor, ...] = ()
    topology_projections: tuple[TopologyProjectionDescriptor, ...] = ()

    def __post_init__(self) -> None:
        resource_kind_ids = [
            descriptor.kind for descriptor in self.resource_kinds
        ]
        if len(resource_kind_ids) != len(set(resource_kind_ids)):
            raise ValueError("plugin resource kind identifiers must be unique")
        relationship_type_ids = [
            descriptor.relation_type for descriptor in self.relationship_types
        ]
        if len(relationship_type_ids) != len(set(relationship_type_ids)):
            raise ValueError(
                "plugin relationship type identifiers must be unique"
            )
        causal_link_type_ids = [
            descriptor.link_type for descriptor in self.causal_link_types
        ]
        if len(causal_link_type_ids) != len(set(causal_link_type_ids)):
            raise ValueError(
                "plugin causal link type identifiers must be unique"
            )
        dashboard_ids = [dashboard.dashboard_id for dashboard in self.dashboards]
        if len(dashboard_ids) != len(set(dashboard_ids)):
            raise ValueError("plugin dashboard identifiers must be unique")
        resource_kinds = set(resource_kind_ids)
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
        view_ids = [view.view_id for view in self.resource_table_views]
        if len(view_ids) != len(set(view_ids)):
            raise ValueError("plugin resource table view identifiers must be unique")
        if sum(view.default_selected for view in self.resource_table_views) > 1:
            raise ValueError("only one plugin resource table view may be selected by default")
        view_resource_kinds = {
            kind
            for view in self.resource_table_views
            for kind in (
                *view.root_kinds,
                *(kind for level in view.levels for kind in level.target_kinds),
            )
        }
        if unknown := view_resource_kinds - resource_kinds:
            raise ValueError(
                "plugin resource table views reference unknown resource kinds: "
                + ", ".join(sorted(unknown))
            )
        relationship_types = set(relationship_type_ids)
        view_relationship_types = {
            relation_type
            for view in self.resource_table_views
            for level in view.levels
            for relation_type in level.relation_types
        }
        if unknown := view_relationship_types - relationship_types:
            raise ValueError(
                "plugin resource table views reference unknown relationship types: "
                + ", ".join(sorted(unknown))
            )
        source_types = [descriptor.source_type for descriptor in self.source_record_types]
        if len(source_types) != len(set(source_types)):
            raise ValueError("plugin source record types must be unique")
        source_group_ids = [
            descriptor.group_id for descriptor in self.source_record_groups
        ]
        if len(source_group_ids) != len(set(source_group_ids)):
            raise ValueError("plugin source record groups must be unique")
        referenced_source_groups = {
            descriptor.stream_group
            for descriptor in self.source_record_types
            if descriptor.stream_group is not None
        }
        if unknown := referenced_source_groups - set(source_group_ids):
            raise ValueError(
                "plugin source record types reference unknown source groups: "
                + ", ".join(sorted(unknown))
            )
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
        perspective_ids = [
            descriptor.perspective_id for descriptor in self.status_perspectives
        ]
        if len(perspective_ids) != len(set(perspective_ids)):
            raise ValueError("plugin status perspective identifiers must be unique")
        projection_ids = [
            descriptor.projection_id for descriptor in self.topology_projections
        ]
        if len(projection_ids) != len(set(projection_ids)):
            raise ValueError("plugin topology projection identifiers must be unique")
        referenced_perspectives = {
            perspective_id
            for descriptor in self.topology_projections
            for perspective_id in descriptor.supported_status_perspective_ids
        }
        if unknown := referenced_perspectives - set(perspective_ids):
            raise ValueError(
                "plugin topology projections reference unknown status perspectives: "
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
    match_kind: ProbeMatchKind = ProbeMatchKind.COMPATIBLE

    def __post_init__(self) -> None:
        try:
            ProbeMatchKind(self.match_kind)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported probe match kind") from error


@dataclass(frozen=True, slots=True)
class ProbeReport:
    result: ProbeResult | None
    diagnostics: tuple[PluginDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class InputSpec:
    """One logical parser input, possibly assembled from multiple artifacts.

    ``parser_kind`` tells the core which safe parser hook to call. ``parser_id``
    and ``role`` remain opaque plug-in vocabulary. ``None`` is retained only so
    existing plug-ins can be loaded by a compatibility adapter; new plug-ins
    should always provide an explicit parser kind.
    """

    artifact_ids: tuple[UUID, ...]
    role: str
    node: str
    layer: str
    parser_id: str
    logical_root: PurePosixPath | None = None
    options: Properties = field(default_factory=dict)
    parser_kind: InputParserKind | None = None

    def __post_init__(self) -> None:
        if self.parser_kind is not None:
            try:
                object.__setattr__(
                    self,
                    "parser_kind",
                    InputParserKind(self.parser_kind),
                )
            except (TypeError, ValueError) as error:
                raise ValueError("unsupported input parser kind") from error

    @property
    def dispatch_hook(self) -> str | None:
        """The protocol hook selected by ``parser_kind``, or ``None`` for legacy input."""

        if self.parser_kind is None:
            return None
        return INPUT_PARSER_HOOKS[self.parser_kind]

    @property
    def required_capability(self) -> PluginCapability | None:
        """Capability that authorizes this input's parser dispatch."""

        if self.parser_kind is None:
            return None
        return INPUT_PARSER_CAPABILITIES[self.parser_kind]


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
class SourceRecordEmission:
    """A decoded generic input record emitted before core identity assignment.

    Parser hooks yield this value for both matched and unmatched input.  The
    core validates it, assigns ``SourceRecord.source_record_uid``, persists the
    resulting ``SourceRecord``, and indexes any ``matched_event_uid`` link.
    """

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
    condition: Value = None
    condition_class: ConditionClass = ConditionClass.UNKNOWN
    perspective_ref: StatusPerspectiveRef | None = None


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
    perspective_ref: StatusPerspectiveRef | None = None


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
    perspective_ref: StatusPerspectiveRef | None = None


@dataclass(frozen=True, slots=True)
class SourceRecordRef:
    """Core-assigned source identity retained through domain mapping."""

    source_id: str
    message_ordinal: int
    trace_uid: str | None = None
    stream_uid: str | None = None
    packet_sequence: int | None = None


def derive_event_uid(
    plugin_id: str,
    parser_id: str,
    source: SourceRecordRef,
    local_discriminator: KeyScalar | None = None,
) -> bytes:
    """Derive one stable 32-byte event ID from canonical source identity.

    ``local_discriminator`` distinguishes several domain events emitted from
    one source record. Its type is encoded, so integer ``1``, string ``"1"``,
    and byte ``b"1"`` never alias. Plug-in versions are deliberately excluded:
    a compatible parser upgrade preserves event identity when the source
    mapping itself has not changed.
    """

    for label, value in (
        ("plugin_id", plugin_id),
        ("parser_id", parser_id),
        ("source.source_id", source.source_id),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty string")
    for label, value in (
        ("source.message_ordinal", source.message_ordinal),
        ("source.packet_sequence", source.packet_sequence),
    ):
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool)
        ):
            raise ValueError(f"{label} must be an integer or None")
    for label, value in (
        ("source.trace_uid", source.trace_uid),
        ("source.stream_uid", source.stream_uid),
    ):
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{label} must be a string or None")
    if isinstance(local_discriminator, bool) or (
        local_discriminator is not None
        and not isinstance(local_discriminator, (int, str, bytes, UUID))
    ):
        raise ValueError(
            "local_discriminator must be int, string, bytes, UUID, or None"
        )

    def encode(value: KeyScalar | None) -> bytes:
        if value is None:
            return b"n"
        if isinstance(value, int):
            return b"i" + str(value).encode("ascii")
        if isinstance(value, str):
            return b"s" + value.encode("utf-8")
        if isinstance(value, bytes):
            return b"b" + value
        return b"u" + value.bytes

    digest = sha256()
    digest.update(b"router-dump-analyzer:event-uid:v1")
    for component in (
        plugin_id,
        parser_id,
        source.source_id,
        source.message_ordinal,
        source.trace_uid,
        source.stream_uid,
        source.packet_sequence,
        local_discriminator,
    ):
        encoded = encode(component)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.digest()


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
    condition: Value = None
    condition_class: ConditionClass = ConditionClass.UNKNOWN
    perspective_ref: StatusPerspectiveRef | None = None


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
    perspective_ref: StatusPerspectiveRef | None = None


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
    clock_domain: str | None = None


@dataclass(frozen=True, slots=True)
class ReconstructionWatermark:
    """Latest complete reconstructed status for one exact query scope."""

    scope: WatermarkScope
    local_time_ns: int
    clock_domain: str
    provenance: Provenance
    quality: Quality
    absolute_min_ns: int | None = None
    absolute_max_ns: int | None = None
    mapping_method: str | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.local_time_ns, int) or isinstance(
            self.local_time_ns, bool
        ):
            raise ValueError("watermark local_time_ns must be an integer, not a boolean")
        if not self.clock_domain or len(self.clock_domain) > 256:
            raise ValueError("watermark clock_domain must contain 1 to 256 characters")
        if (self.absolute_min_ns is None) != (self.absolute_max_ns is None):
            raise ValueError("watermark absolute bounds must both be present or both be absent")
        if any(
            value is not None
            and (not isinstance(value, int) or isinstance(value, bool))
            for value in (self.absolute_min_ns, self.absolute_max_ns)
        ):
            raise ValueError("watermark absolute bounds must be integers")
        if (
            self.absolute_min_ns is not None
            and self.absolute_max_ns is not None
            and self.absolute_min_ns > self.absolute_max_ns
        ):
            raise ValueError("watermark absolute bounds are reversed")
        if self.mapping_method is not None and (
            not self.mapping_method or len(self.mapping_method) > 256
        ):
            raise ValueError("watermark mapping_method must contain 1 to 256 characters")


@dataclass(frozen=True, slots=True)
class ResolvedNodeBasis:
    """Per-node temporal resolution; absent ranges carry an explicit reason code."""

    node_id: str
    local_clock_domain: str | None
    local_min_ns: int | None
    local_max_ns: int | None
    absolute_min_ns: int | None
    absolute_max_ns: int | None
    mapping_method: str | None
    quality: Quality
    reason_code: str | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.node_id or len(self.node_id) > 256:
            raise ValueError("resolved node_id must contain 1 to 256 characters")
        for label, minimum, maximum in (
            ("local", self.local_min_ns, self.local_max_ns),
            ("absolute", self.absolute_min_ns, self.absolute_max_ns),
        ):
            if (minimum is None) != (maximum is None):
                raise ValueError(
                    f"resolved node {label} bounds must both be present or both be absent"
                )
            if any(
                value is not None
                and (not isinstance(value, int) or isinstance(value, bool))
                for value in (minimum, maximum)
            ):
                raise ValueError(f"resolved node {label} bounds must be integers")
            if minimum is not None and maximum is not None and minimum > maximum:
                raise ValueError(f"resolved node {label} bounds are reversed")
        if self.local_min_ns is not None and not self.local_clock_domain:
            raise ValueError("resolved local bounds require a local clock domain")
        if self.local_clock_domain is not None and (
            not self.local_clock_domain or len(self.local_clock_domain) > 256
        ):
            raise ValueError(
                "resolved local_clock_domain must contain 1 to 256 characters"
            )
        if self.mapping_method is not None and (
            not self.mapping_method or len(self.mapping_method) > 256
        ):
            raise ValueError(
                "resolved mapping_method must contain 1 to 256 characters"
            )
        if self.reason_code is not None and (
            not self.reason_code or len(self.reason_code) > 128
        ):
            raise ValueError("resolved reason_code must contain 1 to 128 characters")
        if (
            self.local_min_ns is None
            and self.absolute_min_ns is None
            and self.reason_code is None
        ):
            raise ValueError("an unresolved node basis requires a reason_code")


@dataclass(frozen=True, slots=True)
class WorldBasis:
    kind: WorldBasisKind
    requested_time_ns: int | None
    resolved_at_min_ns: int | None
    resolved_at_max_ns: int | None
    capture_ranges: tuple[CaptureRange, ...]
    provenance: Provenance
    quality: Quality
    clock_domain: str | None = None
    selector: TemporalSelector | None = None
    node_resolutions: tuple[ResolvedNodeBasis, ...] = ()
    watermark: ReconstructionWatermark | None = None
    unresolved_reason: str | None = None


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
    perspective_ref: StatusPerspectiveRef | None = None


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
    perspective_ref: StatusPerspectiveRef | None = None


@dataclass(frozen=True, slots=True)
class TopologyProjectionRequest:
    """One coordinator-bounded projection over an already resolved world."""

    projection_id: str
    status_perspective_id: str
    max_records: int = 10_000
    max_world_reads: int = 50_000
    seed_resources: tuple[ResourceKey, ...] = ()

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.projection_id, "topology projection request ID")
        _validate_dashboard_id(
            self.status_perspective_id,
            "topology status perspective request ID",
        )
        if (
            not isinstance(self.max_records, int)
            or isinstance(self.max_records, bool)
            or not 1 <= self.max_records <= 100_000
        ):
            raise ValueError("topology max_records must be between 1 and 100000")
        if (
            not isinstance(self.max_world_reads, int)
            or isinstance(self.max_world_reads, bool)
            or not 1 <= self.max_world_reads <= 1_000_000
        ):
            raise ValueError(
                "topology max_world_reads must be between 1 and 1000000"
            )
        if len(self.seed_resources) != len(set(self.seed_resources)):
            raise ValueError("topology seed resources must be unique")


@dataclass(frozen=True, slots=True)
class TopologyMatchReference:
    """Declarative plugin matcher; the core stores it but never executes semantics."""

    matcher_id: str
    arguments: Properties
    resolved_candidates: tuple[ResourceKey, ...] = ()

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.matcher_id, "topology matcher_id")
        if len(self.resolved_candidates) != len(set(self.resolved_candidates)):
            raise ValueError("topology match candidates must be unique")


@dataclass(frozen=True, slots=True)
class TopologyEndpointReference:
    """Exactly one canonical resource or one declarative match reference."""

    resource: ResourceKey | None = None
    match: TopologyMatchReference | None = None

    def __post_init__(self) -> None:
        if (self.resource is None) == (self.match is None):
            raise ValueError(
                "topology endpoint reference requires exactly one resource or match"
            )
        if self.resource is not None and not isinstance(self.resource, ResourceKey):
            raise ValueError("topology endpoint resource must be a ResourceKey")
        if self.match is not None and not isinstance(self.match, TopologyMatchReference):
            raise ValueError("topology endpoint match must be a TopologyMatchReference")


@dataclass(frozen=True, slots=True)
class TopologyResourcePresentation:
    """Bounded display hints for a plug-in-owned topology resource."""

    two_participant_shape: TopologyTwoParticipantShape = (
        TopologyTwoParticipantShape.DOMAIN_NODE
    )

    def __post_init__(self) -> None:
        try:
            TopologyTwoParticipantShape(self.two_participant_shape)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported topology two-participant shape") from error


@dataclass(frozen=True, slots=True)
class TopologyResourceRecord:
    """One graph vertex; plug-ins may use a role such as connectivity-domain.

    Shared media do not require a special core hyperedge.  A plug-in can emit a
    resource vertex for the domain and ordinary links from every attachment to
    that vertex, while keeping prefix, VLAN, VRF, and role semantics in the
    surrounding :class:`TopologyProjectionRecord` properties.
    """

    resource: ResourceKey
    role: str | None = None
    presentation: TopologyResourcePresentation = field(
        default_factory=TopologyResourcePresentation
    )

    def __post_init__(self) -> None:
        if self.role is not None and (not self.role or len(self.role) > 128):
            raise ValueError("topology resource role must contain 1 to 128 characters")
        if not isinstance(self.presentation, TopologyResourcePresentation):
            raise ValueError(
                "topology resource presentation must be TopologyResourcePresentation"
            )


@dataclass(frozen=True, slots=True)
class TopologyEndpointRecord:
    endpoint_id: str
    target: TopologyEndpointReference
    role: str | None = None

    def __post_init__(self) -> None:
        if not self.endpoint_id or len(self.endpoint_id) > 256:
            raise ValueError("topology endpoint_id must contain 1 to 256 characters")
        if self.role is not None and (not self.role or len(self.role) > 128):
            raise ValueError("topology endpoint role must contain 1 to 128 characters")


@dataclass(frozen=True, slots=True)
class TopologyLinkRecord:
    """One generic graph edge, including an endpoint-to-domain attachment."""

    link_id: str
    source: TopologyEndpointReference
    target: TopologyEndpointReference
    directed: bool = False

    def __post_init__(self) -> None:
        if not self.link_id or len(self.link_id) > 256:
            raise ValueError("topology link_id must contain 1 to 256 characters")
        if not isinstance(self.directed, bool):
            raise ValueError("topology link directed must be a boolean")


type TopologyProjectionPayload = (
    TopologyResourceRecord | TopologyEndpointRecord | TopologyLinkRecord
)


@dataclass(frozen=True, slots=True)
class TopologyProjectionRecord:
    """Generic validated envelope for one plugin-projected topology fact."""

    projection_id: str
    status_perspective_id: str
    payload: TopologyProjectionPayload
    usability: TopologyUsability
    source_resources: tuple[ResourceKey, ...]
    provenance: Provenance
    quality: Quality
    exists: bool | None = True
    properties: Properties = field(default_factory=dict)
    unknown_fields: tuple[UnknownField, ...] = ()
    valid_from_ns: int | None = None
    valid_to_ns: int | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.projection_id, "topology projection record ID")
        _validate_dashboard_id(
            self.status_perspective_id,
            "topology status perspective record ID",
        )
        try:
            TopologyUsability(self.usability)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported topology usability") from error
        if self.exists is not None and not isinstance(self.exists, bool):
            raise ValueError("topology projection existence must be boolean or unknown")
        if not isinstance(
            self.payload,
            (TopologyResourceRecord, TopologyEndpointRecord, TopologyLinkRecord),
        ):
            raise ValueError("unsupported topology projection payload")
        if len(self.source_resources) != len(set(self.source_resources)):
            raise ValueError("topology source resources must be unique")
        for value in (self.valid_from_ns, self.valid_to_ns):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise ValueError("topology validity bounds must be integers")
        if (
            self.valid_from_ns is not None
            and self.valid_to_ns is not None
            and self.valid_from_ns > self.valid_to_ns
        ):
            raise ValueError("topology validity bounds are reversed")


@dataclass(frozen=True, slots=True)
class GlobalResourceRef:
    """A canonical resource qualified by its immutable assembly member revision."""

    member_id: str
    revision_id: str
    plugin_instance_id: str
    resource: ResourceKey

    def __post_init__(self) -> None:
        _validate_opaque_id(self.member_id, "global resource member_id")
        _validate_opaque_id(self.revision_id, "global resource revision_id")
        _validate_opaque_id(
            self.plugin_instance_id,
            "global resource plugin_instance_id",
        )
        if not isinstance(self.resource, ResourceKey):
            raise ValueError("global resource reference must contain a ResourceKey")


def _connector_argument_units(value: KeyValue, depth: int = 0) -> int:
    """Validate one opaque typed claim argument and return its bounded size."""

    if depth > 4:
        raise ValueError("connector claim arguments support at most four tuple levels")
    if isinstance(value, bool):
        raise ValueError("Boolean connector claim arguments are forbidden")
    if isinstance(value, KeyAtom):
        payload = value.value
        if isinstance(payload, int) and payload.bit_length() > 4_096:
            raise ValueError("connector claim integer arguments exceed 4096 bits")
        return 1
    if isinstance(value, int):
        if value.bit_length() > 4_096:
            raise ValueError("connector claim integer arguments exceed 4096 bits")
        return 1
    if isinstance(value, (str, bytes)):
        if len(value) > _KEY_ATOM_MAX_PAYLOAD_LENGTH:
            raise ValueError("connector claim argument exceeds 4096 units")
        return 1
    if isinstance(value, UUID):
        return 1
    if isinstance(value, tuple):
        if len(value) > 32:
            raise ValueError(
                "connector claim argument tuples support at most 32 values"
            )
        return 1 + sum(
            _connector_argument_units(item, depth + 1) for item in value
        )
    raise ValueError(
        "connector claim arguments must use KeyValue scalars, KeyAtom, or tuples"
    )


@dataclass(frozen=True, slots=True)
class ConnectorClaim:
    """One node-local boundary claim with no remote candidate knowledge."""

    claim_id: str
    endpoint: ResourceKey
    claim_contract_id: str
    match_policy_id: str
    arguments: tuple[tuple[str, KeyValue], ...]
    provenance: Provenance
    quality: Quality
    status_perspective: StatusPerspectiveRef | None = None
    role: str | None = None
    valid_from_ns: int | None = None
    valid_to_ns: int | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_opaque_id(self.claim_id, "connector claim_id")
        if not isinstance(self.endpoint, ResourceKey):
            raise ValueError("connector claim endpoint must be a ResourceKey")
        _validate_dashboard_id(
            self.claim_contract_id,
            "connector claim_contract_id",
        )
        _validate_dashboard_id(self.match_policy_id, "connector match_policy_id")
        if not isinstance(self.arguments, tuple):
            raise ValueError("connector claim arguments must be a tuple")
        if not 1 <= len(self.arguments) <= 32:
            raise ValueError("connector claims require 1 to 32 typed arguments")
        names: list[str] = []
        total_units = 0
        for argument in self.arguments:
            if (
                not isinstance(argument, tuple)
                or len(argument) != 2
                or not isinstance(argument[0], str)
            ):
                raise ValueError(
                    "connector claim arguments must be (name, KeyValue) pairs"
                )
            name, value = argument
            _validate_dashboard_field(name, "connector claim argument name")
            names.append(name)
            total_units += _connector_argument_units(value)
        if len(names) != len(set(names)):
            raise ValueError("connector claim argument names must be unique")
        if total_units > 1_024:
            raise ValueError(
                "connector claims support at most 1024 typed argument units"
            )
        try:
            Provenance(self.provenance)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported connector claim provenance") from error
        try:
            Quality(self.quality)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported connector claim quality") from error
        if self.status_perspective is not None and not isinstance(
            self.status_perspective,
            StatusPerspectiveRef,
        ):
            raise ValueError(
                "connector claim status_perspective must be a StatusPerspectiveRef"
            )
        if self.role is not None:
            _validate_dashboard_id(self.role, "connector claim role")
        for label, value in (
            ("valid_from_ns", self.valid_from_ns),
            ("valid_to_ns", self.valid_to_ns),
        ):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise ValueError(f"connector claim {label} must be an integer")
        if (
            self.valid_from_ns is not None
            and self.valid_to_ns is not None
            and self.valid_from_ns > self.valid_to_ns
        ):
            raise ValueError("connector claim validity bounds are reversed")
        if not isinstance(self.evidence, tuple):
            raise ValueError("connector claim evidence must be a tuple")
        if len(self.evidence) > 64:
            raise ValueError("connector claims support at most 64 evidence items")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise ValueError("connector claim evidence must contain Evidence values")


@dataclass(frozen=True, slots=True)
class FederatedConnectorClaim:
    """A coordinator-qualified view of one otherwise node-local claim."""

    endpoint: GlobalResourceRef
    claim: ConnectorClaim

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, GlobalResourceRef):
            raise ValueError(
                "federated connector endpoint must be a GlobalResourceRef"
            )
        if not isinstance(self.claim, ConnectorClaim):
            raise ValueError("federated connector claim must be a ConnectorClaim")
        if self.endpoint.resource != self.claim.endpoint:
            raise ValueError(
                "federated connector endpoint does not match its local claim"
            )
        perspective = self.claim.status_perspective
        if (
            perspective is not None
            and perspective.plugin_instance_id is not None
            and perspective.plugin_instance_id != self.endpoint.plugin_instance_id
        ):
            raise ValueError(
                "federated connector plug-in scope conflicts with its status perspective"
            )


@dataclass(frozen=True, slots=True)
class FederationMatchCandidate:
    """One linker-proposed remote claim; it is never embedded in local state."""

    claim_id: str
    endpoint: GlobalResourceRef
    quality: Quality
    confidence: float | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_opaque_id(self.claim_id, "federation candidate claim_id")
        if not isinstance(self.endpoint, GlobalResourceRef):
            raise ValueError(
                "federation candidate endpoint must be a GlobalResourceRef"
            )
        try:
            Quality(self.quality)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported federation candidate quality") from error
        if self.confidence is not None and (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0 <= float(self.confidence) <= 1
        ):
            raise ValueError(
                "federation candidate confidence must be between zero and one"
            )
        if not isinstance(self.evidence, tuple):
            raise ValueError("federation candidate evidence must be a tuple")
        if len(self.evidence) > 64:
            raise ValueError(
                "federation candidates support at most 64 evidence items"
            )
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise ValueError(
                "federation candidate evidence must contain Evidence values"
            )


@dataclass(frozen=True, slots=True)
class FederationLinkResult:
    """One bounded linker decision for a globally scoped source claim."""

    result_id: str
    match_policy_id: str
    source: FederatedConnectorClaim
    state: FederationMatchState
    candidates: tuple[FederationMatchCandidate, ...]
    provenance: Provenance
    quality: Quality
    link_type: str | None = None
    directed: bool = False
    properties: Properties = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_opaque_id(self.result_id, "federation result_id")
        _validate_dashboard_id(
            self.match_policy_id,
            "federation result match_policy_id",
        )
        if not isinstance(self.source, FederatedConnectorClaim):
            raise ValueError(
                "federation result source must be a FederatedConnectorClaim"
            )
        try:
            state = FederationMatchState(self.state)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported federation match state") from error
        if not isinstance(self.candidates, tuple):
            raise ValueError("federation result candidates must be a tuple")
        if len(self.candidates) > 64:
            raise ValueError("federation results support at most 64 candidates")
        if any(
            not isinstance(candidate, FederationMatchCandidate)
            for candidate in self.candidates
        ):
            raise ValueError(
                "federation result candidates must be FederationMatchCandidate values"
            )
        candidate_ids = [
            (
                candidate.endpoint.member_id,
                candidate.endpoint.revision_id,
                candidate.endpoint.plugin_instance_id,
                candidate.claim_id,
                candidate.endpoint.resource,
            )
            for candidate in self.candidates
        ]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("federation result candidates must be unique")
        if any(
            candidate.endpoint.member_id == self.source.endpoint.member_id
            for candidate in self.candidates
        ):
            raise ValueError(
                "federation result candidates must belong to another member"
            )
        if state is FederationMatchState.MATCHED and len(self.candidates) != 1:
            raise ValueError("matched federation results require exactly one candidate")
        if state is FederationMatchState.AMBIGUOUS and len(self.candidates) < 2:
            raise ValueError(
                "ambiguous federation results require at least two candidates"
            )
        if state is FederationMatchState.CONFLICT and not self.candidates:
            raise ValueError(
                "conflicting federation results require at least one candidate"
            )
        try:
            Provenance(self.provenance)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported federation result provenance") from error
        try:
            Quality(self.quality)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported federation result quality") from error
        if self.link_type is not None:
            _validate_dashboard_id(self.link_type, "federation result link_type")
        if not isinstance(self.directed, bool):
            raise ValueError("federation result directed must be a boolean")
        if not isinstance(self.properties, Mapping):
            raise ValueError("federation result properties must be a mapping")
        if len(self.properties) > 64:
            raise ValueError("federation results support at most 64 properties")
        if not isinstance(self.evidence, tuple):
            raise ValueError("federation result evidence must be a tuple")
        if len(self.evidence) > 64:
            raise ValueError("federation results support at most 64 evidence items")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise ValueError(
                "federation result evidence must contain Evidence values"
            )


@dataclass(frozen=True, slots=True)
class FederationLinkRequest:
    """Bounded normalized claims passed to one allowlisted linker plug-in."""

    policy: ConnectorMatchPolicyDescriptor
    claims: tuple[FederatedConnectorClaim, ...]
    max_results: int = 10_000
    max_candidates_per_result: int = 64

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ConnectorMatchPolicyDescriptor):
            raise ValueError(
                "federation request policy must be a ConnectorMatchPolicyDescriptor"
            )
        if (
            ConnectorMatchPolicyKind(self.policy.kind)
            is not ConnectorMatchPolicyKind.LINKER
        ):
            raise ValueError(
                "exact-token policies are resolved by the core, not a linker plug-in"
            )
        if not isinstance(self.claims, tuple):
            raise ValueError("federation request claims must be a tuple")
        if len(self.claims) > 100_000:
            raise ValueError("federation requests support at most 100000 claims")
        if any(
            not isinstance(claim, FederatedConnectorClaim) for claim in self.claims
        ):
            raise ValueError(
                "federation request claims must be FederatedConnectorClaim values"
            )
        claim_ids = [
            (
                claim.endpoint.member_id,
                claim.endpoint.revision_id,
                claim.endpoint.plugin_instance_id,
                claim.claim.claim_id,
            )
            for claim in self.claims
        ]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("federation request claims must be unique")
        for claim in self.claims:
            if claim.claim.match_policy_id != self.policy.policy_id:
                raise ValueError(
                    "federation request claim references a different match policy"
                )
            if claim.claim.claim_contract_id != self.policy.claim_contract_id:
                raise ValueError(
                    "federation request claim uses a different claim contract"
                )
            names = tuple(name for name, _value in claim.claim.arguments)
            if names != self.policy.argument_names:
                raise ValueError(
                    "federation request claim arguments do not match policy order"
                )
        if (
            not isinstance(self.max_results, int)
            or isinstance(self.max_results, bool)
            or not 1 <= self.max_results <= 100_000
        ):
            raise ValueError("federation max_results must be between 1 and 100000")
        if (
            not isinstance(self.max_candidates_per_result, int)
            or isinstance(self.max_candidates_per_result, bool)
            or not 1 <= self.max_candidates_per_result <= 64
        ):
            raise ValueError(
                "federation max_candidates_per_result must be between 1 and 64"
            )


class FederationLinkerPlugin(Protocol):
    """Cross-node matcher isolated from every node/device analyzer plug-in."""

    linker_plugin_id: str
    linker_plugin_version: str

    def describe_match_policies(
        self,
    ) -> tuple[ConnectorMatchPolicyDescriptor, ...]: ...

    def link(
        self,
        request: FederationLinkRequest,
    ) -> Iterable[FederationLinkResult | PluginDiagnostic]: ...


class ReadOnlyWorld(Protocol):
    @property
    def basis(self) -> WorldBasis: ...

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None: ...

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
class RoutePresentationDescriptor:
    """Plug-in-owned, declarative graph presentation for forwarding output.

    The core treats ``presentation_id`` as opaque, resolves topology references
    only through canonical resources or declared exact-match topology contracts,
    and maps ``style`` through its own accessible theme.  It does not infer a
    protocol from labels, facts, keys, or presentation choices.
    """

    presentation_id: str
    role: RoutePresentationRole
    scope: RoutePresentationScope
    style: RoutePresentationStyle
    label: str
    topology_references: tuple[TopologyEndpointReference, ...]
    anchor_resources: tuple[ResourceKey, ...] = ()
    facts: Properties = field(default_factory=dict)
    description: str = ""

    def __post_init__(self) -> None:
        _validate_opaque_id(self.presentation_id, "route presentation_id")
        try:
            RoutePresentationRole(self.role)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported route presentation role") from error
        try:
            RoutePresentationScope(self.scope)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported route presentation scope") from error
        try:
            RoutePresentationStyle(self.style)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported route presentation style") from error
        if not isinstance(self.label, str) or not self.label or len(self.label) > 120:
            raise ValueError("route presentation label must contain 1 to 120 characters")
        if not isinstance(self.description, str) or len(self.description) > 500:
            raise ValueError("route presentation description must be at most 500 characters")
        if not isinstance(self.topology_references, tuple):
            raise ValueError("route presentation topology references must be a tuple")
        if not 1 <= len(self.topology_references) <= 64:
            raise ValueError("route presentations require 1 to 64 topology references")
        if any(
            not isinstance(reference, TopologyEndpointReference)
            for reference in self.topology_references
        ):
            raise ValueError(
                "route presentation topology references must be TopologyEndpointReference values"
            )
        if not isinstance(self.anchor_resources, tuple):
            raise ValueError("route presentation anchor resources must be a tuple")
        if len(self.anchor_resources) > 64:
            raise ValueError("route presentations support at most 64 anchor resources")
        if any(
            not isinstance(resource, ResourceKey)
            for resource in self.anchor_resources
        ):
            raise ValueError("route presentation anchors must be ResourceKey values")
        if len(self.anchor_resources) != len(set(self.anchor_resources)):
            raise ValueError("route presentation anchor resources must be unique")
        if (
            RoutePresentationScope(self.scope) is RoutePresentationScope.SPAN
            and len(self.anchor_resources) < 2
        ):
            raise ValueError("span route presentations require at least two anchor resources")
        if not isinstance(self.facts, Mapping):
            raise ValueError("route presentation facts must be a mapping")
        if len(self.facts) > 64:
            raise ValueError("route presentations support at most 64 facts")
        for fact_id in self.facts:
            _validate_opaque_id(fact_id, "route presentation fact identifier")


@dataclass(frozen=True, slots=True)
class ForwardingProjectionRequest:
    """One coordinator-bounded projection against a single status perspective."""

    ir_version: str
    status_perspective: StatusPerspectiveRef
    changes: ChangeSet | None = None
    max_records: int = 10_000
    max_world_reads: int = 50_000

    def __post_init__(self) -> None:
        _validate_opaque_id(self.ir_version, "forwarding IR version")
        if len(self.ir_version) > 64:
            raise ValueError("forwarding IR version must be at most 64 characters")
        if not isinstance(self.status_perspective, StatusPerspectiveRef):
            raise ValueError(
                "forwarding status_perspective must be a StatusPerspectiveRef"
            )
        if self.changes is not None and not isinstance(self.changes, ChangeSet):
            raise ValueError("forwarding changes must be a ChangeSet or None")
        if (
            not isinstance(self.max_records, int)
            or isinstance(self.max_records, bool)
            or not 1 <= self.max_records <= 100_000
        ):
            raise ValueError("forwarding max_records must be between 1 and 100000")
        if (
            not isinstance(self.max_world_reads, int)
            or isinstance(self.max_world_reads, bool)
            or not 1 <= self.max_world_reads <= 1_000_000
        ):
            raise ValueError(
                "forwarding max_world_reads must be between 1 and 1000000"
            )


@dataclass(frozen=True, slots=True)
class ResolutionContribution:
    """Bounded plug-in explanation attached to a local forwarding choice."""

    phase: str
    text: str
    quality: Quality
    resource_references: tuple[ResourceKey, ...] = ()
    topology_references: tuple[TopologyEndpointReference, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        _validate_dashboard_id(self.phase, "resolution contribution phase")
        if (
            not isinstance(self.text, str)
            or not self.text
            or len(self.text) > 2_000
            or any(
                ord(character) < 32 and character not in "\t\r\n"
                for character in self.text
            )
        ):
            raise ValueError(
                "resolution contribution text must contain 1 to 2000 plain-text characters"
            )
        try:
            Quality(self.quality)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported resolution contribution quality") from error
        if not isinstance(self.resource_references, tuple):
            raise ValueError("resolution resource references must be a tuple")
        if len(self.resource_references) > 64:
            raise ValueError(
                "resolution contributions support at most 64 resource references"
            )
        if any(
            not isinstance(reference, ResourceKey)
            for reference in self.resource_references
        ):
            raise ValueError(
                "resolution resource references must be ResourceKey values"
            )
        if len(self.resource_references) != len(set(self.resource_references)):
            raise ValueError("resolution resource references must be unique")
        if not isinstance(self.topology_references, tuple):
            raise ValueError("resolution topology references must be a tuple")
        if len(self.topology_references) > 64:
            raise ValueError(
                "resolution contributions support at most 64 topology references"
            )
        if any(
            not isinstance(reference, TopologyEndpointReference)
            for reference in self.topology_references
        ):
            raise ValueError(
                "resolution topology references must be TopologyEndpointReference values"
            )
        if not isinstance(self.evidence, tuple):
            raise ValueError("resolution evidence must be a tuple")
        if len(self.evidence) > 64:
            raise ValueError("resolution contributions support at most 64 evidence items")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise ValueError("resolution evidence must contain Evidence values")


def _forwarding_value_units(
    value: KeyValue,
    label: str,
    depth: int = 0,
) -> int:
    """Validate a bounded, exactly comparable forwarding value."""

    if depth > 4:
        raise ValueError(f"{label} supports at most four tuple levels")
    if isinstance(value, bool):
        raise ValueError(f"Boolean {label} values are forbidden")
    if isinstance(value, KeyAtom):
        payload = value.value
        if isinstance(payload, int) and payload.bit_length() > 4_096:
            raise ValueError(f"{label} integer values exceed 4096 bits")
        return 1
    if isinstance(value, int):
        if value.bit_length() > 4_096:
            raise ValueError(f"{label} integer values exceed 4096 bits")
        return 1
    if isinstance(value, (str, bytes)):
        if len(value) > _KEY_ATOM_MAX_PAYLOAD_LENGTH:
            raise ValueError(f"{label} values exceed 4096 units")
        return 1
    if isinstance(value, UUID):
        return 1
    if isinstance(value, tuple):
        if len(value) > 32:
            raise ValueError(f"{label} tuples support at most 32 values")
        return 1 + sum(
            _forwarding_value_units(item, label, depth + 1)
            for item in value
        )
    raise ValueError(
        f"{label} must use KeyValue scalars, KeyAtom, or tuples"
    )


def _validate_forwarding_parts(
    parts: tuple[tuple[str, KeyValue], ...],
    label: str,
    *,
    require_nonempty: bool,
) -> None:
    """Validate canonical plug-in-owned exact-match parts."""

    if not isinstance(parts, tuple):
        raise ValueError(f"{label} must be a tuple")
    minimum = 1 if require_nonempty else 0
    if not minimum <= len(parts) <= 32:
        if require_nonempty:
            raise ValueError(f"{label} requires 1 to 32 typed parts")
        raise ValueError(f"{label} supports at most 32 typed parts")
    names: list[str] = []
    total_units = 0
    for part in parts:
        if (
            not isinstance(part, tuple)
            or len(part) != 2
            or not isinstance(part[0], str)
        ):
            raise ValueError(f"{label} must contain (name, KeyValue) pairs")
        name, value = part
        _validate_dashboard_field(name, f"{label} name")
        names.append(name)
        total_units += _forwarding_value_units(value, label)
    if len(names) != len(set(names)):
        raise ValueError(f"{label} names must be unique")
    if total_units > 1_024:
        raise ValueError(f"{label} supports at most 1024 typed value units")


@dataclass(frozen=True, slots=True)
class ForwardingPolicyScope:
    """One plug-in-owned scope that the core may compare only by equality.

    ``contract_id`` names the semantic vocabulary.  ``arguments`` is an
    ordered canonical tuple whose atom types are significant.  The core must
    never parse, normalize, prefix-match, or otherwise infer meaning from
    either field; equality of the complete frozen value is the only authorized
    match.  This makes the primitive usable for split-horizon domains without
    embedding EVPN, BGP, or vendor policy in the core.
    """

    contract_id: str
    arguments: tuple[tuple[str, KeyValue], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.contract_id, str):
            raise ValueError(
                "forwarding policy scope contract_id must be a string"
            )
        _validate_dashboard_id(
            self.contract_id,
            "forwarding policy scope contract_id",
        )
        _validate_forwarding_parts(
            self.arguments,
            "forwarding policy scope arguments",
            require_nonempty=True,
        )


@dataclass(frozen=True, slots=True)
class ForwardingCandidateConstraint:
    """A protocol-neutral, ingress-dependent rule on one candidate.

    For ``EXCLUDE_EXACT_SCOPE``, the candidate is blocked when an ingress scope
    equals ``candidate_scope`` and the current traffic class is applicable.
    An empty ``traffic_classes`` set means every traffic class.  Plug-ins own
    scope construction, traffic-class vocabulary, and explanatory
    contributions; the core owns exact comparison and verdict reporting.
    """

    constraint_id: str
    kind: ForwardingConstraintKind
    candidate_scope: ForwardingPolicyScope
    traffic_classes: frozenset[str] = frozenset()
    contributions: tuple[ResolutionContribution, ...] = ()

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.constraint_id,
            "forwarding candidate constraint_id",
        )
        try:
            object.__setattr__(
                self,
                "kind",
                ForwardingConstraintKind(self.kind),
            )
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported forwarding constraint kind") from error
        if not isinstance(self.candidate_scope, ForwardingPolicyScope):
            raise ValueError(
                "forwarding candidate constraint scope must be a "
                "ForwardingPolicyScope"
            )
        if not isinstance(self.traffic_classes, frozenset):
            raise ValueError(
                "forwarding constraint traffic_classes must be a frozenset"
            )
        if len(self.traffic_classes) > 64:
            raise ValueError(
                "forwarding constraints support at most 64 traffic classes"
            )
        for traffic_class in self.traffic_classes:
            if not isinstance(traffic_class, str):
                raise ValueError(
                    "forwarding constraint traffic classes must be strings"
                )
            _validate_dashboard_id(
                traffic_class,
                "forwarding constraint traffic class",
            )
        if not isinstance(self.contributions, tuple):
            raise ValueError(
                "forwarding candidate constraint contributions must be a tuple"
            )
        if len(self.contributions) > 64:
            raise ValueError(
                "forwarding candidate constraints support at most 64 "
                "resolution contributions"
            )
        if any(
            not isinstance(contribution, ResolutionContribution)
            for contribution in self.contributions
        ):
            raise ValueError(
                "forwarding candidate constraint contributions must be "
                "ResolutionContribution values"
            )

    def applies_to(self, traffic_class: str | None) -> bool | None:
        """Return exact applicability, or ``None`` when class is unknown."""

        if traffic_class is not None:
            if not isinstance(traffic_class, str):
                raise ValueError(
                    "forwarding policy traffic class must be a string or None"
                )
            _validate_dashboard_id(
                traffic_class,
                "forwarding policy traffic class",
            )
        if not self.traffic_classes:
            return True
        if traffic_class is None:
            return None
        return traffic_class in self.traffic_classes


@dataclass(frozen=True, slots=True)
class ForwardingPolicyDecision:
    """A core-reported evaluation of one candidate constraint.

    ``ingress_scopes_complete=False`` means additional scopes may exist.  An
    exact known match can still block, but absence of a match is then unknown
    rather than permission.
    """

    candidate: ResourceKey
    constraint: ForwardingCandidateConstraint
    verdict: ForwardingPolicyVerdict
    traffic_class: str | None
    ingress_scopes: frozenset[ForwardingPolicyScope]
    ingress_scopes_complete: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, ResourceKey):
            raise ValueError(
                "forwarding policy decision candidate must be a ResourceKey"
            )
        if not isinstance(self.constraint, ForwardingCandidateConstraint):
            raise ValueError(
                "forwarding policy decision constraint must be a "
                "ForwardingCandidateConstraint"
            )
        try:
            verdict = ForwardingPolicyVerdict(self.verdict)
            object.__setattr__(self, "verdict", verdict)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported forwarding policy verdict") from error
        if self.traffic_class is not None:
            if not isinstance(self.traffic_class, str):
                raise ValueError(
                    "forwarding policy decision traffic class must be a "
                    "string or None"
                )
            _validate_dashboard_id(
                self.traffic_class,
                "forwarding policy decision traffic class",
            )
        if not isinstance(self.ingress_scopes, frozenset):
            raise ValueError(
                "forwarding policy decision ingress_scopes must be a frozenset"
            )
        if len(self.ingress_scopes) > 64:
            raise ValueError(
                "forwarding policy decisions support at most 64 ingress scopes"
            )
        if any(
            not isinstance(scope, ForwardingPolicyScope)
            for scope in self.ingress_scopes
        ):
            raise ValueError(
                "forwarding policy decision ingress_scopes must contain "
                "ForwardingPolicyScope values"
            )
        if not isinstance(self.ingress_scopes_complete, bool):
            raise ValueError(
                "forwarding policy decision ingress_scopes_complete must be "
                "a boolean"
            )

        applies = self.constraint.applies_to(self.traffic_class)
        exact_match = self.constraint.candidate_scope in self.ingress_scopes
        if applies is None and verdict is not ForwardingPolicyVerdict.UNKNOWN:
            raise ValueError(
                "an unknown applicable traffic class requires an unknown "
                "forwarding policy verdict"
            )
        if applies is False and verdict is not ForwardingPolicyVerdict.NOT_APPLICABLE:
            raise ValueError(
                "traffic outside the constraint classes requires a "
                "not-applicable forwarding policy verdict"
            )
        if (
            applies is True
            and exact_match
            and verdict is not ForwardingPolicyVerdict.BLOCKED
        ):
            raise ValueError(
                "an applicable exact scope match requires a blocked forwarding "
                "policy verdict"
            )
        if (
            applies is True
            and not exact_match
            and not self.ingress_scopes_complete
            and verdict is not ForwardingPolicyVerdict.UNKNOWN
        ):
            raise ValueError(
                "an incomplete applicable ingress scope set without an exact "
                "match requires an unknown forwarding policy verdict"
            )
        if (
            applies is True
            and not exact_match
            and self.ingress_scopes_complete
            and verdict is not ForwardingPolicyVerdict.PERMITTED
        ):
            raise ValueError(
                "a complete applicable ingress scope set without an exact "
                "match requires a permitted forwarding policy verdict"
            )


@dataclass(frozen=True, slots=True)
class ForwardingTraversalStateKey:
    """Canonical forwarding state whose complete equality proves a cycle.

    A node/member revisit alone is never sufficient.  The key also carries the
    selected perspective, forwarding object and domain, ingress resource,
    opaque lookup and packet contexts, active policy scopes, and whether that
    scope set is complete.  Plug-ins canonicalize the typed context tuples; the
    core compares the frozen values exactly and does not interpret protocol
    fields.
    """

    member_id: str
    status_perspective: StatusPerspectiveRef
    forwarding_object: ResourceKey
    forwarding_domain: ResourceKey | None = None
    ingress_resource: ResourceKey | None = None
    lookup_context: tuple[tuple[str, KeyValue], ...] = ()
    packet_context: tuple[tuple[str, KeyValue], ...] = ()
    policy_scopes: frozenset[ForwardingPolicyScope] = frozenset()
    policy_scopes_complete: bool = True

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.member_id,
            "forwarding traversal member_id",
        )
        if not isinstance(self.status_perspective, StatusPerspectiveRef):
            raise ValueError(
                "forwarding traversal status_perspective must be a "
                "StatusPerspectiveRef"
            )
        if not isinstance(self.forwarding_object, ResourceKey):
            raise ValueError(
                "forwarding traversal forwarding_object must be a ResourceKey"
            )
        for label, resource in (
            ("forwarding_domain", self.forwarding_domain),
            ("ingress_resource", self.ingress_resource),
        ):
            if resource is not None and not isinstance(resource, ResourceKey):
                raise ValueError(
                    f"forwarding traversal {label} must be a ResourceKey or None"
                )
        _validate_forwarding_parts(
            self.lookup_context,
            "forwarding traversal lookup_context",
            require_nonempty=False,
        )
        _validate_forwarding_parts(
            self.packet_context,
            "forwarding traversal packet_context",
            require_nonempty=False,
        )
        if not isinstance(self.policy_scopes, frozenset):
            raise ValueError(
                "forwarding traversal policy_scopes must be a frozenset"
            )
        if len(self.policy_scopes) > 64:
            raise ValueError(
                "forwarding traversal states support at most 64 policy scopes"
            )
        if any(
            not isinstance(scope, ForwardingPolicyScope)
            for scope in self.policy_scopes
        ):
            raise ValueError(
                "forwarding traversal policy_scopes must contain "
                "ForwardingPolicyScope values"
            )
        if not isinstance(self.policy_scopes_complete, bool):
            raise ValueError(
                "forwarding traversal policy_scopes_complete must be a boolean"
            )


@dataclass(frozen=True, slots=True)
class ForwardingCycleReport:
    """One bounded cycle segment closed by an exactly repeated state key."""

    first_seen_step: int
    repeated_at_step: int
    cycle_states: tuple[ForwardingTraversalStateKey, ...]
    contributions: tuple[ResolutionContribution, ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("first_seen_step", self.first_seen_step),
            ("repeated_at_step", self.repeated_at_step),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"forwarding cycle {label} must be a non-negative integer"
                )
        if self.repeated_at_step <= self.first_seen_step:
            raise ValueError(
                "forwarding cycle repeated_at_step must follow first_seen_step"
            )
        if not isinstance(self.cycle_states, tuple):
            raise ValueError("forwarding cycle states must be a tuple")
        if not 2 <= len(self.cycle_states) <= 4_097:
            raise ValueError(
                "forwarding cycles require 2 to 4097 traversal states"
            )
        if any(
            not isinstance(state, ForwardingTraversalStateKey)
            for state in self.cycle_states
        ):
            raise ValueError(
                "forwarding cycle states must be "
                "ForwardingTraversalStateKey values"
            )
        if self.cycle_states[0] != self.cycle_states[-1]:
            raise ValueError(
                "forwarding cycle must close on an exactly repeated state key"
            )
        if len(set(self.cycle_states[:-1])) != len(self.cycle_states) - 1:
            raise ValueError(
                "forwarding cycle must stop at the first repeated state key"
            )
        if (
            self.repeated_at_step - self.first_seen_step
            != len(self.cycle_states) - 1
        ):
            raise ValueError(
                "forwarding cycle step span must match the reported cycle states"
            )
        if not isinstance(self.contributions, tuple):
            raise ValueError("forwarding cycle contributions must be a tuple")
        if len(self.contributions) > 64:
            raise ValueError(
                "forwarding cycles support at most 64 resolution contributions"
            )
        if any(
            not isinstance(contribution, ResolutionContribution)
            for contribution in self.contributions
        ):
            raise ValueError(
                "forwarding cycle contributions must be "
                "ResolutionContribution values"
            )


@dataclass(frozen=True, slots=True)
class ForwardingMember:
    target: ResourceKey
    role: str | None = None
    weight: int | None = None
    priority: int | None = None
    eligible: bool | None = None
    activity: ForwardingMemberActivity | None = None
    selection: ForwardingMemberSelection | None = None
    contributions: tuple[ResolutionContribution, ...] = ()
    policy_constraints: tuple[ForwardingCandidateConstraint, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.target, ResourceKey):
            raise ValueError("forwarding member target must be a ResourceKey")
        if self.role is not None and (
            not isinstance(self.role, str) or not self.role or len(self.role) > 128
        ):
            raise ValueError(
                "forwarding member role must contain 1 to 128 characters"
            )
        for label, value in (("weight", self.weight), ("priority", self.priority)):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 2**63 - 1
            ):
                raise ValueError(
                    f"forwarding member {label} must be a non-negative 64-bit integer"
                )
        if self.eligible is not None and not isinstance(self.eligible, bool):
            raise ValueError("forwarding member eligible must be boolean or unknown")
        if self.activity is not None:
            try:
                ForwardingMemberActivity(self.activity)
            except (TypeError, ValueError) as error:
                raise ValueError("unsupported forwarding member activity") from error
        if self.selection is not None:
            try:
                ForwardingMemberSelection(self.selection)
            except (TypeError, ValueError) as error:
                raise ValueError("unsupported forwarding member selection") from error
        if not isinstance(self.contributions, tuple):
            raise ValueError("forwarding member contributions must be a tuple")
        if len(self.contributions) > 64:
            raise ValueError(
                "forwarding members support at most 64 resolution contributions"
            )
        if any(
            not isinstance(contribution, ResolutionContribution)
            for contribution in self.contributions
        ):
            raise ValueError(
                "forwarding member contributions must be ResolutionContribution values"
            )
        if not isinstance(self.policy_constraints, tuple):
            raise ValueError(
                "forwarding member policy_constraints must be a tuple"
            )
        if len(self.policy_constraints) > 64:
            raise ValueError(
                "forwarding members support at most 64 candidate constraints"
            )
        if any(
            not isinstance(constraint, ForwardingCandidateConstraint)
            for constraint in self.policy_constraints
        ):
            raise ValueError(
                "forwarding member policy_constraints must be "
                "ForwardingCandidateConstraint values"
            )
        constraint_ids = [
            constraint.constraint_id
            for constraint in self.policy_constraints
        ]
        if len(constraint_ids) != len(set(constraint_ids)):
            raise ValueError(
                "forwarding member candidate constraint identifiers must be unique"
            )


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
    presentations: tuple[RoutePresentationDescriptor, ...] = ()

    def __post_init__(self) -> None:
        if len(self.presentations) > 64:
            raise ValueError("FIB entries support at most 64 route presentations")
        if any(
            not isinstance(presentation, RoutePresentationDescriptor)
            for presentation in self.presentations
        ):
            raise ValueError(
                "FIB entry presentations must be RoutePresentationDescriptor values"
            )
        presentation_ids = [item.presentation_id for item in self.presentations]
        if len(presentation_ids) != len(set(presentation_ids)):
            raise ValueError("FIB entry presentation identifiers must be unique")


@dataclass(frozen=True, slots=True)
class NextHopGroup:
    key: ResourceKey
    members: tuple[ForwardingMember, ...]
    hash_policy: str | None
    attributes: Properties
    unresolved_dependencies: tuple[ResourceKey, ...] = ()
    mode: PathGroupMode | None = None
    contributions: tuple[ResolutionContribution, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.key, ResourceKey):
            raise ValueError("next-hop group key must be a ResourceKey")
        if not isinstance(self.members, tuple):
            raise ValueError("next-hop group members must be a tuple")
        if len(self.members) > 4_096:
            raise ValueError("next-hop groups support at most 4096 members")
        if any(not isinstance(member, ForwardingMember) for member in self.members):
            raise ValueError(
                "next-hop group members must be ForwardingMember values"
            )
        if self.hash_policy is not None and (
            not isinstance(self.hash_policy, str)
            or not self.hash_policy
            or len(self.hash_policy) > 256
        ):
            raise ValueError(
                "next-hop group hash_policy must contain 1 to 256 characters"
            )
        if not isinstance(self.attributes, Mapping):
            raise ValueError("next-hop group attributes must be a mapping")
        if len(self.attributes) > 256:
            raise ValueError("next-hop groups support at most 256 attributes")
        if not isinstance(self.unresolved_dependencies, tuple):
            raise ValueError(
                "next-hop group unresolved_dependencies must be a tuple"
            )
        if len(self.unresolved_dependencies) > 4_096:
            raise ValueError(
                "next-hop groups support at most 4096 unresolved dependencies"
            )
        if any(
            not isinstance(dependency, ResourceKey)
            for dependency in self.unresolved_dependencies
        ):
            raise ValueError(
                "next-hop group unresolved dependencies must be ResourceKey values"
            )
        if len(self.unresolved_dependencies) != len(
            set(self.unresolved_dependencies)
        ):
            raise ValueError(
                "next-hop group unresolved dependencies must be unique"
            )
        if self.mode is not None:
            try:
                mode = PathGroupMode(self.mode)
            except (TypeError, ValueError) as error:
                raise ValueError("unsupported next-hop group mode") from error
            if mode is PathGroupMode.SINGLE_ACTIVE:
                selected = sum(
                    member.selection is not None
                    and ForwardingMemberSelection(member.selection)
                    is ForwardingMemberSelection.SELECTED
                    for member in self.members
                )
                active = sum(
                    member.activity is not None
                    and ForwardingMemberActivity(member.activity)
                    is ForwardingMemberActivity.ACTIVE
                    for member in self.members
                )
                if selected > 1 or active > 1:
                    raise ValueError(
                        "single-active next-hop groups may have at most one selected active member"
                    )
        if not isinstance(self.contributions, tuple):
            raise ValueError("next-hop group contributions must be a tuple")
        if len(self.contributions) > 64:
            raise ValueError(
                "next-hop groups support at most 64 resolution contributions"
            )
        if any(
            not isinstance(contribution, ResolutionContribution)
            for contribution in self.contributions
        ):
            raise ValueError(
                "next-hop group contributions must be ResolutionContribution values"
            )


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
    presentations: tuple[RoutePresentationDescriptor, ...] = ()

    def __post_init__(self) -> None:
        if len(self.presentations) > 64:
            raise ValueError("tunnel actions support at most 64 route presentations")
        if any(
            not isinstance(presentation, RoutePresentationDescriptor)
            for presentation in self.presentations
        ):
            raise ValueError(
                "tunnel action presentations must be RoutePresentationDescriptor values"
            )
        presentation_ids = [item.presentation_id for item in self.presentations]
        if len(presentation_ids) != len(set(presentation_ids)):
            raise ValueError("tunnel action presentation identifiers must be unique")


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


type StatusParseOutput = (
    SnapshotObservation
    | RelationshipObservation
    | RelationshipCollectionObservation
    | SourceRecordEmission
    | PluginDiagnostic
)

type TraceParseOutput = DomainEvent | SourceRecordEmission | PluginDiagnostic


class AnalyzerPluginBase:
    """Convenience base with fail-loud required hooks and safe optional no-ops.

    Subclasses implement ``describe()``, ``probe()``, and ``locate_inputs()``.
    Optional hooks may be omitted when their capability is not declared.  If a
    capability is declared but its hook is not overridden, the inherited method
    raises ``NotImplementedError`` instead of silently dropping input.
    """

    manifest: PluginManifest

    def _require_capability_override(
        self,
        capability: PluginCapability,
        hook_name: str,
    ) -> None:
        if self.manifest.supports(capability):
            raise NotImplementedError(
                f"{hook_name}() must be overridden because the manifest declares "
                f"{capability.value!r}"
            )

    def describe(self) -> PluginSchema:
        raise NotImplementedError("describe() is required for every analyzer plugin")

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        raise NotImplementedError("probe() is required for every analyzer plugin")

    def locate_inputs(
        self,
        inventory: DumpInventory,
    ) -> Iterable[InputSpec | PluginDiagnostic]:
        raise NotImplementedError("locate_inputs() is required for every analyzer plugin")

    def parse_status(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[StatusParseOutput]:
        self._require_capability_override(
            PluginCapability.STATUS_PARSE,
            "parse_status",
        )
        return ()

    def parse_ctf(
        self,
        spec: InputSpec,
        messages: Iterable[CtfMessage],
    ) -> Iterable[TraceParseOutput]:
        self._require_capability_override(PluginCapability.CTF_PARSE, "parse_ctf")
        return ()

    def parse_text_trace(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[TraceParseOutput]:
        self._require_capability_override(
            PluginCapability.TEXT_TRACE_PARSE,
            "parse_text_trace",
        )
        return ()

    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet:
        self._require_capability_override(
            PluginCapability.EVENT_REDUCTION,
            "apply",
        )
        return ChangeSet()

    def revert(
        self,
        event: DomainEvent,
        world_after: ReadOnlyWorld,
    ) -> ChangeSet:
        self._require_capability_override(
            PluginCapability.EVENT_REVERSION,
            "revert",
        )
        return ChangeSet()

    def correlate(
        self,
        reader: CorrelationReader,
        window: CorrelationWindow,
    ) -> Iterable[
        CausalLink | RelationshipMutation | ClockAnchor | PluginDiagnostic
    ]:
        self._require_capability_override(
            PluginCapability.CORRELATION,
            "correlate",
        )
        return ()

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> Iterable[ConsistencyFinding | PluginDiagnostic]:
        self._require_capability_override(
            PluginCapability.CONSISTENCY_CHECK,
            "check_consistency",
        )
        return ()

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> Iterable[TopologyProjectionRecord | PluginDiagnostic]:
        self._require_capability_override(
            PluginCapability.TOPOLOGY_PROJECTION,
            "project_topology",
        )
        return ()

    def project_forwarding(
        self,
        request: ForwardingProjectionRequest,
        world: ReadOnlyWorld,
    ) -> Iterable[ForwardingMutation | PluginDiagnostic]:
        self._require_capability_override(
            PluginCapability.FORWARDING_PROJECTION,
            "project_forwarding",
        )
        return ()


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
    ) -> Iterable[StatusParseOutput]: ...

    def parse_ctf(
        self,
        spec: InputSpec,
        messages: Iterable[CtfMessage],
    ) -> Iterable[TraceParseOutput]: ...

    def parse_text_trace(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[TraceParseOutput]: ...

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

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> Iterable[TopologyProjectionRecord | PluginDiagnostic]: ...

    def project_forwarding(
        self,
        request: ForwardingProjectionRequest,
        world: ReadOnlyWorld,
    ) -> Iterable[ForwardingMutation | PluginDiagnostic]: ...
