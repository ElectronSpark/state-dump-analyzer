"""Bounded core callers for optional analyzer plug-in capabilities.

The plug-in API deliberately describes domain-neutral records.  This module is
the matching trust boundary: it checks that a plug-in advertised a capability,
limits every world read and yielded result, validates references against the
plug-in's immutable schema, closes plug-in iterators, and preserves recoverable
diagnostics without assigning meaning to opaque plug-in vocabulary.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from math import isfinite
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from .canonical import strict_canonical_json
from .plugin_api import (
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    AbsoluteTimeSelector,
    Adjacency,
    AnalyzerPlugin,
    CaptureRange,
    CausalLink,
    ChangeSet,
    ClockAnchor,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConsistencyFinding,
    CorrelationReader,
    CorrelationWindow,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    DomainEvent,
    Evidence,
    EvidenceAnalysisFact,
    EvidenceAnalysisKind,
    EvidenceAnalysisObservation,
    EvidenceAnalysisRequest,
    FailoverGroup,
    FibEntry,
    FindingResult,
    ForwardingMutation,
    ForwardingOperation,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingProjectionRequest,
    ForwardingSizeObservation,
    ForwardingSteeringRule,
    ForwardingStepRequest,
    ForwardingStepResult,
    ForwardingTransitionOrigin,
    InterfaceForwardingState,
    InterNodeLinkPresentation,
    KeyAtom,
    MutationOperation,
    NextHop,
    NextHopGroup,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionCoverage,
    ReconstructionWatermark,
    RelationshipMutation,
    RelationshipOperation,
    RelationshipView,
    RelativeToWatermarkSelector,
    ResolvedNodeBasis,
    ResourceKey,
    ResourceStateView,
    StateMutation,
    StatusPerspectiveRef,
    TopologyEndpointRecord,
    TopologyEndpointReference,
    TopologyLinkRecord,
    TopologyMatchReference,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourcePresentation,
    TopologyResourceRecord,
    TopologyTwoParticipantShape,
    TopologyUsability,
    TunnelAction,
    UnknownChange,
    UnknownField,
    VrfForwardingState,
    WorldBasis,
    WorldBasisKind,
    validate_plugin_diagnostic,
)
from .plugin_execution_plan import (
    PluginExecutionPin,
    plugin_execution_pin_uses_legacy_identity,
)
from .plugin_schema_identity import plugin_schema_digest
from .process_control import PROCESS_CONTROL_EXCEPTIONS


class PluginCapabilityExecutionError(RuntimeError):
    """An optional plug-in capability could not produce a safe core result."""

    def __init__(
        self,
        message: str,
        *,
        capability: PluginCapability,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> None:
        super().__init__(message)
        self.capability: PluginCapability = capability
        self.diagnostics: tuple[PluginDiagnostic, ...] = diagnostics


class PluginCapabilityUnavailableError(PluginCapabilityExecutionError):
    """The plug-in did not advertise a requested standard capability."""


class PluginCapabilityInputError(PluginCapabilityExecutionError):
    """The caller supplied an invalid capability request."""


class PluginCapabilityOutputError(PluginCapabilityExecutionError):
    """The plug-in returned a malformed or over-limit capability result."""


class PluginCapabilityBindingError(RuntimeError):
    """A live executor does not match its immutable execution-plan pin."""


@dataclass(frozen=True, slots=True)
class PluginCapabilityLimits:
    """Core-owned ceilings independent of plug-in-provided request limits."""

    max_world_reads: int = 50_000
    max_change_items: int = 50_000
    max_correlation_outputs: int = 50_000
    max_consistency_outputs: int = 10_000
    max_topology_outputs: int = 100_000
    max_forwarding_outputs: int = 100_000
    max_evidence_analysis_outputs: int = 1_000
    max_evidence_analysis_input_bytes: int = 1_000_000
    max_evidence_analysis_output_bytes: int = 1_000_000
    max_diagnostics: int = 1_000
    max_evidence_per_output: int = 64
    max_resource_references: int = 4_096
    max_topology_claims: int = 100_000

    def __post_init__(self) -> None:
        for name, value in (
            ("max_world_reads", self.max_world_reads),
            ("max_change_items", self.max_change_items),
            ("max_correlation_outputs", self.max_correlation_outputs),
            ("max_consistency_outputs", self.max_consistency_outputs),
            ("max_topology_outputs", self.max_topology_outputs),
            ("max_topology_claims", self.max_topology_claims),
            ("max_forwarding_outputs", self.max_forwarding_outputs),
            (
                "max_evidence_analysis_outputs",
                self.max_evidence_analysis_outputs,
            ),
            (
                "max_evidence_analysis_input_bytes",
                self.max_evidence_analysis_input_bytes,
            ),
            (
                "max_evidence_analysis_output_bytes",
                self.max_evidence_analysis_output_bytes,
            ),
            ("max_diagnostics", self.max_diagnostics),
            ("max_evidence_per_output", self.max_evidence_per_output),
            ("max_resource_references", self.max_resource_references),
        ):
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError(f"{name} must be an integer between 1 and 1000000")


@dataclass(frozen=True, slots=True)
class CorrelationExecutionResult:
    causal_links: tuple[CausalLink, ...]
    relationship_mutations: tuple[RelationshipMutation, ...]
    clock_anchors: tuple[ClockAnchor, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ConsistencyExecutionResult:
    findings: tuple[ConsistencyFinding, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class TopologyExecutionResult:
    records: tuple[TopologyProjectionRecord, ...]
    diagnostics: tuple[PluginDiagnostic, ...]
    claims: tuple[ConnectorClaim, ...] = ()
    match_policies: tuple[ConnectorMatchPolicyDescriptor, ...] = ()
    records_complete: bool = True
    claims_complete: bool = True


@dataclass(frozen=True, slots=True)
class ForwardingProjectionExecutionResult:
    mutations: tuple[ForwardingMutation, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ForwardingStepExecutionResult:
    result: ForwardingStepResult | None
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisExecutionResult:
    observations: tuple[EvidenceAnalysisObservation, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class _SchemaIndex:
    key_fields_by_kind: Mapping[str, tuple[str, ...]]
    property_roots_by_kind: Mapping[str, frozenset[str]]
    relationship_types: frozenset[str]
    causal_link_types: frozenset[str]
    perspectives: frozenset[str]
    topology_perspectives: Mapping[str, frozenset[str]]
    connector_match_policies: Mapping[str, ConnectorMatchPolicyDescriptor]

    @classmethod
    def build(cls, schema: PluginSchema) -> _SchemaIndex:
        key_fields: dict[str, tuple[str, ...]] = {}
        property_roots: dict[str, frozenset[str]] = {}
        for resource_kind in schema.resource_kinds:
            key_fields[resource_kind.kind] = resource_kind.key_fields
            property_roots[resource_kind.kind] = frozenset(
                item.name.partition(".")[0]
                for item in resource_kind.properties
            )
        policies = schema.connector_match_policies
        if type(policies) is not tuple or any(
            type(policy) is not ConnectorMatchPolicyDescriptor
            for policy in policies
        ):
            raise ValueError(
                "connector match policies must be an exact descriptor tuple"
            )
        for policy in policies:
            ConnectorMatchPolicyDescriptor.__post_init__(policy)
        detached_policies = tuple(
            ConnectorMatchPolicyDescriptor(
                policy_id=policy.policy_id,
                claim_contract_id=policy.claim_contract_id,
                kind=policy.kind,
                argument_names=tuple(policy.argument_names),
                linker_plugin_id=policy.linker_plugin_id,
            )
            for policy in policies
        )
        policy_ids = [policy.policy_id for policy in detached_policies]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("connector match policy identifiers must be unique")
        return cls(
            key_fields_by_kind=key_fields,
            property_roots_by_kind=property_roots,
            relationship_types=frozenset(
                descriptor.relation_type
                for descriptor in schema.relationship_types
            ),
            causal_link_types=frozenset(
                descriptor.link_type for descriptor in schema.causal_link_types
            ),
            perspectives=frozenset(
                descriptor.perspective_id
                for descriptor in schema.status_perspectives
            ),
            topology_perspectives={
                descriptor.projection_id: frozenset(
                    descriptor.supported_status_perspective_ids
                )
                for descriptor in schema.topology_projections
            },
            connector_match_policies={
                descriptor.policy_id: descriptor
                for descriptor in detached_policies
            },
        )


class _BoundedWorld:
    """Read-only world facade that charges every returned state or relation."""

    def __init__(
        self,
        world: ReadOnlyWorld,
        maximum_reads: int,
        capability: PluginCapability,
        *,
        basis: WorldBasis,
        perspective_ref: StatusPerspectiveRef | None,
    ) -> None:
        self._world = world
        self._remaining = maximum_reads
        self._capability = capability
        self._basis = basis
        self._perspective_ref = perspective_ref

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._perspective_ref

    @property
    def remaining_reads(self) -> int:
        return self._remaining

    def _charge(self) -> None:
        if self._remaining <= 0:
            raise PluginCapabilityOutputError(
                "plug-in exceeded the configured world-read limit",
                capability=self._capability,
            )
        self._remaining -= 1

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self._charge()
        return self._world.state_of(resource)

    def _bounded_iter[Item](
        self,
        producer: Callable[[int], Iterable[Item]],
        requested_limit: int | None,
    ) -> Iterator[Item]:
        if self._remaining <= 0:
            raise PluginCapabilityOutputError(
                "plug-in exceeded the configured world-read limit",
                capability=self._capability,
            )
        allowed = self._remaining
        if requested_limit is not None:
            if type(requested_limit) is not int or requested_limit < 0:
                raise ValueError("world read limit must be a non-negative integer")
            allowed = min(allowed, requested_limit)
        iterator = iter(producer(allowed))
        count = 0
        try:
            for item in iterator:
                if count >= allowed:
                    raise PluginCapabilityOutputError(
                        "world provider exceeded the bounded read request",
                        capability=self._capability,
                    )
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
        direction: Any = None,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        if direction is None:
            from .plugin_api import RelationDirection

            direction = RelationDirection.OUTGOING
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


class _ValueBudget:
    def __init__(self) -> None:
        self.units = 0
        self.active: set[int] = set()


def _evidence_analysis_json_projection(value: Any) -> Any:
    """Return plain JSON containers for an already-validated analysis DTO.

    The public evidence-analysis DTOs deeply freeze dictionaries and lists as
    mapping proxies and tuples.  Canonical byte accounting must therefore thaw
    every container level, not only the top-level mapping.
    """

    if isinstance(value, Mapping):
        return {
            key: _evidence_analysis_json_projection(item)
            for key, item in value.items()
        }
    if type(value) is tuple:
        return [_evidence_analysis_json_projection(item) for item in value]
    return value


def _validate_value(
    value: Any,
    label: str,
    *,
    budget: _ValueBudget | None = None,
    depth: int = 0,
) -> None:
    """Validate one bounded Properties-compatible value without interpretation."""

    current = budget or _ValueBudget()
    current.units += 1
    if current.units > 4_096:
        raise ValueError(f"{label} exceeds 4096 value units")
    if depth > 16:
        raise ValueError(f"{label} exceeds 16 container levels")
    if value is None or type(value) is bool or isinstance(value, UUID):
        return
    if type(value) is int:
        if value.bit_length() > 4_096:
            raise ValueError(f"{label} contains an integer exceeding 4096 bits")
        return
    if type(value) is float:
        if not isfinite(value):
            raise ValueError(f"{label} contains a non-finite float")
        return
    if isinstance(value, (str, bytes)):
        if len(value) > 65_536:
            raise ValueError(f"{label} contains an atom exceeding 65536 units")
        return
    if isinstance(value, tuple):
        if len(value) > 1_024:
            raise ValueError(f"{label} contains a tuple exceeding 1024 items")
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        try:
            for item in value:
                _validate_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
        finally:
            current.active.remove(identity)
        return
    if isinstance(value, Mapping):
        if len(value) > 1_024:
            raise ValueError(f"{label} contains a mapping exceeding 1024 items")
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValueError(
                        f"{label} mapping keys must contain 1 to 256 characters"
                    )
                _validate_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
        finally:
            current.active.remove(identity)
        return
    raise ValueError(f"{label} contains unsupported type {type(value).__name__}")


def _snapshot_property_value(
    value: Any,
    label: str,
    *,
    budget: _ValueBudget | None = None,
    depth: int = 0,
) -> Any:
    """Deeply detach one already-bounded plug-in value.

    Validation alone is not an ownership transfer: a generator can mutate a
    mapping after yielding it but before the core asks for the next item.  The
    returned graph therefore uses only exact immutable atoms, tuples, and
    read-only mapping proxies constructed by the core.  Custom containers are
    read inside the surrounding plug-in boundary but are never retained.
    """

    current = budget or _ValueBudget()
    current.units += 1
    if current.units > 4_096:
        raise ValueError(f"{label} exceeds 4096 value units")
    if depth > 16:
        raise ValueError(f"{label} exceeds 16 container levels")
    value_type = type(value)
    if value is None or value_type is bool:
        return value
    if value_type is int:
        if value.bit_length() > 4_096:
            raise ValueError(f"{label} contains an integer exceeding 4096 bits")
        return value
    if value_type is float:
        if not isfinite(value):
            raise ValueError(f"{label} contains a non-finite float")
        return value
    if value_type is str:
        if len(value) > 65_536:
            raise ValueError(f"{label} contains an atom exceeding 65536 units")
        return value
    if value_type is bytes:
        if len(value) > 65_536:
            raise ValueError(f"{label} contains an atom exceeding 65536 units")
        return bytes(value)
    if value_type is UUID:
        return UUID(bytes=value.bytes)
    if value_type is tuple:
        if len(value) > 1_024:
            raise ValueError(f"{label} contains a tuple exceeding 1024 items")
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        try:
            return tuple(
                _snapshot_property_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
                for item in value
            )
        finally:
            current.active.remove(identity)
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        detached: dict[str, Any] = {}
        try:
            for index, (key, item) in enumerate(value.items()):
                if index >= 1_024:
                    raise ValueError(
                        f"{label} contains a mapping exceeding 1024 items"
                    )
                if type(key) is not str or not key or len(key) > 256:
                    raise ValueError(
                        f"{label} mapping keys must contain 1 to 256 characters"
                    )
                detached[key] = _snapshot_property_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
        finally:
            current.active.remove(identity)
        return MappingProxyType(detached)
    raise ValueError(f"{label} contains unsupported type {value_type.__name__}")


def _snapshot_key_value(value: Any, label: str, *, depth: int = 0) -> Any:
    if depth > 4:
        raise ValueError(f"{label} exceeds four tuple levels")
    value_type = type(value)
    if value_type in {int, str}:
        return value
    if value_type is bytes:
        return bytes(value)
    if value_type is UUID:
        return UUID(bytes=value.bytes)
    if value_type is KeyAtom:
        return KeyAtom(
            type_tag=value.type_tag,
            value=_snapshot_key_value(
                value.value,
                f"{label}.value",
                depth=depth + 1,
            ),
        )
    if value_type is tuple:
        return tuple(
            _snapshot_key_value(item, f"{label}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        )
    raise ValueError(f"{label} contains an unsupported key value")


def _snapshot_resource_key(value: ResourceKey, label: str) -> ResourceKey:
    if type(value) is not ResourceKey:
        raise ValueError(f"{label} must be an exact ResourceKey")
    return ResourceKey(
        namespace=value.namespace,
        node=value.node,
        layer=value.layer,
        kind=value.kind,
        parts=tuple(
            (
                name,
                _snapshot_key_value(part, f"{label}.parts[{index}][1]"),
            )
            for index, (name, part) in enumerate(value.parts)
        ),
    )


def _snapshot_evidence(value: Evidence, label: str) -> Evidence:
    if type(value) is not Evidence:
        raise ValueError(f"{label} must be an exact Evidence")
    return Evidence(
        artifact_id=UUID(bytes=value.artifact_id.bytes),
        locator=value.locator,
        raw_timestamp_ns=value.raw_timestamp_ns,
        clock_domain=value.clock_domain,
        excerpt_sha256=value.excerpt_sha256,
    )


def _snapshot_evidence_items(
    values: tuple[Evidence, ...],
    label: str,
) -> tuple[Evidence, ...]:
    return tuple(
        _snapshot_evidence(item, f"{label}[{index}]")
        for index, item in enumerate(values)
    )


def _snapshot_status_perspective(
    value: StatusPerspectiveRef | None,
) -> StatusPerspectiveRef | None:
    if value is None:
        return None
    if type(value) is not StatusPerspectiveRef:
        raise ValueError(
            "connector claim status_perspective must be an exact "
            "StatusPerspectiveRef"
        )
    return StatusPerspectiveRef(
        perspective_id=value.perspective_id,
        plugin_instance_id=value.plugin_instance_id,
        schema_digest=value.schema_digest,
    )


def _snapshot_topology_reference(
    value: TopologyEndpointReference,
    label: str,
) -> TopologyEndpointReference:
    if type(value) is not TopologyEndpointReference:
        raise ValueError(f"{label} must be an exact TopologyEndpointReference")
    if value.resource is not None:
        return TopologyEndpointReference(
            resource=_snapshot_resource_key(value.resource, f"{label}.resource")
        )
    assert value.match is not None
    match = value.match
    if type(match) is not TopologyMatchReference:
        raise ValueError(f"{label}.match must be an exact TopologyMatchReference")
    return TopologyEndpointReference(
        match=TopologyMatchReference(
            matcher_id=match.matcher_id,
            arguments=_snapshot_property_value(
                match.arguments,
                f"{label}.match.arguments",
            ),
            resolved_candidates=tuple(
                _snapshot_resource_key(
                    candidate,
                    f"{label}.match.resolved_candidates[{index}]",
                )
                for index, candidate in enumerate(match.resolved_candidates)
            ),
        )
    )


def _snapshot_topology_record(
    value: TopologyProjectionRecord,
    label: str,
) -> TopologyProjectionRecord:
    payload = value.payload
    if type(payload) is TopologyResourceRecord:
        presentation = payload.presentation
        if type(presentation) is not TopologyResourcePresentation:
            raise ValueError(
                f"{label}.payload.presentation must be an exact "
                "TopologyResourcePresentation"
            )
        detached_payload: Any = TopologyResourceRecord(
            resource=_snapshot_resource_key(
                payload.resource,
                f"{label}.payload.resource",
            ),
            role=payload.role,
            presentation=TopologyResourcePresentation(
                two_participant_shape=TopologyTwoParticipantShape(
                    presentation.two_participant_shape
                )
            ),
        )
    elif type(payload) is TopologyEndpointRecord:
        detached_payload = TopologyEndpointRecord(
            endpoint_id=payload.endpoint_id,
            target=_snapshot_topology_reference(
                payload.target,
                f"{label}.payload.target",
            ),
            role=payload.role,
        )
    elif type(payload) is TopologyLinkRecord:
        detached_payload = TopologyLinkRecord(
            link_id=payload.link_id,
            source=_snapshot_topology_reference(
                payload.source,
                f"{label}.payload.source",
            ),
            target=_snapshot_topology_reference(
                payload.target,
                f"{label}.payload.target",
            ),
            directed=payload.directed,
        )
    else:
        raise ValueError(f"{label}.payload is unsupported")
    return TopologyProjectionRecord(
        projection_id=value.projection_id,
        status_perspective_id=value.status_perspective_id,
        payload=detached_payload,
        usability=TopologyUsability(value.usability),
        source_resources=tuple(
            _snapshot_resource_key(
                resource,
                f"{label}.source_resources[{index}]",
            )
            for index, resource in enumerate(value.source_resources)
        ),
        provenance=Provenance(value.provenance),
        quality=Quality(value.quality),
        exists=value.exists,
        properties=_snapshot_property_value(value.properties, f"{label}.properties"),
        unknown_fields=tuple(
            UnknownField(
                name=item.name,
                reason_code=item.reason_code,
                message=item.message,
                evidence=_snapshot_evidence_items(
                    item.evidence,
                    f"{label}.unknown_fields[{index}].evidence",
                ),
            )
            for index, item in enumerate(value.unknown_fields)
        ),
        valid_from_ns=value.valid_from_ns,
        valid_to_ns=value.valid_to_ns,
        evidence=_snapshot_evidence_items(value.evidence, f"{label}.evidence"),
    )


def _snapshot_connector_claim(value: ConnectorClaim, label: str) -> ConnectorClaim:
    presentation = value.presentation
    if type(presentation) is not InterNodeLinkPresentation:
        raise ValueError(
            f"{label}.presentation must be an exact InterNodeLinkPresentation"
        )
    return ConnectorClaim(
        claim_id=value.claim_id,
        endpoint=_snapshot_resource_key(value.endpoint, f"{label}.endpoint"),
        claim_contract_id=value.claim_contract_id,
        match_policy_id=value.match_policy_id,
        arguments=tuple(
            (
                name,
                _snapshot_key_value(argument, f"{label}.arguments[{index}][1]"),
            )
            for index, (name, argument) in enumerate(value.arguments)
        ),
        provenance=Provenance(value.provenance),
        quality=Quality(value.quality),
        status_perspective=_snapshot_status_perspective(value.status_perspective),
        role=value.role,
        link_type=value.link_type,
        presentation=InterNodeLinkPresentation(
            route_trace=presentation.route_trace,
        ),
        valid_from_ns=value.valid_from_ns,
        valid_to_ns=value.valid_to_ns,
        evidence=_snapshot_evidence_items(value.evidence, f"{label}.evidence"),
    )


def _snapshot_topology_projection_request(
    value: TopologyProjectionRequest,
    label: str,
) -> TopologyProjectionRequest:
    """Detach plug-in-visible topology input from core-owned authority."""

    if type(value) is not TopologyProjectionRequest:
        raise ValueError(f"{label} must be an exact TopologyProjectionRequest")
    return TopologyProjectionRequest(
        projection_id=value.projection_id,
        status_perspective_id=value.status_perspective_id,
        max_records=value.max_records,
        max_world_reads=value.max_world_reads,
        seed_resources=tuple(
            _snapshot_resource_key(
                resource,
                f"{label}.seed_resources[{index}]",
            )
            for index, resource in enumerate(value.seed_resources)
        ),
        max_claims=value.max_claims,
    )


def _snapshot_forwarding_packet_state(
    value: ForwardingPacketState,
    label: str,
) -> ForwardingPacketState:
    if type(value) is not ForwardingPacketState:
        raise ValueError(f"{label} must be an exact ForwardingPacketState")
    layers = tuple(
        ForwardingPacketLayer(
            layer_id=layer.layer_id,
            contract_id=layer.contract_id,
            label=layer.label,
            fields=tuple(
                (
                    name,
                    _snapshot_key_value(
                        part,
                        f"{label}.layers[{layer_index}].fields[{part_index}][1]",
                    ),
                )
                for part_index, (name, part) in enumerate(layer.fields)
            ),
            size_bytes=layer.size_bytes,
            complete=layer.complete,
        )
        for layer_index, layer in enumerate(value.layers)
    )
    size = value.size
    return ForwardingPacketState(
        layers=layers,
        size=(
            None
            if size is None
            else ForwardingSizeObservation(
                basis_contract_id=size.basis_contract_id,
                size_bytes=size.size_bytes,
                complete=size.complete,
            )
        ),
        complete=value.complete,
    )


def _snapshot_forwarding_steering_rule(
    value: ForwardingSteeringRule,
    label: str,
) -> ForwardingSteeringRule:
    if type(value) is not ForwardingSteeringRule:
        raise ValueError(f"{label} must be an exact ForwardingSteeringRule")
    return ForwardingSteeringRule(
        rule_id=value.rule_id,
        target_step_id=value.target_step_id,
        action_contract_id=value.action_contract_id,
        reason=value.reason,
        priority=value.priority,
        expected_before=(
            None
            if value.expected_before is None
            else _snapshot_forwarding_packet_state(
                value.expected_before,
                f"{label}.expected_before",
            )
        ),
        selected_candidate=(
            None
            if value.selected_candidate is None
            else _snapshot_resource_key(
                value.selected_candidate,
                f"{label}.selected_candidate",
            )
        ),
        packet_after=(
            None
            if value.packet_after is None
            else _snapshot_forwarding_packet_state(
                value.packet_after,
                f"{label}.packet_after",
            )
        ),
        disposition=value.disposition,
    )


def _snapshot_forwarding_step_request(
    value: ForwardingStepRequest,
    label: str,
) -> ForwardingStepRequest:
    if type(value) is not ForwardingStepRequest:
        raise ValueError(f"{label} must be an exact ForwardingStepRequest")
    return ForwardingStepRequest(
        step_id=value.step_id,
        member_id=value.member_id,
        status_perspective=cast(
            StatusPerspectiveRef,
            _snapshot_status_perspective(value.status_perspective),
        ),
        forwarding_object=_snapshot_resource_key(
            value.forwarding_object,
            f"{label}.forwarding_object",
        ),
        packet_state=_snapshot_forwarding_packet_state(
            value.packet_state,
            f"{label}.packet_state",
        ),
        lookup_context=tuple(
            (
                name,
                _snapshot_key_value(
                    part,
                    f"{label}.lookup_context[{index}][1]",
                ),
            )
            for index, (name, part) in enumerate(value.lookup_context)
        ),
        ingress_resource=(
            None
            if value.ingress_resource is None
            else _snapshot_resource_key(
                value.ingress_resource,
                f"{label}.ingress_resource",
            )
        ),
        steering_rules=tuple(
            _snapshot_forwarding_steering_rule(
                rule,
                f"{label}.steering_rules[{index}]",
            )
            for index, rule in enumerate(value.steering_rules)
        ),
        max_candidates=value.max_candidates,
        ir_version=value.ir_version,
    )


def _snapshot_forwarding_projection_request(
    value: ForwardingProjectionRequest,
    label: str,
) -> ForwardingProjectionRequest:
    if type(value) is not ForwardingProjectionRequest:
        raise ValueError(f"{label} must be an exact ForwardingProjectionRequest")
    return ForwardingProjectionRequest(
        ir_version=value.ir_version,
        status_perspective=cast(
            StatusPerspectiveRef,
            _snapshot_status_perspective(value.status_perspective),
        ),
        # ChangeSet is validated before invocation and is not consulted to
        # authorize plug-in output. The enclosing request is still detached so
        # a hook cannot rewrite the authoritative IR, perspective, or bounds.
        changes=value.changes,
        max_records=value.max_records,
        max_world_reads=value.max_world_reads,
    )


class PluginCapabilityExecutor:
    """Invoke optional analyzer hooks through one bounded validation boundary."""

    def __init__(
        self,
        plugin: AnalyzerPlugin,
        schema: PluginSchema | None = None,
        *,
        limits: PluginCapabilityLimits | None = None,
    ) -> None:
        try:
            manifest = getattr(plugin, "manifest", None)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise TypeError(
                "capability executor could not resolve the plug-in manifest"
            ) from error
        if not isinstance(manifest, PluginManifest):
            raise TypeError("capability executor requires a PluginManifest")
        try:
            raw_capabilities = manifest.capabilities
            if type(raw_capabilities) is not frozenset:
                raise TypeError(
                    "manifest capabilities must be an exact frozenset"
                )
            declared_capabilities = frozenset(
                item.value if type(item) is PluginCapability else item
                for item in raw_capabilities
            )
            if any(type(item) is not str for item in declared_capabilities):
                raise TypeError(
                    "manifest capabilities must contain strings or "
                    "PluginCapability values"
                )
            forwarding_ir_versions = manifest.forwarding_ir_versions
            if type(forwarding_ir_versions) is not tuple or any(
                type(version) is not str for version in forwarding_ir_versions
            ):
                raise TypeError(
                    "manifest forwarding_ir_versions must be an exact tuple of strings"
                )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise TypeError(
                "capability executor could not resolve manifest forwarding IR versions"
            ) from error
        if schema is None:
            try:
                selected_schema = plugin.describe()
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise TypeError(
                    "capability executor could not resolve the plug-in schema"
                ) from error
        else:
            selected_schema = schema
        if type(selected_schema) is not PluginSchema:
            raise TypeError("capability executor requires an exact PluginSchema")
        try:
            schema_identity = plugin_schema_digest(selected_schema)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise TypeError(
                "capability executor requires a bounded plug-in schema"
            ) from error
        self.plugin: AnalyzerPlugin = plugin
        self.manifest: PluginManifest = manifest
        self._declared_capabilities = declared_capabilities
        self._forwarding_ir_versions = forwarding_ir_versions
        self.schema: PluginSchema = selected_schema
        self.limits: PluginCapabilityLimits = limits or PluginCapabilityLimits()
        try:
            self._schema = _SchemaIndex.build(selected_schema)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise TypeError(
                "capability executor could not index the plug-in schema"
            ) from error
        self._schema_identity = schema_identity
        self._bound_instance_id: str | None = None
        self._bound_schema_digest: str | None = None
        self._bound_member_id: str | None = None

    @classmethod
    def for_execution_pin(
        cls,
        plugin: AnalyzerPlugin,
        pin: PluginExecutionPin,
        *,
        member_id: str,
        schema: PluginSchema | None = None,
        limits: PluginCapabilityLimits | None = None,
    ) -> PluginCapabilityExecutor:
        """Build an executor constrained to one exact plan pin and member."""

        if type(pin) is not PluginExecutionPin:
            raise TypeError("pin must be an exact PluginExecutionPin")
        if plugin_execution_pin_uses_legacy_identity(pin):
            raise PluginCapabilityBindingError(
                "retained v1 execution pins cannot authorize capability execution"
            )
        if type(member_id) is not str or not member_id or len(member_id) > 256:
            raise ValueError("member_id must contain 1 to 256 characters")
        executor = cls(plugin, schema, limits=limits)
        try:
            manifest = executor.manifest
            manifest_plugin_id = manifest.plugin_id
            manifest_plugin_version = manifest.plugin_version
            manifest_core_api_version = manifest.core_api_version
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise PluginCapabilityBindingError(
                "plug-in manifest identity could not be bound"
            ) from error
        if (
            type(manifest_plugin_id) is not str
            or type(manifest_plugin_version) is not str
            or type(manifest_core_api_version) is not str
            or manifest_plugin_id != pin.plugin_id
            or manifest_plugin_version != pin.plugin_version
            or manifest_core_api_version != pin.core_api_version
            or tuple(sorted(executor._declared_capabilities)) != pin.capabilities
        ):
            raise PluginCapabilityBindingError(
                "plug-in manifest does not match the execution-plan pin"
            )
        actual_schema_digest = executor._schema_identity
        if actual_schema_digest != pin.schema_digest:
            raise PluginCapabilityBindingError(
                "plug-in schema does not match the execution-plan pin"
            )
        executor._bound_instance_id = pin.instance_id
        executor._bound_schema_digest = pin.schema_digest
        executor._bound_member_id = member_id
        return executor

    def _error(
        self,
        capability: PluginCapability,
        message: str,
        *,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> PluginCapabilityOutputError:
        return PluginCapabilityOutputError(
            message,
            capability=capability,
            diagnostics=diagnostics,
        )

    def _input_error(
        self,
        capability: PluginCapability,
        message: str,
        *,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> PluginCapabilityInputError:
        return PluginCapabilityInputError(
            message,
            capability=capability,
            diagnostics=diagnostics,
        )

    def _validate_caller_input(
        self,
        capability: PluginCapability,
        validator: Callable[[], Any],
        *,
        unreadable_message: str,
    ) -> None:
        """Validate core-owned request data before any plug-in hook is invoked."""

        try:
            validator()
        except PluginCapabilityInputError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise self._input_error(capability, str(error)) from error
        except BaseException as error:
            raise self._input_error(capability, unreadable_message) from error

    def _snapshot_caller_input(
        self,
        capability: PluginCapability,
        snapshotter: Callable[[], Any],
        *,
        unreadable_message: str,
    ) -> Any:
        """Return a detached authority snapshot or a caller-input error."""

        try:
            return snapshotter()
        except PluginCapabilityInputError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise self._input_error(capability, str(error)) from error
        except BaseException as error:
            raise self._input_error(capability, unreadable_message) from error

    def _require(
        self,
        capability: PluginCapability,
        hook_name: str,
    ) -> Callable[..., Any]:
        if capability.value not in self._declared_capabilities:
            raise PluginCapabilityUnavailableError(
                f"plug-in does not advertise {capability.value!r}",
                capability=capability,
            )
        try:
            hook = getattr(self.plugin, hook_name, None)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "plug-in capability hook could not be resolved",
            ) from error
        if not callable(hook):
            raise PluginCapabilityUnavailableError(
                f"plug-in capability {capability.value!r} has no {hook_name}() hook",
                capability=capability,
            )
        return hook

    def _resource(self, value: Any, label: str) -> ResourceKey:
        if type(value) is not ResourceKey:
            raise ValueError(f"{label} must be an exact ResourceKey")
        expected = self._schema.key_fields_by_kind.get(value.kind)
        if expected is None:
            raise ValueError(
                f"{label} references undeclared resource kind {value.kind!r}"
            )
        actual = tuple(name for name, _item in value.parts)
        if actual != expected:
            raise ValueError(
                f"{label} key fields do not match the declared order for "
                f"{value.kind!r}"
            )
        return value

    def _evidence(self, value: Any, label: str) -> Evidence:
        if type(value) is not Evidence:
            raise ValueError(f"{label} must be an exact Evidence")
        if not isinstance(value.artifact_id, UUID):
            raise TypeError(f"{label}.artifact_id must be a UUID")
        if (
            not isinstance(value.locator, str)
            or not value.locator
            or len(value.locator) > 4_096
        ):
            raise ValueError(f"{label}.locator must contain 1 to 4096 characters")
        self._optional_time(
            value.raw_timestamp_ns,
            f"{label}.raw_timestamp_ns",
        )
        if value.clock_domain is not None and (
            not isinstance(value.clock_domain, str)
            or not value.clock_domain
            or len(value.clock_domain) > 256
        ):
            raise ValueError(
                f"{label}.clock_domain must contain 1 to 256 characters or be None"
            )
        if value.excerpt_sha256 is not None and (
            not isinstance(value.excerpt_sha256, str)
            or len(value.excerpt_sha256) != 64
            or any(
                character not in "0123456789abcdefABCDEF"
                for character in value.excerpt_sha256
            )
        ):
            raise ValueError(f"{label}.excerpt_sha256 must be a 64-digit hex digest")
        return value

    def _evidence_tuple(self, value: Any, label: str) -> tuple[Evidence, ...]:
        if not isinstance(value, tuple):
            raise TypeError(f"{label} must be a tuple")
        if len(value) > self.limits.max_evidence_per_output:
            raise ValueError(f"{label} exceeds the configured evidence limit")
        for index, item in enumerate(value):
            self._evidence(item, f"{label}[{index}]")
        return cast(tuple[Evidence, ...], value)

    def _diagnostic(self, value: Any, label: str) -> PluginDiagnostic:
        diagnostic = validate_plugin_diagnostic(
            value,
            label=label,
            expected_origin=DiagnosticOrigin.PLUGIN,
            maximum_evidence_items=self.limits.max_evidence_per_output,
        )
        return PluginDiagnostic(
            stage=DiagnosticStage(diagnostic.stage),
            severity=DiagnosticSeverity(diagnostic.severity),
            code=diagnostic.code,
            message=diagnostic.message,
            recoverable=diagnostic.recoverable,
            evidence=_snapshot_evidence_items(
                diagnostic.evidence,
                f"{label}.evidence",
            ),
            details=_snapshot_property_value(
                diagnostic.details,
                f"{label}.details",
            ),
            origin=DiagnosticOrigin(diagnostic.origin),
        )

    def _diagnostics(
        self,
        values: Any,
        capability: PluginCapability,
        label: str,
    ) -> tuple[PluginDiagnostic, ...]:
        if not isinstance(values, tuple):
            raise self._error(capability, f"{label} must be a tuple")
        if len(values) > self.limits.max_diagnostics:
            raise self._error(
                capability,
                f"{label} exceeds the configured diagnostic limit",
            )
        diagnostics: list[PluginDiagnostic] = []
        try:
            for index, value in enumerate(values):
                diagnostic = self._diagnostic(value, f"{label}[{index}]")
                diagnostics.append(diagnostic)
                if not diagnostic.recoverable:
                    raise self._error(
                        capability,
                        f"{label} failed: {diagnostic.code}: {diagnostic.message}",
                        diagnostics=tuple(diagnostics),
                    )
        except PluginCapabilityExecutionError:
            raise
        except (TypeError, ValueError) as error:
            raise self._error(capability, str(error)) from error
        return tuple(diagnostics)

    def _perspective(
        self,
        value: StatusPerspectiveRef | None,
        label: str,
        *,
        require_bound_qualifiers: bool = False,
    ) -> None:
        if value is None:
            return
        if type(value) is not StatusPerspectiveRef:
            raise ValueError(f"{label} must be an exact StatusPerspectiveRef")
        if value.perspective_id not in self._schema.perspectives:
            raise ValueError(
                f"{label} references undeclared perspective "
                f"{value.perspective_id!r}"
            )
        if (
            value.plugin_instance_id is not None
            and self._bound_instance_id is not None
            and value.plugin_instance_id != self._bound_instance_id
        ):
            raise ValueError(
                f"{label} references a different plug-in instance"
            )
        if (
            require_bound_qualifiers
            and self._bound_instance_id is not None
            and value.plugin_instance_id != self._bound_instance_id
        ):
            raise ValueError(
                f"{label} must identify the bound plug-in instance"
            )
        if (
            value.schema_digest is not None
            and self._bound_schema_digest is not None
            and value.schema_digest != self._bound_schema_digest
        ):
            raise ValueError(f"{label} references a different schema")
        if (
            require_bound_qualifiers
            and self._bound_schema_digest is not None
            and value.schema_digest != self._bound_schema_digest
        ):
            raise ValueError(f"{label} must identify the bound schema")

    def _bounded_world(
        self,
        world: ReadOnlyWorld,
        capability: PluginCapability,
        maximum_reads: int,
        *,
        expected_perspective_id: str | None = None,
    ) -> ReadOnlyWorld:
        """Validate and snapshot a core-owned world before a plug-in sees it."""

        snapshot: list[Any] = []

        def validate_world() -> None:
            basis = world.basis
            perspective_ref = world.perspective_ref
            self._world_basis(basis, "world.basis")
            if expected_perspective_id is not None and perspective_ref is None:
                raise ValueError(
                    "world.perspective_ref is required for a perspective-specific request"
                )
            self._perspective(
                perspective_ref,
                "world.perspective_ref",
                require_bound_qualifiers=expected_perspective_id is not None,
            )
            if (
                expected_perspective_id is not None
                and perspective_ref is not None
                and perspective_ref.perspective_id != expected_perspective_id
            ):
                raise ValueError(
                    "world.perspective_ref does not match the requested perspective"
                )
            snapshot.extend((basis, perspective_ref))

        self._validate_caller_input(
            capability,
            validate_world,
            unreadable_message="world binding could not be validated",
        )
        basis, perspective_ref = snapshot
        return cast(
            ReadOnlyWorld,
            _BoundedWorld(
                world,
                maximum_reads,
                capability,
                basis=cast(WorldBasis, basis),
                perspective_ref=cast(StatusPerspectiveRef | None, perspective_ref),
            ),
        )

    def _patch(
        self,
        value: Any,
        label: str,
        *,
        resource_kind: str | None = None,
    ) -> PropertyPatch:
        if type(value) is not PropertyPatch:
            raise ValueError(f"{label} must be an exact PropertyPatch")
        if len(value.set_values) > 1_024:
            raise ValueError(f"{label}.set_values exceeds 1024 entries")
        _validate_value(value.set_values, f"{label}.set_values")
        if not isinstance(value.remove_fields, tuple) or len(value.remove_fields) > 1_024:
            raise ValueError(f"{label}.remove_fields must be a bounded tuple")
        if not isinstance(value.unknown_fields, tuple) or len(value.unknown_fields) > 1_024:
            raise ValueError(f"{label}.unknown_fields must be a bounded tuple")
        mentioned = {
            *(str(name).split(".", 1)[0] for name in value.set_values),
            *(str(name).split(".", 1)[0] for name in value.remove_fields),
            *(
                str(unknown.name).split(".", 1)[0]
                for unknown in value.unknown_fields
            ),
        }
        if resource_kind is not None:
            allowed = self._schema.property_roots_by_kind[resource_kind]
            if unknown_roots := mentioned - allowed:
                raise ValueError(
                    f"{label} references undeclared properties: "
                    + ", ".join(sorted(unknown_roots))
                )
        for field_name in value.remove_fields:
            if not isinstance(field_name, str) or not field_name:
                raise ValueError(f"{label}.remove_fields contains an invalid name")
        for index, unknown_field in enumerate(value.unknown_fields):
            if type(unknown_field) is not UnknownField:
                raise ValueError(
                    f"{label}.unknown_fields[{index}] must be an exact UnknownField"
                )
            self._evidence_tuple(
                unknown_field.evidence,
                f"{label}.unknown_fields[{index}].evidence",
            )
        if type(value.complete) is not bool:
            raise ValueError(f"{label}.complete must be a boolean")
        return value

    @staticmethod
    def _enum(value: Any, enum_type: type[Enum], label: str) -> None:
        if not isinstance(value, enum_type):
            raise TypeError(f"{label} is invalid")

    @staticmethod
    def _optional_time(value: Any, label: str, *, nonnegative: bool = False) -> None:
        if value is None:
            return
        minimum = 0 if nonnegative else MIN_TIMESTAMP_NS
        if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP_NS:
            qualifier = "a non-negative " if nonnegative else "a "
            raise ValueError(
                f"{label} must be {qualifier}signed 64-bit integer or None"
            )

    def _common_fact(
        self,
        *,
        provenance: Any,
        quality: Any,
        evidence: Any,
        label: str,
    ) -> None:
        self._enum(provenance, Provenance, f"{label}.provenance")
        self._enum(quality, Quality, f"{label}.quality")
        self._evidence_tuple(evidence, f"{label}.evidence")

    def _relationship_mutation(
        self,
        value: Any,
        label: str,
    ) -> RelationshipMutation:
        if type(value) is not RelationshipMutation:
            raise ValueError(f"{label} must be an exact RelationshipMutation")
        self._resource(value.source, f"{label}.source")
        self._resource(value.target, f"{label}.target")
        if value.relation_type not in self._schema.relationship_types:
            raise ValueError(
                f"{label} references undeclared relationship type "
                f"{value.relation_type!r}"
            )
        self._enum(value.operation, RelationshipOperation, f"{label}.operation")
        self._patch(value.attributes, f"{label}.attributes")
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        self._perspective(value.perspective_ref, f"{label}.perspective_ref")
        return value

    @staticmethod
    def _event_uid(value: Any, label: str) -> bytes:
        if not isinstance(value, bytes) or not 1 <= len(value) <= 64:
            raise ValueError(f"{label} must contain 1 to 64 bytes")
        return value

    def _causal_link(self, value: Any, label: str) -> CausalLink:
        if type(value) is not CausalLink:
            raise ValueError(f"{label} must be an exact CausalLink")
        self._event_uid(value.source_event_uid, f"{label}.source_event_uid")
        self._event_uid(value.target_event_uid, f"{label}.target_event_uid")
        if value.link_type not in self._schema.causal_link_types:
            raise ValueError(
                f"{label} references undeclared causal link type "
                f"{value.link_type!r}"
            )
        if (
            isinstance(value.confidence, bool)
            or not isinstance(value.confidence, (int, float))
            or not isfinite(float(value.confidence))
            or not 0 <= float(value.confidence) <= 1
        ):
            raise ValueError(f"{label}.confidence must be finite and between 0 and 1")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        return value

    def _clock_anchor(self, value: Any, label: str) -> ClockAnchor:
        if type(value) is not ClockAnchor:
            raise ValueError(f"{label} must be an exact ClockAnchor")
        for field_name, clock_text in (
            ("left_clock_domain", value.left_clock_domain),
            ("right_clock_domain", value.right_clock_domain),
            ("method", value.method),
        ):
            if (
                not isinstance(clock_text, str)
                or not clock_text
                or len(clock_text) > 256
            ):
                raise ValueError(
                    f"{label}.{field_name} must contain 1 to 256 characters"
                )
        for field_name, clock_ns in (
            ("left_raw_ns", value.left_raw_ns),
            ("right_raw_ns", value.right_raw_ns),
        ):
            if type(clock_ns) is not int:
                raise ValueError(f"{label}.{field_name} must be an integer")
            self._optional_time(clock_ns, f"{label}.{field_name}")
        if type(value.uncertainty_ns) is not int:
            raise ValueError(f"{label}.uncertainty_ns must be non-negative")
        self._optional_time(
            value.uncertainty_ns,
            f"{label}.uncertainty_ns",
            nonnegative=True,
        )
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        return value

    def _state_mutation(self, value: Any, label: str) -> StateMutation:
        if type(value) is not StateMutation:
            raise ValueError(f"{label} must be an exact StateMutation")
        resource = self._resource(value.resource, f"{label}.resource")
        self._enum(value.operation, MutationOperation, f"{label}.operation")
        if value.before is not None:
            self._patch(
                value.before,
                f"{label}.before",
                resource_kind=resource.kind,
            )
        if value.after is not None:
            self._patch(
                value.after,
                f"{label}.after",
                resource_kind=resource.kind,
            )
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        _validate_value(value.condition, f"{label}.condition")
        self._perspective(value.perspective_ref, f"{label}.perspective_ref")
        return value

    def _unknown_change(self, value: Any, label: str) -> UnknownChange:
        if type(value) is not UnknownChange:
            raise ValueError(f"{label} must be an exact UnknownChange")
        for field_name, field_value, maximum in (
            ("change_kind", value.change_kind, 128),
            ("reason_code", value.reason_code, 128),
            ("message", value.message, 8_192),
        ):
            if (
                not isinstance(field_value, str)
                or not field_value
                or len(field_value) > maximum
            ):
                raise ValueError(
                    f"{label}.{field_name} must contain 1 to {maximum} characters"
                )
        if (
            not isinstance(value.affected_resources, tuple)
            or len(value.affected_resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.affected_resources must be a bounded tuple")
        for index, resource in enumerate(value.affected_resources):
            self._resource(resource, f"{label}.affected_resources[{index}]")
        if not isinstance(value.affected_fields, tuple) or len(
            value.affected_fields
        ) > self.limits.max_resource_references:
            raise ValueError(f"{label}.affected_fields must be a bounded tuple")
        if (
            value.relation_type is not None
            and value.relation_type not in self._schema.relationship_types
        ):
            raise ValueError(
                f"{label} references undeclared relationship type "
                f"{value.relation_type!r}"
            )
        self._evidence_tuple(value.evidence, f"{label}.evidence")
        return value

    def _coverage(self, value: Any, label: str) -> ReconstructionCoverage:
        if type(value) is not ReconstructionCoverage:
            raise ValueError(f"{label} must be an exact ReconstructionCoverage")
        if (
            not isinstance(value.scope, str)
            or not value.scope
            or len(value.scope) > 256
        ):
            raise ValueError(f"{label}.scope must contain 1 to 256 characters")
        for field_name in (
            "exact_outputs",
            "best_effort_outputs",
            "ambiguous_outputs",
            "unknown_outputs",
        ):
            field_value = getattr(value, field_name)
            if type(field_value) is not int or not 0 <= field_value <= 2**63 - 1:
                raise ValueError(f"{label}.{field_name} must be non-negative")
        return value

    def _change_set(
        self,
        value: Any,
        capability: PluginCapability,
    ) -> ChangeSet:
        if type(value) is not ChangeSet:
            raise self._error(capability, "hook must return an exact ChangeSet")
        collections: tuple[tuple[str, Any, type[Any], Callable[[Any, str], Any]], ...] = (
            ("state", value.state, StateMutation, self._state_mutation),
            (
                "relationships",
                value.relationships,
                RelationshipMutation,
                self._relationship_mutation,
            ),
            ("causal_links", value.causal_links, CausalLink, self._causal_link),
            ("unknowns", value.unknowns, UnknownChange, self._unknown_change),
            (
                "coverage",
                value.coverage,
                ReconstructionCoverage,
                self._coverage,
            ),
        )
        total = len(value.diagnostics) if isinstance(value.diagnostics, tuple) else 0
        try:
            for name, items, item_type, validator in collections:
                if not isinstance(items, tuple):
                    raise TypeError(f"ChangeSet.{name} must be a tuple")
                total += len(items)
                if any(type(item) is not item_type for item in items):
                    raise ValueError(
                        f"ChangeSet.{name} contains an unsupported output"
                    )
                for index, item in enumerate(items):
                    validator(item, f"ChangeSet.{name}[{index}]")
            if total > self.limits.max_change_items:
                raise ValueError("ChangeSet exceeds the configured item limit")
            self._diagnostics(
                value.diagnostics,
                capability,
                "ChangeSet.diagnostics",
            )
        except PluginCapabilityExecutionError:
            raise
        except (TypeError, ValueError) as error:
            raise self._error(capability, str(error)) from error
        return value

    def _event(self, value: Any, label: str) -> DomainEvent:
        if type(value) is not DomainEvent:
            raise ValueError(f"{label} must be an exact DomainEvent")
        self._event_uid(value.event_uid, f"{label}.event_uid")
        _validate_value(value.attributes, f"{label}.attributes")
        if (
            not isinstance(value.subjects, tuple)
            or len(value.subjects) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.subjects must be a bounded tuple")
        for index, resource in enumerate(value.subjects):
            self._resource(resource, f"{label}.subjects[{index}]")
        self._evidence(value.evidence, f"{label}.evidence")
        return value

    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet:
        capability = PluginCapability.EVENT_REDUCTION
        self._validate_caller_input(
            capability,
            lambda: self._event(event, "event"),
            unreadable_message="event could not be validated",
        )
        bounded_world = self._bounded_world(
            world,
            capability,
            self.limits.max_world_reads,
        )
        hook = self._require(capability, "apply")
        try:
            result = hook(event, bounded_world)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(capability, "apply() failed inside plug-in") from error
        try:
            return self._change_set(result, capability)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "apply() returned an unreadable result",
            ) from error

    def revert(
        self,
        event: DomainEvent,
        world_after: ReadOnlyWorld,
    ) -> ChangeSet:
        capability = PluginCapability.EVENT_REVERSION
        self._validate_caller_input(
            capability,
            lambda: self._event(event, "event"),
            unreadable_message="event could not be validated",
        )
        bounded_world = self._bounded_world(
            world_after,
            capability,
            self.limits.max_world_reads,
        )
        hook = self._require(capability, "revert")
        try:
            result = hook(event, bounded_world)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(capability, "revert() failed inside plug-in") from error
        try:
            return self._change_set(result, capability)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "revert() returned an unreadable result",
            ) from error

    def _consume(
        self,
        capability: PluginCapability,
        outputs: Iterable[Any],
        *,
        maximum: int,
        allowed: tuple[type[Any], ...],
        validator: Callable[[Any, str], None],
        detacher: Callable[[Any], Any] | None = None,
    ) -> tuple[tuple[Any, ...], tuple[PluginDiagnostic, ...]]:
        values: list[Any] = []
        diagnostics: list[PluginDiagnostic] = []
        try:
            iterator = iter(outputs)
        except TypeError as error:
            raise self._error(
                capability,
                "capability hook must return an iterable",
            ) from error
        try:
            for index, output in enumerate(iterator):
                if index >= maximum:
                    raise self._error(
                        capability,
                        "capability output exceeded the configured limit",
                        diagnostics=tuple(diagnostics),
                    )
                if type(output) is PluginDiagnostic:
                    try:
                        diagnostic = self._diagnostic(
                            output,
                            f"{capability.value}[{index}]",
                        )
                    except (TypeError, ValueError) as error:
                        raise self._error(capability, str(error)) from error
                    diagnostics.append(diagnostic)
                    if len(diagnostics) > self.limits.max_diagnostics:
                        raise self._error(
                            capability,
                            "capability output exceeded the diagnostic limit",
                            diagnostics=tuple(diagnostics),
                        )
                    if not diagnostic.recoverable:
                        raise self._error(
                            capability,
                            f"{capability.value} failed: {diagnostic.code}: "
                            f"{diagnostic.message}",
                            diagnostics=tuple(diagnostics),
                        )
                    continue
                if type(output) not in allowed:
                    raise self._error(
                        capability,
                        f"capability emitted unsupported {type(output).__name__}",
                        diagnostics=tuple(diagnostics),
                    )
                try:
                    validator(output, f"{capability.value}[{index}]")
                    detached_output = (
                        output if detacher is None else detacher(output)
                    )
                    if detacher is not None:
                        validator(
                            detached_output,
                            f"{capability.value}[{index}]",
                        )
                except (TypeError, ValueError) as error:
                    raise self._error(
                        capability,
                        str(error),
                        diagnostics=tuple(diagnostics),
                    ) from error
                values.append(detached_output)
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        return tuple(values), tuple(diagnostics)

    def correlate(
        self,
        reader: CorrelationReader,
        window: CorrelationWindow,
    ) -> CorrelationExecutionResult:
        capability = PluginCapability.CORRELATION
        if type(window) is not CorrelationWindow:
            raise self._input_error(
                capability,
                "window must be an exact CorrelationWindow",
            )

        def validate_window() -> None:
            self._optional_time(window.start_ns, "window.start_ns")
            self._optional_time(window.end_ns, "window.end_ns")
            if (
                window.start_ns is not None
                and window.end_ns is not None
                and window.start_ns > window.end_ns
            ):
                raise ValueError("window time bounds are reversed")
            if (
                type(window.max_events) is not int
                or not 1
                <= window.max_events
                <= self.limits.max_correlation_outputs
            ):
                raise ValueError("window max_events is outside core bounds")
            if (
                type(window.max_world_reads) is not int
                or not 1 <= window.max_world_reads <= self.limits.max_world_reads
            ):
                raise ValueError("window max_world_reads is outside core bounds")

        self._validate_caller_input(
            capability,
            validate_window,
            unreadable_message="correlation window could not be validated",
        )
        hook = self._require(capability, "correlate")
        maximum = min(window.max_events, self.limits.max_correlation_outputs)
        try:
            outputs = hook(reader, window)
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(CausalLink, RelationshipMutation, ClockAnchor),
                validator=self._validate_correlation_output,
            )
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "correlate() failed inside plug-in",
            ) from error
        return CorrelationExecutionResult(
            causal_links=tuple(
                item for item in values if type(item) is CausalLink
            ),
            relationship_mutations=tuple(
                item for item in values if type(item) is RelationshipMutation
            ),
            clock_anchors=tuple(
                item for item in values if type(item) is ClockAnchor
            ),
            diagnostics=diagnostics,
        )

    def _validate_correlation_output(self, value: Any, label: str) -> None:
        if type(value) is CausalLink:
            self._causal_link(value, label)
        elif type(value) is RelationshipMutation:
            self._relationship_mutation(value, label)
        else:
            self._clock_anchor(value, label)

    def _validate_evidence_analysis_observation(
        self,
        request: EvidenceAnalysisRequest,
        value: Any,
        label: str,
    ) -> None:
        if type(value) is not EvidenceAnalysisObservation:
            raise ValueError(
                f"{label} must be an exact EvidenceAnalysisObservation"
            )
        if (
            type(value.observation_id) is not str
            or not value.observation_id
            or len(value.observation_id) > 256
        ):
            raise ValueError(f"{label}.observation_id must contain 1 to 256 characters")
        if (
            type(value.category) is not str
            or not value.category
            or len(value.category) > 256
        ):
            raise ValueError(f"{label}.category must contain 1 to 256 characters")
        if (
            type(value.summary) is not str
            or not 1 <= len(value.summary) <= 8_192
        ):
            raise ValueError(f"{label}.summary must contain 1 to 8192 characters")
        if type(value.cited_reference_digests) is not tuple:
            raise TypeError(f"{label}.cited_reference_digests must be a tuple")
        if (
            not value.cited_reference_digests
            or len(value.cited_reference_digests) > 256
            or tuple(sorted(value.cited_reference_digests))
            != value.cited_reference_digests
            or len(set(value.cited_reference_digests))
            != len(value.cited_reference_digests)
        ):
            raise ValueError(
                f"{label}.cited_reference_digests must be 1 to 256 unique "
                "canonically ordered values"
            )
        admitted = {fact.reference_digest for fact in request.facts}
        if any(
            digest not in admitted for digest in value.cited_reference_digests
        ):
            raise ValueError(f"{label} cites evidence outside its request")
        self._enum(value.quality, Quality, f"{label}.quality")
        _validate_value(value.details, f"{label}.details")

    def analyze_evidence(
        self,
        request: EvidenceAnalysisRequest,
    ) -> EvidenceAnalysisExecutionResult:
        capability = PluginCapability.EVIDENCE_ANALYSIS
        if type(request) is not EvidenceAnalysisRequest:
            raise self._input_error(
                capability,
                "request must be an exact EvidenceAnalysisRequest",
            )
        try:
            request = EvidenceAnalysisRequest(
                invocation_id=request.invocation_id,
                analysis_kind=request.analysis_kind,
                facts=request.facts,
                parameters=_evidence_analysis_json_projection(request.parameters),
                max_observations=request.max_observations,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise self._input_error(capability, str(error)) from error
        except BaseException as error:
            raise self._input_error(
                capability,
                "evidence analysis request could not be detached",
            ) from error

        def validate_request() -> None:
            if (
                type(request.invocation_id) is not str
                or not request.invocation_id
                or len(request.invocation_id) > 256
            ):
                raise ValueError(
                    "request.invocation_id must contain 1 to 256 characters"
                )
            self._enum(
                request.analysis_kind,
                EvidenceAnalysisKind,
                "request.analysis_kind",
            )
            if (
                type(request.facts) is not tuple
                or not request.facts
                or len(request.facts) > 256
            ):
                raise ValueError("request.facts must contain 1 to 256 facts")
            digests: set[str] = set()
            for index, fact in enumerate(request.facts):
                if type(fact) is not EvidenceAnalysisFact:
                    raise TypeError(
                        f"request.facts[{index}] must be an exact "
                        "EvidenceAnalysisFact"
                    )
                if fact.reference_digest in digests:
                    raise ValueError("request.facts must have unique references")
                digests.add(fact.reference_digest)
                for field_name in (
                    "evidence_kind",
                    "subject_kind",
                    "node_id",
                    "revision_id",
                    "payload_schema",
                    "fact_provenance",
                    "time_basis",
                ):
                    field_value = getattr(fact, field_name)
                    if (
                        type(field_value) is not str
                        or not field_value
                        or len(field_value) > 256
                    ):
                        raise ValueError(
                            f"request.facts[{index}].{field_name} is invalid"
                        )
                self._optional_time(
                    fact.time_start_ns,
                    f"request.facts[{index}].time_start_ns",
                )
                self._optional_time(
                    fact.time_end_ns,
                    f"request.facts[{index}].time_end_ns",
                )
                if (fact.time_start_ns is None) != (fact.time_end_ns is None):
                    raise ValueError(
                        f"request.facts[{index}] time bounds disagree"
                    )
                if (
                    fact.time_start_ns is not None
                    and fact.time_end_ns is not None
                    and fact.time_start_ns > fact.time_end_ns
                ):
                    raise ValueError(
                        f"request.facts[{index}] time bounds are reversed"
                    )
                if fact.time_clock_domain is not None and (
                    type(fact.time_clock_domain) is not str
                    or not fact.time_clock_domain
                    or len(fact.time_clock_domain) > 256
                ):
                    raise ValueError(
                        f"request.facts[{index}].time_clock_domain is invalid"
                    )
                _validate_value(fact.payload, f"request.facts[{index}].payload")
            _validate_value(request.parameters, "request.parameters")
            input_bytes = len(
                strict_canonical_json(
                    {
                        "facts": [
                            {
                                "reference_digest": fact.reference_digest,
                                "evidence_kind": fact.evidence_kind,
                                "subject_kind": fact.subject_kind,
                                "node_id": fact.node_id,
                                "revision_id": fact.revision_id,
                                "payload_schema": fact.payload_schema,
                                "fact_provenance": fact.fact_provenance,
                                "time_basis": fact.time_basis,
                                "time_start_ns": fact.time_start_ns,
                                "time_end_ns": fact.time_end_ns,
                                "time_clock_domain": fact.time_clock_domain,
                                "payload": _evidence_analysis_json_projection(
                                    fact.payload
                                ),
                            }
                            for fact in request.facts
                        ],
                        "parameters": _evidence_analysis_json_projection(
                            request.parameters
                        ),
                    }
                ).encode("utf-8")
            )
            if input_bytes > self.limits.max_evidence_analysis_input_bytes:
                raise ValueError("evidence analysis input exceeds its byte limit")
            if (
                type(request.max_observations) is not int
                or not 1
                <= request.max_observations
                <= self.limits.max_evidence_analysis_outputs
            ):
                raise ValueError("request.max_observations is outside core bounds")

        self._validate_caller_input(
            capability,
            validate_request,
            unreadable_message="evidence analysis request could not be validated",
        )
        hook = self._require(capability, "analyze_evidence")
        maximum = min(
            request.max_observations,
            self.limits.max_evidence_analysis_outputs,
        )
        hook_request = EvidenceAnalysisRequest(
            invocation_id=request.invocation_id,
            analysis_kind=request.analysis_kind,
            facts=request.facts,
            parameters=_evidence_analysis_json_projection(request.parameters),
            max_observations=request.max_observations,
        )

        def detach_observation(value: Any) -> EvidenceAnalysisObservation:
            return EvidenceAnalysisObservation(
                observation_id=value.observation_id,
                category=value.category,
                summary=value.summary,
                cited_reference_digests=value.cited_reference_digests,
                quality=value.quality,
                details=_evidence_analysis_json_projection(value.details),
            )

        try:
            outputs = hook(hook_request)
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(EvidenceAnalysisObservation,),
                validator=lambda value, label: (
                    self._validate_evidence_analysis_observation(
                        request,
                        value,
                        label,
                    )
                ),
                detacher=detach_observation,
            )
            observation_ids = tuple(value.observation_id for value in values)
            if (
                tuple(sorted(observation_ids)) != observation_ids
                or len(set(observation_ids)) != len(observation_ids)
            ):
                raise self._error(
                    capability,
                    "evidence analysis observation IDs must be unique and "
                    "canonically ordered",
                    diagnostics=diagnostics,
                )
            output_bytes = len(
                strict_canonical_json(
                    [
                        {
                            "observation_id": value.observation_id,
                            "category": value.category,
                            "summary": value.summary,
                            "cited_reference_digests": list(
                                value.cited_reference_digests
                            ),
                            "quality": value.quality.value,
                            "details": _evidence_analysis_json_projection(
                                value.details
                            ),
                        }
                        for value in values
                    ]
                ).encode("utf-8")
            )
            if output_bytes > self.limits.max_evidence_analysis_output_bytes:
                raise self._error(
                    capability,
                    "evidence analysis output exceeds its byte limit",
                    diagnostics=diagnostics,
                )
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "analyze_evidence() failed inside plug-in",
            ) from error
        return EvidenceAnalysisExecutionResult(
            observations=cast(tuple[EvidenceAnalysisObservation, ...], values),
            diagnostics=diagnostics,
        )

    def _world_basis(self, value: Any, label: str) -> WorldBasis:
        if type(value) is not WorldBasis:
            raise ValueError(f"{label} must be an exact WorldBasis")
        self._enum(value.kind, WorldBasisKind, f"{label}.kind")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        for field_name in (
            "requested_time_ns",
            "resolved_at_min_ns",
            "resolved_at_max_ns",
        ):
            self._optional_time(getattr(value, field_name), f"{label}.{field_name}")
        if (
            value.resolved_at_min_ns is not None
            and value.resolved_at_max_ns is not None
            and value.resolved_at_min_ns > value.resolved_at_max_ns
        ):
            raise ValueError(f"{label} resolved bounds are reversed")
        if not isinstance(value.capture_ranges, tuple) or len(
            value.capture_ranges
        ) > 1_024:
            raise ValueError(f"{label}.capture_ranges must be a bounded tuple")
        for index, item in enumerate(value.capture_ranges):
            if type(item) is not CaptureRange:
                raise ValueError(
                    f"{label}.capture_ranges[{index}] must be an exact CaptureRange"
                )
            self._optional_time(
                item.observed_at_min_ns,
                f"{label}.capture_ranges[{index}].observed_at_min_ns",
            )
            self._optional_time(
                item.observed_at_max_ns,
                f"{label}.capture_ranges[{index}].observed_at_max_ns",
            )
            if (
                item.observed_at_min_ns is not None
                and item.observed_at_max_ns is not None
                and item.observed_at_min_ns > item.observed_at_max_ns
            ):
                raise ValueError(
                    f"{label}.capture_ranges[{index}] bounds are reversed"
                )
            self._evidence_tuple(
                item.evidence,
                f"{label}.capture_ranges[{index}].evidence",
            )
        selector = value.selector
        if selector is not None:
            if type(selector) is AbsoluteTimeSelector:
                self._optional_time(
                    selector.time_ns,
                    f"{label}.selector.time_ns",
                )
            elif type(selector) is RelativeToWatermarkSelector:
                self._optional_time(
                    selector.offset_ns,
                    f"{label}.selector.offset_ns",
                )
                if selector.offset_ns > 0:
                    raise ValueError(
                        f"{label}.selector.offset_ns must be zero or negative"
                    )
            else:
                raise ValueError(f"{label}.selector is invalid")
        if not isinstance(value.node_resolutions, tuple):
            raise TypeError(f"{label}.node_resolutions must be a tuple")
        for index, resolution in enumerate(value.node_resolutions):
            if type(resolution) is not ResolvedNodeBasis:
                raise ValueError(
                    f"{label}.node_resolutions[{index}] must be an exact "
                    "ResolvedNodeBasis"
                )
            for field_name in (
                "local_min_ns",
                "local_max_ns",
                "absolute_min_ns",
                "absolute_max_ns",
            ):
                self._optional_time(
                    getattr(resolution, field_name),
                    f"{label}.node_resolutions[{index}].{field_name}",
                )
        watermark = value.watermark
        if watermark is not None:
            if type(watermark) is not ReconstructionWatermark:
                raise ValueError(
                    f"{label}.watermark must be an exact ReconstructionWatermark"
                )
            self._optional_time(
                watermark.local_time_ns,
                f"{label}.watermark.local_time_ns",
            )
            self._optional_time(
                watermark.absolute_min_ns,
                f"{label}.watermark.absolute_min_ns",
            )
            self._optional_time(
                watermark.absolute_max_ns,
                f"{label}.watermark.absolute_max_ns",
            )
        return value

    def _finding(self, value: Any, label: str) -> None:
        if type(value) is not ConsistencyFinding:
            raise ValueError(f"{label} must be an exact ConsistencyFinding")
        if (
            not isinstance(value.rule_id, str)
            or not value.rule_id
            or len(value.rule_id) > 256
        ):
            raise ValueError(f"{label}.rule_id must contain 1 to 256 characters")
        self._enum(value.severity, DiagnosticSeverity, f"{label}.severity")
        self._enum(value.result, FindingResult, f"{label}.result")
        if (
            not isinstance(value.summary, str)
            or not value.summary
            or len(value.summary) > 8_192
        ):
            raise ValueError(f"{label}.summary must contain 1 to 8192 characters")
        if (
            not isinstance(value.resources, tuple)
            or len(value.resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.resources must be a bounded tuple")
        for index, resource in enumerate(value.resources):
            self._resource(resource, f"{label}.resources[{index}]")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        self._world_basis(value.basis, f"{label}.basis")
        _validate_value(value.details, f"{label}.details")

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> ConsistencyExecutionResult:
        capability = PluginCapability.CONSISTENCY_CHECK
        bounded_world = self._bounded_world(
            world,
            capability,
            self.limits.max_world_reads,
        )
        hook = self._require(capability, "check_consistency")
        try:
            outputs = hook(bounded_world)
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=self.limits.max_consistency_outputs,
                allowed=(ConsistencyFinding,),
                validator=self._finding,
            )
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "check_consistency() failed inside plug-in",
            ) from error
        return ConsistencyExecutionResult(
            findings=cast(tuple[ConsistencyFinding, ...], values),
            diagnostics=diagnostics,
        )

    def _topology_reference(
        self,
        value: Any,
        label: str,
    ) -> TopologyEndpointReference:
        if type(value) is not TopologyEndpointReference:
            raise ValueError(f"{label} must be an exact TopologyEndpointReference")
        if value.resource is not None:
            self._resource(value.resource, f"{label}.resource")
        else:
            assert value.match is not None
            _validate_value(value.match.arguments, f"{label}.match.arguments")
            if len(value.match.resolved_candidates) > self.limits.max_resource_references:
                raise ValueError(
                    f"{label}.match.resolved_candidates exceeds the reference limit"
                )
            for index, resource in enumerate(value.match.resolved_candidates):
                self._resource(
                    resource,
                    f"{label}.match.resolved_candidates[{index}]",
                )
        return value

    def _topology_record(
        self,
        request: TopologyProjectionRequest,
        value: Any,
        label: str,
    ) -> None:
        if type(value) is not TopologyProjectionRecord:
            raise ValueError(f"{label} must be an exact TopologyProjectionRecord")
        if value.projection_id != request.projection_id:
            raise ValueError(f"{label}.projection_id does not match the request")
        if value.status_perspective_id != request.status_perspective_id:
            raise ValueError(
                f"{label}.status_perspective_id does not match the request"
            )
        self._enum(value.usability, TopologyUsability, f"{label}.usability")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        if value.exists is not None and type(value.exists) is not bool:
            raise ValueError(f"{label}.exists must be a boolean or None")
        if (
            not isinstance(value.source_resources, tuple)
            or len(value.source_resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.source_resources must be a bounded tuple")
        for index, resource in enumerate(value.source_resources):
            self._resource(resource, f"{label}.source_resources[{index}]")
        payload = value.payload
        if type(payload) is TopologyResourceRecord:
            self._resource(payload.resource, f"{label}.payload.resource")
        elif type(payload) is TopologyEndpointRecord:
            self._topology_reference(payload.target, f"{label}.payload.target")
        elif type(payload) is TopologyLinkRecord:
            self._topology_reference(payload.source, f"{label}.payload.source")
            self._topology_reference(payload.target, f"{label}.payload.target")
        else:
            raise ValueError(f"{label}.payload is unsupported")
        _validate_value(value.properties, f"{label}.properties")
        if not isinstance(value.unknown_fields, tuple) or len(
            value.unknown_fields
        ) > 1_024:
            raise ValueError(f"{label}.unknown_fields must be a bounded tuple")
        for index, item in enumerate(value.unknown_fields):
            if type(item) is not UnknownField:
                raise ValueError(
                    f"{label}.unknown_fields[{index}] must be an exact UnknownField"
                )
            for field_name, field_value, maximum, allow_empty in (
                ("name", item.name, 1_024, False),
                ("reason_code", item.reason_code, 256, False),
                ("message", item.message, 8_192, True),
            ):
                if (
                    type(field_value) is not str
                    or len(field_value) > maximum
                    or (not allow_empty and not field_value)
                ):
                    raise ValueError(
                        f"{label}.unknown_fields[{index}].{field_name} is invalid"
                    )
            self._evidence_tuple(
                item.evidence,
                f"{label}.unknown_fields[{index}].evidence",
            )
        self._optional_time(value.valid_from_ns, f"{label}.valid_from_ns")
        self._optional_time(value.valid_to_ns, f"{label}.valid_to_ns")
        if (
            value.valid_from_ns is not None
            and value.valid_to_ns is not None
            and value.valid_from_ns > value.valid_to_ns
        ):
            raise ValueError(f"{label} validity bounds are reversed")
        self._evidence_tuple(value.evidence, f"{label}.evidence")

    def _connector_argument(
        self,
        value: Any,
        label: str,
        *,
        depth: int = 0,
    ) -> None:
        if depth > 4:
            raise ValueError(f"{label} exceeds four tuple levels")
        if type(value) in (int, str, bytes) or isinstance(value, UUID):
            return
        if type(value) is KeyAtom:
            KeyAtom.__post_init__(value)
            return
        if type(value) is tuple:
            if len(value) > 32:
                raise ValueError(f"{label} exceeds 32 tuple items")
            for index, item in enumerate(value):
                self._connector_argument(
                    item,
                    f"{label}[{index}]",
                    depth=depth + 1,
                )
            return
        raise ValueError(
            f"{label} must use exact KeyValue scalars, KeyAtom, or tuples"
        )

    def _connector_claim(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
        value: Any,
        label: str,
    ) -> ConnectorMatchPolicyDescriptor:
        if type(value) is not ConnectorClaim:
            raise ValueError(f"{label} must be an exact ConnectorClaim")
        ConnectorClaim.__post_init__(value)
        ResourceKey.__post_init__(value.endpoint)
        self._resource(value.endpoint, f"{label}.endpoint")
        policy = self._schema.connector_match_policies.get(value.match_policy_id)
        if policy is None:
            raise ValueError(
                f"{label}.match_policy_id references an undeclared connector "
                "match policy"
            )
        ConnectorMatchPolicyDescriptor.__post_init__(policy)
        if value.claim_contract_id != policy.claim_contract_id:
            raise ValueError(
                f"{label}.claim_contract_id does not match its declared policy"
            )
        argument_names = tuple(name for name, _argument in value.arguments)
        if argument_names != policy.argument_names:
            raise ValueError(
                f"{label}.arguments do not match the declared policy order"
            )
        for index, (_name, argument) in enumerate(value.arguments):
            self._connector_argument(argument, f"{label}.arguments[{index}][1]")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        if type(value.link_type) is not str:
            raise ValueError(f"{label}.link_type must be an exact string")
        if type(value.presentation) is not InterNodeLinkPresentation:
            raise ValueError(
                f"{label}.presentation must be an exact "
                "InterNodeLinkPresentation"
            )
        InterNodeLinkPresentation.__post_init__(value.presentation)
        perspective = value.status_perspective
        if perspective is not None:
            StatusPerspectiveRef.__post_init__(perspective)
            self._perspective(
                perspective,
                f"{label}.status_perspective",
                require_bound_qualifiers=True,
            )
            if perspective.perspective_id != request.status_perspective_id:
                raise ValueError(
                    f"{label}.status_perspective does not match the request"
                )
            if perspective != world.perspective_ref:
                raise ValueError(
                    f"{label}.status_perspective does not match the bounded world"
                )
        self._optional_time(value.valid_from_ns, f"{label}.valid_from_ns")
        self._optional_time(value.valid_to_ns, f"{label}.valid_to_ns")
        if (
            value.valid_from_ns is not None
            and value.valid_to_ns is not None
            and value.valid_from_ns > value.valid_to_ns
        ):
            raise ValueError(f"{label} validity bounds are reversed")
        self._evidence_tuple(value.evidence, f"{label}.evidence")
        return policy

    def _consume_topology(
        self,
        capability: PluginCapability,
        outputs: Iterable[Any],
        *,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
        maximum_records: int,
        maximum_claims: int,
    ) -> tuple[
        tuple[TopologyProjectionRecord, ...],
        tuple[ConnectorClaim, ...],
        tuple[ConnectorMatchPolicyDescriptor, ...],
        tuple[PluginDiagnostic, ...],
        frozenset[ResourceKey],
        bool,
        bool,
    ]:
        records: list[TopologyProjectionRecord] = []
        claims: list[ConnectorClaim] = []
        emitted_resources: set[ResourceKey] = set()
        policies_by_id: dict[str, ConnectorMatchPolicyDescriptor] = {}
        diagnostics: list[PluginDiagnostic] = []
        records_complete = True
        claims_complete = True
        try:
            iterator = iter(outputs)
        except TypeError as error:
            raise self._error(
                capability,
                "capability hook must return an iterable",
            ) from error

        # One extra typed output lets the executor distinguish an exactly full
        # result from a truncated stream. The aggregate scan ceiling prevents a
        # plug-in from hiding an unbounded run of one output category before the
        # other category while still permitting independently bounded results.
        maximum_scanned = (
            maximum_records
            + maximum_claims
            + self.limits.max_diagnostics
            + 1
        )
        exhausted = False
        try:
            for index, output in enumerate(iterator):
                if index >= maximum_scanned:
                    records_complete = False
                    claims_complete = False
                    break
                label = f"{capability.value}[{index}]"
                if type(output) is PluginDiagnostic:
                    try:
                        diagnostic = self._diagnostic(output, label)
                    except (TypeError, ValueError) as error:
                        raise self._error(capability, str(error)) from error
                    diagnostics.append(diagnostic)
                    if len(diagnostics) > self.limits.max_diagnostics:
                        raise self._error(
                            capability,
                            "capability output exceeded the diagnostic limit",
                            diagnostics=tuple(diagnostics),
                        )
                    if not diagnostic.recoverable:
                        raise self._error(
                            capability,
                            f"{capability.value} failed: {diagnostic.code}: "
                            f"{diagnostic.message}",
                            diagnostics=tuple(diagnostics),
                        )
                    continue
                try:
                    if type(output) is TopologyProjectionRecord:
                        self._topology_record(request, output, label)
                        detached_record = _snapshot_topology_record(output, label)
                        if type(detached_record.payload) is TopologyResourceRecord:
                            emitted_resources.add(detached_record.payload.resource)
                        if len(records) < maximum_records:
                            records.append(detached_record)
                        else:
                            records_complete = False
                    elif type(output) is ConnectorClaim:
                        policy = self._connector_claim(request, world, output, label)
                        detached_claim = _snapshot_connector_claim(output, label)
                        if len(claims) < maximum_claims:
                            claims.append(detached_claim)
                            policies_by_id[policy.policy_id] = policy
                        else:
                            claims_complete = False
                    else:
                        raise ValueError(
                            f"capability emitted unsupported {type(output).__name__}"
                        )
                except (TypeError, ValueError) as error:
                    raise self._error(
                        capability,
                        str(error),
                        diagnostics=tuple(diagnostics),
                    ) from error
            else:
                exhausted = True
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        if not exhausted:
            records_complete = False
            claims_complete = False
        claim_ids = [claim.claim_id for claim in claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise self._error(
                capability,
                "topology connector claim identifiers must be unique",
                diagnostics=tuple(diagnostics),
            )
        match_policies = tuple(
            policies_by_id[policy_id] for policy_id in sorted(policies_by_id)
        )
        return (
            tuple(records),
            tuple(claims),
            match_policies,
            tuple(diagnostics),
            frozenset(emitted_resources),
            records_complete,
            claims_complete,
        )

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> TopologyExecutionResult:
        capability = PluginCapability.TOPOLOGY_PROJECTION
        if type(request) is not TopologyProjectionRequest:
            raise self._input_error(
                capability,
                "request must be an exact TopologyProjectionRequest",
            )
        request = cast(
            TopologyProjectionRequest,
            self._snapshot_caller_input(
                capability,
                lambda: _snapshot_topology_projection_request(request, "request"),
                unreadable_message="topology request could not be snapshotted",
            ),
        )
        supported = self._schema.topology_perspectives.get(request.projection_id)
        if supported is None:
            raise self._input_error(
                capability,
                f"projection {request.projection_id!r} is not declared",
            )
        if request.status_perspective_id not in supported:
            raise self._input_error(
                capability,
                "requested status perspective is not supported by the projection",
            )

        def validate_request() -> None:
            for field_name, value, maximum in (
                ("max_records", request.max_records, 100_000),
                ("max_claims", request.max_claims, 100_000),
                ("max_world_reads", request.max_world_reads, 1_000_000),
            ):
                if type(value) is not int or not 1 <= value <= maximum:
                    raise ValueError(
                        f"request.{field_name} must be an integer between 1 and "
                        f"{maximum}"
                    )
            if (
                type(request.seed_resources) is not tuple
                or len(request.seed_resources) > self.limits.max_resource_references
            ):
                raise ValueError(
                    "request.seed_resources must be a bounded exact tuple"
                )
            if len(request.seed_resources) != len(set(request.seed_resources)):
                raise ValueError("request.seed_resources must be unique")
            for index, resource in enumerate(request.seed_resources):
                self._resource(resource, f"request.seed_resources[{index}]")

        self._validate_caller_input(
            capability,
            validate_request,
            unreadable_message="topology request could not be validated",
        )
        bounded_world = self._bounded_world(
            world,
            capability,
            min(request.max_world_reads, self.limits.max_world_reads),
            expected_perspective_id=request.status_perspective_id,
        )
        hook = self._require(capability, "project_topology")
        maximum_records = min(
            request.max_records,
            self.limits.max_topology_outputs,
        )
        maximum_claims = min(
            request.max_claims,
            self.limits.max_topology_claims,
        )
        hook_request = _snapshot_topology_projection_request(request, "request")
        try:
            outputs = hook(hook_request, bounded_world)
            (
                records,
                claims,
                match_policies,
                diagnostics,
                emitted_resources,
                records_complete,
                claims_complete,
            ) = self._consume_topology(
                capability,
                outputs,
                request=request,
                world=bounded_world,
                maximum_records=maximum_records,
                maximum_claims=maximum_claims,
            )
            checked_world_resources: set[ResourceKey] = set()
            for index, claim in enumerate(claims):
                endpoint = claim.endpoint
                if (
                    endpoint in emitted_resources
                    or endpoint in checked_world_resources
                ):
                    continue
                state = bounded_world.state_of(endpoint)
                if state is None:
                    raise self._error(
                        capability,
                        f"topology connector claim[{index}].endpoint is neither "
                        "an emitted topology resource nor present in the bounded world",
                        diagnostics=diagnostics,
                    )
                if type(state) is not ResourceStateView or state.resource != endpoint:
                    raise self._error(
                        capability,
                        f"topology connector claim[{index}].endpoint resolved to "
                        "an invalid bounded-world state",
                        diagnostics=diagnostics,
                    )
                checked_world_resources.add(endpoint)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "project_topology() failed inside plug-in",
            ) from error
        return TopologyExecutionResult(
            records=records,
            diagnostics=diagnostics,
            claims=claims,
            match_policies=match_policies,
            records_complete=records_complete,
            claims_complete=claims_complete,
        )

    def _supported_ir(
        self,
        capability: PluginCapability,
        ir_version: Any,
    ) -> str:
        if not isinstance(ir_version, str) or not ir_version:
            raise ValueError("forwarding IR version must be a string")
        if ir_version not in self._forwarding_ir_versions:
            raise ValueError(
                f"forwarding IR {ir_version!r} is not declared by the plug-in",
            )
        return ir_version

    def _nested_contract(
        self,
        value: Any,
        label: str,
        *,
        depth: int = 0,
        units: list[int] | None = None,
    ) -> None:
        """Walk typed forwarding records to validate every embedded ResourceKey."""

        budget = units or [0]
        budget[0] += 1
        if budget[0] > 20_000 or depth > 24:
            raise ValueError(f"{label} exceeds the nested contract limit")
        if type(value) is ResourceKey:
            self._resource(value, label)
            return
        if type(value) is Evidence:
            self._evidence(value, label)
            return
        if value is None or isinstance(value, (str, bytes, UUID, Enum)):
            return
        if type(value) in (bool, int):
            return
        if type(value) is float:
            if not isfinite(value):
                raise ValueError(f"{label} contains a non-finite float")
            return
        if isinstance(value, Mapping):
            _validate_value(value, label)
            return
        if isinstance(value, tuple):
            if len(value) > 4_096:
                raise ValueError(f"{label} exceeds 4096 items")
            for index, item in enumerate(value):
                self._nested_contract(
                    item,
                    f"{label}[{index}]",
                    depth=depth + 1,
                    units=budget,
                )
            return
        if is_dataclass(value):
            for contract_field in fields(value):
                self._nested_contract(
                    getattr(value, contract_field.name),
                    f"{label}.{contract_field.name}",
                    depth=depth + 1,
                    units=budget,
                )
            return
        raise ValueError(f"{label} contains unsupported type {type(value).__name__}")

    def _forwarding_mutation(
        self,
        request: ForwardingProjectionRequest,
        value: Any,
        label: str,
    ) -> None:
        if type(value) is not ForwardingMutation:
            raise ValueError(f"{label} must be an exact ForwardingMutation")
        self._enum(value.operation, ForwardingOperation, f"{label}.operation")
        self._resource(value.key, f"{label}.key")
        record_types = (
            FibEntry,
            NextHopGroup,
            NextHop,
            FailoverGroup,
            Adjacency,
            TunnelAction,
            InterfaceForwardingState,
            VrfForwardingState,
        )
        if value.operation is ForwardingOperation.UPSERT:
            if type(value.record) not in record_types:
                raise ValueError(f"{label}.record is not a supported forwarding record")
            assert value.record is not None
            if value.record.key != value.key:
                raise ValueError(f"{label}.record key does not match mutation key")
            self._nested_contract(value.record, f"{label}.record")
        elif value.record is not None:
            raise ValueError(f"{label} delete must not include a record")
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        self._world_basis(value.basis, f"{label}.basis")
        self._evidence_tuple(value.evidence, f"{label}.evidence")
        if value.ir_version != request.ir_version:
            raise ValueError(f"{label}.ir_version does not match the request")

    def project_forwarding(
        self,
        request: ForwardingProjectionRequest,
        world: ReadOnlyWorld,
    ) -> ForwardingProjectionExecutionResult:
        capability = PluginCapability.FORWARDING_PROJECTION
        if type(request) is not ForwardingProjectionRequest:
            raise self._input_error(
                capability,
                "request must be an exact ForwardingProjectionRequest",
            )
        request = cast(
            ForwardingProjectionRequest,
            self._snapshot_caller_input(
                capability,
                lambda: _snapshot_forwarding_projection_request(
                    request,
                    "request",
                ),
                unreadable_message=(
                    "forwarding projection request could not be snapshotted"
                ),
            ),
        )

        def validate_request() -> None:
            self._supported_ir(capability, request.ir_version)
            self._perspective(
                request.status_perspective,
                "request.status_perspective",
            )
            if request.changes is not None:
                try:
                    self._change_set(request.changes, capability)
                except PluginCapabilityOutputError as error:
                    raise ValueError(str(error)) from error

        self._validate_caller_input(
            capability,
            validate_request,
            unreadable_message="forwarding projection request could not be validated",
        )
        bounded_world = self._bounded_world(
            world,
            capability,
            min(request.max_world_reads, self.limits.max_world_reads),
            expected_perspective_id=(
                request.status_perspective.perspective_id
                if request.status_perspective is not None
                else None
            ),
        )
        hook = self._require(capability, "project_forwarding")
        maximum = min(request.max_records, self.limits.max_forwarding_outputs)
        hook_request = _snapshot_forwarding_projection_request(request, "request")
        try:
            outputs = hook(hook_request, bounded_world)
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(ForwardingMutation,),
                validator=lambda value, label: self._forwarding_mutation(
                    request,
                    value,
                    label,
                ),
            )
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "project_forwarding() failed inside plug-in",
            ) from error
        return ForwardingProjectionExecutionResult(
            mutations=cast(tuple[ForwardingMutation, ...], values),
            diagnostics=diagnostics,
        )

    def _forwarding_step_result(
        self,
        request: ForwardingStepRequest,
        value: Any,
    ) -> ForwardingStepResult:
        if type(value) is not ForwardingStepResult:
            raise ValueError(
                "resolve_forwarding_step() must return an exact "
                "ForwardingStepResult or PluginDiagnostic"
            )
        if value.step_id != request.step_id:
            raise ValueError("forwarding step result step_id does not match request")
        if value.transition.before != request.packet_state:
            raise ValueError(
                "forwarding step transition before-state does not match request"
            )
        self._resource(request.forwarding_object, "request.forwarding_object")
        if request.ingress_resource is not None:
            self._resource(request.ingress_resource, "request.ingress_resource")
        for label, resource in (
            ("selected_candidate", value.selected_candidate),
            ("next_forwarding_object", value.next_forwarding_object),
        ):
            if resource is not None:
                self._resource(resource, f"forwarding step result.{label}")
        self._nested_contract(value.transition, "forwarding step result.transition")
        if (
            value.transition.origin is ForwardingTransitionOrigin.USER_FORCED
            and not any(
                rule.rule_id == value.transition.forced_rule_id
                and rule.target_step_id == request.step_id
                for rule in request.steering_rules
            )
        ):
            raise ValueError(
                "user-forced forwarding transition does not match a request rule"
            )
        self._enum(value.quality, Quality, "forwarding step result.quality")
        return value

    def resolve_forwarding_step(
        self,
        request: ForwardingStepRequest,
        world: ReadOnlyWorld,
    ) -> ForwardingStepExecutionResult:
        capability = PluginCapability.FORWARDING_TRACE
        if type(request) is not ForwardingStepRequest:
            raise self._input_error(
                capability,
                "request must be an exact ForwardingStepRequest",
            )
        request = cast(
            ForwardingStepRequest,
            self._snapshot_caller_input(
                capability,
                lambda: _snapshot_forwarding_step_request(request, "request"),
                unreadable_message=(
                    "forwarding step request could not be snapshotted"
                ),
            ),
        )

        def validate_request() -> None:
            if (
                self._bound_member_id is not None
                and request.member_id != self._bound_member_id
            ):
                raise ValueError(
                    "request.member_id does not match the bound revision-set member"
                )
            self._supported_ir(capability, request.ir_version)
            self._perspective(
                request.status_perspective,
                "request.status_perspective",
            )
            self._resource(
                request.forwarding_object,
                "request.forwarding_object",
            )
            if request.ingress_resource is not None:
                self._resource(
                    request.ingress_resource,
                    "request.ingress_resource",
                )
            for index, rule in enumerate(request.steering_rules):
                if rule.selected_candidate is not None:
                    self._resource(
                        rule.selected_candidate,
                        f"request.steering_rules[{index}].selected_candidate",
                    )

        self._validate_caller_input(
            capability,
            validate_request,
            unreadable_message="forwarding step request could not be validated",
        )
        bounded_world = self._bounded_world(
            world,
            capability,
            self.limits.max_world_reads,
            expected_perspective_id=(
                request.status_perspective.perspective_id
                if request.status_perspective is not None
                else None
            ),
        )
        hook = self._require(capability, "resolve_forwarding_step")
        hook_request = _snapshot_forwarding_step_request(request, "request")
        try:
            output = hook(hook_request, bounded_world)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise self._error(
                capability,
                "resolve_forwarding_step() failed inside plug-in",
            ) from error
        try:
            if type(output) is PluginDiagnostic:
                diagnostic = self._diagnostic(output, "forwarding_trace")
                diagnostics = (diagnostic,)
                if not diagnostic.recoverable:
                    raise self._error(
                        capability,
                        f"forwarding_trace failed: {diagnostic.code}: "
                        f"{diagnostic.message}",
                        diagnostics=diagnostics,
                    )
                return ForwardingStepExecutionResult(
                    result=None,
                    diagnostics=diagnostics,
                )
            result = self._forwarding_step_result(request, output)
        except PluginCapabilityExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise self._error(capability, str(error)) from error
        except BaseException as error:
            raise self._error(
                capability,
                "resolve_forwarding_step() returned an unreadable result",
            ) from error
        return ForwardingStepExecutionResult(result=result, diagnostics=())


__all__ = [
    "ConsistencyExecutionResult",
    "CorrelationExecutionResult",
    "EvidenceAnalysisExecutionResult",
    "ForwardingProjectionExecutionResult",
    "ForwardingStepExecutionResult",
    "PluginCapabilityBindingError",
    "PluginCapabilityExecutionError",
    "PluginCapabilityExecutor",
    "PluginCapabilityInputError",
    "PluginCapabilityLimits",
    "PluginCapabilityOutputError",
    "PluginCapabilityUnavailableError",
    "TopologyExecutionResult",
]
