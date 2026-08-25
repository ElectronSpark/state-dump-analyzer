from __future__ import annotations

import unittest
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import replace
from typing import Any, Self
from unittest.mock import patch
from uuid import UUID

import router_dump_analyzer.capability_executor as capability_executor_module
from router_dump_analyzer.capability_executor import (
    PluginCapabilityBindingError,
    PluginCapabilityExecutionError,
    PluginCapabilityExecutor,
    PluginCapabilityInputError,
    PluginCapabilityLimits,
    PluginCapabilityOutputError,
    PluginCapabilityUnavailableError,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    FORWARDING_IR_VERSION,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    AnalyzerPluginBase,
    CausalLink,
    CausalLinkTypeDescriptor,
    ChangeSet,
    ClockAnchor,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    ConsistencyFinding,
    CorrelationWindow,
    DiagnosticSeverity,
    DiagnosticStage,
    DomainEvent,
    Evidence,
    EvidenceAnalysisFact,
    EvidenceAnalysisKind,
    EvidenceAnalysisObservation,
    EvidenceAnalysisRequest,
    FindingResult,
    ForwardingMutation,
    ForwardingOperation,
    ForwardingPacketDisposition,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingProjectionRequest,
    ForwardingSteeringRule,
    ForwardingStepRequest,
    ForwardingStepResult,
    ForwardingTransitionOrigin,
    MutationOperation,
    Outcome,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    PropertyDescriptor,
    PropertyPatch,
    Provenance,
    Quality,
    ReconstructionSupport,
    RelationshipDeclaration,
    RelationshipMutation,
    RelationshipOperation,
    RelationshipTypeDescriptor,
    RelationshipView,
    ResolvedNodeBasis,
    ResourceKey,
    ResourceKindDescriptor,
    ResourceStateView,
    SourceRecordRef,
    StateMutation,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRef,
    StatusPerspectiveRole,
    TopologyEndpointReference,
    TopologyLinkRecord,
    TopologyProjectionDescriptor,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourceRecord,
    TopologyUsability,
    VrfForwardingState,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
)
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest

CAPABILITIES = frozenset(
    {
        PluginCapability.EVENT_REDUCTION,
        PluginCapability.EVENT_REVERSION,
        PluginCapability.CORRELATION,
        PluginCapability.RELATIONSHIP_PROJECTION,
        PluginCapability.CONSISTENCY_CHECK,
        PluginCapability.TOPOLOGY_PROJECTION,
        PluginCapability.FORWARDING_PROJECTION,
        PluginCapability.FORWARDING_TRACE,
        PluginCapability.EVIDENCE_ANALYSIS,
    }
)


class Boom(BaseException):
    """Adversarial non-process-control throwable supplied by a plug-in."""


def _schema() -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind="opaque.item",
                label="Opaque item",
                key_fields=("id",),
                properties=(
                    PropertyDescriptor(
                        name="state",
                        label="State",
                        value_type="text",
                    ),
                ),
            ),
        ),
        relationship_types=(
            RelationshipTypeDescriptor(
                relation_type="opaque.relation",
                label="Opaque relation",
                directed=True,
                structural=False,
            ),
        ),
        causal_link_types=(
            CausalLinkTypeDescriptor(
                link_type="opaque.cause",
                label="Opaque cause",
            ),
        ),
        status_perspectives=(
            StatusPerspectiveDescriptor(
                perspective_id="opaque.status",
                label="Opaque status",
                layer_id="opaque.layer",
                role=StatusPerspectiveRole.OTHER,
            ),
        ),
        topology_projections=(
            TopologyProjectionDescriptor(
                projection_id="opaque.graph",
                label="Opaque graph",
                supported_status_perspective_ids=("opaque.status",),
            ),
        ),
        connector_match_policies=(
            ConnectorMatchPolicyDescriptor(
                policy_id="opaque.connector.exact.v1",
                claim_contract_id="opaque.connector.v1",
                kind=ConnectorMatchPolicyKind.EXACT_TOKEN,
                argument_names=("token",),
            ),
            ConnectorMatchPolicyDescriptor(
                policy_id="opaque.connector.alt.v1",
                claim_contract_id="opaque.connector.alt.v1",
                kind=ConnectorMatchPolicyKind.EXACT_TOKEN,
                argument_names=("port",),
            ),
        ),
    )


def _manifest(
    capabilities: frozenset[PluginCapability | str] = CAPABILITIES,
) -> PluginManifest:
    return PluginManifest(
        plugin_id="opaque.plugin",
        plugin_version="1",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("opaque",),
        supported_software_versions="*",
        capabilities=capabilities,
        reconstruction_default=ReconstructionSupport.EXACT,
        forwarding_ir_versions=(FORWARDING_IR_VERSION,),
    )


def _execution_pin(plugin: _Plugin) -> PluginExecutionPin:
    schema = plugin.describe()
    return PluginExecutionPin(
        instance_id="opaque.instance",
        plugin_id=plugin.manifest.plugin_id,
        plugin_version=plugin.manifest.plugin_version,
        core_api_version=plugin.manifest.core_api_version,
        artifact=PluginArtifactIdentity(
            distribution_name="opaque-plugin",
            distribution_version="1",
            package_hash="package-sha256:" + "a" * 64,
            entry_point_name="opaque",
            module_target="opaque:plugin",
        ),
        configuration_digest="sha256:" + "b" * 64,
        schema_digest=plugin_schema_digest(schema),
        registered_execution_identity="sha256:" + "e" * 64,
        process_bootstrap_digest="sha256:" + "f" * 64,
        schema_versions=("router_dump_analyzer.plugin_schema.v1",),
        capabilities=tuple(
            sorted(
                item.value if type(item) is PluginCapability else item
                for item in plugin.manifest.capabilities
            )
        ),
        roles=("primary_parser",),
    )


RESOURCE = ResourceKey(
    namespace="opaque",
    node="node-a",
    layer="opaque.layer",
    kind="opaque.item",
    parts=(("id", "one"),),
)
OTHER_RESOURCE = replace(RESOURCE, parts=(("id", "two"),))
EVIDENCE = Evidence(
    artifact_id=UUID("00000000-0000-0000-0000-000000000001"),
    locator="record:1",
    raw_timestamp_ns=1,
    clock_domain="clock-a",
)
PERSPECTIVE = StatusPerspectiveRef("opaque.status")
BASIS = WorldBasis(
    kind=WorldBasisKind.ABSOLUTE_TIME,
    requested_time_ns=1,
    resolved_at_min_ns=1,
    resolved_at_max_ns=1,
    capture_ranges=(),
    provenance=Provenance.RECONSTRUCTED,
    quality=Quality.EXACT,
)
EVENT = DomainEvent(
    event_uid=b"e" * 32,
    timestamp_ns=1,
    timestamp_uncertainty_ns=0,
    source_sequence=1,
    event_type="opaque.event",
    action="change",
    outcome=Outcome.SUCCESS,
    attributes={},
    subjects=(RESOURCE,),
    provenance=Provenance.OBSERVED,
    quality=Quality.EXACT,
    source=SourceRecordRef(source_id="source", message_ordinal=1),
    evidence=EVIDENCE,
)


class _World:
    def __init__(
        self,
        states: Iterable[Any] = (),
        *,
        basis: WorldBasis = BASIS,
        perspective_ref: StatusPerspectiveRef | None = PERSPECTIVE,
        states_by_resource: dict[ResourceKey, ResourceStateView] | None = None,
        relationships: Iterable[Any] = (),
        honor_limit: bool = False,
    ) -> None:
        self._states = states
        self._basis = basis
        self._perspective_ref = perspective_ref
        self._states_by_resource = states_by_resource or {}
        self._relationships = relationships
        self._honor_limit = honor_limit
        self.last_limit: int | None = None
        self.state_reads: list[ResourceKey] = []

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._perspective_ref

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self.state_reads.append(resource)
        return self._states_by_resource.get(resource)

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        if self._honor_limit and limit is not None:
            return tuple(self._states)[:limit]
        return self._states

    def related(
        self,
        resource: ResourceKey,
        direction: Any = None,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        if self._honor_limit and limit is not None:
            return tuple(self._relationships)[:limit]
        return self._relationships

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        if self._honor_limit and limit is not None:
            return tuple(self._relationships)[:limit]
        return self._relationships


class _Plugin(AnalyzerPluginBase):
    def __init__(
        self,
        *,
        manifest: PluginManifest | None = None,
    ) -> None:
        self.manifest = manifest or _manifest()
        self.apply_output: Any = ChangeSet()
        self.revert_output: Any = ChangeSet()
        self.correlation_output: Iterable[Any] = ()
        self.relationship_projection_output: Iterable[Any] = ()
        self.consistency_output: Iterable[Any] = ()
        self.topology_output: Iterable[Any] = ()
        self.forwarding_output: Iterable[Any] = ()
        self.step_output: Any = None
        self.evidence_analysis_output: Iterable[Any] = ()
        self.apply_called = False
        self.revert_called = False
        self.correlate_called = False
        self.project_relationships_called = False
        self.topology_called = False
        self.forwarding_called = False
        self.forwarding_step_called = False
        self.evidence_analysis_called = False
        self.evidence_analysis_request: Any = None

    def describe(self) -> PluginSchema:
        return _schema()

    def probe(self, inventory: Any) -> Any:
        raise AssertionError("not used")

    def locate_inputs(self, inventory: Any) -> Iterable[Any]:
        return ()

    def apply(self, event: DomainEvent, world: Any) -> ChangeSet:
        self.apply_called = True
        return self.apply_output

    def revert(self, event: DomainEvent, world_after: Any) -> ChangeSet:
        self.revert_called = True
        return self.revert_output

    def correlate(self, reader: Any, window: Any) -> Iterable[Any]:
        self.correlate_called = True
        return self.correlation_output

    def project_relationships(self, world: Any) -> Iterable[Any]:
        self.project_relationships_called = True
        return self.relationship_projection_output

    def check_consistency(self, world: Any) -> Iterable[Any]:
        return self.consistency_output

    def project_topology(self, request: Any, world: Any) -> Iterable[Any]:
        self.topology_called = True
        return self.topology_output

    def project_forwarding(self, request: Any, world: Any) -> Iterable[Any]:
        self.forwarding_called = True
        return self.forwarding_output

    def resolve_forwarding_step(self, request: Any, world: Any) -> Any:
        self.forwarding_step_called = True
        return self.step_output

    def analyze_evidence(self, request: Any) -> Iterable[Any]:
        self.evidence_analysis_called = True
        self.evidence_analysis_request = request
        return self.evidence_analysis_output


class _ChangingMapping(Mapping[str, Any]):
    """Return a different scalar on the validator and snapshot passes."""

    def __init__(self) -> None:
        self._items_calls = 0

    def __getitem__(self, key: str) -> Any:
        if key != "value":
            raise KeyError(key)
        return 1.0

    def __iter__(self) -> Iterator[str]:
        yield "value"

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        self._items_calls += 1
        value = 1.0 if self._items_calls == 1 else float("nan")
        return (("value", value),)


class _ExplodingManifestPlugin:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def manifest(self):
        raise self.error


class _ExplodingDescribePlugin(_Plugin):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def describe(self) -> PluginSchema:
        raise self.error


class _ExplodingApplyDescriptorPlugin(_Plugin):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    @property
    def apply(self):
        raise self.error


class _CountingApplyDescriptorPlugin(_Plugin):
    def __init__(self) -> None:
        super().__init__()
        self.apply_descriptor_reads = 0

    @property
    def apply(self):
        self.apply_descriptor_reads += 1

        def execute(_event: DomainEvent, _world: Any) -> ChangeSet:
            self.apply_called = True
            return self.apply_output

        return execute


class _ExplodingApplyPlugin(_Plugin):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def apply(self, event: DomainEvent, world: Any) -> ChangeSet:
        del event, world
        raise self.error


class _ExplodingSupportsManifest(PluginManifest):
    __slots__ = ("failure",)

    failure: BaseException

    def supports(self, capability: PluginCapability | str) -> bool:
        del capability
        raise self.failure


class _GuardedForwardingVersionsManifest(PluginManifest):
    __slots__ = ("failure", "maximum_reads", "reads")

    failure: BaseException
    maximum_reads: int
    reads: int

    def __getattribute__(self, name: str) -> Any:
        if name == "forwarding_ir_versions":
            reads = object.__getattribute__(self, "reads")
            maximum_reads = object.__getattribute__(self, "maximum_reads")
            if reads >= maximum_reads:
                raise object.__getattribute__(self, "failure")
            object.__setattr__(self, "reads", reads + 1)
        return super().__getattribute__(name)


def _exploding_supports_manifest(error: BaseException) -> PluginManifest:
    source = _manifest()
    result = _ExplodingSupportsManifest(
        plugin_id=source.plugin_id,
        plugin_version=source.plugin_version,
        core_api_version=source.core_api_version,
        supported_platforms=source.supported_platforms,
        supported_software_versions=source.supported_software_versions,
        capabilities=source.capabilities,
        reconstruction_default=source.reconstruction_default,
        forwarding_ir_versions=source.forwarding_ir_versions,
    )
    object.__setattr__(result, "failure", error)
    return result


def _guarded_forwarding_versions_manifest(
    error: BaseException,
    *,
    maximum_reads: int,
) -> _GuardedForwardingVersionsManifest:
    source = _manifest()
    result = _GuardedForwardingVersionsManifest(
        plugin_id=source.plugin_id,
        plugin_version=source.plugin_version,
        core_api_version=source.core_api_version,
        supported_platforms=source.supported_platforms,
        supported_software_versions=source.supported_software_versions,
        capabilities=source.capabilities,
        reconstruction_default=source.reconstruction_default,
        forwarding_ir_versions=source.forwarding_ir_versions,
    )
    object.__setattr__(result, "failure", error)
    object.__setattr__(result, "maximum_reads", maximum_reads)
    object.__setattr__(result, "reads", 0)
    return result


class _ExplodingTuple(tuple[Any, ...]):
    failure: BaseException

    def __new__(cls, failure: BaseException) -> Self:
        result = super().__new__(cls)
        result.failure = failure
        return result

    def __len__(self) -> int:
        raise self.failure


def _diagnostic(
    *,
    recoverable: bool = True,
    stage: DiagnosticStage = DiagnosticStage.CONSISTENCY,
) -> PluginDiagnostic:
    return PluginDiagnostic(
        stage=stage,
        severity=DiagnosticSeverity.WARNING,
        code="opaque.warning",
        message="Opaque warning",
        recoverable=recoverable,
    )


def _state_mutation() -> StateMutation:
    return StateMutation(
        resource=RESOURCE,
        operation=MutationOperation.UPSERT,
        before=None,
        after=PropertyPatch(set_values={"state": "ready"}),
        effective_time_ns=1,
        time_uncertainty_ns=0,
        cause_event_uid=EVENT.event_uid,
        provenance=Provenance.EVENT_DERIVED,
        quality=Quality.EXACT,
        evidence=(EVIDENCE,),
        perspective_ref=PERSPECTIVE,
    )


def _relationship_mutation(
    relation_type: str = "opaque.relation",
) -> RelationshipMutation:
    return RelationshipMutation(
        source=RESOURCE,
        target=OTHER_RESOURCE,
        relation_type=relation_type,
        operation=RelationshipOperation.ADD,
        attributes=PropertyPatch(),
        effective_time_ns=1,
        time_uncertainty_ns=0,
        cause_event_uid=EVENT.event_uid,
        provenance=Provenance.CORRELATED,
        quality=Quality.EXACT,
        evidence=(EVIDENCE,),
        perspective_ref=PERSPECTIVE,
    )


def _relationship_declaration(
    relation_type: str = "opaque.relation",
    *,
    attributes: PropertyPatch | None = None,
) -> RelationshipDeclaration:
    return RelationshipDeclaration(
        source=RESOURCE,
        target=OTHER_RESOURCE,
        relation_type=relation_type,
        attributes=attributes or PropertyPatch(complete=True),
        evidence=(EVIDENCE,),
        provenance=Provenance.CORRELATED,
        quality=Quality.EXACT,
        perspective_ref=PERSPECTIVE,
    )


def _causal_link(link_type: str = "opaque.cause") -> CausalLink:
    return CausalLink(
        source_event_uid=b"a" * 32,
        target_event_uid=b"b" * 32,
        link_type=link_type,
        confidence=0.9,
        provenance=Provenance.CORRELATED,
        quality=Quality.EXACT,
        evidence=(EVIDENCE,),
    )


def _topology_record(
    *,
    projection_id: str = "opaque.graph",
) -> TopologyProjectionRecord:
    return TopologyProjectionRecord(
        projection_id=projection_id,
        status_perspective_id="opaque.status",
        payload=TopologyLinkRecord(
            link_id="opaque-link",
            source=TopologyEndpointReference(resource=RESOURCE),
            target=TopologyEndpointReference(resource=OTHER_RESOURCE),
        ),
        usability=TopologyUsability.USABLE,
        source_resources=(RESOURCE, OTHER_RESOURCE),
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
    )


def _topology_resource_record(
    resource: ResourceKey = RESOURCE,
) -> TopologyProjectionRecord:
    return TopologyProjectionRecord(
        projection_id="opaque.graph",
        status_perspective_id="opaque.status",
        payload=TopologyResourceRecord(resource=resource),
        usability=TopologyUsability.USABLE,
        source_resources=(resource,),
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
    )


def _topology_claim(
    *,
    claim_id: str = "claim-one",
    endpoint: ResourceKey = RESOURCE,
    claim_contract_id: str = "opaque.connector.v1",
    match_policy_id: str = "opaque.connector.exact.v1",
    arguments: tuple[tuple[str, Any], ...] = (("token", "one"),),
    status_perspective: StatusPerspectiveRef | None = PERSPECTIVE,
) -> ConnectorClaim:
    return ConnectorClaim(
        claim_id=claim_id,
        endpoint=endpoint,
        claim_contract_id=claim_contract_id,
        match_policy_id=match_policy_id,
        arguments=arguments,
        provenance=Provenance.OBSERVED,
        quality=Quality.EXACT,
        status_perspective=status_perspective,
        evidence=(EVIDENCE,),
    )


def _resource_state(
    resource: ResourceKey,
    *,
    exists: bool | None = False,
) -> ResourceStateView:
    return ResourceStateView(
        resource=resource,
        exists=exists,
        properties={},
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
        valid_from_ns=None,
        valid_to_ns=None,
        perspective_ref=PERSPECTIVE,
    )


def _relationship() -> RelationshipView:
    return RelationshipView(
        source=RESOURCE,
        target=RESOURCE,
        relation_type="opaque.link",
        attributes={"nested": {"status": "up"}},
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
        valid_from_ns=1,
        valid_to_ns=None,
        evidence=(EVIDENCE,),
        perspective_ref=PERSPECTIVE,
    )


def _projection_request(ir_version: str = FORWARDING_IR_VERSION) -> Any:
    return ForwardingProjectionRequest(
        ir_version=ir_version,
        status_perspective=PERSPECTIVE,
        max_records=10,
        max_world_reads=10,
    )


def _forwarding_mutation() -> ForwardingMutation:
    return ForwardingMutation(
        operation=ForwardingOperation.UPSERT,
        key=RESOURCE,
        record=VrfForwardingState(
            key=RESOURCE,
            name="opaque",
            active=True,
            attributes={},
        ),
        effective_time_ns=1,
        time_uncertainty_ns=0,
        cause_event_uid=EVENT.event_uid,
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
        basis=BASIS,
        ir_version=FORWARDING_IR_VERSION,
    )


def _step_request(ir_version: str = FORWARDING_IR_VERSION) -> ForwardingStepRequest:
    return ForwardingStepRequest(
        step_id="step-1",
        member_id="member-a",
        status_perspective=PERSPECTIVE,
        forwarding_object=RESOURCE,
        packet_state=ForwardingPacketState(layers=()),
        ir_version=ir_version,
    )


def _step_result(request: ForwardingStepRequest) -> ForwardingStepResult:
    return ForwardingStepResult(
        step_id=request.step_id,
        transition=ForwardingPacketTransition(
            transition_id="transition-1",
            step_id=request.step_id,
            before=request.packet_state,
            after=request.packet_state,
            action_contract_id="opaque.action",
            action_label="Deliver",
            disposition=ForwardingPacketDisposition.DELIVER,
            origin=ForwardingTransitionOrigin.NODE_PLUGIN,
            actor_id="opaque.actor",
        ),
        selected_candidate=RESOURCE,
        next_forwarding_object=None,
        terminal=True,
    )


class PluginCapabilityExecutorTests(unittest.TestCase):
    def test_schema_budget_is_checked_before_building_the_executor_index(self) -> None:
        oversized = PluginSchema(
            resource_kinds=tuple(
                ResourceKindDescriptor(
                    kind=f"opaque.item.{index}",
                    label="Opaque item",
                    key_fields=("id",),
                    properties=(),
                )
                for index in range(1_025)
            ),
            relationship_types=(),
        )
        with (
            patch(
                "router_dump_analyzer.capability_executor._SchemaIndex.build"
            ) as build,
            self.assertRaisesRegex(TypeError, "bounded plug-in schema"),
        ):
            PluginCapabilityExecutor(_Plugin(), oversized)
        build.assert_not_called()

    def test_executor_is_available_from_the_curated_core_surface(self) -> None:
        import router_dump_analyzer

        self.assertIs(
            router_dump_analyzer.PluginCapabilityExecutor,
            PluginCapabilityExecutor,
        )
        self.assertIs(
            router_dump_analyzer.PluginCapabilityInputError,
            PluginCapabilityInputError,
        )

    def test_manifest_capability_is_checked_before_invocation(self) -> None:
        plugin = _Plugin(manifest=_manifest(frozenset()))
        executor = PluginCapabilityExecutor(plugin)

        with self.assertRaises(PluginCapabilityUnavailableError):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]
        self.assertFalse(plugin.apply_called)

    def test_capability_hook_descriptor_is_snapshotted_once_per_invocation(
        self,
    ) -> None:
        plugin = _CountingApplyDescriptorPlugin()
        executor = PluginCapabilityExecutor(plugin)

        self.assertEqual(executor.apply(EVENT, _World()), ChangeSet())  # type: ignore[arg-type]
        self.assertTrue(plugin.apply_called)
        self.assertEqual(plugin.apply_descriptor_reads, 1)

    def test_caller_validation_uses_the_input_error_domain_before_hooks(self) -> None:
        cases = (
            (
                "apply",
                lambda executor: executor.apply(object(), _World()),
                "apply_called",
            ),
            (
                "revert",
                lambda executor: executor.revert(object(), _World()),
                "revert_called",
            ),
            (
                "correlate",
                lambda executor: executor.correlate(object(), object()),
                "correlate_called",
            ),
            (
                "project_topology",
                lambda executor: executor.project_topology(object(), _World()),
                "topology_called",
            ),
            (
                "project_forwarding",
                lambda executor: executor.project_forwarding(object(), _World()),
                "forwarding_called",
            ),
            (
                "resolve_forwarding_step",
                lambda executor: executor.resolve_forwarding_step(
                    object(),
                    _World(),
                ),
                "forwarding_step_called",
            ),
        )
        for label, invoke, called_attribute in cases:
            with self.subTest(label=label):
                plugin = _Plugin()
                executor = PluginCapabilityExecutor(plugin)
                with self.assertRaises(PluginCapabilityInputError):
                    invoke(executor)
                self.assertFalse(getattr(plugin, called_attribute))

    def test_nonstandard_base_exceptions_are_bounded_at_capability_boundaries(
        self,
    ) -> None:
        supplied = r"capability failed at C:\private\tenant\plugin.py"
        with self.assertRaisesRegex(
            TypeError, "could not resolve.*manifest"
        ) as manifest_error:
            PluginCapabilityExecutor(_ExplodingManifestPlugin(Boom(supplied)))  # type: ignore[arg-type]
        self.assertNotIn(supplied, str(manifest_error.exception))

        with self.assertRaisesRegex(
            TypeError, "could not resolve.*schema"
        ) as schema_error:
            PluginCapabilityExecutor(_ExplodingDescribePlugin(Boom(supplied)))
        self.assertNotIn(supplied, str(schema_error.exception))

        descriptor_plugin = _ExplodingApplyDescriptorPlugin(Boom(supplied))
        descriptor_executor = PluginCapabilityExecutor(descriptor_plugin)
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "hook could not be resolved",
        ) as descriptor_error:
            descriptor_executor.apply(EVENT, _World())  # type: ignore[arg-type]
        self.assertNotIn(supplied, str(descriptor_error.exception))

        hook_plugin = _ExplodingApplyPlugin(Boom(supplied))
        hook_executor = PluginCapabilityExecutor(hook_plugin)
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "failed inside plug-in",
        ) as hook_error:
            hook_executor.apply(EVENT, _World())  # type: ignore[arg-type]
        self.assertNotIn(supplied, str(hook_error.exception))

    def test_manifest_capability_gate_uses_the_snapshotted_declared_set(
        self,
    ) -> None:
        supplied = r"manifest failed at C:\private\tenant\plugin.py"
        for failure in (
            Boom(supplied),
            KeyboardInterrupt("process control"),
            SystemExit("process control"),
            GeneratorExit("process control"),
        ):
            with self.subTest(failure=type(failure).__name__):
                plugin = _Plugin(manifest=_exploding_supports_manifest(failure))
                executor = PluginCapabilityExecutor(plugin)
                self.assertEqual(
                    executor.apply(EVENT, _World()),  # type: ignore[arg-type]
                    ChangeSet(),
                )
                self.assertTrue(plugin.apply_called)

    def test_forwarding_ir_versions_descriptor_is_snapshotted_once(
        self,
    ) -> None:
        manifest = _guarded_forwarding_versions_manifest(
            Boom(r"re-read at C:\private\tenant\plugin.py"),
            maximum_reads=1,
        )
        plugin = _Plugin(manifest=manifest)
        request = _step_request()
        plugin.step_output = _step_result(request)

        executor = PluginCapabilityExecutor(plugin)

        self.assertEqual(manifest.reads, 1)
        executor.project_forwarding(
            _projection_request(),
            _World(),  # type: ignore[arg-type]
        )
        executor.resolve_forwarding_step(
            request,
            _World(),  # type: ignore[arg-type]
        )
        self.assertEqual(manifest.reads, 1)

    def test_plan_bound_executor_rejects_foreign_perspective_and_member(self) -> None:
        plugin = _Plugin()
        pin = _execution_pin(plugin)
        executor = PluginCapabilityExecutor.for_execution_pin(
            plugin,
            pin,
            member_id="member-a",
        )
        foreign_instance = replace(
            _projection_request(),
            status_perspective=StatusPerspectiveRef(
                "opaque.status",
                plugin_instance_id="other.instance",
                schema_digest=pin.schema_digest,
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "different plug-in instance",
        ):
            executor.project_forwarding(
                foreign_instance,
                _World(),  # type: ignore[arg-type]
            )
        foreign_schema = replace(
            _projection_request(),
            status_perspective=StatusPerspectiveRef(
                "opaque.status",
                plugin_instance_id=pin.instance_id,
                schema_digest="sha256:" + "f" * 64,
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "different schema",
        ):
            executor.project_forwarding(
                foreign_schema,
                _World(),  # type: ignore[arg-type]
            )
        plugin.relationship_projection_output = (
            replace(
                _relationship_declaration(),
                perspective_ref=StatusPerspectiveRef(
                    "opaque.status",
                    plugin_instance_id="other.instance",
                    schema_digest=pin.schema_digest,
                ),
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "different plug-in instance",
        ):
            executor.project_relationships(_World())  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "revision-set member",
        ):
            executor.resolve_forwarding_step(
                replace(_step_request(), member_id="member-b"),
                _World(),  # type: ignore[arg-type]
            )
        foreign_world = _World(
            perspective_ref=StatusPerspectiveRef(
                "opaque.status",
                plugin_instance_id="other.instance",
                schema_digest=pin.schema_digest,
            )
        )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "different plug-in instance",
        ):
            executor.project_forwarding(
                _projection_request(),
                foreign_world,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "different plug-in instance",
        ):
            request = _step_request()
            plugin.step_output = _step_result(request)
            executor.resolve_forwarding_step(
                request,
                foreign_world,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "required for a perspective-specific request",
        ):
            executor.project_forwarding(
                _projection_request(),
                _World(perspective_ref=None),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "must identify the bound plug-in instance",
        ):
            executor.project_forwarding(
                _projection_request(),
                _World(),  # type: ignore[arg-type]
            )
        self.assertFalse(plugin.forwarding_called)
        self.assertFalse(plugin.forwarding_step_called)

    def test_plan_bound_executor_rejects_manifest_and_schema_mismatch(self) -> None:
        plugin = _Plugin()
        pin = _execution_pin(plugin)
        with self.assertRaisesRegex(
            PluginCapabilityBindingError,
            "manifest does not match",
        ):
            PluginCapabilityExecutor.for_execution_pin(
                plugin,
                replace(pin, plugin_version="other"),
                member_id="member-a",
            )
        with self.assertRaisesRegex(
            PluginCapabilityBindingError,
            "schema does not match",
        ):
            PluginCapabilityExecutor.for_execution_pin(
                plugin,
                replace(pin, schema_digest="sha256:" + "f" * 64),
                member_id="member-a",
            )

    def test_plan_bound_executor_rejects_retained_v1_pin(self) -> None:
        plugin = _Plugin()
        legacy_pin = replace(
            _execution_pin(plugin),
            registered_execution_identity="sha256:" + "0" * 64,
        )
        with self.assertRaisesRegex(
            PluginCapabilityBindingError,
            "retained v1",
        ):
            PluginCapabilityExecutor.for_execution_pin(
                plugin,
                legacy_pin,
                member_id="member-a",
            )

    def test_forwarding_ir_versions_descriptor_uses_the_plugin_error_domain(
        self,
    ) -> None:
        supplied = r"manifest failed at C:\private\tenant\plugin.py"
        with self.assertRaisesRegex(
            TypeError,
            "could not resolve manifest forwarding IR versions",
        ) as caught:
            PluginCapabilityExecutor(
                _Plugin(
                    manifest=_guarded_forwarding_versions_manifest(
                        Boom(supplied),
                        maximum_reads=0,
                    )
                )
            )
        self.assertNotIn(supplied, str(caught.exception))

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                PluginCapabilityExecutor(
                    _Plugin(
                        manifest=_guarded_forwarding_versions_manifest(
                            exception_type("process control"),
                            maximum_reads=0,
                        )
                    )
                )

    def test_apply_and_revert_contain_unreadable_outputs_and_preserve_process_controls(
        self,
    ) -> None:
        supplied = r"output failed at C:\private\tenant\plugin.py"
        for hook_name, output_name in (
            ("apply", "apply_output"),
            ("revert", "revert_output"),
        ):
            with self.subTest(hook=hook_name, failure="boom"):
                plugin = _Plugin()
                setattr(
                    plugin,
                    output_name,
                    ChangeSet(state=_ExplodingTuple(Boom(supplied))),
                )
                executor = PluginCapabilityExecutor(plugin)
                with self.assertRaisesRegex(
                    PluginCapabilityOutputError,
                    f"{hook_name}\\(\\) returned an unreadable result",
                ) as caught:
                    getattr(executor, hook_name)(EVENT, _World())
                self.assertNotIn(supplied, str(caught.exception))

            for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
                with self.subTest(
                    hook=hook_name,
                    exception_type=exception_type.__name__,
                ):
                    plugin = _Plugin()
                    setattr(
                        plugin,
                        output_name,
                        ChangeSet(
                            state=_ExplodingTuple(exception_type("process control"))
                        ),
                    )
                    executor = PluginCapabilityExecutor(plugin)
                    with self.assertRaises(exception_type):
                        getattr(executor, hook_name)(EVENT, _World())

    def test_capability_boundaries_preserve_process_control_exceptions(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception_type=exception_type.__name__):
                with self.assertRaises(exception_type):
                    PluginCapabilityExecutor(
                        _ExplodingManifestPlugin(exception_type("process control"))  # type: ignore[arg-type]
                    )

                plugin = _ExplodingApplyPlugin(exception_type("process control"))
                executor = PluginCapabilityExecutor(plugin)
                with self.assertRaises(exception_type):
                    executor.apply(EVENT, _World())  # type: ignore[arg-type]

    def test_apply_and_revert_require_exact_bounded_change_sets(self) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)
        changes = ChangeSet(
            state=(_state_mutation(),),
            relationships=(_relationship_mutation(),),
            causal_links=(_causal_link(),),
            diagnostics=(_diagnostic(),),
        )
        plugin.apply_output = changes
        plugin.revert_output = changes

        self.assertIs(executor.apply(EVENT, _World()), changes)  # type: ignore[arg-type]
        self.assertIs(executor.revert(EVENT, _World()), changes)  # type: ignore[arg-type]

        plugin.apply_output = object()
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "exact ChangeSet",
        ):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]

    def test_all_capability_temporal_coordinates_are_signed_64_bit(self) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)

        # Mutation validation is shared by apply/revert and accepts both exact
        # signed-64 endpoints while rejecting the first value outside them.
        for value in (MIN_TIMESTAMP_NS, MAX_TIMESTAMP_NS):
            plugin.apply_output = ChangeSet(
                state=(replace(_state_mutation(), effective_time_ns=value),),
            )
            self.assertIs(executor.apply(EVENT, _World()), plugin.apply_output)  # type: ignore[arg-type]
        plugin.apply_output = ChangeSet(
            state=(
                replace(
                    _state_mutation(),
                    effective_time_ns=MAX_TIMESTAMP_NS + 1,
                ),
            ),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "signed 64-bit"):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]

        # Correlation adds clock anchors and request windows to the same domain.
        plugin.correlation_output = (
            ClockAnchor(
                left_clock_domain="left",
                left_raw_ns=MIN_TIMESTAMP_NS - 1,
                right_clock_domain="right",
                right_raw_ns=0,
                uncertainty_ns=0,
                method="opaque",
                provenance=Provenance.CORRELATED,
                quality=Quality.BEST_EFFORT,
            ),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "signed 64-bit"):
            executor.correlate(
                object(),  # type: ignore[arg-type]
                CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
            )

        # Consistency findings may carry deeply nested world-basis coordinates;
        # do not trust construction-time validation at an executable boundary.
        plugin.consistency_output = (
            ConsistencyFinding(
                rule_id="opaque.rule",
                severity=DiagnosticSeverity.WARNING,
                result=FindingResult.UNKNOWN,
                summary="Out-of-range world basis",
                resources=(RESOURCE,),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.UNKNOWN,
                basis=replace(BASIS, requested_time_ns=MAX_TIMESTAMP_NS + 1),
                evidence=(EVIDENCE,),
            ),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "signed 64-bit"):
            executor.check_consistency(_World())  # type: ignore[arg-type]

        resolution = ResolvedNodeBasis(
            node_id="node-a",
            local_clock_domain=None,
            local_min_ns=None,
            local_max_ns=None,
            absolute_min_ns=None,
            absolute_max_ns=None,
            mapping_method=None,
            quality=Quality.UNKNOWN,
            reason_code="not-observed",
        )
        plugin.consistency_output = (
            replace(
                plugin.consistency_output[0],
                basis=replace(
                    BASIS,
                    node_resolutions=(
                        resolution,
                        replace(resolution, node_id="node-b"),
                    ),
                ),
            ),
        )
        bounded_executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_world_basis_node_resolutions=1),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "node_resolutions must be a bounded tuple",
        ):
            bounded_executor.check_consistency(_World())  # type: ignore[arg-type]

    def test_change_set_schema_references_and_limits_are_enforced(self) -> None:
        plugin = _Plugin()
        plugin.apply_output = ChangeSet(
            relationships=(_relationship_mutation("opaque.undeclared"),),
        )
        executor = PluginCapabilityExecutor(plugin)

        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "undeclared relationship type",
        ):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]

        plugin.apply_output = ChangeSet(
            state=(_state_mutation(), _state_mutation()),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_change_items=1),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "item limit"):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]

    def test_nonrecoverable_change_set_diagnostic_fails_with_context(self) -> None:
        plugin = _Plugin()
        plugin.apply_output = ChangeSet(
            diagnostics=(_diagnostic(), _diagnostic(recoverable=False)),
        )

        with self.assertRaises(PluginCapabilityExecutionError) as caught:
            PluginCapabilityExecutor(plugin).apply(EVENT, _World())  # type: ignore[arg-type]

        self.assertEqual(len(caught.exception.diagnostics), 2)
        self.assertFalse(caught.exception.diagnostics[-1].recoverable)

    def test_correlation_groups_typed_outputs_and_retains_diagnostics(self) -> None:
        plugin = _Plugin()
        anchor = ClockAnchor(
            left_clock_domain="left",
            left_raw_ns=1,
            right_clock_domain="right",
            right_raw_ns=2,
            uncertainty_ns=1,
            method="opaque",
            provenance=Provenance.CORRELATED,
            quality=Quality.BEST_EFFORT,
        )
        plugin.correlation_output = (
            _causal_link(),
            _relationship_mutation(),
            anchor,
            _diagnostic(),
        )
        result = PluginCapabilityExecutor(plugin).correlate(
            object(),  # type: ignore[arg-type]
            CorrelationWindow(
                start_ns=0,
                end_ns=10,
                max_events=10,
                max_world_reads=10,
            ),
        )

        self.assertEqual(result.causal_links, (_causal_link(),))
        self.assertEqual(result.relationship_mutations, (_relationship_mutation(),))
        self.assertEqual(result.clock_anchors, (anchor,))
        self.assertEqual(result.diagnostics, (_diagnostic(),))

    def test_correlation_closes_an_over_limit_generator(self) -> None:
        plugin = _Plugin()
        closed = False

        def outputs() -> Iterable[Any]:
            nonlocal closed
            try:
                yield _causal_link()
                yield _causal_link()
            finally:
                closed = True

        plugin.correlation_output = outputs()
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_correlation_outputs=1),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "exceeded",
        ):
            executor.correlate(
                object(),  # type: ignore[arg-type]
                CorrelationWindow(
                    start_ns=0,
                    end_ns=10,
                    max_events=1,
                    max_world_reads=1,
                ),
            )
        self.assertTrue(closed)

    def test_relationship_projection_validates_detaches_and_groups_outputs(
        self,
    ) -> None:
        plugin = _Plugin()
        nested = {"status": "matched"}
        declaration = _relationship_declaration(
            attributes=PropertyPatch(
                set_values={"metadata": nested},
                field_quality={"metadata": Quality.EXACT},
                field_provenance={"metadata": Provenance.CORRELATED},
                complete=True,
            )
        )

        def outputs() -> Iterable[Any]:
            yield declaration
            nested["late"] = "must-not-cross-boundary"
            yield _diagnostic(stage=DiagnosticStage.RELATIONSHIP_PROJECTION)

        plugin.relationship_projection_output = outputs()
        result = PluginCapabilityExecutor(plugin).project_relationships(
            _World()  # type: ignore[arg-type]
        )

        self.assertTrue(plugin.project_relationships_called)
        self.assertEqual(
            result.diagnostics,
            (_diagnostic(stage=DiagnosticStage.RELATIONSHIP_PROJECTION),),
        )
        self.assertEqual(len(result.declarations), 1)
        detached = result.declarations[0]
        self.assertIsNot(detached, declaration)
        self.assertIsNot(detached.source, declaration.source)
        self.assertIsNot(detached.evidence[0], declaration.evidence[0])
        self.assertEqual(detached.attributes.set_values["metadata"], {"status": "matched"})
        with self.assertRaises(TypeError):
            detached.attributes.set_values["new"] = "forbidden"  # type: ignore[index]

    def test_relationship_projection_enforces_schema_and_exact_output_shapes(
        self,
    ) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)
        invalid_kind = replace(
            RESOURCE,
            kind="opaque.undeclared",
        )
        invalid_perspective = StatusPerspectiveRef("opaque.undeclared")
        cases: tuple[tuple[str, RelationshipDeclaration, str], ...] = (
            (
                "relation",
                _relationship_declaration("opaque.undeclared"),
                "undeclared relationship type",
            ),
            (
                "resource",
                replace(_relationship_declaration(), source=invalid_kind),
                "undeclared resource kind",
            ),
            (
                "perspective",
                replace(
                    _relationship_declaration(),
                    perspective_ref=invalid_perspective,
                ),
                "undeclared perspective",
            ),
        )
        for label, declaration, message in cases:
            with self.subTest(label=label):
                plugin.relationship_projection_output = (declaration,)
                with self.assertRaisesRegex(PluginCapabilityOutputError, message):
                    executor.project_relationships(_World())  # type: ignore[arg-type]

        invalid_evidence = _relationship_declaration()
        object.__setattr__(invalid_evidence, "evidence", [EVIDENCE])
        plugin.relationship_projection_output = (invalid_evidence,)
        with self.assertRaisesRegex(PluginCapabilityOutputError, "exact tuple"):
            executor.project_relationships(_World())  # type: ignore[arg-type]

        plugin.relationship_projection_output = (object(),)
        with self.assertRaisesRegex(PluginCapabilityOutputError, "unsupported object"):
            executor.project_relationships(_World())  # type: ignore[arg-type]

        plugin.relationship_projection_output = (_diagnostic(),)
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "relationship_projection stage",
        ):
            executor.project_relationships(_World())  # type: ignore[arg-type]

        for label, attributes, message in (
            (
                "incomplete",
                PropertyPatch(),
                "complete relationship assertion",
            ),
            (
                "removal",
                PropertyPatch(remove_fields=("obsolete",), complete=True),
                "cannot remove fields",
            ),
        ):
            with self.subTest(label=label):
                plugin.relationship_projection_output = (
                    _relationship_declaration(attributes=attributes),
                )
                with self.assertRaisesRegex(PluginCapabilityOutputError, message):
                    executor.project_relationships(_World())  # type: ignore[arg-type]

    def test_relationship_projection_can_use_coordinator_authoritative_schema(
        self,
    ) -> None:
        plugin = _Plugin()
        plugin.relationship_projection_output = (_relationship_declaration(),)
        executor = PluginCapabilityExecutor(
            plugin,
            schema=PluginSchema(resource_kinds=(), relationship_types=()),
        )

        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "undeclared resource kind",
        ):
            executor.project_relationships(  # type: ignore[arg-type]
                _World(perspective_ref=None)
            )

        result = executor._project_relationships_for_revision(
            _World(),  # type: ignore[arg-type]
            declaration_schema=_schema(),
        )
        self.assertEqual(result.declarations, (_relationship_declaration(),))

        fresh = _Plugin()
        fresh.relationship_projection_output = (_relationship_declaration(),)
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "declaration_schema must be an exact PluginSchema",
        ):
            PluginCapabilityExecutor(fresh)._project_relationships_for_revision(
                _World(),  # type: ignore[arg-type]
                declaration_schema=object(),  # type: ignore[arg-type]
            )
        self.assertFalse(fresh.project_relationships_called)

    def test_relationship_projection_bounds_world_and_output_iterators(self) -> None:
        plugin = _Plugin()
        world = _World(
            (_resource_state(RESOURCE), _resource_state(OTHER_RESOURCE)),
            honor_limit=True,
        )

        def scan(bounded_world: Any) -> Iterable[Any]:
            tuple(bounded_world.iter_states())
            return ()

        plugin.project_relationships = scan  # type: ignore[method-assign]
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_world_reads=1),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "world-read limit"):
            executor.project_relationships(world)  # type: ignore[arg-type]
        self.assertEqual(world.last_limit, 2)

        closed = False

        def declarations() -> Iterable[Any]:
            nonlocal closed
            try:
                yield _relationship_declaration()
                yield _relationship_declaration()
            finally:
                closed = True

        plugin = _Plugin()
        plugin.relationship_projection_output = declarations()
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_relationship_projection_outputs=1),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "exceeded"):
            executor.project_relationships(_World())  # type: ignore[arg-type]
        self.assertTrue(closed)

        plugin = _Plugin()
        plugin.relationship_projection_output = (
            _relationship_declaration(),
            _relationship_declaration(),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(
                max_relationship_projection_evidence_references=1
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "aggregate evidence-reference limit",
        ):
            executor.project_relationships(_World())  # type: ignore[arg-type]

        plugin.relationship_projection_output = (
            _relationship_declaration(
                attributes=PropertyPatch(
                    set_values={"payload": "x" * 100},
                    complete=True,
                )
            ),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(
                max_relationship_projection_snapshot_units=50
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "aggregate snapshot-unit limit",
        ):
            executor.project_relationships(_World())  # type: ignore[arg-type]

    def test_relationship_projection_preserves_process_control_exceptions(
        self,
    ) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception_type=exception_type.__name__):
                plugin = _Plugin()

                def fail(_world: Any, *, error_type: type[BaseException] = exception_type):
                    raise error_type("process control")

                plugin.project_relationships = fail  # type: ignore[method-assign]
                with self.assertRaises(exception_type):
                    PluginCapabilityExecutor(plugin).project_relationships(  # type: ignore[arg-type]
                        _World()
                    )

    def test_consistency_bounds_world_reads_and_typed_findings(self) -> None:
        plugin = _Plugin()
        finding = ConsistencyFinding(
            rule_id="opaque.rule",
            severity=DiagnosticSeverity.WARNING,
            result=FindingResult.UNKNOWN,
            summary="Opaque result",
            resources=(RESOURCE,),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.UNKNOWN,
            basis=BASIS,
            evidence=(EVIDENCE,),
        )

        def check(world: Any) -> Iterable[Any]:
            list(world.iter_states())
            return (finding,)

        plugin.check_consistency = check  # type: ignore[method-assign]
        world = _World(
            (_resource_state(RESOURCE), _resource_state(RESOURCE)),
            honor_limit=True,
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_world_reads=1),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "world-read limit",
        ):
            executor.check_consistency(world)  # type: ignore[arg-type]
        self.assertEqual(world.last_limit, 2)

        plugin = _Plugin()
        plugin.consistency_output = (finding, _diagnostic())
        result = PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
            _World()
        )
        self.assertEqual(result.findings, (finding,))
        self.assertEqual(result.diagnostics, (_diagnostic(),))

    def test_consistency_receives_detached_world_basis_and_perspective(self) -> None:
        plugin = _Plugin()
        perspective = StatusPerspectiveRef("opaque.status")
        caller_world = _World(perspective_ref=perspective)

        def mutate_world(world: Any) -> Iterable[Any]:
            object.__setattr__(
                world.basis,
                "unresolved_reason",
                "mutated-by-plugin",
            )
            object.__setattr__(
                world.perspective_ref,
                "perspective_id",
                "mutated.by-plugin",
            )
            return ()

        plugin.check_consistency = mutate_world  # type: ignore[method-assign]
        PluginCapabilityExecutor(plugin).check_consistency(caller_world)  # type: ignore[arg-type]

        self.assertIsNone(BASIS.unresolved_reason)
        self.assertEqual(perspective.perspective_id, "opaque.status")

    def test_consistency_world_reads_return_detached_state_and_relationships(
        self,
    ) -> None:
        plugin = _Plugin()
        state = replace(
            _resource_state(RESOURCE, exists=True),
            properties={"nested": {"status": "up"}},
            evidence=(EVIDENCE,),
        )
        relationship = _relationship()
        caller_world = _World(
            (state,),
            states_by_resource={RESOURCE: state},
            relationships=(relationship,),
            honor_limit=True,
        )
        returned: list[object] = []

        def mutate_views(world: Any) -> Iterable[Any]:
            state_by_key = world.state_of(RESOURCE)
            state_by_scan = next(iter(world.iter_states()))
            related = next(iter(world.related(RESOURCE)))
            relationship_by_scan = next(iter(world.iter_relationships()))
            returned.extend(
                (state_by_key, state_by_scan, related, relationship_by_scan)
            )
            object.__setattr__(state_by_key, "exists", False)
            object.__setattr__(state_by_scan, "properties", {"status": "mutated"})
            object.__setattr__(related, "relation_type", "mutated.link")
            object.__setattr__(
                relationship_by_scan,
                "attributes",
                {"status": "mutated"},
            )
            return ()

        plugin.check_consistency = mutate_views  # type: ignore[method-assign]
        PluginCapabilityExecutor(plugin).check_consistency(caller_world)  # type: ignore[arg-type]

        self.assertTrue(state.exists)
        self.assertEqual(state.properties, {"nested": {"status": "up"}})
        self.assertEqual(relationship.relation_type, "opaque.link")
        self.assertEqual(
            relationship.attributes,
            {"nested": {"status": "up"}},
        )
        self.assertTrue(all(item is not state for item in returned[:2]))
        self.assertTrue(all(item is not relationship for item in returned[2:]))

    def test_consistency_world_provider_failures_use_the_input_error_domain(
        self,
    ) -> None:
        class FaultIterator:
            def __init__(self, mode: str) -> None:
                self.mode = mode
                self.returned = False

            def __iter__(self) -> Self:
                return self

            def __next__(self) -> ResourceStateView:
                if self.mode == "next":
                    raise Boom("caller world next failed")
                if self.returned:
                    raise StopIteration
                self.returned = True
                return _resource_state(RESOURCE)

            def close(self) -> None:
                if self.mode == "close":
                    raise Boom("caller world close failed")

        class FaultWorld(_World):
            def __init__(self, mode: str) -> None:
                super().__init__()
                self.mode = mode

            def state_of(self, resource: ResourceKey) -> None:
                del resource
                raise Boom("caller world state failed")

            def iter_states(self, **_kwargs: Any) -> Iterable[Any]:
                if self.mode == "iter":
                    raise Boom("caller world iterator construction failed")
                return FaultIterator(self.mode)

        for mode in ("state", "iter", "next", "close"):
            with self.subTest(mode=mode):
                plugin = _Plugin()

                def read(world: Any, *, selected: str = mode) -> Iterable[Any]:
                    if selected == "state":
                        world.state_of(RESOURCE)
                    else:
                        tuple(world.iter_states())
                    return ()

                plugin.check_consistency = read  # type: ignore[method-assign]
                with self.assertRaises(PluginCapabilityInputError) as raised:
                    PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
                        FaultWorld(mode)
                    )
                self.assertIs(
                    raised.exception.capability,
                    PluginCapability.CONSISTENCY_CHECK,
                )

    def test_consistency_world_field_quality_has_a_sentinel_bound(self) -> None:
        class LyingFieldQuality(Mapping[str, Quality]):
            def __getitem__(self, key: str) -> Quality:
                return Quality.EXACT

            def __iter__(self) -> Iterator[str]:
                for index in range(2_000):
                    yield f"field-{index}"

            def __len__(self) -> int:
                return 0

            def items(self) -> Iterable[tuple[str, Quality]]:
                for index in range(2_000):
                    yield f"field-{index}", Quality.EXACT

        plugin = _Plugin()

        def scan(world: Any) -> Iterable[Any]:
            tuple(world.iter_states())
            return ()

        plugin.check_consistency = scan  # type: ignore[method-assign]
        state = replace(
            _resource_state(RESOURCE),
            field_quality=LyingFieldQuality(),
        )
        with self.assertRaisesRegex(PluginCapabilityInputError, "unreadable state"):
            PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
                _World((state,))
            )

    def test_consistency_resource_identity_is_bounded_before_traversal(self) -> None:
        class TupleSubclass(tuple):
            pass

        for label, parts in (
            ("tuple_subclass", TupleSubclass((("id", "one"),))),
            (
                "too_many_parts",
                tuple((f"part-{index}", index) for index in range(33)),
            ),
        ):
            with self.subTest(label=label):
                resource = replace(RESOURCE)
                object.__setattr__(resource, "parts", parts)
                plugin = _Plugin()
                plugin.consistency_output = (
                    ConsistencyFinding(
                        rule_id="opaque.resource-shape",
                        severity=DiagnosticSeverity.WARNING,
                        result=FindingResult.UNKNOWN,
                        summary="Invalid resource identity",
                        resources=(resource,),
                        provenance=Provenance.RECONSTRUCTED,
                        quality=Quality.UNKNOWN,
                        basis=BASIS,
                        evidence=(),
                    ),
                )
                with self.assertRaisesRegex(
                    PluginCapabilityOutputError,
                    "parts must be an exact tuple of 1 to 32 items",
                ):
                    PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
                        _World()
                    )

    def test_consistency_requires_mapping_details_and_detaches_before_advance(
        self,
    ) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)
        invalid = ConsistencyFinding(
            rule_id="opaque.rule",
            severity=DiagnosticSeverity.WARNING,
            result=FindingResult.UNKNOWN,
            summary="Invalid details root",
            resources=(RESOURCE,),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.UNKNOWN,
            basis=BASIS,
            evidence=(EVIDENCE,),
            details="not-a-properties-mapping",  # type: ignore[arg-type]
        )
        plugin.consistency_output = (invalid,)
        with self.assertRaisesRegex(PluginCapabilityOutputError, "must be a mapping"):
            executor.check_consistency(_World())  # type: ignore[arg-type]

        nested = {"before": "safe"}
        details = {"nested": nested}
        finding = replace(invalid, details=details)

        def outputs() -> Iterable[Any]:
            yield finding
            nested["late"] = object()
            details["also_late"] = object()
            yield _diagnostic()

        plugin.consistency_output = outputs()
        result = executor.check_consistency(_World())  # type: ignore[arg-type]
        detached = result.findings[0]
        self.assertIsNot(detached, finding)
        self.assertEqual(dict(detached.details), {"nested": {"before": "safe"}})
        self.assertNotIn("late", detached.details["nested"])
        self.assertIsNot(detached.basis, finding.basis)
        self.assertIsNot(detached.resources[0], finding.resources[0])
        self.assertIsNot(detached.evidence[0], finding.evidence[0])
        with self.assertRaises(TypeError):
            detached.details["new"] = "forbidden"  # type: ignore[index]

    def test_consistency_reuses_one_detached_copy_of_a_shared_large_basis(self) -> None:
        plugin = _Plugin()
        resolution = ResolvedNodeBasis(
            node_id="node-0",
            local_clock_domain=None,
            local_min_ns=None,
            local_max_ns=None,
            absolute_min_ns=None,
            absolute_max_ns=None,
            mapping_method=None,
            quality=Quality.UNKNOWN,
            reason_code="not-observed",
        )
        large_basis = replace(
            BASIS,
            node_resolutions=tuple(
                replace(resolution, node_id=f"node-{index}")
                for index in range(256)
            ),
        )
        finding = ConsistencyFinding(
            rule_id="opaque.shared-basis",
            severity=DiagnosticSeverity.WARNING,
            result=FindingResult.UNKNOWN,
            summary="Shared revision basis",
            resources=(),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.UNKNOWN,
            basis=large_basis,
            evidence=(),
        )
        plugin.consistency_output = (finding,) * 100

        original_snapshot = capability_executor_module._snapshot_world_basis
        with patch.object(
            capability_executor_module,
            "_snapshot_world_basis",
            wraps=original_snapshot,
        ) as snapshot:
            result = PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
                _World(basis=large_basis)
            )

        self.assertEqual(len(result.findings), 100)
        # bounded-world copy, authoritative copy, first emitted basis, and the
        # final post-generator mutation check. Cache hits do not resnapshot.
        self.assertEqual(snapshot.call_count, 4)
        self.assertEqual(len({id(item.basis) for item in result.findings}), 1)
        self.assertIsNot(result.findings[0].basis, large_basis)

    def test_consistency_detachment_has_invocation_wide_aggregate_limits(self) -> None:
        plugin = _Plugin()
        finding = ConsistencyFinding(
            rule_id="opaque.aggregate",
            severity=DiagnosticSeverity.WARNING,
            result=FindingResult.UNKNOWN,
            summary="A summary too large for the configured aggregate budget",
            resources=(RESOURCE,),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.UNKNOWN,
            basis=BASIS,
            evidence=(EVIDENCE,),
            details={"nested": {"value": "payload"}},
        )
        plugin.consistency_output = (finding,) * 2
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_consistency_snapshot_units=10),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "aggregate snapshot-unit limit",
        ):
            executor.check_consistency(_World())  # type: ignore[arg-type]

        plugin.consistency_output = (
            finding,
            replace(finding, basis=replace(BASIS)),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_consistency_basis_variants=1),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "distinct basis limit",
        ):
            executor.check_consistency(_World())  # type: ignore[arg-type]

        oversized_key = ResourceKey(
            namespace="opaque",
            node="node-a",
            layer="control",
            kind="opaque.item",
            parts=(("id", ("x" * 200,) * 10),),
        )
        plugin.consistency_output = (
            replace(finding, resources=(oversized_key,), evidence=(), details={}),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_consistency_snapshot_units=1_000),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "aggregate snapshot-unit limit",
        ):
            executor.check_consistency(_World())  # type: ignore[arg-type]

        plugin.consistency_output = (
            replace(_diagnostic(), details={"payload": "x" * 100}),
        )
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_consistency_snapshot_units=50),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "aggregate snapshot-unit limit",
        ):
            executor.check_consistency(_World())  # type: ignore[arg-type]

    def test_consistency_rejects_a_cached_basis_mutated_between_yields(self) -> None:
        plugin = _Plugin()
        mutable_basis = replace(BASIS)
        finding = ConsistencyFinding(
            rule_id="opaque.mutable-basis",
            severity=DiagnosticSeverity.WARNING,
            result=FindingResult.UNKNOWN,
            summary="Mutable basis",
            resources=(),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.UNKNOWN,
            basis=mutable_basis,
            evidence=(),
        )

        def outputs() -> Iterable[Any]:
            yield finding
            object.__setattr__(mutable_basis, "unresolved_reason", "mutated")
            yield finding
            object.__setattr__(mutable_basis, "unresolved_reason", None)

        plugin.consistency_output = outputs()
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "basis changed after it was yielded",
        ):
            PluginCapabilityExecutor(plugin).check_consistency(_World())  # type: ignore[arg-type]

    def test_topology_requires_declared_request_and_matching_records(self) -> None:
        plugin = _Plugin()
        plugin.topology_output = (_topology_record(), _diagnostic())
        executor = PluginCapabilityExecutor(plugin)
        request = TopologyProjectionRequest(
            projection_id="opaque.graph",
            status_perspective_id="opaque.status",
            max_records=10,
            max_world_reads=10,
        )

        result = executor.project_topology(request, _World())  # type: ignore[arg-type]
        self.assertEqual(result.records, (_topology_record(),))
        self.assertEqual(result.diagnostics, (_diagnostic(),))

        plugin.topology_output = (_topology_record(projection_id="opaque.other"),)
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "does not match",
        ):
            executor.project_topology(request, _World())  # type: ignore[arg-type]

        undeclared = replace(request, projection_id="opaque.missing")
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "not declared",
        ):
            executor.project_topology(undeclared, _World())  # type: ignore[arg-type]

        forged_bound = replace(request)
        object.__setattr__(forged_bound, "max_claims", True)
        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "max_claims",
        ):
            executor.project_topology(forged_bound, _World())  # type: ignore[arg-type]

    def test_topology_plugin_cannot_mutate_authoritative_request_scope(self) -> None:
        plugin = _Plugin()
        request = TopologyProjectionRequest(
            projection_id="opaque.graph",
            status_perspective_id="opaque.status",
            seed_resources=(RESOURCE,),
        )
        observed_request: TopologyProjectionRequest | None = None

        def mutate_request(
            hook_request: TopologyProjectionRequest,
            _world: Any,
        ) -> Iterable[Any]:
            nonlocal observed_request
            observed_request = hook_request
            object.__setattr__(hook_request, "projection_id", "opaque.other")
            object.__setattr__(
                hook_request.seed_resources[0],
                "kind",
                "MUTATED",
            )
            return (_topology_record(projection_id="opaque.other"),)

        plugin.project_topology = mutate_request  # type: ignore[method-assign]
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "projection_id does not match the request",
        ):
            PluginCapabilityExecutor(plugin).project_topology(
                request,
                _World(),  # type: ignore[arg-type]
            )

        self.assertIsNot(observed_request, request)
        self.assertEqual(request.projection_id, "opaque.graph")
        self.assertEqual(request.seed_resources[0], RESOURCE)
        self.assertEqual(request.seed_resources[0].kind, RESOURCE.kind)

    def test_topology_returns_claims_and_canonical_referenced_policies(self) -> None:
        plugin = _Plugin()
        primary_claim = _topology_claim()
        alternate_claim = _topology_claim(
            claim_id="claim-two",
            endpoint=OTHER_RESOURCE,
            claim_contract_id="opaque.connector.alt.v1",
            match_policy_id="opaque.connector.alt.v1",
            arguments=(("port", 2),),
        )
        plugin.topology_output = (
            primary_claim,
            _diagnostic(),
            alternate_claim,
            _topology_resource_record(RESOURCE),
            _topology_resource_record(OTHER_RESOURCE),
        )
        world = _World()
        result = PluginCapabilityExecutor(plugin).project_topology(
            TopologyProjectionRequest(
                projection_id="opaque.graph",
                status_perspective_id="opaque.status",
                max_records=10,
                max_claims=10,
            ),
            world,  # type: ignore[arg-type]
        )

        self.assertEqual(result.claims, (primary_claim, alternate_claim))
        self.assertEqual(
            tuple(policy.policy_id for policy in result.match_policies),
            ("opaque.connector.alt.v1", "opaque.connector.exact.v1"),
        )
        self.assertEqual(len(result.records), 2)
        self.assertEqual(result.diagnostics, (_diagnostic(),))
        self.assertTrue(result.records_complete)
        self.assertTrue(result.claims_complete)
        self.assertEqual(world.state_reads, [])

        plugin.topology_output = (_topology_record(),)
        compatible = PluginCapabilityExecutor(plugin).project_topology(
            TopologyProjectionRequest(
                projection_id="opaque.graph",
                status_perspective_id="opaque.status",
            ),
            _World(),  # type: ignore[arg-type]
        )
        self.assertEqual(compatible.claims, ())
        self.assertEqual(compatible.match_policies, ())

    def test_topology_outputs_are_deeply_detached_before_stream_advances(
        self,
    ) -> None:
        plugin = _Plugin()
        nested = {"label": "safe"}
        properties = {"nested": nested}
        diagnostic_details = {"phase": {"name": "safe"}}
        resource_record = replace(
            _topology_resource_record(),
            properties=properties,
        )
        claim = _topology_claim()
        diagnostic = replace(_diagnostic(), details=diagnostic_details)

        def outputs() -> Iterable[Any]:
            yield resource_record
            # This runs only when the core asks for the next output. A raw
            # retained record would therefore acquire an unvalidated object
            # after its initial validation.
            nested["late"] = object()
            properties["also_late"] = object()
            yield claim
            yield diagnostic
            diagnostic_details["phase"]["late"] = object()

        plugin.topology_output = outputs()
        result = PluginCapabilityExecutor(plugin).project_topology(
            TopologyProjectionRequest(
                projection_id="opaque.graph",
                status_perspective_id="opaque.status",
                max_records=10,
                max_claims=10,
            ),
            _World(),  # type: ignore[arg-type]
        )

        detached_properties = result.records[0].properties
        self.assertEqual(dict(detached_properties), {"nested": {"label": "safe"}})
        self.assertNotIn("also_late", detached_properties)
        self.assertNotIn("late", detached_properties["nested"])
        self.assertIsNot(result.records[0], resource_record)
        self.assertIsNot(result.claims[0], claim)
        self.assertIsNot(result.claims[0].endpoint, claim.endpoint)
        self.assertIsNot(result.diagnostics[0], diagnostic)
        self.assertEqual(
            dict(result.diagnostics[0].details["phase"]),
            {"name": "safe"},
        )
        with self.assertRaises(TypeError):
            detached_properties["new"] = "forbidden"  # type: ignore[index]
        with self.assertRaises(TypeError):
            detached_properties["nested"]["new"] = "forbidden"  # type: ignore[index]

    def test_topology_snapshot_revalidates_stateful_mapping_values(self) -> None:
        plugin = _Plugin()
        plugin.topology_output = (
            replace(
                _topology_resource_record(),
                properties=_ChangingMapping(),
            ),
        )

        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "non-finite float",
        ):
            PluginCapabilityExecutor(plugin).project_topology(
                TopologyProjectionRequest(
                    projection_id="opaque.graph",
                    status_perspective_id="opaque.status",
                    max_records=10,
                    max_claims=10,
                ),
                _World(),  # type: ignore[arg-type]
            )

    def test_topology_record_and_claim_bounds_report_independent_completeness(
        self,
    ) -> None:
        plugin = _Plugin()
        claim = _topology_claim()
        plugin.topology_output = (
            _topology_record(),
            _topology_resource_record(),
            claim,
        )
        world = _World()
        result = PluginCapabilityExecutor(plugin).project_topology(
            TopologyProjectionRequest(
                projection_id="opaque.graph",
                status_perspective_id="opaque.status",
                max_records=1,
                max_claims=1,
            ),
            world,  # type: ignore[arg-type]
        )
        self.assertEqual(result.records, (_topology_record(),))
        self.assertEqual(result.claims, (claim,))
        self.assertFalse(result.records_complete)
        self.assertTrue(result.claims_complete)
        self.assertEqual(world.state_reads, [])

        second_claim = _topology_claim(claim_id="claim-two")
        plugin.topology_output = (
            _topology_resource_record(),
            claim,
            second_claim,
        )
        claims_truncated = PluginCapabilityExecutor(plugin).project_topology(
            TopologyProjectionRequest(
                projection_id="opaque.graph",
                status_perspective_id="opaque.status",
                max_records=1,
                max_claims=1,
            ),
            _World(),  # type: ignore[arg-type]
        )
        self.assertTrue(claims_truncated.records_complete)
        self.assertFalse(claims_truncated.claims_complete)
        self.assertEqual(claims_truncated.claims, (claim,))

    def test_topology_claims_match_declared_policy_and_world_perspective(
        self,
    ) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)
        request = TopologyProjectionRequest(
            projection_id="opaque.graph",
            status_perspective_id="opaque.status",
        )
        invalid_claims = (
            (_topology_claim(match_policy_id="opaque.missing"), "undeclared"),
            (
                _topology_claim(claim_contract_id="opaque.connector.other.v1"),
                "claim_contract_id",
            ),
            (
                _topology_claim(arguments=(("other", "one"),)),
                "policy order",
            ),
            (
                _topology_claim(
                    status_perspective=StatusPerspectiveRef(
                        "opaque.status",
                        plugin_instance_id="foreign.instance",
                    )
                ),
                "bounded world",
            ),
        )
        for claim, message in invalid_claims:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    PluginCapabilityOutputError,
                    message,
                ),
            ):
                plugin.topology_output = (claim, _topology_resource_record())
                executor.project_topology(request, _World())  # type: ignore[arg-type]

        forged = _topology_claim()
        object.__setattr__(forged, "quality", "exact")
        plugin.topology_output = (forged, _topology_resource_record())
        with self.assertRaisesRegex(PluginCapabilityOutputError, "quality"):
            executor.project_topology(request, _World())  # type: ignore[arg-type]

        forged_endpoint = replace(RESOURCE)
        object.__setattr__(forged_endpoint, "parts", (("id", True),))
        plugin.topology_output = (
            _topology_claim(endpoint=forged_endpoint),
            _topology_resource_record(forged_endpoint),
        )
        with self.assertRaisesRegex(PluginCapabilityOutputError, "Boolean"):
            executor.project_topology(request, _World())  # type: ignore[arg-type]

    def test_topology_claim_endpoints_are_emitted_or_bounded_world_members(
        self,
    ) -> None:
        plugin = _Plugin()
        executor = PluginCapabilityExecutor(plugin)
        request = TopologyProjectionRequest(
            projection_id="opaque.graph",
            status_perspective_id="opaque.status",
            max_world_reads=1,
        )
        claim = _topology_claim()

        plugin.topology_output = (claim,)
        absent_state_world = _World(
            states_by_resource={RESOURCE: _resource_state(RESOURCE, exists=False)}
        )
        result = executor.project_topology(
            request,
            absent_state_world,  # type: ignore[arg-type]
        )
        self.assertEqual(result.claims, (claim,))
        self.assertEqual(absent_state_world.state_reads, [RESOURCE])

        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "neither an emitted topology resource nor present",
        ):
            executor.project_topology(request, _World())  # type: ignore[arg-type]

        plugin.topology_output = (
            claim,
            _topology_claim(claim_id="claim-two", endpoint=OTHER_RESOURCE),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "world-read limit",
        ):
            executor.project_topology(
                request,
                _World(
                    states_by_resource={
                        RESOURCE: _resource_state(RESOURCE),
                        OTHER_RESOURCE: _resource_state(OTHER_RESOURCE),
                    }
                ),  # type: ignore[arg-type]
            )

        plugin.topology_output = (claim, claim, _topology_resource_record())
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "claim identifiers must be unique",
        ):
            executor.project_topology(request, _World())  # type: ignore[arg-type]

    def test_forwarding_projection_requires_supported_ir_and_typed_mutations(
        self,
    ) -> None:
        plugin = _Plugin()
        plugin.forwarding_output = (_forwarding_mutation(), _diagnostic())
        executor = PluginCapabilityExecutor(plugin)

        result = executor.project_forwarding(
            _projection_request(),
            _World(),  # type: ignore[arg-type]
        )
        self.assertEqual(result.mutations, (_forwarding_mutation(),))
        self.assertEqual(result.diagnostics, (_diagnostic(),))

        with self.assertRaisesRegex(
            PluginCapabilityInputError,
            "not declared",
        ):
            executor.project_forwarding(
                _projection_request("opaque.ir"),
                _World(),  # type: ignore[arg-type]
            )

        plugin.forwarding_output = (object(),)
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "unsupported object",
        ):
            executor.project_forwarding(
                _projection_request(),
                _World(),  # type: ignore[arg-type]
            )

    def test_forwarding_plugin_cannot_rewrite_authoritative_ir(self) -> None:
        plugin = _Plugin()
        request = _projection_request()
        observed_request: ForwardingProjectionRequest | None = None

        def mutate_request(
            hook_request: ForwardingProjectionRequest,
            _world: Any,
        ) -> Iterable[Any]:
            nonlocal observed_request
            observed_request = hook_request
            object.__setattr__(hook_request, "ir_version", "opaque.undeclared-ir")
            return (
                replace(
                    _forwarding_mutation(),
                    ir_version="opaque.undeclared-ir",
                ),
            )

        plugin.project_forwarding = mutate_request  # type: ignore[method-assign]
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "ir_version does not match the request",
        ):
            PluginCapabilityExecutor(plugin).project_forwarding(
                request,
                _World(),  # type: ignore[arg-type]
            )

        self.assertIsNot(observed_request, request)
        self.assertEqual(request.ir_version, FORWARDING_IR_VERSION)

    def test_forwarding_step_requires_exact_result_and_matching_before_state(
        self,
    ) -> None:
        plugin = _Plugin()
        request = _step_request()
        plugin.step_output = _step_result(request)
        executor = PluginCapabilityExecutor(plugin)

        result = executor.resolve_forwarding_step(
            request,
            _World(),  # type: ignore[arg-type]
        )
        self.assertEqual(result.result, _step_result(request))
        self.assertEqual(result.diagnostics, ())

        wrong_request = replace(
            request,
            packet_state=ForwardingPacketState(layers=(), complete=False),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "before-state",
        ):
            executor.resolve_forwarding_step(
                wrong_request,
                _World(),  # type: ignore[arg-type]
            )

        plugin.step_output = object()
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "exact ForwardingStepResult",
        ):
            executor.resolve_forwarding_step(
                request,
                _World(),  # type: ignore[arg-type]
            )

    def test_forwarding_plugin_cannot_inject_user_steering_authority(self) -> None:
        plugin = _Plugin()
        request = _step_request()
        observed_request: ForwardingStepRequest | None = None

        def inject_rule(
            hook_request: ForwardingStepRequest,
            _world: Any,
        ) -> ForwardingStepResult:
            nonlocal observed_request
            observed_request = hook_request
            injected = ForwardingSteeringRule(
                rule_id="rule-injected",
                target_step_id=hook_request.step_id,
                action_contract_id="opaque.action",
                reason="Injected by plug-in",
                disposition=ForwardingPacketDisposition.DELIVER,
            )
            object.__setattr__(hook_request, "steering_rules", (injected,))
            result = _step_result(hook_request)
            return replace(
                result,
                transition=replace(
                    result.transition,
                    origin=ForwardingTransitionOrigin.USER_FORCED,
                    forced_rule_id=injected.rule_id,
                ),
            )

        plugin.resolve_forwarding_step = inject_rule  # type: ignore[method-assign]
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "does not match a request rule",
        ):
            PluginCapabilityExecutor(plugin).resolve_forwarding_step(
                request,
                _World(),  # type: ignore[arg-type]
            )

        self.assertIsNot(observed_request, request)
        self.assertIsNot(observed_request.packet_state, request.packet_state)
        self.assertEqual(request.steering_rules, ())

    def test_forwarding_step_retains_recoverable_diagnostic_and_fails_fatal(
        self,
    ) -> None:
        plugin = _Plugin()
        request = _step_request()
        executor = PluginCapabilityExecutor(plugin)
        plugin.step_output = _diagnostic()

        result = executor.resolve_forwarding_step(
            request,
            _World(),  # type: ignore[arg-type]
        )
        self.assertIsNone(result.result)
        self.assertEqual(result.diagnostics, (_diagnostic(),))

        plugin.step_output = _diagnostic(recoverable=False)
        with self.assertRaises(PluginCapabilityExecutionError) as caught:
            executor.resolve_forwarding_step(
                request,
                _World(),  # type: ignore[arg-type]
            )
        self.assertEqual(
            caught.exception.diagnostics,
            (_diagnostic(recoverable=False),),
        )

    def test_evidence_analysis_is_bounded_canonical_and_citation_scoped(self) -> None:
        digest = "sha256:" + "a" * 64
        fact = EvidenceAnalysisFact(
            reference_digest=digest,
            evidence_kind="source_record",
            subject_kind="normalized_source_record",
            node_id="node-a",
            revision_id="revision-a",
            payload_schema="example.source.v1",
            fact_provenance="log_derived",
            time_basis="source_clock_ns",
            time_start_ns=10,
            time_end_ns=10,
            time_clock_domain="trace.clock",
            payload={
                "tracepoint": "fib.lookup",
                "packet": {"labels": [16000, 16001]},
            },
        )
        request = EvidenceAnalysisRequest(
            invocation_id="invocation-a",
            analysis_kind=EvidenceAnalysisKind.TRACE_CORRELATION,
            facts=(fact,),
            parameters={"vrf": "blue", "constraints": {"layers": ["fib"]}},
            max_observations=2,
        )
        observation = EvidenceAnalysisObservation(
            observation_id="observation-1",
            category="route_resolution",
            summary="The tracepoint belongs to one route-resolution step.",
            cited_reference_digests=(digest,),
            quality=Quality.EXACT,
            details={"step": 1, "packet": {"labels": [16000, 16001]}},
        )
        plugin = _Plugin()
        plugin.evidence_analysis_output = (observation, _diagnostic())
        executor = PluginCapabilityExecutor(plugin)
        result = executor.analyze_evidence(request)
        self.assertTrue(plugin.evidence_analysis_called)
        self.assertEqual(result.observations, (observation,))
        self.assertEqual(result.diagnostics, (_diagnostic(),))
        self.assertIsNot(result.observations[0], observation)
        object.__setattr__(
            observation,
            "cited_reference_digests",
            ("sha256:" + "b" * 64,),
        )
        self.assertEqual(result.observations[0].cited_reference_digests, (digest,))

        late_mutated = replace(
            observation,
            cited_reference_digests=(digest,),
        )

        def mutate_after_yield() -> Any:
            yield late_mutated
            object.__setattr__(
                late_mutated,
                "cited_reference_digests",
                ("sha256:" + "b" * 64,),
            )

        plugin.evidence_analysis_output = mutate_after_yield()
        late_snapshot = executor.analyze_evidence(request)
        self.assertEqual(
            late_snapshot.observations[0].cited_reference_digests,
            (digest,),
        )

        observation = replace(
            observation,
            cited_reference_digests=(digest,),
        )

        valid_other_digest = "sha256:" + "b" * 64
        valid_to_valid = replace(observation)

        def mutate_valid_values_after_yield() -> Any:
            yield valid_to_valid
            assert plugin.evidence_analysis_request is not None
            object.__setattr__(
                plugin.evidence_analysis_request.facts[0],
                "reference_digest",
                valid_other_digest,
            )
            object.__setattr__(
                valid_to_valid,
                "cited_reference_digests",
                (valid_other_digest,),
            )

        plugin.evidence_analysis_output = mutate_valid_values_after_yield()
        valid_snapshot = executor.analyze_evidence(request)
        self.assertEqual(
            valid_snapshot.observations[0].cited_reference_digests,
            (digest,),
        )
        self.assertEqual(request.facts[0].reference_digest, digest)

        plugin.evidence_analysis_output = (
            replace(
                observation,
                cited_reference_digests=("sha256:" + "b" * 64,),
            ),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "outside its request",
        ):
            executor.analyze_evidence(request)

        plugin.evidence_analysis_output = (
            replace(observation, observation_id="observation-2"),
            observation,
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "canonically ordered",
        ):
            executor.analyze_evidence(request)


if __name__ == "__main__":
    unittest.main()
