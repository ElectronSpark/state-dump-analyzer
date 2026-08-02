from __future__ import annotations

import unittest
from collections.abc import Iterable
from dataclasses import replace
from typing import Any
from uuid import UUID

from router_dump_analyzer.capability_executor import (
    PluginCapabilityExecutionError,
    PluginCapabilityExecutor,
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
    ConsistencyFinding,
    CorrelationWindow,
    DiagnosticSeverity,
    DiagnosticStage,
    DomainEvent,
    Evidence,
    FindingResult,
    ForwardingMutation,
    ForwardingOperation,
    ForwardingPacketDisposition,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingProjectionRequest,
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
    RelationshipMutation,
    RelationshipOperation,
    RelationshipTypeDescriptor,
    ResourceKey,
    ResourceKindDescriptor,
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
    TopologyUsability,
    VrfForwardingState,
    WorldBasis,
    WorldBasisKind,
)

CAPABILITIES = frozenset(
    {
        PluginCapability.EVENT_REDUCTION,
        PluginCapability.EVENT_REVERSION,
        PluginCapability.CORRELATION,
        PluginCapability.CONSISTENCY_CHECK,
        PluginCapability.TOPOLOGY_PROJECTION,
        PluginCapability.FORWARDING_PROJECTION,
        PluginCapability.FORWARDING_TRACE,
    }
)


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
    def __init__(self, states: Iterable[Any] = ()) -> None:
        self._states = states
        self.last_limit: int | None = None

    @property
    def basis(self) -> WorldBasis:
        return BASIS

    @property
    def perspective_ref(self) -> StatusPerspectiveRef:
        return PERSPECTIVE

    def state_of(self, resource: ResourceKey) -> None:
        return None

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        return self._states

    def related(
        self,
        resource: ResourceKey,
        direction: Any = None,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        return ()

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[Any]:
        self.last_limit = limit
        return ()


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
        self.consistency_output: Iterable[Any] = ()
        self.topology_output: Iterable[Any] = ()
        self.forwarding_output: Iterable[Any] = ()
        self.step_output: Any = None
        self.apply_called = False

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
        return self.revert_output

    def correlate(self, reader: Any, window: Any) -> Iterable[Any]:
        return self.correlation_output

    def check_consistency(self, world: Any) -> Iterable[Any]:
        return self.consistency_output

    def project_topology(self, request: Any, world: Any) -> Iterable[Any]:
        return self.topology_output

    def project_forwarding(self, request: Any, world: Any) -> Iterable[Any]:
        return self.forwarding_output

    def resolve_forwarding_step(self, request: Any, world: Any) -> Any:
        return self.step_output


def _diagnostic(*, recoverable: bool = True) -> PluginDiagnostic:
    return PluginDiagnostic(
        stage=DiagnosticStage.CONSISTENCY,
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
    def test_executor_is_available_from_the_curated_core_surface(self) -> None:
        import router_dump_analyzer

        self.assertIs(
            router_dump_analyzer.PluginCapabilityExecutor,
            PluginCapabilityExecutor,
        )

    def test_manifest_capability_is_checked_before_invocation(self) -> None:
        plugin = _Plugin(manifest=_manifest(frozenset()))
        executor = PluginCapabilityExecutor(plugin)

        with self.assertRaises(PluginCapabilityUnavailableError):
            executor.apply(EVENT, _World())  # type: ignore[arg-type]

        self.assertFalse(plugin.apply_called)

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
        world = _World((object(), object()))
        executor = PluginCapabilityExecutor(
            plugin,
            limits=PluginCapabilityLimits(max_world_reads=1),
        )
        with self.assertRaisesRegex(
            PluginCapabilityOutputError,
            "bounded read",
        ):
            executor.check_consistency(world)  # type: ignore[arg-type]
        self.assertEqual(world.last_limit, 1)

        plugin = _Plugin()
        plugin.consistency_output = (finding, _diagnostic())
        result = PluginCapabilityExecutor(plugin).check_consistency(  # type: ignore[arg-type]
            _World()
        )
        self.assertEqual(result.findings, (finding,))
        self.assertEqual(result.diagnostics, (_diagnostic(),))

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
            PluginCapabilityOutputError,
            "not declared",
        ):
            executor.project_topology(undeclared, _World())  # type: ignore[arg-type]

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
            PluginCapabilityOutputError,
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


if __name__ == "__main__":
    unittest.main()
