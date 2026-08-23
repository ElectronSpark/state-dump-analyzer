from __future__ import annotations

import ast
import inspect
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import UUID

from router_dump_analyzer.capability_router import (
    CapabilityProviderRegistry,
    PlanBoundCapabilityRouter,
    RevisionSetCapabilityKey,
    RevisionSetCapabilityRouter,
)
from router_dump_analyzer.federation_executor import (
    FederationExecutionProvenance,
    FederationLinkerIdentity,
    FederationLinkerLimits,
    FederationLinkerRegistry,
    FederationLinkExecutor,
)
from router_dump_analyzer.ingestion_pipeline import PluginRegistry, RegisteredPlugin
from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyRequestError,
    MultiNodeTopologyService,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    FederatedConnectorClaim,
    FederationLinkRequest,
    FederationLinkResult,
    FederationMatchCandidate,
    FederationMatchState,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    Provenance,
    Quality,
    ReconstructionSupport,
    RelationDirection,
    ResourceKey,
    ResourceKindDescriptor,
    ResourceStateView,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRef,
    StatusPerspectiveRole,
    TopologyEndpointRecord,
    TopologyEndpointReference,
    TopologyLinkRecord,
    TopologyProjectionDescriptor,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourceRecord,
    TopologyUsability,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest
from router_dump_analyzer.topology_federation import (
    TopologyFederationCoordinator,
    TopologyFederationError,
    TopologyFederationLimits,
    TopologyFederationPolicyConflictError,
    TopologyProjectionInvocation,
    TopologyProjectionSelection,
    TopologyProjectionSelectionError,
)

EMPTY_CONFIGURATION = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)


def _policy(
    *,
    kind: ConnectorMatchPolicyKind = ConnectorMatchPolicyKind.EXACT_TOKEN,
    argument_names: tuple[str, ...] = ("token",),
    policy_id: str = "gate.connector.match.v1",
    claim_contract_id: str = "gate.connector.v1",
) -> ConnectorMatchPolicyDescriptor:
    return ConnectorMatchPolicyDescriptor(
        policy_id=policy_id,
        claim_contract_id=claim_contract_id,
        kind=kind,
        argument_names=argument_names,
        linker_plugin_id=("gate.federation-linker" if kind is ConnectorMatchPolicyKind.LINKER else None),
    )


def _schema(
    policies: tuple[ConnectorMatchPolicyDescriptor, ...],
) -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind="gate.port",
                label="Gate port",
                key_fields=("id",),
                properties=(),
            ),
        ),
        relationship_types=(),
        status_perspectives=(
            StatusPerspectiveDescriptor(
                perspective_id="gate.status",
                label="Gate status",
                layer_id="physical",
                role=StatusPerspectiveRole.OTHER,
            ),
        ),
        topology_projections=(
            TopologyProjectionDescriptor(
                projection_id="gate.graph",
                label="Gate graph",
                supported_status_perspective_ids=("gate.status",),
            ),
        ),
        connector_match_policies=policies,
    )


def _resource(node_id: str, endpoint_id: str) -> ResourceKey:
    return ResourceKey(
        namespace="gate",
        node=node_id,
        layer="physical",
        kind="gate.port",
        parts=(("id", endpoint_id),),
    )


def _resource_record(resource: ResourceKey) -> TopologyProjectionRecord:
    return TopologyProjectionRecord(
        projection_id="gate.graph",
        status_perspective_id="gate.status",
        payload=TopologyResourceRecord(resource=resource),
        usability=TopologyUsability.USABLE,
        source_resources=(resource,),
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
    )


def _claim(
    resource: ResourceKey,
    claim_id: str,
    arguments: tuple[tuple[str, Any], ...],
    *,
    policy: ConnectorMatchPolicyDescriptor,
    valid_from_ns: int | None = None,
    valid_to_ns: int | None = None,
    link_type: str = "connector",
) -> ConnectorClaim:
    return ConnectorClaim(
        claim_id=claim_id,
        endpoint=resource,
        claim_contract_id=policy.claim_contract_id,
        match_policy_id=policy.policy_id,
        arguments=arguments,
        provenance=Provenance.OBSERVED,
        quality=Quality.EXACT,
        link_type=link_type,
        valid_from_ns=valid_from_ns,
        valid_to_ns=valid_to_ns,
    )


class _TopologyPlugin(AnalyzerPluginBase):
    def __init__(
        self,
        *,
        plugin_id: str,
        plugin_version: str,
        policies: tuple[ConnectorMatchPolicyDescriptor, ...],
        records: tuple[TopologyProjectionRecord, ...],
        claims: tuple[ConnectorClaim, ...] = (),
    ) -> None:
        self.manifest = PluginManifest(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=(plugin_id,),
            supported_software_versions="*",
            capabilities=frozenset({PluginCapability.TOPOLOGY_PROJECTION}),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        self.schema = _schema(policies)
        self.records = records
        self.claims = claims
        self.project_calls = 0

    def describe(self) -> PluginSchema:
        return self.schema

    def project_topology(self, request: Any, world: Any):
        del request, world
        self.project_calls += 1
        return (*self.records, *self.claims)


class _World:
    def __init__(
        self,
        perspective_ref: StatusPerspectiveRef,
        *,
        basis_time_ns: int | None = 50,
        resolved_at_min_ns: int | None = None,
        resolved_at_max_ns: int | None = None,
    ) -> None:
        self._perspective_ref = perspective_ref
        if (
            basis_time_ns is not None
            and resolved_at_min_ns is None
            and resolved_at_max_ns is None
        ):
            resolved_at_min_ns = basis_time_ns
            resolved_at_max_ns = basis_time_ns
        self._basis = WorldBasis(
            kind=WorldBasisKind.ABSOLUTE_TIME,
            requested_time_ns=basis_time_ns,
            resolved_at_min_ns=resolved_at_min_ns,
            resolved_at_max_ns=resolved_at_max_ns,
            capture_ranges=(),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.EXACT,
        )

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef:
        return self._perspective_ref

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        del resource
        return None

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> tuple[()]:
        del layers, kinds, limit
        return ()

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> tuple[()]:
        del resource, direction, relation_types, limit
        return ()

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> tuple[()]:
        del relation_types, layers, limit
        return ()


@dataclass(frozen=True, slots=True)
class _BoundMember:
    member_id: str
    catalog_revision_id: str
    basis_revision_id: str
    node_id: str
    instance_id: str
    registered: RegisteredPlugin
    pin: PluginExecutionPin


def _register(
    registry: PluginRegistry,
    plugin: _TopologyPlugin,
    *,
    instance_id: str,
) -> RegisteredPlugin:
    return registry.register(
        plugin,
        instance_id=instance_id,
        distribution_name=f"{plugin.manifest.plugin_id}.distribution",
        distribution_version=plugin.manifest.plugin_version,
        entry_point_name=instance_id,
        configuration_digest=EMPTY_CONFIGURATION,
    )


def _pin(registered: RegisteredPlugin, schema: PluginSchema) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=registered.instance_id,
        plugin_id=registered.plugin_id,
        plugin_version=registered.plugin_version,
        core_api_version=registered.core_api_version,
        artifact=PluginArtifactIdentity(
            distribution_name=registered.distribution_name,
            distribution_version=registered.distribution_version,
            package_hash=registered.package_hash,
            entry_point_name=registered.entry_point_name,
            module_target=registered.module_target,
        ),
        configuration_digest=registered.configuration_digest,
        schema_digest=plugin_schema_digest(schema),
        registered_execution_identity=registered.registered_execution_identity,
        schema_versions=registered.schema_versions,
        capabilities=registered.capabilities,
        roles=("primary_parser", "topology_provider"),
    )


def _coordinator(
    plugins: tuple[_TopologyPlugin, ...],
    *,
    executor: FederationLinkExecutor | None = None,
    limits: TopologyFederationLimits | None = None,
) -> tuple[
    TopologyFederationCoordinator,
    tuple[_BoundMember, ...],
    tuple[TopologyProjectionSelection, ...],
    tuple[_World, ...],
]:
    registry = PluginRegistry()
    registered = tuple(
        _register(registry, plugin, instance_id=f"gate.topology-{index}")
        for index, plugin in enumerate(plugins)
    )
    pins = tuple(
        _pin(record, plugin.schema)
        for record, plugin in zip(registered, plugins, strict=True)
    )
    providers = CapabilityProviderRegistry(registered)
    members: list[_BoundMember] = []
    routers: list[PlanBoundCapabilityRouter] = []
    selections: list[TopologyProjectionSelection] = []
    worlds: list[_World] = []
    for index, (record, pin) in enumerate(zip(registered, pins, strict=True)):
        member_id = f"member-{index}"
        catalog_revision_id = f"catalog-{index}"
        basis_revision_id = f"basis-{index}"
        node_id = f"node-{index}"
        members.append(
            _BoundMember(
                member_id,
                catalog_revision_id,
                basis_revision_id,
                node_id,
                record.instance_id,
                record,
                pin,
            )
        )
        routers.append(
            PlanBoundCapabilityRouter(
                providers,
                PluginExecutionPlan(
                    node_id=node_id,
                    basis_revision_id=basis_revision_id,
                    plugins=(pin,),
                ),
                catalog_revision_id=catalog_revision_id,
                member_id=member_id,
            )
        )
        selections.append(
            TopologyProjectionSelection(
                key=RevisionSetCapabilityKey(catalog_revision_id, member_id),
                plugin_instance_id=record.instance_id,
                expected_node_id=node_id,
                expected_basis_revision_id=basis_revision_id,
                request=TopologyProjectionRequest(
                    projection_id="gate.graph",
                    status_perspective_id="gate.status",
                    max_records=100,
                    max_claims=100,
                ),
                basis_time_ns=50,
            )
        )
        worlds.append(
            _World(
                StatusPerspectiveRef(
                    perspective_id="gate.status",
                    plugin_instance_id=record.instance_id,
                    schema_digest=pin.schema_digest,
                )
            )
        )
    # Reverse construction order deliberately: the revision-set router owns
    # canonical selection order and must not inherit caller ordering.
    revision_router = RevisionSetCapabilityRouter(tuple(reversed(routers)))
    return (
        TopologyFederationCoordinator(
            revision_router,
            federation_executor=executor,
            limits=limits,
        ),
        tuple(members),
        tuple(selections),
        tuple(worlds),
    )


def _project_all(
    coordinator: TopologyFederationCoordinator,
    selections: tuple[TopologyProjectionSelection, ...],
    worlds: tuple[_World, ...],
) -> tuple[TopologyProjectionInvocation, ...]:
    return tuple(
        coordinator.project(selection, world)
        for selection, world in zip(selections, worlds, strict=True)
    )


def _rendering_service(node_ids: tuple[str, ...]) -> MultiNodeTopologyService:
    return MultiNodeTopologyService(
        contract={
            "nodes": [{"node_id": node_id} for node_id in node_ids],
            "federation_plugin": {
                "plugin_id": "gate.renderer",
                "plugin_run_id": "gate.renderer.run",
                "plugin_version": "1",
            },
            "network_segment_matchers": [],
        },
        topology_profiles=[{"profile_id": "gate.profile"}],
        topology_metadata={
            "topology_id": "gate.topology",
            "assembly_id": "gate.assembly",
            "revision_id": "gate.revision",
            "capture_ns": 50,
            "timeline_start_ns": 0,
            "timeline_end_ns": 100,
        },
    )


class _Linker:
    linker_plugin_id = "gate.federation-linker"
    linker_plugin_version = "4.2"

    def __init__(self, policy: ConnectorMatchPolicyDescriptor) -> None:
        self.policy = policy
        self.requests: list[FederationLinkRequest] = []

    def describe_match_policies(
        self,
    ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
        return (self.policy,)

    def link(self, request: FederationLinkRequest):
        self.requests.append(request)
        for source in request.claims:
            candidate = next(
                claim
                for claim in request.claims
                if claim.endpoint.member_id != source.endpoint.member_id
            )
            yield FederationLinkResult(
                result_id=f"linked-{source.claim.claim_id}",
                match_policy_id=request.policy.policy_id,
                source=source,
                state=FederationMatchState.MATCHED,
                candidates=(
                    FederationMatchCandidate(
                        claim_id=candidate.claim.claim_id,
                        endpoint=candidate.endpoint,
                        quality=Quality.EXACT,
                    ),
                ),
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
            )


class _FailingLinker:
    linker_plugin_id = "gate.federation-linker"
    linker_plugin_version = "4.2"

    def __init__(self, policy: ConnectorMatchPolicyDescriptor) -> None:
        self.policy = policy

    def describe_match_policies(
        self,
    ) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
        return (self.policy,)

    def link(self, request: FederationLinkRequest):
        del request
        raise RuntimeError("deliberate linker failure")
        yield  # pragma: no cover - make this a generator hook


class TopologyFederationAcceptanceGateTests(unittest.TestCase):
    def test_public_federate_stub_signature_matches_runtime(self) -> None:
        stub_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "router_dump_analyzer"
            / "topology_federation.pyi"
        )
        tree = ast.parse(stub_path.read_text(encoding="utf-8"))
        coordinator = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "TopologyFederationCoordinator"
        )
        stub_method = next(
            node
            for node in coordinator.body
            if isinstance(node, ast.FunctionDef) and node.name == "federate"
        )
        runtime_parameters = inspect.signature(
            TopologyFederationCoordinator.federate
        ).parameters

        self.assertEqual(
            tuple(runtime_parameters),
            tuple(
                argument.arg
                for argument in (*stub_method.args.args, *stub_method.args.kwonlyargs)
            ),
        )
        self.assertIs(
            runtime_parameters["invocations_complete"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            runtime_parameters["invocations_complete"].default,
            True,
        )
        self.assertEqual(
            [argument.arg for argument in stub_method.args.kwonlyargs],
            ["invocations_complete"],
        )
        self.assertEqual(len(stub_method.args.kw_defaults), 1)
        self.assertIsInstance(stub_method.args.kw_defaults[0], ast.Constant)
        self.assertIs(stub_method.args.kw_defaults[0].value, True)

    def test_frozen_revision_set_selects_heterogeneous_record_only_plugins(
        self,
    ) -> None:
        resources = (_resource("node-0", "port-a"), _resource("node-1", "port-b"))
        plugins = (
            _TopologyPlugin(
                plugin_id="gate.alpha-platform",
                plugin_version="1.7",
                policies=(),
                records=(_resource_record(resources[0]),),
            ),
            _TopologyPlugin(
                plugin_id="gate.beta-asic",
                plugin_version="9.3",
                policies=(),
                records=(_resource_record(resources[1]),),
            ),
        )
        coordinator, members, selections, worlds = _coordinator(plugins)

        invocations = _project_all(coordinator, selections, worlds)
        assembly = coordinator.federate(tuple(reversed(invocations)))

        self.assertEqual(
            tuple(item.invocation.provider.pin.plugin_id for item in assembly.invocations),
            ("gate.alpha-platform", "gate.beta-asic"),
        )
        self.assertEqual(
            tuple(item.invocation.provider.pin.plugin_version for item in assembly.invocations),
            ("1.7", "9.3"),
        )
        self.assertTrue(all(item.invocation.result.claims == () for item in assembly.invocations))
        self.assertTrue(
            all(item.invocation.result.match_policies == () for item in assembly.invocations)
        )
        self.assertEqual(assembly.claims, ())
        self.assertEqual(assembly.policy_executions, ())
        self.assertTrue(assembly.complete)
        self.assertFalse(assembly.truncated)
        self.assertEqual([plugin.project_calls for plugin in plugins], [1, 1])

        with self.assertRaises(TopologyProjectionSelectionError):
            coordinator.project(
                replace(
                    selections[0],
                    plugin_instance_id=members[1].instance_id,
                ),
                worlds[0],
            )
        self.assertEqual([plugin.project_calls for plugin in plugins], [1, 1])

    def test_exact_token_gate_covers_types_cardinality_and_temporal_filtering(
        self,
    ) -> None:
        policy = _policy()
        # Multiple connector endpoints may belong to one node.  Three member
        # providers are enough to cover matched, unresolved, ambiguous, typed,
        # and inactive claims while also proving same-member claims are never
        # treated as remote candidates.
        cases: tuple[tuple[tuple[Any, int | None, int | None], ...], ...] = (
            (
                (7, None, None),
                ("7", None, None),
                ("fanout", None, None),
                ("stale", None, 40),
            ),
            (
                (7, None, None),
                ("fanout", None, None),
                ("stale", 45, 60),
            ),
            (("fanout", None, None),),
        )
        plugins: list[_TopologyPlugin] = []
        claim_index = 0
        for member_index, member_cases in enumerate(cases):
            resources: list[ResourceKey] = []
            claims: list[ConnectorClaim] = []
            for token, valid_from_ns, valid_to_ns in member_cases:
                resource = _resource(
                    f"node-{member_index}",
                    f"port-{claim_index}",
                )
                resources.append(resource)
                claims.append(
                    _claim(
                        resource,
                        f"claim-{claim_index}",
                        (("token", token),),
                        policy=policy,
                        valid_from_ns=valid_from_ns,
                        valid_to_ns=valid_to_ns,
                    )
                )
                claim_index += 1
            plugins.append(
                _TopologyPlugin(
                    plugin_id=f"gate.platform-{member_index}",
                    plugin_version=f"{member_index + 1}.0",
                    policies=(policy,),
                    records=tuple(_resource_record(resource) for resource in resources),
                    claims=tuple(claims),
                )
            )
        coordinator, _members, selections, worlds = _coordinator(tuple(plugins))

        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )

        self.assertEqual(assembly.inactive_claim_count, 1)
        self.assertEqual(len(assembly.claims), 7)
        self.assertTrue(assembly.complete)
        self.assertFalse(assembly.truncated)
        self.assertEqual(len(assembly.policy_executions), 1)
        execution = assembly.policy_executions[0].execution
        self.assertIs(
            execution.provenance,
            FederationExecutionProvenance.CORE_EXACT_TOKEN,
        )
        self.assertIsNone(execution.linker_identity)
        by_claim = {result.source.claim.claim_id: result for result in execution.results}
        self.assertIs(by_claim["claim-0"].state, FederationMatchState.MATCHED)
        self.assertEqual(
            tuple(item.claim_id for item in by_claim["claim-0"].candidates),
            ("claim-4",),
        )
        self.assertIs(by_claim["claim-4"].state, FederationMatchState.MATCHED)
        # The string "7" must not alias integer 7.
        self.assertIs(by_claim["claim-1"].state, FederationMatchState.UNRESOLVED)
        for claim_id in ("claim-2", "claim-5", "claim-7"):
            self.assertIs(by_claim[claim_id].state, FederationMatchState.AMBIGUOUS)
            self.assertEqual(len(by_claim[claim_id].candidates), 2)
        self.assertNotIn("claim-3", by_claim)
        self.assertIs(by_claim["claim-6"].state, FederationMatchState.UNRESOLVED)

    def test_claim_validity_is_half_open_and_unknown_basis_fails_closed(
        self,
    ) -> None:
        policy = _policy()
        resource = _resource("node-0", "boundary")
        plugin = _TopologyPlugin(
            plugin_id="gate.temporal-platform",
            plugin_version="1",
            policies=(policy,),
            records=(_resource_record(resource),),
            claims=(
                _claim(
                    resource,
                    "boundary-claim",
                    (("token", "shared"),),
                    policy=policy,
                    valid_from_ns=10,
                    valid_to_ns=50,
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator((plugin,))

        boundary = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )
        self.assertEqual(boundary.total_claim_count, 1)
        self.assertEqual(boundary.inactive_claim_count, 1)
        self.assertEqual(boundary.temporal_basis_unknown_claim_count, 0)
        self.assertEqual(boundary.claims, ())
        self.assertTrue(boundary.complete)
        self.assertFalse(boundary.truncated)

        unknown_selection = (replace(selections[0], basis_time_ns=None),)
        unknown_worlds = (
            _World(worlds[0].perspective_ref, basis_time_ns=None),
        )
        unknown = coordinator.federate(
            _project_all(coordinator, unknown_selection, unknown_worlds)
        )
        self.assertEqual(unknown.total_claim_count, 1)
        self.assertEqual(unknown.inactive_claim_count, 0)
        self.assertEqual(unknown.temporal_basis_unknown_claim_count, 1)
        self.assertEqual(unknown.claims, ())
        self.assertFalse(unknown.complete)
        self.assertFalse(unknown.truncated)

    def test_projection_binds_claim_filtering_to_the_world_clock_window(
        self,
    ) -> None:
        policy = _policy()
        resource = _resource("node-0", "windowed")
        plugin = _TopologyPlugin(
            plugin_id="gate.windowed-platform",
            plugin_version="1",
            policies=(policy,),
            records=(_resource_record(resource),),
            claims=(
                _claim(
                    resource,
                    "windowed-claim",
                    (("token", "shared"),),
                    policy=policy,
                    valid_from_ns=40,
                    valid_to_ns=60,
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator((plugin,))
        perspective = worlds[0].perspective_ref

        exact = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )
        self.assertEqual(len(exact.claims), 1)
        self.assertTrue(exact.complete)

        wholly_active = coordinator.federate(
            _project_all(
                coordinator,
                selections,
                (
                    _World(
                        perspective,
                        basis_time_ns=50,
                        resolved_at_min_ns=45,
                        resolved_at_max_ns=55,
                    ),
                ),
            )
        )
        self.assertEqual(len(wholly_active.claims), 1)
        self.assertTrue(wholly_active.complete)

        wholly_inactive = coordinator.federate(
            _project_all(
                coordinator,
                (replace(selections[0], basis_time_ns=62),),
                (
                    _World(
                        perspective,
                        basis_time_ns=62,
                        resolved_at_min_ns=60,
                        resolved_at_max_ns=65,
                    ),
                ),
            )
        )
        self.assertEqual(wholly_inactive.claims, ())
        self.assertEqual(wholly_inactive.inactive_claim_count, 1)
        self.assertTrue(wholly_inactive.complete)

        boundary_crossing = coordinator.federate(
            _project_all(
                coordinator,
                selections,
                (
                    _World(
                        perspective,
                        basis_time_ns=50,
                        resolved_at_min_ns=45,
                        resolved_at_max_ns=65,
                    ),
                ),
            )
        )
        self.assertEqual(boundary_crossing.claims, ())
        self.assertEqual(
            boundary_crossing.temporal_basis_unknown_claim_count,
            1,
        )
        self.assertFalse(boundary_crossing.complete)
        self.assertFalse(boundary_crossing.truncated)

        with self.assertRaisesRegex(
            TopologyProjectionSelectionError,
            "does not match",
        ):
            coordinator.project(
                selections[0],
                _World(perspective, basis_time_ns=51),
            )

    def test_projection_record_crossing_world_window_is_not_rendered_current(
        self,
    ) -> None:
        resource = _resource("node-0", "windowed-record")
        plugin = _TopologyPlugin(
            plugin_id="gate.windowed-record-platform",
            plugin_version="1",
            policies=(),
            records=(
                replace(
                    _resource_record(resource),
                    valid_from_ns=40,
                    valid_to_ns=60,
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator((plugin,))
        invocation = coordinator.project(
            selections[0],
            _World(
                worlds[0].perspective_ref,
                basis_time_ns=50,
                resolved_at_min_ns=45,
                resolved_at_max_ns=65,
            ),
        )

        (
            rows,
            local_links,
            endpoints,
            scoped_resources,
            inactive_count,
            unknown_count,
        ) = _rendering_service(("node-0",))._render_typed_projection(
            {},
            "gate.plugin-set",
            {
                "plugin_id": "gate.windowed-record-platform",
                "plugin_instance_id": "gate.topology-0",
                "plugin_run_id": "gate.run",
                "version": "1",
            },
            {"projection_id": "gate.graph"},
            "gate.status",
            {},
            {},
            "gate.context",
            invocation,
        )

        self.assertEqual(rows, [])
        self.assertEqual(local_links, [])
        self.assertEqual(endpoints, [])
        self.assertEqual(scoped_resources, {})
        self.assertEqual(inactive_count, 0)
        self.assertEqual(unknown_count, 1)

    def test_plugin_request_mutation_cannot_rewrite_federation_scope(self) -> None:
        policy = _policy()
        resource = _resource("node-0", "detached-request")
        claim = _claim(
            resource,
            "detached-claim",
            (("token", "detached"),),
            policy=policy,
        )
        plugin = _TopologyPlugin(
            plugin_id="gate.detached-request-platform",
            plugin_version="1",
            policies=(policy,),
            records=(),
        )
        observed_request = None

        def mutate_request(request: Any, _world: Any):
            nonlocal observed_request
            observed_request = request
            object.__setattr__(request, "projection_id", "gate.other-graph")
            object.__setattr__(request, "status_perspective_id", "gate.other-status")
            return (_resource_record(resource), claim)

        plugin.project_topology = mutate_request  # type: ignore[method-assign]
        coordinator, _members, selections, worlds = _coordinator((plugin,))
        invocation = coordinator.project(selections[0], worlds[0])
        assembly = coordinator.federate((invocation,))

        self.assertIsNot(observed_request, selections[0].request)
        self.assertEqual(selections[0].request.projection_id, "gate.graph")
        self.assertEqual(
            selections[0].request.status_perspective_id,
            "gate.status",
        )
        self.assertEqual(len(assembly.claim_contexts), 1)
        self.assertEqual(assembly.claim_contexts[0].projection_id, "gate.graph")
        self.assertEqual(
            assembly.claim_contexts[0].status_perspective_id,
            "gate.status",
        )

    def test_inactive_claims_are_bounded_and_deduplicated_before_filtering(
        self,
    ) -> None:
        policy = _policy()
        resources = (
            _resource("node-0", "expired-a"),
            _resource("node-0", "expired-b"),
        )
        over_limit = _TopologyPlugin(
            plugin_id="gate.expired-limit",
            plugin_version="1",
            policies=(policy,),
            records=tuple(_resource_record(item) for item in resources),
            claims=tuple(
                _claim(
                    resource,
                    f"expired-{index}",
                    (("token", index),),
                    policy=policy,
                    valid_to_ns=40,
                )
                for index, resource in enumerate(resources)
            ),
        )
        coordinator, _members, selections, worlds = _coordinator(
            (over_limit,),
            limits=TopologyFederationLimits(max_claims=1),
        )
        with self.assertRaisesRegex(TopologyFederationError, "claim limit"):
            coordinator.federate(_project_all(coordinator, selections, worlds))

        duplicates = _TopologyPlugin(
            plugin_id="gate.expired-duplicate",
            plugin_version="1",
            policies=(policy,),
            records=tuple(_resource_record(item) for item in resources),
            claims=(
                _claim(
                    resources[0],
                    "same-expired-id",
                    (("token", 0),),
                    policy=policy,
                    valid_to_ns=40,
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator((duplicates,))
        projected = _project_all(coordinator, selections, worlds)[0]
        duplicate_claim = replace(
            projected.invocation.result.claims[0],
            endpoint=resources[1],
            arguments=(("token", 1),),
        )
        duplicate_result = replace(
            projected.invocation.result,
            claims=(*projected.invocation.result.claims, duplicate_claim),
        )
        duplicated_invocation = TopologyProjectionInvocation(
            projected.selection,
            replace(projected.invocation, result=duplicate_result),
            projected.world_basis,
        )
        with self.assertRaisesRegex(TopologyFederationError, "identities"):
            coordinator.federate((duplicated_invocation,))

    def test_coordinator_caps_result_request_to_executor_limit(self) -> None:
        policy = _policy()
        resources = (_resource("node-0", "left"), _resource("node-1", "right"))
        plugins = tuple(
            _TopologyPlugin(
                plugin_id=f"gate.capped-{index}",
                plugin_version="1",
                policies=(policy,),
                records=(_resource_record(resource),),
                claims=(
                    _claim(
                        resource,
                        f"capped-{index}",
                        (("token", "shared"),),
                        policy=policy,
                    ),
                ),
            )
            for index, resource in enumerate(resources)
        )
        executor = FederationLinkExecutor(
            limits=FederationLinkerLimits(max_results=1)
        )
        coordinator, _members, selections, worlds = _coordinator(
            plugins,
            executor=executor,
        )

        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )

        self.assertEqual(assembly.failures, ())
        self.assertEqual(len(assembly.policy_executions), 1)
        execution = assembly.policy_executions[0].execution
        self.assertEqual(len(execution.results), 1)
        self.assertTrue(execution.truncated)
        self.assertFalse(execution.complete)
        self.assertTrue(assembly.truncated)
        self.assertFalse(assembly.complete)
        service = _rendering_service(("node-0", "node-1"))
        links, resolutions, _unmatched, truncated = service._federated_claim_links(
            assembly,
            {},
            100,
            "gate-context",
            {"kind": "absolute_time", "time_ns": "50"},
        )
        self.assertTrue(truncated)
        self.assertEqual(links, [])
        self.assertEqual(resolutions[0]["returned_count"], 1)
        self.assertIsNone(resolutions[0]["total_count"])
        self.assertFalse(resolutions[0]["complete"])
        self.assertTrue(resolutions[0]["truncated"])

    def test_unscoped_input_gaps_taint_every_surviving_federated_link(
        self,
    ) -> None:
        policy = _policy()
        resources = tuple(
            _resource(f"node-{index}", f"tainted-{index}")
            for index in range(3)
        )
        plugins = tuple(
            _TopologyPlugin(
                plugin_id=f"gate.tainted-{index}",
                plugin_version="1",
                policies=(policy,),
                records=(_resource_record(resource),),
                claims=(
                    _claim(
                        resource,
                        f"tainted-{index}",
                        (("token", "shared"),),
                        policy=policy,
                        valid_from_ns=(40 if index == 2 else None),
                        valid_to_ns=(60 if index == 2 else None),
                    ),
                ),
            )
            for index, resource in enumerate(resources)
        )
        coordinator, members, selections, worlds = _coordinator(plugins)
        projected = list(_project_all(coordinator, selections, worlds))
        incomplete_result = replace(
            projected[0].invocation.result,
            claims_complete=False,
        )
        projected[0] = replace(
            projected[0],
            invocation=replace(
                projected[0].invocation,
                result=incomplete_result,
            ),
        )
        service = _rendering_service(tuple(item.node_id for item in members))

        claim_truncated = coordinator.federate(tuple(projected))
        links, resolutions, _unmatched, truncated = service._federated_claim_links(
            claim_truncated,
            {},
            100,
            "gate-context",
            {"kind": "absolute_time", "time_ns": "50"},
        )
        self.assertFalse(claim_truncated.claims_complete)
        self.assertTrue(truncated)
        self.assertEqual(links, [])
        self.assertTrue(resolutions[0]["results"])
        self.assertFalse(resolutions[0]["complete"])
        self.assertTrue(resolutions[0]["truncated"])

        omitted_member = coordinator.federate(
            _project_all(coordinator, selections, worlds),
            invocations_complete=False,
        )
        omitted_links, _resolutions, _unmatched, omitted_truncated = (
            service._federated_claim_links(
                omitted_member,
                {},
                100,
                "gate-context",
                {"kind": "absolute_time", "time_ns": "50"},
            )
        )
        self.assertFalse(omitted_member.invocations_complete)
        self.assertTrue(omitted_truncated)
        self.assertEqual(omitted_links, [])

        uncertain_worlds = (
            worlds[0],
            worlds[1],
            _World(
                worlds[2].perspective_ref,
                basis_time_ns=50,
                resolved_at_min_ns=45,
                resolved_at_max_ns=65,
            ),
        )
        temporal_unknown = coordinator.federate(
            _project_all(coordinator, selections, uncertain_worlds)
        )
        unknown_links, _resolutions, _unmatched, _truncated = (
            service._federated_claim_links(
                temporal_unknown,
                {},
                100,
                "gate-context",
                {"kind": "absolute_time", "time_ns": "50"},
            )
        )
        self.assertEqual(
            temporal_unknown.temporal_basis_unknown_claim_count,
            1,
        )
        self.assertEqual(unknown_links, [])

    def test_route_typed_boundary_rejects_real_link_page_slice(self) -> None:
        policies = (
            _policy(
                policy_id="gate.route-page.alpha.v1",
                claim_contract_id="gate.route-page.alpha",
            ),
            _policy(
                policy_id="gate.route-page.beta.v1",
                claim_contract_id="gate.route-page.beta",
            ),
        )
        resources = (
            _resource("node-0", "shared-left"),
            _resource("node-1", "shared-right"),
        )
        plugins = tuple(
            _TopologyPlugin(
                plugin_id=f"gate.route-page-{index}",
                plugin_version="1",
                policies=policies,
                records=(_resource_record(resource),),
                claims=tuple(
                    _claim(
                        resource,
                        f"route-page-{policy_index}-{index}",
                        (("token", "shared"),),
                        policy=policy,
                    )
                    for policy_index, policy in enumerate(policies)
                ),
            )
            for index, resource in enumerate(resources)
        )
        coordinator, members, selections, worlds = _coordinator(plugins)
        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )
        service = _rendering_service(
            tuple(item.node_id for item in members)
        )

        sliced_links, _resolutions, _unmatched, page_truncated = (
            service._federated_claim_links(
                assembly,
                {},
                1,
                "gate-context",
                {"kind": "absolute_time", "time_ns": "50"},
            )
        )
        full_links, _resolutions, _unmatched, full_truncated = (
            service._federated_claim_links(
                assembly,
                {},
                100,
                "gate-context",
                {"kind": "absolute_time", "time_ns": "50"},
            )
        )
        self.assertTrue(assembly.complete)
        self.assertFalse(assembly.truncated)
        self.assertTrue(page_truncated)
        self.assertEqual(len(sliced_links), 1)
        self.assertFalse(full_truncated)
        self.assertEqual(len(full_links), 2)
        self.assertEqual(
            len({link["link_id"] for link in full_links}),
            2,
        )

        source_ref = full_links[0]["endpoint_a"]["resource_ref"]
        target_ref = full_links[0]["endpoint_b"]["resource_ref"]
        reference = {
            "reference_kind": "typed_inter_node_link",
            "source_endpoint": {
                "node_id": source_ref["node_id"],
                "resource_id": source_ref["local_resource_id"],
                "typed_resource_key": source_ref["typed_resource_key"],
            },
            "target_endpoint": {
                "node_id": target_ref["node_id"],
                "resource_id": target_ref["local_resource_id"],
                "typed_resource_key": target_ref["typed_resource_key"],
            },
        }

        def resolve(
            links: list[dict[str, Any]],
            *,
            links_truncated: bool,
        ) -> tuple[dict[str, Any], dict[str, Any] | None, object]:
            return MultiNodeRouteService._resolve_typed_boundary_reference(
                {
                    "inter_node_links": links,
                    "completeness": {
                        "typed_federation_complete": assembly.complete,
                        "typed_federation_truncated": assembly.truncated,
                        "inter_node_links_truncated": links_truncated,
                    },
                },
                reference,
                source_node_id=source_ref["node_id"],
                target_node_id=target_ref["node_id"],
                source_resource_id=source_ref["local_resource_id"],
                target_resource_id=target_ref["local_resource_id"],
            )

        sliced_binding, sliced_link, sliced_refs = resolve(
            sliced_links,
            links_truncated=page_truncated,
        )
        self.assertEqual(
            sliced_binding["reason_code"],
            "typed_boundary_inter_node_links_truncated",
        )
        self.assertIsNone(sliced_link)
        self.assertIsNone(sliced_refs)

        full_binding, full_link, full_refs = resolve(
            full_links,
            links_truncated=full_truncated,
        )
        self.assertEqual(
            full_binding["reason_code"],
            "typed_boundary_link_ambiguous",
        )
        self.assertCountEqual(
            full_binding["candidate_link_ids"],
            [link["link_id"] for link in full_links],
        )
        self.assertIsNone(full_link)
        self.assertIsNone(full_refs)

    def test_linker_failure_is_scoped_while_other_policy_results_survive(
        self,
    ) -> None:
        exact_policy = _policy(
            policy_id="gate.exact.match.v1",
            claim_contract_id="gate.exact.v1",
        )
        linker_policy = _policy(
            kind=ConnectorMatchPolicyKind.LINKER,
            policy_id="gate.linker.match.v1",
            claim_contract_id="gate.linker.v1",
        )
        linker = _FailingLinker(linker_policy)
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))
        plugins: list[_TopologyPlugin] = []
        for index in range(2):
            exact_resource = _resource(f"node-{index}", f"exact-{index}")
            linked_resource = _resource(f"node-{index}", f"linked-{index}")
            plugins.append(
                _TopologyPlugin(
                    plugin_id=f"gate.scoped-failure-{index}",
                    plugin_version="1",
                    policies=(exact_policy, linker_policy),
                    records=(
                        _resource_record(exact_resource),
                        _resource_record(linked_resource),
                    ),
                    claims=(
                        _claim(
                            exact_resource,
                            f"exact-{index}",
                            (("token", "exact-shared"),),
                            policy=exact_policy,
                        ),
                        _claim(
                            linked_resource,
                            f"linked-{index}",
                            (("token", f"local-{index}"),),
                            policy=linker_policy,
                        ),
                    ),
                )
            )
        coordinator, _members, selections, worlds = _coordinator(
            tuple(plugins),
            executor=executor,
        )

        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )

        self.assertEqual(len(assembly.policy_executions), 1)
        self.assertEqual(
            assembly.policy_executions[0].policy.policy_id,
            exact_policy.policy_id,
        )
        self.assertTrue(assembly.policy_executions[0].execution.complete)
        self.assertEqual(len(assembly.failures), 1)
        self.assertEqual(assembly.failures[0].policy_id, linker_policy.policy_id)
        self.assertEqual(
            assembly.failures[0].reason_code,
            "federation_linker_failed",
        )
        self.assertFalse(assembly.complete)
        self.assertFalse(assembly.truncated)

    def test_renderer_applies_half_open_validity_to_all_typed_record_kinds(
        self,
    ) -> None:
        active_resource = _resource("node-0", "active")
        expired_resource = _resource("node-0", "expired")
        active_reference = TopologyEndpointReference(resource=active_resource)

        def record(
            payload: Any,
            *,
            valid_from_ns: int | None = None,
            valid_to_ns: int | None = None,
            properties=None,
        ):
            return TopologyProjectionRecord(
                projection_id="gate.graph",
                status_perspective_id="gate.status",
                payload=payload,
                usability=TopologyUsability.USABLE,
                source_resources=(active_resource,),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.EXACT,
                properties=properties or {},
                valid_from_ns=valid_from_ns,
                valid_to_ns=valid_to_ns,
            )

        plugin = _TopologyPlugin(
            plugin_id="gate.render-records",
            plugin_version="1",
            policies=(),
            records=(
                record(TopologyResourceRecord(resource=active_resource)),
                record(
                    TopologyResourceRecord(resource=expired_resource),
                    valid_to_ns=45,
                ),
                record(
                    TopologyResourceRecord(
                        resource=_resource("node-0", "crossing")
                    ),
                    valid_from_ns=40,
                    valid_to_ns=60,
                ),
                record(
                    TopologyEndpointRecord(
                        endpoint_id="active-endpoint",
                        target=active_reference,
                    ),
                    properties={
                        "binary": b"\x00\xff",
                        "identifier": UUID(int=7),
                    },
                ),
                record(
                    TopologyEndpointRecord(
                        endpoint_id="expired-endpoint",
                        target=active_reference,
                    ),
                    valid_to_ns=45,
                ),
                record(
                    TopologyEndpointRecord(
                        endpoint_id="crossing-endpoint",
                        target=active_reference,
                    ),
                    valid_from_ns=40,
                    valid_to_ns=60,
                ),
                record(
                    TopologyLinkRecord(
                        link_id="active-link",
                        source=active_reference,
                        target=active_reference,
                    )
                ),
                record(
                    TopologyLinkRecord(
                        link_id="expired-link",
                        source=active_reference,
                        target=active_reference,
                    ),
                    valid_to_ns=45,
                ),
                record(
                    TopologyLinkRecord(
                        link_id="crossing-link",
                        source=active_reference,
                        target=active_reference,
                    ),
                    valid_from_ns=40,
                    valid_to_ns=60,
                ),
            ),
        )
        coordinator, members, selections, worlds = _coordinator((plugin,))
        invocation = coordinator.project(
            selections[0],
            _World(
                worlds[0].perspective_ref,
                basis_time_ns=50,
                resolved_at_min_ns=45,
                resolved_at_max_ns=65,
            ),
        )
        service = _rendering_service(("node-0",))
        member = members[0]

        rows, links, endpoints, scoped_rows, inactive, unknown = (
            service._render_typed_projection(
                {
                    "node_id": member.node_id,
                    "member_id": member.member_id,
                    "revision_id": member.basis_revision_id,
                },
                "gate.plugin-set",
                {
                    "plugin_id": plugin.manifest.plugin_id,
                    "plugin_instance_id": member.instance_id,
                    "plugin_run_id": "gate.run",
                    "version": plugin.manifest.plugin_version,
                },
                {"projection_id": "gate.graph"},
                "gate.status",
                {"kind": "absolute_time", "time_ns": "50"},
                {"query_time_ns": "50"},
                "gate-context",
                invocation,
            )
        )

        self.assertEqual([item["label"] for item in rows], ["active"])
        self.assertEqual([item["link_id"] for item in links], ["active-link"])
        self.assertEqual(
            [item["endpoint_id"] for item in endpoints],
            ["active-endpoint"],
        )
        self.assertEqual(endpoints[0]["properties"]["binary"]["type"], "bytes")
        self.assertEqual(
            endpoints[0]["properties"]["identifier"]["type"],
            "uuid",
        )
        self.assertEqual(inactive, 3)
        self.assertEqual(unknown, 3)
        self.assertEqual(len(scoped_rows), 1)

    def test_typed_revision_coordinates_require_exact_strings_without_fallback(
        self,
    ) -> None:
        self.assertEqual(
            MultiNodeTopologyService._typed_revision_key(
                {
                    "catalog_revision_id": "catalog-a",
                    "revision_id": "basis-a",
                    "member_id": "member-a",
                }
            ),
            RevisionSetCapabilityKey("catalog-a", "member-a"),
        )
        for malformed in (
            {
                "revision_id": "basis-a",
                "member_id": "member-a",
            },
            {
                "catalog_revision_id": 7,
                "revision_id": "basis-a",
                "member_id": "member-a",
            },
            {
                "catalog_revision_id": "catalog-a",
                "revision_id": "basis-a",
                "member_id": b"member-a",
            },
        ):
            with self.subTest(malformed=malformed), self.assertRaises(
                MultiNodeTopologyRequestError
            ):
                MultiNodeTopologyService._typed_revision_key(malformed)

    def test_federation_endpoint_status_is_projection_scoped_not_last_writer(
        self,
    ) -> None:
        policy = _policy()
        resource = _resource("node-0", "shared-resource")
        plugin = _TopologyPlugin(
            plugin_id="gate.scoped-status",
            plugin_version="1",
            policies=(policy,),
            records=(_resource_record(resource),),
            claims=(
                _claim(
                    resource,
                    "scoped-claim",
                    (("token", "local"),),
                    policy=policy,
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator((plugin,))
        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )
        context = assembly.claim_contexts[0]
        other_context = replace(context, projection_id="gate.other-graph")
        endpoint = assembly.claims[0].endpoint
        observed_row = {
            "resource_id": "observed-row",
            "status": "usable",
            "status_class": "usable",
            "quality": "exact",
            "deep_link": {"href": "/observed"},
        }
        other_row = {
            "resource_id": "other-row",
            "status": "failed",
            "status_class": "unusable",
            "quality": "exact",
            "deep_link": {"href": "/other"},
        }
        resources = {
            (
                endpoint,
                context.projection_id,
                context.status_perspective_id,
            ): (observed_row,),
            (
                endpoint,
                other_context.projection_id,
                other_context.status_perspective_id,
            ): (other_row,),
        }

        observed = MultiNodeTopologyService._typed_federation_endpoint(
            endpoint,
            "scoped-claim",
            context,
            resources,
        )
        other = MultiNodeTopologyService._typed_federation_endpoint(
            endpoint,
            "scoped-claim",
            other_context,
            resources,
        )
        self.assertEqual(observed["status"], "usable")
        self.assertIs(observed["usable"], True)
        self.assertEqual(other["status"], "failed")
        self.assertIs(other["usable"], False)

        ambiguous_rows = dict(resources)
        ambiguous_rows[
            (
                endpoint,
                context.projection_id,
                context.status_perspective_id,
            )
        ] = (observed_row, other_row)
        ambiguous = MultiNodeTopologyService._typed_federation_endpoint(
            endpoint,
            "scoped-claim",
            context,
            ambiguous_rows,
        )
        self.assertEqual(ambiguous["status"], "unknown")
        self.assertIsNone(ambiguous["usable"])
        self.assertEqual(len(ambiguous["projected_resource_candidates"]), 2)

    def test_fanout_rendering_is_ambiguous_and_permutation_invariant(self) -> None:
        policy = _policy()
        member_claim_counts = (2, 1)
        plugins: list[_TopologyPlugin] = []
        for member_index, count in enumerate(member_claim_counts):
            resources = tuple(
                _resource(f"node-{member_index}", f"port-{claim_index}")
                for claim_index in range(count)
            )
            plugins.append(
                _TopologyPlugin(
                    plugin_id=f"gate.fanout-{member_index}",
                    plugin_version="1",
                    policies=(policy,),
                    records=tuple(_resource_record(item) for item in resources),
                    claims=tuple(
                        _claim(
                            resource,
                            f"fanout-{member_index}-{claim_index}",
                            (("token", "shared"),),
                            policy=policy,
                        )
                        for claim_index, resource in enumerate(resources)
                    ),
                )
            )
        coordinator, members, selections, worlds = _coordinator(tuple(plugins))
        invocations = _project_all(coordinator, selections, worlds)
        service = _rendering_service(tuple(item.node_id for item in members))

        rendered = []
        for ordered in (invocations, tuple(reversed(invocations))):
            assembly = coordinator.federate(ordered)
            links, resolutions, unmatched, truncated = (
                service._federated_claim_links(
                    assembly,
                    {},
                    100,
                    "gate-context",
                    {"kind": "absolute_time", "time_ns": "50"},
                )
            )
            self.assertEqual(links, [])
            self.assertFalse(truncated)
            self.assertEqual(unmatched, [])
            self.assertEqual(len(resolutions), 1)
            # One source has two candidates while the reciprocal source has
            # one.  The policy audit therefore preserves both a matched and
            # an ambiguous result instead of flattening the group to either.
            self.assertEqual(resolutions[0]["resolution"], "mixed")
            self.assertEqual(
                resolutions[0]["result_counts"],
                {"ambiguous": 1, "matched": 2},
            )
            self.assertTrue(resolutions[0]["results"])
            for audit in resolutions[0]["results"]:
                self.assertIn("properties", audit)
                self.assertIn("evidence", audit)
                self.assertIn("provenance", audit)
                self.assertEqual(
                    audit["source"]["presentation"]["route_trace"],
                    "include",
                )
                self.assertEqual(audit["source"]["link_type"], "connector")
                for candidate in audit["candidates"]:
                    self.assertIn("quality", candidate)
                    self.assertIn("confidence", candidate)
                    self.assertIn("evidence", candidate)
                    self.assertIsNotNone(candidate["claim"])
            rendered.append(resolutions)
        self.assertEqual(rendered[0], rendered[1])

    def test_exact_link_type_mismatch_renders_as_conflict(self) -> None:
        policy = _policy()
        resources = (_resource("node-0", "left"), _resource("node-1", "right"))
        plugins = tuple(
            _TopologyPlugin(
                plugin_id=f"gate.link-type-{index}",
                plugin_version="1",
                policies=(policy,),
                records=(_resource_record(resource),),
                claims=(
                    _claim(
                        resource,
                        f"type-{index}",
                        (("token", "shared"),),
                        policy=policy,
                        link_type=("physical" if index == 0 else "overlay"),
                    ),
                ),
            )
            for index, resource in enumerate(resources)
        )
        coordinator, members, selections, worlds = _coordinator(plugins)
        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )
        service = _rendering_service(tuple(item.node_id for item in members))

        links, resolutions, _unmatched, _truncated = service._federated_claim_links(
            assembly,
            {},
            100,
            "gate-context",
            {"kind": "absolute_time", "time_ns": "50"},
        )

        self.assertEqual(links, [])
        self.assertTrue(
            all(
                result["properties"]["reason"] == "plugin_link_type_mismatch"
                for result in resolutions[0]["results"]
            )
        )

    def test_policy_drift_between_members_fails_closed(self) -> None:
        alpha_policy = _policy(argument_names=("token",))
        beta_policy = _policy(argument_names=("token", "port"))
        resources = (_resource("node-0", "left"), _resource("node-1", "right"))
        plugins = (
            _TopologyPlugin(
                plugin_id="gate.policy-alpha",
                plugin_version="1",
                policies=(alpha_policy,),
                records=(_resource_record(resources[0]),),
                claims=(
                    _claim(
                        resources[0],
                        "alpha-claim",
                        (("token", "shared"),),
                        policy=alpha_policy,
                    ),
                ),
            ),
            _TopologyPlugin(
                plugin_id="gate.policy-beta",
                plugin_version="2",
                policies=(beta_policy,),
                records=(_resource_record(resources[1]),),
                claims=(
                    _claim(
                        resources[1],
                        "beta-claim",
                        (("token", "shared"), ("port", 7)),
                        policy=beta_policy,
                    ),
                ),
            ),
        )
        coordinator, _members, selections, worlds = _coordinator(plugins)

        with self.assertRaisesRegex(
            TopologyFederationPolicyConflictError,
            "disagree",
        ):
            coordinator.federate(_project_all(coordinator, selections, worlds))

    def test_linker_policy_invokes_only_the_allowlisted_frozen_linker(self) -> None:
        policy = _policy(kind=ConnectorMatchPolicyKind.LINKER)
        linker = _Linker(policy)
        executor = FederationLinkExecutor(FederationLinkerRegistry((linker,)))
        resources = (_resource("node-0", "left"), _resource("node-1", "right"))
        plugins = tuple(
            _TopologyPlugin(
                plugin_id=f"gate.linked-platform-{index}",
                plugin_version=f"3.{index}",
                policies=(policy,),
                records=(_resource_record(resource),),
                # Deliberately unequal tokens: only the linker owns aliasing.
                claims=(
                    _claim(
                        resource,
                        f"linked-claim-{index}",
                        (("token", f"local-alias-{index}"),),
                        policy=policy,
                    ),
                ),
            )
            for index, resource in enumerate(resources)
        )
        coordinator, _members, selections, worlds = _coordinator(
            plugins,
            executor=executor,
        )

        assembly = coordinator.federate(
            _project_all(coordinator, selections, worlds)
        )

        self.assertEqual(len(linker.requests), 1)
        self.assertIs(type(linker.requests[0]), FederationLinkRequest)
        self.assertTrue(
            all(
                type(claim) is FederatedConnectorClaim
                for claim in linker.requests[0].claims
            )
        )
        execution = assembly.policy_executions[0].execution
        self.assertIs(
            execution.provenance,
            FederationExecutionProvenance.LINKER_PLUGIN,
        )
        self.assertEqual(
            execution.linker_identity,
            FederationLinkerIdentity("gate.federation-linker", "4.2"),
        )
        self.assertEqual(len(execution.results), 2)
        self.assertTrue(
            all(
                result.state is FederationMatchState.MATCHED
                for result in execution.results
            )
        )


if __name__ == "__main__":
    unittest.main()
