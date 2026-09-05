"""Typed topology provider and reconstructed worlds for the generated demo.

The generated dump remains the only data source.  The plug-in is deliberately
stateless and process-reconstructible: node-local facts enter through the
core-owned ``ReadOnlyWorld`` contract, never through hidden instance state.
The core revision-set router and federation coordinator own cross-node
selection and joining.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from router_dump_analyzer.capability_router import (
    CapabilityProviderRef,
    CapabilityProviderRegistry,
    PlanBoundCapabilityRouter,
    RevisionSetCapabilityRouter,
)
from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionSupport,
    ResourceKey,
    ResourceKindDescriptor,
    ResourceStateView,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRole,
    TopologyProjectionDescriptor,
    TopologyProjectionOutput,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourceRecord,
    TopologyUsability,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest
from router_dump_analyzer.topology_federation import (
    TopologyFederationCoordinator,
)
from router_dump_analyzer.value_core import parse_canonical_decimal_integer

from .assembly_store import DemoAssemblyStore
from ._identity import (
    PLUGIN_ID as DEMO_TOPOLOGY_PLUGIN_ID,
    PLUGIN_VERSION as DEMO_TOPOLOGY_PLUGIN_VERSION,
)

DEMO_CONNECTOR_CLAIM_CONTRACT_ID = "demo.topology.connector.v1"
DEMO_CONNECTOR_POLICY_ID = "demo.topology.connector.exact.v1"
DEMO_TOPOLOGY_RESOURCE_KIND = "demo.topology.endpoint"
DEMO_TOPOLOGY_CLAIM_KIND = "demo.topology.connector_claim"
DEMO_CONNECTOR_LINK_TYPE = "demo.underlay.point_to_point"
DEMO_TOPOLOGY_PROJECTION_ID = "demo.generated-topology"
DEMO_TOPOLOGY_PERSPECTIVE_ID = "demo.generated-observed"
DEMO_TOPOLOGY_PROCESS_TARGET = (
    "rsl_demo_plugin.typed_topology:demo_topology_projection_plugin"
)


def _exact_coordinate(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError(f"{label} must be an exact non-empty string")
    return value


def _optional_temporal_ns(value: Any, label: str) -> int | None:
    if value is None:
        return None
    return parse_canonical_decimal_integer(
        value,
        label,
        minimum=-(1 << 63),
        maximum=(1 << 63) - 1,
    )


def _resource(node_id: str, raw_resource_id: str) -> ResourceKey:
    return ResourceKey(
        namespace="demo.generated.topology",
        node=node_id,
        layer="underlay",
        kind=DEMO_TOPOLOGY_RESOURCE_KIND,
        parts=(("resource_id", raw_resource_id),),
    )


def _claim_resource(
    node_id: str,
    raw_resource_id: str,
    claim_id: str,
) -> ResourceKey:
    return ResourceKey(
        namespace="demo.generated.topology",
        node=node_id,
        layer="underlay",
        kind=DEMO_TOPOLOGY_CLAIM_KIND,
        parts=(("resource_id", raw_resource_id), ("claim_id", claim_id)),
    )


_DEMO_CONNECTOR_POLICY = ConnectorMatchPolicyDescriptor(
    policy_id=DEMO_CONNECTOR_POLICY_ID,
    claim_contract_id=DEMO_CONNECTOR_CLAIM_CONTRACT_ID,
    kind=ConnectorMatchPolicyKind.EXACT_TOKEN,
    argument_names=("segment_key",),
)

_DEMO_TOPOLOGY_SCHEMA = PluginSchema(
    resource_kinds=(
        ResourceKindDescriptor(
            kind=DEMO_TOPOLOGY_RESOURCE_KIND,
            label="Generated topology endpoint",
            key_fields=("resource_id",),
            properties=(),
        ),
        ResourceKindDescriptor(
            kind=DEMO_TOPOLOGY_CLAIM_KIND,
            label="Generated connector observation",
            key_fields=("resource_id", "claim_id"),
            properties=(),
        ),
    ),
    relationship_types=(),
    status_perspectives=(
        StatusPerspectiveDescriptor(
            perspective_id=DEMO_TOPOLOGY_PERSPECTIVE_ID,
            label="Generated observed topology",
            layer_id="underlay",
            role=StatusPerspectiveRole.OBSERVED,
        ),
    ),
    topology_projections=(
        TopologyProjectionDescriptor(
            projection_id=DEMO_TOPOLOGY_PROJECTION_ID,
            label="Generated point-to-point connectors",
            supported_status_perspective_ids=(DEMO_TOPOLOGY_PERSPECTIVE_ID,),
            default_status_perspective_id=DEMO_TOPOLOGY_PERSPECTIVE_ID,
        ),
    ),
    connector_match_policies=(_DEMO_CONNECTOR_POLICY,),
)


class DemoTopologyProjectionPlugin(AnalyzerPluginBase):
    """Project node-local facts supplied through a reconstructed world."""

    manifest: PluginManifest = PluginManifest(
        plugin_id=DEMO_TOPOLOGY_PLUGIN_ID,
        plugin_version=DEMO_TOPOLOGY_PLUGIN_VERSION,
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("demo.generated",),
        supported_software_versions="*",
        capabilities=frozenset({PluginCapability.TOPOLOGY_PROJECTION}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self) -> PluginSchema:
        return _DEMO_TOPOLOGY_SCHEMA

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> tuple[TopologyProjectionOutput, ...]:
        if (
            request.projection_id != DEMO_TOPOLOGY_PROJECTION_ID
            or request.status_perspective_id != DEMO_TOPOLOGY_PERSPECTIVE_ID
        ):
            return ()
        outputs: list[TopologyProjectionOutput] = []
        for state in world.iter_states(
            kinds=frozenset({DEMO_TOPOLOGY_CLAIM_KIND}),
            limit=request.max_world_reads,
        ):
            raw_claim = dict(state.properties)
            if (
                raw_claim.get("render_hint") != "direct_line"
                or raw_claim.get("excluded_from_connectivity") is True
            ):
                continue
            raw_resource_id = raw_claim.get("interface_resource_id")
            segment_key = raw_claim.get("segment_key")
            claim_id = raw_claim.get("claim_id")
            if (
                not isinstance(raw_resource_id, str)
                or not raw_resource_id
                or not isinstance(segment_key, str)
                or not segment_key
                or not isinstance(claim_id, str)
                or not claim_id
            ):
                continue
            endpoint = _resource(state.resource.node, raw_resource_id)
            raw_status = str(raw_claim.get("status") or "unknown").casefold()
            usability = (
                TopologyUsability.USABLE
                if raw_status in {"active", "established", "programmed", "up", "usable"}
                else TopologyUsability.UNUSABLE
                if raw_status in {"down", "failed", "withdrawn", "unusable"}
                else TopologyUsability.UNKNOWN
            )
            raw_confidence = str(raw_claim.get("confidence") or "best_effort")
            quality = state.quality
            if raw_confidence in {"exact", "plugin_declared"}:
                quality = Quality.EXACT
            outputs.append(
                TopologyProjectionRecord(
                    projection_id=DEMO_TOPOLOGY_PROJECTION_ID,
                    status_perspective_id=DEMO_TOPOLOGY_PERSPECTIVE_ID,
                    payload=TopologyResourceRecord(
                        resource=endpoint,
                        role="connector_endpoint",
                    ),
                    usability=usability,
                    source_resources=(endpoint,),
                    provenance=state.provenance,
                    quality=quality,
                    exists=True,
                    properties={
                        "label": str(
                            raw_claim.get("interface_name") or raw_resource_id
                        ),
                        "source_resource_id": raw_resource_id,
                        "plugin_role": raw_claim.get("attachment_kind"),
                    },
                    valid_from_ns=state.valid_from_ns,
                    valid_to_ns=state.valid_to_ns,
                )
            )
            outputs.append(
                ConnectorClaim(
                    claim_id=claim_id,
                    endpoint=endpoint,
                    claim_contract_id=DEMO_CONNECTOR_CLAIM_CONTRACT_ID,
                    match_policy_id=DEMO_CONNECTOR_POLICY_ID,
                    arguments=(("segment_key", segment_key),),
                    provenance=state.provenance,
                    quality=quality,
                    link_type=DEMO_CONNECTOR_LINK_TYPE,
                    presentation=InterNodeLinkPresentation(
                        route_trace=InterNodeRouteTraceRole.INCLUDE,
                    ),
                    status_perspective=world.perspective_ref,
                    role="point_to_point_attachment",
                    valid_from_ns=state.valid_from_ns,
                    valid_to_ns=state.valid_to_ns,
                )
            )
        return tuple(outputs)


demo_topology_projection_plugin: DemoTopologyProjectionPlugin = (
    DemoTopologyProjectionPlugin()
)


_EMPTY_TOPOLOGY_STATES: Mapping[ResourceKey, ResourceStateView] = MappingProxyType({})


class _DemoTopologyProjectionStateProvider:
    """Immutable adapter from generated revision evidence to core worlds."""

    def __init__(
        self,
        states_by_instance: Mapping[
            str,
            Mapping[ResourceKey, ResourceStateView],
        ],
    ) -> None:
        self._states_by_instance = MappingProxyType(
            {
                instance_id: MappingProxyType(dict(states))
                for instance_id, states in states_by_instance.items()
            }
        )

    def __call__(
        self,
        provider: CapabilityProviderRef,
        perspective_id: str,
        resolved_time: Mapping[str, Any],
    ) -> Mapping[ResourceKey, ResourceStateView]:
        del perspective_id, resolved_time
        return self._states_by_instance.get(
            provider.pin.instance_id,
            _EMPTY_TOPOLOGY_STATES,
        )


def _claim_state(node_id: str, raw_claim: Mapping[str, Any]) -> ResourceStateView:
    raw_resource_id = _exact_coordinate(
        raw_claim.get("interface_resource_id"),
        "demo topology interface_resource_id",
    )
    claim_id = _exact_coordinate(
        raw_claim.get("claim_id"),
        "demo topology claim_id",
    )
    segment_key = _exact_coordinate(
        raw_claim.get("segment_key"),
        "demo topology segment_key",
    )
    subnet = raw_claim.get("subnet")
    if type(subnet) is not dict:
        raise ValueError("demo topology claim subnet must be an exact object")
    valid_from = _optional_temporal_ns(
        raw_claim.get("valid_from_ns"),
        "demo topology valid_from_ns",
    )
    valid_to = _optional_temporal_ns(
        raw_claim.get("valid_to_ns"),
        "demo topology valid_to_ns",
    )
    raw_confidence = str(raw_claim.get("confidence") or "best_effort")
    quality = (
        Quality.EXACT
        if raw_confidence in {"exact", "plugin_declared"}
        else Quality.BEST_EFFORT
    )
    return ResourceStateView(
        resource=_claim_resource(node_id, raw_resource_id, claim_id),
        exists=True,
        properties={
            "interface_resource_id": raw_resource_id,
            "interface_name": str(raw_claim.get("interface_name") or raw_resource_id),
            "claim_id": claim_id,
            "segment_key": segment_key,
            "render_hint": str(subnet.get("render_hint") or "shared_subnet"),
            "excluded_from_connectivity": bool(
                raw_claim.get("excluded_from_connectivity")
            ),
            "status": str(raw_claim.get("status") or "unknown"),
            "confidence": raw_confidence,
            "attachment_kind": str(raw_claim.get("attachment_kind") or "logical"),
        },
        provenance=Provenance.OBSERVED,
        quality=quality,
        valid_from_ns=valid_from,
        valid_to_ns=valid_to,
    )


def _is_typed_point_to_point_claim(raw_claim: Mapping[str, Any]) -> bool:
    subnet = raw_claim.get("subnet")
    return (
        type(subnet) is dict
        and subnet.get("render_hint") == "direct_line"
        and raw_claim.get("excluded_from_connectivity") is not True
    )


def _execution_pin(registered: Any, schema: PluginSchema) -> PluginExecutionPin:
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
        process_bootstrap_digest=registered.process_bootstrap_digest,
        schema_versions=registered.schema_versions,
        capabilities=registered.capabilities,
        roles=("primary_parser", "topology_projection"),
    )


def build_demo_topology_federation(
    contract: Mapping[str, Any],
) -> TopologyFederationCoordinator:
    """Freeze one process-attested stateless provider per node revision."""

    registry = PluginRegistry(require_executable_identity=True)
    registered_by_member: dict[str, tuple[Any, PluginSchema]] = {}
    for node in contract["nodes"]:
        plugin_set = next(
            value
            for value in node["plugin_sets"]
            if value["plugin_set_id"] == node["active_plugin_set_id"]
        )
        plugin_metadata = plugin_set["plugins"][0]
        plugin = demo_topology_projection_plugin
        schema = plugin.describe()
        registered = registry.register(
            plugin,
            instance_id=plugin_metadata["plugin_instance_id"],
            distribution_name="rsl-demo-plugin",
            distribution_version=plugin_metadata["version"],
            entry_point_name=plugin_metadata["plugin_id"],
            module_target=DEMO_TOPOLOGY_PROCESS_TARGET,
            plugin_process_module_target=DEMO_TOPOLOGY_PROCESS_TARGET,
        )
        registered_by_member[node["member_id"]] = (registered, schema)

    providers = CapabilityProviderRegistry(
        registered for registered, _schema in registered_by_member.values()
    )
    routers: list[PlanBoundCapabilityRouter] = []
    for node in contract["nodes"]:
        registered, schema = registered_by_member[node["member_id"]]
        routers.append(
            PlanBoundCapabilityRouter(
                providers,
                PluginExecutionPlan(
                    node_id=_exact_coordinate(
                        node.get("node_id"),
                        "demo topology node_id",
                    ),
                    basis_revision_id=_exact_coordinate(
                        node.get("revision_id"),
                        "demo topology revision_id",
                    ),
                    plugins=(_execution_pin(registered, schema),),
                ),
                catalog_revision_id=_exact_coordinate(
                    node.get("catalog_revision_id"),
                    "demo topology catalog_revision_id",
                ),
                member_id=_exact_coordinate(
                    node.get("member_id"),
                    "demo topology member_id",
                ),
            )
        )
    return TopologyFederationCoordinator(RevisionSetCapabilityRouter(tuple(routers)))


def build_demo_topology_projection_state_provider(
    contract: Mapping[str, Any],
    revision_store: DemoAssemblyStore,
) -> _DemoTopologyProjectionStateProvider:
    """Snapshot node-local generated observations for reconstructed worlds."""

    states_by_instance: dict[str, dict[ResourceKey, ResourceStateView]] = {}
    for node in contract["nodes"]:
        plugin_set = next(
            value
            for value in node["plugin_sets"]
            if value["plugin_set_id"] == node["active_plugin_set_id"]
        )
        plugin_metadata = plugin_set["plugins"][0]
        topology = revision_store.projection_for_node(node["node_id"])["topology"]
        raw_claims = topology.get("claims")
        if type(raw_claims) is not list:
            raise ValueError("demo topology claims must be an exact array")
        states: dict[ResourceKey, ResourceStateView] = {}
        for raw_claim in raw_claims:
            if type(raw_claim) is not dict:
                raise ValueError("demo topology claim must be an exact object")
            # This typed capability owns only pairwise connector claims. The
            # separate connectivity-domain projection retains every shared,
            # external, management, loopback, and VPN attachment. Filtering
            # here keeps the reconstructed world proportional to the actual
            # capability input instead of copying thousands of unrelated
            # multi-access observations into each invocation.
            if not _is_typed_point_to_point_claim(raw_claim):
                continue
            state = _claim_state(node["node_id"], raw_claim)
            if state.resource in states:
                raise ValueError("demo topology claim identity must be unique")
            states[state.resource] = state
        states_by_instance[plugin_metadata["plugin_instance_id"]] = states
    return _DemoTopologyProjectionStateProvider(states_by_instance)


__all__ = [
    "DEMO_CONNECTOR_CLAIM_CONTRACT_ID",
    "DEMO_CONNECTOR_LINK_TYPE",
    "DEMO_CONNECTOR_POLICY_ID",
    "DEMO_TOPOLOGY_CLAIM_KIND",
    "DEMO_TOPOLOGY_PERSPECTIVE_ID",
    "DEMO_TOPOLOGY_PLUGIN_ID",
    "DEMO_TOPOLOGY_PLUGIN_VERSION",
    "DEMO_TOPOLOGY_PROCESS_TARGET",
    "DEMO_TOPOLOGY_PROJECTION_ID",
    "DEMO_TOPOLOGY_RESOURCE_KIND",
    "DemoTopologyProjectionPlugin",
    "build_demo_topology_federation",
    "build_demo_topology_projection_state_provider",
    "demo_topology_projection_plugin",
]
