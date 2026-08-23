from .assembly_store import DemoAssemblyStore
from collections.abc import Mapping
from router_dump_analyzer.capability_router import CapabilityProviderRef
from router_dump_analyzer.plugin_api import AnalyzerPluginBase, PluginManifest, PluginSchema, ReadOnlyWorld, ResourceKey, ResourceStateView, TopologyProjectionOutput, TopologyProjectionRequest
from router_dump_analyzer.topology_federation import TopologyFederationCoordinator
from typing import Any

__all__ = ['DEMO_CONNECTOR_CLAIM_CONTRACT_ID', 'DEMO_CONNECTOR_POLICY_ID', 'DEMO_TOPOLOGY_RESOURCE_KIND', 'DEMO_TOPOLOGY_CLAIM_KIND', 'DEMO_CONNECTOR_LINK_TYPE', 'DEMO_TOPOLOGY_PLUGIN_ID', 'DEMO_TOPOLOGY_PLUGIN_VERSION', 'DEMO_TOPOLOGY_PROJECTION_ID', 'DEMO_TOPOLOGY_PERSPECTIVE_ID', 'DEMO_TOPOLOGY_PROCESS_TARGET', 'DemoTopologyProjectionPlugin', 'demo_topology_projection_plugin', 'build_demo_topology_federation', 'build_demo_topology_projection_state_provider']

DEMO_CONNECTOR_CLAIM_CONTRACT_ID: str
DEMO_CONNECTOR_POLICY_ID: str
DEMO_TOPOLOGY_RESOURCE_KIND: str
DEMO_TOPOLOGY_CLAIM_KIND: str
DEMO_CONNECTOR_LINK_TYPE: str
DEMO_TOPOLOGY_PLUGIN_ID: str
DEMO_TOPOLOGY_PLUGIN_VERSION: str
DEMO_TOPOLOGY_PROJECTION_ID: str
DEMO_TOPOLOGY_PERSPECTIVE_ID: str
DEMO_TOPOLOGY_PROCESS_TARGET: str

class DemoTopologyProjectionPlugin(AnalyzerPluginBase):
    manifest: PluginManifest
    def describe(self) -> PluginSchema: ...
    def project_topology(self, request: TopologyProjectionRequest, world: ReadOnlyWorld) -> tuple[TopologyProjectionOutput, ...]: ...

demo_topology_projection_plugin: DemoTopologyProjectionPlugin

class _DemoTopologyProjectionStateProvider:
    def __init__(self, states_by_instance: Mapping[str, Mapping[ResourceKey, ResourceStateView]]) -> None: ...
    def __call__(self, provider: CapabilityProviderRef, perspective_id: str, resolved_time: Mapping[str, Any]) -> Mapping[ResourceKey, ResourceStateView]: ...

def build_demo_topology_federation(contract: Mapping[str, Any]) -> TopologyFederationCoordinator: ...
def build_demo_topology_projection_state_provider(contract: Mapping[str, Any], revision_store: DemoAssemblyStore) -> _DemoTopologyProjectionStateProvider: ...
