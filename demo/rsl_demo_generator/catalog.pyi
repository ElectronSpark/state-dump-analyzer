from .scenario_source import DemoScenarioSource, LinkSpec as LinkSpec, NodeSpec as NodeSpec
from collections.abc import Mapping
from dataclasses import dataclass
from rsl_demo_plugin import GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID as GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID, GENERATED_TOPOLOGY_PROFILE as GENERATED_TOPOLOGY_PROFILE, GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID as GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID, TopologyProfileSpec as TopologyProfileSpec
from typing import Any

__all__ = ['GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID', 'GENERATED_TOPOLOGY_PROFILE', 'GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID', 'TopologyProfileSpec', 'LinkSpec', 'NodeSpec', 'TopologyEvidenceSelector', 'TemporalEvidenceSelector', 'CoverageCaseSpec', 'PACKET_PROFILES', 'DEFAULT_SCENARIO_SOURCE', 'DEMO_NODES', 'DEMO_LINKS', 'COVERAGE_CASES', 'node_by_id', 'links_for_node', 'adjacent_nodes', 'route_inventory_contexts_for_node']

@dataclass(frozen=True, slots=True)
class TopologyEvidenceSelector:
    selector_kind: str
    reference_id: str
    node_ids: tuple[str, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TemporalEvidenceSelector:
    phase: str
    event_name: str
    resource_kind: str
    outcome: str | None = ...
    state_changed: bool | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class CoverageCaseSpec:
    case_id: str
    category: str
    title: str
    route_type: str
    route_family: str
    address_family: str
    vrf: str
    source_node: str
    destination_node: str
    involved_nodes: tuple[str, ...]
    expected_outcome: str
    required_capabilities: tuple[str, ...]
    private_analysis_intents: tuple[str, ...]
    packet_profile_id: str | None = ...
    topology_evidence: tuple[TopologyEvidenceSelector, ...] = ...
    temporal_evidence: tuple[TemporalEvidenceSelector, ...] = ...
    def __post_init__(self) -> None: ...

PACKET_PROFILES: Mapping[str, Mapping[str, Any]]
DEFAULT_SCENARIO_SOURCE: DemoScenarioSource
DEMO_NODES: tuple[NodeSpec, ...]
DEMO_LINKS: tuple[LinkSpec, ...]
COVERAGE_CASES: tuple[CoverageCaseSpec, ...]

def node_by_id(node_id: str) -> NodeSpec: ...
def links_for_node(node_id: str) -> tuple[LinkSpec, ...]: ...
def adjacent_nodes(node_id: str) -> tuple[str, ...]: ...
def route_inventory_contexts_for_node(node_id: str) -> tuple[dict[str, object], ...]: ...
