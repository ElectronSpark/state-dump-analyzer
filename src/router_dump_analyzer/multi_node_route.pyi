from .canonical import CanonicalValueError as CanonicalValueError, packet_value_json as packet_value_json
from .multi_node_topology import MultiNodeTopologyRequestError as MultiNodeTopologyRequestError, MultiNodeTopologyService as MultiNodeTopologyService
from .process_control import PROCESS_CONTROL_EXCEPTIONS as PROCESS_CONTROL_EXCEPTIONS
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from router_dump_analyzer.plugin_api import Evidence as Evidence, ForwardingCandidateConstraint as ForwardingCandidateConstraint, ForwardingPacketLayer as ForwardingPacketLayer, ForwardingPacketState as ForwardingPacketState, ForwardingPacketTransition as ForwardingPacketTransition, ForwardingPolicyScope as ForwardingPolicyScope, ForwardingPolicyVerdict as ForwardingPolicyVerdict, ForwardingTraversalStateKey as ForwardingTraversalStateKey, KeyAtom as KeyAtom, ResourceKey as ResourceKey, StatusPerspectiveRef as StatusPerspectiveRef, TopologyEndpointReference as TopologyEndpointReference
from router_dump_analyzer.route_trace_core import EndpointReachabilityPairEvaluation as EndpointReachabilityPairEvaluation, ForwardingPacketTraceEvaluation as ForwardingPacketTraceEvaluation, ForwardingPacketTransitionEvaluation as ForwardingPacketTransitionEvaluation, ForwardingPolicyEvaluation as ForwardingPolicyEvaluation, RouteTraceContractError as RouteTraceContractError, evaluate_endpoint_reachability_pair as evaluate_endpoint_reachability_pair, evaluate_forwarding_packet_trace as evaluate_forwarding_packet_trace, evaluate_forwarding_policy as evaluate_forwarding_policy, evaluate_forwarding_traversal as evaluate_forwarding_traversal
from router_dump_analyzer.topology_core import resolve_connectivity_domain_reference as resolve_connectivity_domain_reference
from router_dump_analyzer.value_core import parse_decimal_integer as parse_decimal_integer
from typing import Any

class MultiNodeRouteRequestError(MultiNodeTopologyRequestError): ...
PacketTransitionBuilder = Callable[..., tuple[Any, list[Any]]]

@dataclass(frozen=True)
class RouteProjectionSet:
    projections_by_node: Mapping[str, Mapping[str, Any]]
    revision_ids_by_node: Mapping[str, str]
    coverage: Mapping[str, Any]

@dataclass(frozen=True)
class RouteServicePolicy:
    scenarios: Mapping[str, dict[str, Any]]
    default_scenario_id: str
    steering_profiles: tuple[dict[str, Any], ...]
    packet_transition_builder: PacketTransitionBuilder
    endpoint_profiles: Mapping[str, Mapping[str, Any]]
    route_type_profiles: Mapping[str, Mapping[str, Any]]
    route_family_presentations: Mapping[str, Mapping[str, Any]]
    vrf_aliases: Mapping[str, str]
    router_value_aliases: Mapping[str, str]
    route_table_schema_version: str
    packet_trace_schema_version: str
    node_matcher_id: str
    topology_link_matcher_id: str
    connectivity_domain_matcher_id: str
    data_disclosure: str = ...

class MultiNodeRouteService:
    MAX_CANDIDATE_PATHS: int
    MAX_SEGMENTS_PER_PATH: int
    topology: MultiNodeTopologyService
    policy: RouteServicePolicy
    def __init__(self, topology: MultiNodeTopologyService, *, projections: RouteProjectionSet, policy: RouteServicePolicy) -> None: ...
    def capabilities(self) -> dict[str, Any]: ...
    def route_tables(self, body: dict[str, Any]) -> dict[str, Any]: ...
    def trace(self, body: dict[str, Any]) -> dict[str, Any]: ...
