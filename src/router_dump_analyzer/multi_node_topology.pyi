from router_dump_analyzer.canonical import CanonicalValueError as CanonicalValueError, bounded_value_key as bounded_value_key, canonical_opaque_value as canonical_opaque_value, opaque_value_json as opaque_value_json
from router_dump_analyzer.contract_validation import bounded_mapping as bounded_mapping, validate_bounded_json_value as validate_bounded_json_value
from router_dump_analyzer.corroboration import CorroborationError as CorroborationError, ExactMatchClaim as ExactMatchClaim, ExactMatchState as ExactMatchState, MatcherId as MatcherId, exact_match_claims as exact_match_claims
from router_dump_analyzer.normalized_data import contains_time as contains_time
from router_dump_analyzer.plugin_api import FederationMatchState as FederationMatchState, InterNodeLinkPresentation as InterNodeLinkPresentation, InterNodeRouteTraceRole as InterNodeRouteTraceRole, KeyAtom as KeyAtom, TopologyDomainRole as TopologyDomainRole, TopologyPluginSemanticsDescriptor as TopologyPluginSemanticsDescriptor, TopologyTwoParticipantShape as TopologyTwoParticipantShape
from router_dump_analyzer.temporal_core import RESOURCE_CREATION_OPERATIONS as RESOURCE_CREATION_OPERATIONS, RESOURCE_DELETION_OPERATIONS as RESOURCE_DELETION_OPERATIONS, checked_temporal_add as checked_temporal_add, checked_temporal_subtract as checked_temporal_subtract, distinct_temporal_states as distinct_temporal_states, temporal_integer as temporal_integer, temporal_order_key as temporal_order_key
from typing import Any

class MultiNodeTopologyRequestError(ValueError): ...

class MultiNodeTopologyService:
    assembly_id: str
    revision_id: str
    capture_ns: int
    start_ns: int
    end_ns: int
    contract: dict[str, Any]
    topology_profiles: list[dict[str, Any]]
    topology_metadata: dict[str, Any]
    topology_id: str
    nodes_by_id: dict[str, Any]
    def __init__(self, *, contract: dict[str, Any], topology_profiles: list[dict[str, Any]], topology_metadata: dict[str, Any]) -> None: ...
    @staticmethod
    def normalize_basis(basis: Any, field: str = 'basis') -> dict[str, Any]: ...
    def capabilities(self) -> dict[str, Any]: ...
    def node_capabilities(self, node_id: str) -> dict[str, Any]: ...
    def context_member(self, context_id: str, member_id: str) -> dict[str, Any]: ...
    def query_node(self, node_id: str, body: dict[str, Any]) -> dict[str, Any]: ...
    def query(self, body: dict[str, Any]) -> dict[str, Any]: ...
