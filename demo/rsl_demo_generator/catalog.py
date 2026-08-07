"""Deterministic node, fabric, and coverage definitions for generated fixtures.

The values in this module are generator inputs, not runtime answers.  A demo
plug-in can project the generated claims and forwarding rows, while the core
still performs topology reconstruction and route tracing.
"""

from __future__ import annotations

from dataclasses import dataclass

from rsl_demo_plugin import (
    GENERATED_PROJECTION_POLICY,
    GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID,
    GENERATED_TOPOLOGY_PROFILE,
    GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
    TopologyProfileSpec,
)
from rsl_demo_plugin.scenario_registry import (
    ROUTE_INVENTORY_CONTEXTS,
    ROUTE_PROTOCOL_BY_TYPE,
    SCENARIO_BY_ID,
)

from .scenario_source import (
    LinkSpec,
    NodeSpec,
    load_default_scenario_source,
)


@dataclass(frozen=True, slots=True)
class TopologyEvidenceSelector:
    """Select exact generated topology claims for one coverage case.

    ``selector_kind`` is either ``link`` for a :class:`LinkSpec` segment or
    ``local`` for a plug-in-classified one-node scope such as management or
    loopback.  The selector stays deliberately small: evidence materialization
    copies claim, attachment, matcher, and classification details from the
    generated topology projection rather than duplicating those answers here.
    """

    selector_kind: str
    reference_id: str
    node_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.selector_kind not in {"link", "local"}:
            raise ValueError(
                "topology evidence selector kind must be link or local"
            )
        if not self.reference_id:
            raise ValueError("topology evidence selector needs a reference")
        if self.selector_kind == "link" and self.node_ids:
            raise ValueError(
                "link topology evidence derives participants from DEMO_LINKS"
            )
        if self.selector_kind == "local" and not self.node_ids:
            raise ValueError(
                "local topology evidence must identify at least one node"
            )


@dataclass(frozen=True, slots=True)
class TemporalEvidenceSelector:
    """Select one real generated event by semantic phase and event shape."""

    phase: str
    event_name: str
    resource_kind: str
    outcome: str | None = None
    state_changed: bool | None = None

    def __post_init__(self) -> None:
        if not self.phase or not self.event_name or not self.resource_kind:
            raise ValueError(
                "temporal evidence selectors need phase, event, and resource"
            )


@dataclass(frozen=True, slots=True)
class CoverageCaseSpec:
    """A checkable behavior advertised by the generated example plug-in."""

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
    packet_profile_id: str | None = None
    topology_evidence: tuple[TopologyEvidenceSelector, ...] = ()
    temporal_evidence: tuple[TemporalEvidenceSelector, ...] = ()

    def __post_init__(self) -> None:
        allowed = {
            "route_trace",
            "trace_correlation",
            "evidence_correlation",
            "evidence_interpretation",
        }
        if (
            not self.private_analysis_intents
            or self.private_analysis_intents
            != tuple(sorted(set(self.private_analysis_intents)))
            or any(item not in allowed for item in self.private_analysis_intents)
        ):
            raise ValueError(
                "private-analysis intents must be a non-empty canonical subset"
            )
        if "evidence_analysis" not in self.required_capabilities:
            raise ValueError(
                "private-analysis coverage requires evidence_analysis"
            )


PACKET_PROFILES = GENERATED_PROJECTION_POLICY.packet_profiles


DEFAULT_SCENARIO_SOURCE = load_default_scenario_source()
DEMO_NODES: tuple[NodeSpec, ...] = DEFAULT_SCENARIO_SOURCE.nodes
DEMO_LINKS: tuple[LinkSpec, ...] = DEFAULT_SCENARIO_SOURCE.links


def _case(
    case_id: str,
    title: str,
    *,
    category: str = "route",
    route_type: str | None = None,
    route_family: str | None = None,
    address_family: str | None = None,
    vrf: str | None = None,
    source_node: str = "node-a",
    destination_node: str = "node-b",
    involved_nodes: tuple[str, ...] = ("node-a", "transit-p-1", "node-b"),
    expected_outcome: str = "resolved",
    required_capabilities: tuple[str, ...] = (
        "route_resolution",
        "topology_projection",
    ),
    private_analysis_intents: tuple[str, ...] | None = None,
    packet_profile_id: str | None = None,
    topology_evidence: tuple[TopologyEvidenceSelector, ...] = (),
    temporal_evidence: tuple[TemporalEvidenceSelector, ...] = (),
) -> CoverageCaseSpec:
    semantics = SCENARIO_BY_ID.get(case_id)
    if semantics is not None:
        if any(
            value is not None
            for value in (
                route_type,
                route_family,
                address_family,
                vrf,
            )
        ):
            raise ValueError(
                f"{case_id} routing context must come from scenario_registry"
            )
        forward = semantics.get(
            "directional_routing_contexts",
            {},
        ).get("forward", semantics)
        route_type = str(forward["route_type"])
        route_family = str(forward["route_family"])
        address_family = str(forward["address_family"])
        vrf = str(forward["vrf_id"])
    else:
        route_type = route_type or "ipv4_unicast"
        route_family = route_family or "ipv4_unicast"
        address_family = address_family or "ipv4"
        vrf = vrf or "blue"
    if private_analysis_intents is None:
        if category == "route":
            private_analysis_intents = (
                "evidence_interpretation",
                "route_trace",
            )
        elif category == "temporal":
            private_analysis_intents = (
                "evidence_correlation",
                "trace_correlation",
            )
        else:
            private_analysis_intents = ("evidence_correlation",)
    if "evidence_analysis" not in required_capabilities:
        required_capabilities = (*required_capabilities, "evidence_analysis")
    return CoverageCaseSpec(
        case_id=case_id,
        category=category,
        title=title,
        route_type=route_type,
        route_family=route_family,
        address_family=address_family,
        vrf=vrf,
        source_node=source_node,
        destination_node=destination_node,
        involved_nodes=involved_nodes,
        expected_outcome=expected_outcome,
        required_capabilities=required_capabilities,
        private_analysis_intents=private_analysis_intents,
        packet_profile_id=packet_profile_id,
        topology_evidence=topology_evidence,
        temporal_evidence=temporal_evidence,
    )


# This is the public behavior registry for the single generated demo.  Tests
# compare coverage.json against this exact set, so adding a new advertised
# branch requires adding generated evidence rather than only UI text.
COVERAGE_CASES: tuple[CoverageCaseSpec, ...] = (
    _case(
        "single-active-primary",
        "Single-active primary path",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
    ),
    _case(
        "all-active-ecmp",
        "All-active equal-cost multipath",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
    ),
    _case(
        "cross-layer-inconsistent",
        "Cross-layer forwarding inconsistency",
        expected_outcome="inconsistent",
        required_capabilities=(
            "route_resolution",
            "topology_projection",
            "consistency_evaluation",
        ),
    ),
    _case(
        "incomplete-node-resolution",
        "Incomplete node-local resolution",
        expected_outcome="incomplete",
    ),
    _case(
        "router-to-router",
        "Router loopback to router loopback",
        destination_node="node-b",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
    ),
    _case(
        "transit-start-endpoint-reachability",
        "Transit observation with endpoint return validation",
        source_node="node-a",
        involved_nodes=("transit-p-1", "transit-p-2", "node-b"),
        required_capabilities=(
            "route_resolution",
            "endpoint_reachability",
        ),
    ),
    _case(
        "site-a-site-c-asymmetric",
        "Asymmetric PE-A to PE-C service",
        destination_node="node-c",
        involved_nodes=("node-a", "transit-p-2", "node-c"),
        expected_outcome="asymmetric",
    ),
    _case(
        "site-b-site-c-one-way",
        "One-way PE-B to PE-C service",
        source_node="node-b",
        destination_node="node-c",
        involved_nodes=("node-b", "transit-p-2", "node-c"),
        expected_outcome="one_way_drop",
    ),
    _case(
        "evpn-mh-all-active",
        "EVPN multihoming all-active",
        destination_node="node-e",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
            "node-e",
        ),
    ),
    _case(
        "evpn-es-withdraw-failover",
        "EVPN Ethernet-segment withdrawal failover",
        destination_node="node-e",
        involved_nodes=("node-a", "transit-p-2", "node-e"),
        expected_outcome="failed_over",
    ),
    _case(
        "evpn-stale-fib-after-withdraw",
        "Stale FIB after EVPN withdrawal",
        destination_node="node-e",
        involved_nodes=("node-a", "transit-p-1", "node-b", "node-e"),
        expected_outcome="inconsistent",
    ),
    _case(
        "srv6-all-active",
        "SRv6 all-active policies",
        destination_node="node-e",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-e",
        ),
    ),
    _case(
        "recursive-static-to-external",
        "Recursive static route to an external subnet",
        destination_node="node-e",
        involved_nodes=("node-a", "transit-p-2", "node-e", "ce-east"),
    ),
    _case(
        "recursive-resolution-cycle",
        "Recursive next-hop cycle",
        involved_nodes=("node-a", "transit-p-1"),
        expected_outcome="loop",
    ),
    _case(
        "cross-node-forwarding-loop",
        "Cross-node forwarding loop",
        involved_nodes=("node-a", "transit-p-1", "node-b"),
        expected_outcome="loop",
    ),
    _case(
        "evpn-split-horizon-block",
        "EVPN split-horizon policy block",
        source_node="node-b",
        destination_node="node-e",
        involved_nodes=("node-b", "transit-p-2", "node-e"),
        expected_outcome="policy_blocked",
    ),
    _case(
        "connected-external-subnet",
        "Connected external subnet",
        source_node="node-e",
        destination_node="node-e",
        involved_nodes=("node-e", "ce-east"),
    ),
    _case(
        "incomplete-intermediate-resolution",
        "Missing intermediate MPLS resolution",
        source_node="node-d",
        involved_nodes=("node-d", "transit-p-2", "node-b"),
        expected_outcome="incomplete",
    ),
    _case(
        "packet-native-ip",
        "Native IPv4 packet evolution",
        category="packet",
        packet_profile_id="native-ip",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-sr-mpls-php",
        "SR-MPLS label swap and PHP",
        category="packet",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
        packet_profile_id="sr-mpls-php",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-l3vpn-over-sr-mpls",
        "L3VPN over SR-MPLS",
        category="packet",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
        packet_profile_id="l3vpn-over-sr-mpls",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-srv6-encap",
        "SRv6 encapsulation and decapsulation",
        category="packet",
        packet_profile_id="srv6-encap",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-ipv6-over-ipv4",
        "IPv6 over IPv4 recursion",
        category="packet",
        packet_profile_id="ipv6-over-ipv4",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-vpn-over-vpn",
        "Nested VPN over VPN",
        category="packet",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
        packet_profile_id="vpn-over-vpn",
        required_capabilities=("route_resolution", "packet_evolution"),
    ),
    _case(
        "packet-mtu-drop",
        "Encapsulation MTU drop",
        category="packet",
        packet_profile_id="mtu-drop",
        expected_outcome="dropped",
        required_capabilities=(
            "route_resolution",
            "packet_evolution",
            "mtu_validation",
        ),
    ),
    _case(
        "packet-forced-steering",
        "User-forced forwarding steering",
        category="packet",
        involved_nodes=(
            "node-a",
            "transit-p-1",
            "transit-p-2",
            "node-b",
        ),
        packet_profile_id="forced-steering",
        expected_outcome="steered",
        required_capabilities=(
            "route_resolution",
            "packet_evolution",
            "forced_steering",
        ),
    ),
    _case(
        "topology-shared-subnet-multiaccess",
        "Shared multi-access subnet reconstruction",
        category="topology",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="ipv4",
        vrf="default",
        destination_node="transit-p-2",
        involved_nodes=("node-a", "node-d", "transit-p-1", "transit-p-2"),
        required_capabilities=("topology_projection",),
        topology_evidence=(
            TopologyEvidenceSelector("link", "core-west-multi-access"),
        ),
    ),
    _case(
        "topology-point-to-point-collapse",
        "Two-participant subnet line projection",
        category="topology",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="ipv4",
        vrf="default",
        source_node="transit-p-1",
        destination_node="transit-p-2",
        involved_nodes=("transit-p-1", "transit-p-2"),
        required_capabilities=("topology_projection",),
        topology_evidence=(
            TopologyEvidenceSelector("link", "p1-p2-sr"),
        ),
    ),
    _case(
        "topology-vlan-lag-subinterface",
        "VLAN, LAG, and subinterface attachment evidence",
        category="topology",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="l2vpn",
        source_node="node-a",
        destination_node="node-c",
        involved_nodes=(
            "node-a",
            "node-d",
            "transit-p-1",
            "transit-p-2",
            "node-b",
            "node-e",
            "node-c",
        ),
        required_capabilities=("topology_projection",),
        topology_evidence=(
            TopologyEvidenceSelector("link", "core-west-multi-access"),
            TopologyEvidenceSelector("link", "core-east-multi-access"),
            TopologyEvidenceSelector("link", "pe-c-transit"),
        ),
    ),
    _case(
        "topology-external-management-loopback-vpn",
        "External and excluded subnet classifications",
        category="topology",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="ipv4",
        vrf="default",
        source_node="node-c",
        destination_node="edge-c",
        involved_nodes=("node-c", "edge-c"),
        required_capabilities=("topology_projection",),
        topology_evidence=(
            TopologyEvidenceSelector("link", "ottawa-external"),
            TopologyEvidenceSelector("local", "management", ("node-c",)),
            TopologyEvidenceSelector("local", "loopback", ("node-c",)),
        ),
    ),
    _case(
        "temporal-single-home-to-multihome",
        "Single-home to multi-home resource transition",
        category="temporal",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="l2vpn",
        involved_nodes=("node-a", "node-b"),
        required_capabilities=("temporal_resources", "temporal_relationships"),
        temporal_evidence=(
            TemporalEvidenceSelector(
                "single_home_create",
                "evpn_single_home_service_create",
                "ETG",
                outcome="success",
                state_changed=True,
            ),
            TemporalEvidenceSelector(
                "multihome_add",
                "evpn_multihome_attachment_add",
                "EVPN_ES",
                outcome="success",
                state_changed=True,
            ),
        ),
    ),
    _case(
        "temporal-mass-es-withdraw",
        "Mass Ethernet-segment withdrawal",
        category="temporal",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="l2vpn",
        expected_outcome="failed_over",
        required_capabilities=("temporal_resources", "temporal_relationships"),
        temporal_evidence=(
            TemporalEvidenceSelector(
                "mass_es_withdraw",
                "evpn_es_mass_withdraw",
                "EVPN_ES",
                outcome="success",
                state_changed=True,
            ),
        ),
    ),
    _case(
        "temporal-mass-es-restore",
        "Mass Ethernet-segment restoration",
        category="temporal",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="l2vpn",
        required_capabilities=("temporal_resources", "temporal_relationships"),
        temporal_evidence=(
            TemporalEvidenceSelector(
                "mass_es_restore",
                "evpn_es_mass_restore",
                "EVPN_ES",
                outcome="success",
                state_changed=True,
            ),
        ),
    ),
    _case(
        "temporal-next-hop-churn",
        "Changing next-hop dependency",
        category="temporal",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="ipv4",
        required_capabilities=("temporal_resources", "temporal_relationships"),
        temporal_evidence=(
            TemporalEvidenceSelector(
                "next_hop_churn",
                "dte_next_hop_dependency_change",
                "DTE",
                outcome="success",
                state_changed=True,
            ),
        ),
    ),
    _case(
        "temporal-cross-layer-lag",
        "Cross-layer update lag and failed update",
        category="temporal",
        route_type="not_applicable",
        route_family="not_applicable",
        address_family="ipv4",
        expected_outcome="inconsistent",
        required_capabilities=(
            "temporal_resources",
            "consistency_evaluation",
        ),
        temporal_evidence=(
            TemporalEvidenceSelector(
                "next_hop_churn",
                "dte_next_hop_dependency_change",
                "DTE",
                outcome="failure",
                state_changed=False,
            ),
        ),
    ),
)


def node_by_id(node_id: str) -> NodeSpec:
    for node in DEMO_NODES:
        if node.node_id == node_id:
            return node
    raise KeyError(node_id)


def links_for_node(node_id: str) -> tuple[LinkSpec, ...]:
    return tuple(link for link in DEMO_LINKS if node_id in link.participants)


def adjacent_nodes(node_id: str) -> tuple[str, ...]:
    neighbors: set[str] = set()
    for link in links_for_node(node_id):
        neighbors.update(participant for participant in link.participants if participant != node_id)
    return tuple(sorted(neighbors))


def route_inventory_contexts_for_node(
    node_id: str,
) -> tuple[dict[str, object], ...]:
    """Return validated plug-in route inventory contexts for one node.

    The semantic declarations live in :mod:`scenario_registry`; this helper
    merely joins them to the generator's canonical node catalog.
    """

    known_node_ids = {node.node_id for node in DEMO_NODES}
    if node_id not in known_node_ids:
        raise KeyError(node_id)
    result: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    known_roles = {node.role for node in DEMO_NODES}
    known_routing_groups = {
        group
        for node in DEMO_NODES
        for group in node.routing_groups
    }
    for context in ROUTE_INVENTORY_CONTEXTS:
        context_id = str(context.get("context_id") or "")
        explicit_node_ids = tuple(context.get("eligible_node_ids", ()))
        eligible_roles = tuple(context.get("eligible_roles", ()))
        eligible_routing_groups = tuple(
            context.get("eligible_routing_groups", ())
        )
        if (
            not context_id
            or context_id in seen_ids
            or any(
                not isinstance(item, str) or item not in known_node_ids
                for item in explicit_node_ids
            )
            or any(
                not isinstance(item, str) or item not in known_roles
                for item in eligible_roles
            )
            or any(
                not isinstance(item, str)
                or item not in known_routing_groups
                for item in eligible_routing_groups
            )
            or not (
                explicit_node_ids
                or eligible_roles
                or eligible_routing_groups
            )
        ):
            raise ValueError(
                "route inventory context declarations must have unique IDs "
                "and a known role or node eligibility selector"
            )
        seen_ids.add(context_id)
        for field in (
            "route_type",
            "route_family",
            "address_family",
            "vrf_id",
        ):
            if not isinstance(context.get(field), str) or not context[field]:
                raise ValueError(
                    f"route inventory context {context_id} lacks {field}"
                )
        route_type = str(context["route_type"])
        protocol = context.get("protocol") or ROUTE_PROTOCOL_BY_TYPE.get(
            route_type
        )
        if protocol is None:
            raise ValueError(
                f"route inventory context {context_id} has no protocol mapping"
            )
        if not isinstance(protocol, str) or not protocol:
            raise ValueError(
                f"route inventory context {context_id} has an invalid protocol"
            )
        eligible_node_ids = tuple(
            node.node_id
            for node in DEMO_NODES
            if node.node_id in explicit_node_ids
            or node.role in eligible_roles
            or any(
                group in eligible_routing_groups
                for group in node.routing_groups
            )
        )
        if node_id in eligible_node_ids:
            result.append(
                {
                    **dict(context),
                    "protocol": protocol,
                    "eligible_node_ids": eligible_node_ids,
                }
            )
    return tuple(result)


__all__ = [
    "COVERAGE_CASES",
    "DEFAULT_SCENARIO_SOURCE",
    "DEMO_LINKS",
    "DEMO_NODES",
    "GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID",
    "GENERATED_TOPOLOGY_PROFILE",
    "GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID",
    "PACKET_PROFILES",
    "CoverageCaseSpec",
    "LinkSpec",
    "NodeSpec",
    "TemporalEvidenceSelector",
    "TopologyEvidenceSelector",
    "TopologyProfileSpec",
    "adjacent_nodes",
    "links_for_node",
    "node_by_id",
    "route_inventory_contexts_for_node",
]
