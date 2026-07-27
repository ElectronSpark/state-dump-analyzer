"""Example plug-in semantic registry for demo route-trace scenarios.

The generated coverage catalog and executable route tracer consume different
views of these declarations, but neither may restate routing context. Corpus
layout, evidence selectors, and expected generated outcomes remain generator
concerns and therefore do not belong here.
"""

from __future__ import annotations

from typing import Any


def _scenario(
    scenario_id: str,
    label: str,
    description: str,
    *,
    route_type: str,
    vrf: str,
    route_family: str,
    address_family: str,
    multipath_mode: str = "single_active",
    default_source: str = "source:node-a",
    default_destination: str = "destination:node-b",
    destination_role: str = "router",
    **behavior: Any,
) -> dict[str, Any]:
    destination_endpoint_ids: tuple[str, ...] = ()
    destination_values: tuple[str, ...] = ()
    if destination_role == "blue_service":
        destination_endpoint_ids = (
            "destination:blue-service-prefix",
            "endpoint:blue-service-prefix",
        )
        destination_values = (
            "203.0.113.0/24",
            "203.0.113.0",
            "blue service",
        )
    elif destination_role == "evpn_service":
        destination_endpoint_ids = (
            "destination:east-evpn-multihomed-service",
            "endpoint:east-evpn-multihomed-service",
        )
        destination_values = (
            "east evpn service",
            "esi-east:vlan-320",
            "east ethernet segment",
        )
    elif destination_role == "external_subnet":
        destination_endpoint_ids = (
            "destination:eta-external-subnet",
            "endpoint:eta-external-subnet",
        )
        destination_values = (
            "203.0.113.0/24",
            "203.0.113.0",
            "eta external",
            "external subnet",
        )
    return {
        "scenario_id": scenario_id,
        "label": label,
        "description": description,
        "multipath_mode": multipath_mode,
        "route_type": route_type,
        "vrf_id": vrf,
        "vrf": vrf,
        "route_family": route_family,
        "address_family": address_family,
        "default_source": default_source,
        "default_destination": default_destination,
        "destination_role": destination_role,
        "destination_endpoint_ids": destination_endpoint_ids,
        "destination_values": destination_values,
        **behavior,
    }


BASE_ROUTE_TRACE_SCENARIOS: tuple[dict[str, Any], ...] = (
    _scenario(
        "single-active-primary",
        "Single-active primary with eligible standby",
        (
            "Alpha selects one programmed path while retaining the alternate "
            "ambiguous boundary candidate as an inspectable inactive standby."
        ),
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        destination_role="blue_service",
    ),
    _scenario(
        "all-active-ecmp",
        "All-active ECMP",
        (
            "Both plug-in-declared next-hop candidates are active members of one "
            "ECMP set; neither is presented as a singular primary."
        ),
        multipath_mode="all_active",
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        destination_role="blue_service",
    ),
    _scenario(
        "cross-layer-inconsistent",
        "Control/forwarding path mismatch",
        (
            "The EVPN control resolver expects an overlay peer while observed "
            "forwarding traverses P1. Both views are retained and linked to issues."
        ),
        route_type="evpn_service",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        destination_role="blue_service",
        consistency_finding_specs=(
            {
                "issue_id": "issue:cross-layer-egress-mismatch",
                "category": "cross_layer",
                "finding_type": "egress_interface",
                "summary": (
                    "Control-plane and observed forwarding candidates "
                    "resolve through different egress interfaces."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
            {
                "issue_id": "issue:boundary-path-disagreement",
                "category": "boundary",
                "finding_type": "next_hop",
                "summary": (
                    "The declared control and observed forwarding paths "
                    "cross different inter-node boundaries."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
        ),
    ),
    _scenario(
        "incomplete-node-resolution",
        "Incomplete node-local resolution",
        (
            "The Beta next-hop row is absent. Strict tracing stops at the gap; "
            "best effort may bridge it from topology and current resource status."
        ),
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        destination_role="blue_service",
    ),
    _scenario(
        "router-to-router",
        "Any router to any router",
        (
            "A plug-in-owned route catalog resolves every ordered pair in the sparse "
            "seven-router physical topology."
        ),
        route_type="ipv4_unicast",
        vrf="default",
        route_family="ipv4_unicast",
        address_family="ipv4",
        supports_arbitrary_endpoints=True,
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "transit-start-endpoint-reachability",
        "Transit observation with endpoint return validation",
        (
            "The packet source is PE-A, but forward observation begins at P1. "
            "Return traffic is validated from PE-B to the PE-A source endpoint "
            "and is not required to revisit P1."
        ),
        route_type="ipv4_unicast",
        vrf="default",
        route_family="ipv4_unicast",
        address_family="ipv4",
        supports_explicit_start=True,
        default_source="source:node-a",
        default_destination="destination:node-b",
        default_start="start:transit-p-1",
    ),
    _scenario(
        "site-a-site-c-asymmetric",
        "PE-A / PE-C asymmetric service",
        (
            "Forward SRv6 resolution uses P2 directly; reverse MPLS resolution uses "
            "P2 and P1, so both directions work but do not mirror each other."
        ),
        route_type="srv6_policy",
        vrf="blue",
        route_family="ipv6_unicast",
        address_family="ipv6",
        directional_routing_contexts={
            "forward": {
                "route_type": "srv6_policy",
                "vrf_id": "blue",
                "route_family": "ipv6_unicast",
                "address_family": "ipv6",
            },
            "reverse": {
                "route_type": "mpls_transport",
                "vrf_id": "default",
                "route_family": "mpls_labeled_unicast",
                "address_family": "mpls",
            },
        },
        default_source="source:node-a",
        default_destination="destination:node-c",
        pair_id="pair:pe-a-pe-c-asymmetric",
    ),
    _scenario(
        "site-b-site-c-one-way",
        "PE-B / PE-C one-way service drop",
        (
            "PE-B to PE-C succeeds through P2. The reverse trace reaches P2 but a "
            "directional forwarding decision drops the packet toward PE-B."
        ),
        route_type="evpn_service",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        default_source="source:node-b",
        default_destination="destination:node-c",
        pair_id="pair:pe-b-pe-c-one-way",
        consistency_finding_specs=(
            {
                "issue_id": (
                    "issue:directional:node-c:node-b:p2-egress-drop"
                ),
                "category": "directional",
                "finding_type": "terminal_drop",
                "summary": (
                    "The reverse forwarding decision drops traffic at "
                    "the P2 egress."
                ),
                "candidate_directions": ("reverse",),
                "candidate_alternative_states": ("selected_primary",),
            },
        ),
    ),
    _scenario(
        "evpn-mh-all-active",
        "EVPN multihoming all-active",
        (
            "The east Ethernet segment is reachable through independently resolved "
            "PE-B and PE-E VTEPs. Both plug-in-declared members remain active and "
            "neither is promoted to a singular primary."
        ),
        multipath_mode="all_active",
        route_type="evpn_mac_ip",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        default_source="source:node-a",
        default_destination="destination:node-e",
        destination_role="evpn_service",
    ),
    _scenario(
        "evpn-es-withdraw-failover",
        "EVPN ES withdraw and failover",
        (
            "PE-E is selected after the PE-B Ethernet-segment advertisement is "
            "withdrawn. The withdrawn candidate is retained as a focusable dead path."
        ),
        route_type="evpn_mac_ip",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        default_source="source:node-a",
        default_destination="destination:node-e",
        destination_role="evpn_service",
    ),
    _scenario(
        "evpn-stale-fib-after-withdraw",
        "EVPN control/FIB lag after ES withdraw",
        (
            "EVPN control has moved the service to PE-E while the observed FIB still "
            "uses the withdrawn PE-B VTEP and stale encapsulation."
        ),
        route_type="evpn_mac_ip",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        default_source="source:node-a",
        default_destination="destination:node-e",
        destination_role="evpn_service",
        consistency_finding_specs=(
            {
                "category": "cross_layer",
                "finding_type": "next_hop",
                "summary": (
                    "Observed forwarding selects a next hop withdrawn "
                    "from the control-plane view."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
            {
                "category": "cross_layer",
                "finding_type": "egress_interface",
                "summary": (
                    "Observed and intended forwarding use different "
                    "Ethernet-segment egress interfaces."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
            {
                "category": "cross_layer",
                "finding_type": "encapsulation",
                "summary": (
                    "The stale FIB retains encapsulation for the withdrawn "
                    "remote VTEP."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
            {
                "category": "cross_layer",
                "finding_type": "update_lag",
                "summary": (
                    "The forwarding layer has not converged to the later "
                    "control-plane update."
                ),
                "candidate_alternative_states": (
                    "selected_primary",
                    "control_expected_not_observed",
                ),
            },
        ),
    ),
    _scenario(
        "srv6-all-active",
        "SRv6 all-active policies",
        (
            "Two independently programmed SRv6 policies reach PE-E through P1 and "
            "P2 with different plug-in-declared SID lists."
        ),
        multipath_mode="all_active",
        route_type="srv6_policy",
        vrf="blue",
        route_family="ipv6_unicast",
        address_family="ipv6",
        default_source="source:node-a",
        default_destination="destination:node-e",
    ),
    _scenario(
        "recursive-static-to-external",
        "Recursive static route to an external subnet",
        (
            "A tenant static route recursively resolves a BGP next hop, an IS-IS "
            "transport path, and PE-E's external attachment."
        ),
        route_type="static_recursive",
        vrf="blue",
        route_family="ipv4_unicast",
        address_family="ipv4",
        default_source="source:node-a",
        default_destination="destination:node-e",
        destination_role="external_subnet",
    ),
    _scenario(
        "recursive-resolution-cycle",
        "Recursive next-hop cycle",
        (
            "Two plug-in-declared recursive lookups return to the same canonical "
            "forwarding state. The core reports the repeated state instead of "
            "silently discarding the candidate."
        ),
        route_type="static_recursive",
        vrf="blue",
        route_family="ipv4_unicast",
        address_family="ipv4",
        default_source="source:node-a",
        default_destination="destination:node-b",
        destination_role="blue_service",
    ),
    _scenario(
        "cross-node-forwarding-loop",
        "Cross-node forwarding loop",
        (
            "PE-B sends the service route back toward P1, returning to the same "
            "canonical P1 forwarding state. Every router occurrence and the "
            "loop-closing boundary remain inspectable."
        ),
        route_type="ipv4_unicast",
        vrf="blue",
        route_family="ipv4_unicast",
        address_family="ipv4",
        default_source="source:node-a",
        default_destination="destination:node-b",
        destination_role="blue_service",
    ),
    _scenario(
        "evpn-split-horizon-block",
        "EVPN split-horizon policy block",
        (
            "An EVPN frame received from the east Ethernet segment reaches the "
            "remote PE, whose plug-in rejects egress back into the same normalized "
            "split-horizon scope. The rejected candidate is retained."
        ),
        route_type="evpn_mac_ip",
        vrf="blue",
        route_family="l2vpn_evpn",
        address_family="l2vpn",
        default_source="source:node-b",
        default_destination="destination:node-e",
        destination_role="evpn_service",
    ),
    _scenario(
        "connected-external-subnet",
        "PE-E connected external subnet",
        (
            "The connected route terminates on PE-E's external attachment and subnet "
            "without fabricating a remote router."
        ),
        route_type="connected",
        vrf="default",
        route_family="ipv4_unicast",
        address_family="ipv4",
        default_source="source:node-e",
        default_destination="destination:node-e",
        destination_role="external_subnet",
    ),
    _scenario(
        "incomplete-intermediate-resolution",
        "Missing P2 intermediate resolution",
        (
            "The P2 node-local decision between PE-D and PE-B is missing. Strict "
            "tracing preserves the gap; best effort may bridge it with explicit "
            "topology and status evidence."
        ),
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        default_source="source:node-d",
        default_destination="destination:node-b",
    ),
)


PACKET_TRACE_SCENARIOS: tuple[dict[str, Any], ...] = (
    _scenario(
        "packet-native-ip",
        "Packet evolution · native IPv4",
        (
            "Native IPv4 forwarding changes only hop-local header state. This "
            "is the compatibility baseline for basic IP routing."
        ),
        route_type="ipv4_unicast",
        vrf="default",
        route_family="ipv4_unicast",
        address_family="ipv4",
        packet_profile_id="native-ip",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-sr-mpls-php",
        "Packet evolution · SR-MPLS swap and PHP",
        (
            "Ingress pushes a transport label, transit swaps it, the penultimate "
            "hop performs PHP, and egress receives native IPv4."
        ),
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        packet_profile_id="sr-mpls-php",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-l3vpn-over-sr-mpls",
        "Packet evolution · L3VPN over SR-MPLS",
        (
            "An IPv4 tenant packet gains VPN and transport labels. Transit swaps "
            "and PHP affect only the transport layer before egress removes the VPN "
            "label and performs the tenant lookup."
        ),
        route_type="mpls_l3vpn",
        vrf="blue",
        route_family="vpnv4_unicast",
        address_family="ipv4",
        packet_profile_id="l3vpn-over-sr-mpls",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-srv6-encap",
        "Packet evolution · SRv6 encapsulation",
        (
            "Ingress adds an outer IPv6 header and SRH, an SR endpoint advances "
            "the declared SID list, and egress decapsulates the inner IPv6 packet."
        ),
        route_type="srv6_policy",
        vrf="blue",
        route_family="ipv6_unicast",
        address_family="ipv6",
        packet_profile_id="srv6-encap",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-ipv6-over-ipv4",
        "Packet evolution · IPv6 over IPv4",
        (
            "An IPv6 packet is recursively resolved through an IPv4 tunnel, "
            "retaining both header layers until tunnel egress."
        ),
        route_type="ipv6_unicast",
        vrf="default",
        route_family="ipv6_unicast",
        address_family="ipv6",
        packet_profile_id="ipv6-over-ipv4",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-vpn-over-vpn",
        "Packet evolution · nested VPN over VPN",
        (
            "A tenant IPv4 packet is wrapped by Ethernet/VXLAN/UDP/IPv6 and then "
            "carried inside an MPLS L3VPN transport, demonstrating multiple nested "
            "wrappers without protocol branches in core."
        ),
        route_type="mpls_l3vpn",
        vrf="blue",
        route_family="vpnv4_unicast",
        address_family="ipv4",
        packet_profile_id="vpn-over-vpn",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-mtu-drop",
        "Packet evolution · MTU drop after encapsulation",
        (
            "The node plug-in declares a DF packet drop after tunnel overhead "
            "exceeds an egress wire-size constraint. Core performs only the size "
            "comparison."
        ),
        route_type="ipv4_unicast",
        vrf="default",
        route_family="ipv4_unicast",
        address_family="ipv4",
        packet_profile_id="mtu-drop",
        default_source="source:node-a",
        default_destination="destination:node-b",
    ),
    _scenario(
        "packet-forced-steering",
        "Packet evolution · forced steering sandbox",
        (
            "The observed node decision uses P1. An advertised user rule can force "
            "the alternate P2 candidate or inject an outer IPv4 wrapper; every "
            "forced result remains visibly counterfactual."
        ),
        route_type="mpls_transport",
        vrf="default",
        route_family="mpls_labeled_unicast",
        address_family="mpls",
        packet_profile_id="sr-mpls-php",
        default_source="source:node-a",
        default_destination="destination:node-b",
        steering_profiles=(
            "observed",
            "force-alternate-p2",
            "force-outer-ipv4",
            "force-mid-wrapper",
        ),
    ),
)


ROUTE_TRACE_SCENARIOS: tuple[dict[str, Any], ...] = (
    *BASE_ROUTE_TRACE_SCENARIOS,
    *PACKET_TRACE_SCENARIOS,
)

ROUTE_PROTOCOL_BY_TYPE: dict[str, str] = {
    "ipv4_unicast": "ibgp",
    "ipv6_unicast": "ibgp",
    "connected": "connected",
    "static_recursive": "static",
    "isis_underlay": "isis-l2",
    "mpls_transport": "segment-routing-mpls",
    "mpls_l3vpn": "bgp-vpnv4",
    "srv6_policy": "bgp-sr-policy",
    "evpn_service": "bgp-evpn",
    "evpn_mac_ip": "bgp-evpn",
    "evpn_ip_prefix": "bgp-evpn",
}

ROUTE_RESOLUTION_LAYERS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "ipv4_unicast": ("ipv4_unicast",),
    "ipv6_unicast": ("ipv6_unicast",),
    "connected": ("connected",),
    "static_recursive": (
        "static_recursive",
        "ipv4_unicast",
        "isis_underlay",
    ),
    "isis_underlay": ("isis_underlay",),
    "mpls_transport": ("mpls_transport", "isis_underlay"),
    "mpls_l3vpn": (
        "mpls_l3vpn",
        "mpls_transport",
        "isis_underlay",
    ),
    "srv6_policy": (
        "srv6_policy",
        "ipv6_unicast",
        "isis_underlay",
    ),
    "evpn_service": ("evpn_service", "isis_underlay"),
    "evpn_mac_ip": ("evpn_mac_ip", "isis_underlay"),
    "evpn_ip_prefix": ("evpn_ip_prefix", "isis_underlay"),
}


def _scenario_inventory_contexts() -> tuple[dict[str, Any], ...]:
    """Derive generic all-pair contexts from canonical scenario semantics."""

    contexts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for scenario in ROUTE_TRACE_SCENARIOS:
        directional = scenario.get("directional_routing_contexts", {})
        candidates = [
            scenario,
            *(
                item
                for item in directional.values()
                if isinstance(item, dict)
            ),
        ]
        for context in candidates:
            key = (
                str(context["route_type"]),
                str(context["route_family"]),
                str(context["address_family"]),
                str(context["vrf_id"]),
            )
            if key in seen:
                continue
            seen.add(key)
            route_type, route_family, address_family, vrf_id = key
            if route_type == "connected":
                # Connected state terminates on a local attachment; it is not
                # an all-pairs routing context.
                continue
            eligible_roles = (
                "provider_edge",
                "provider_core",
            )
            if route_type == "ipv4_unicast" and vrf_id == "default":
                eligible_roles = (*eligible_roles, "customer_edge")
            contexts.append(
                {
                    "context_id": (
                        f"generic-{route_type}-{vrf_id}-{route_family}"
                    ),
                    "route_type": route_type,
                    "route_family": route_family,
                    "address_family": address_family,
                    "vrf_id": vrf_id,
                    "eligible_roles": eligible_roles,
                }
            )
    return tuple(contexts)


# Plug-in-owned routing contexts which are useful inventory/trace inputs but do
# not need a dedicated behavior scenario. Contexts already exercised by a
# scenario are derived above, so the plug-in has one routing declaration rather
# than a second manually synchronized catalog.
ROUTE_INVENTORY_CONTEXTS: tuple[dict[str, Any], ...] = (
    *_scenario_inventory_contexts(),
    {
        "context_id": "underlay-isis-default",
        "route_type": "isis_underlay",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "vrf_id": "default",
        "eligible_roles": ("provider_edge", "provider_core"),
    },
    {
        "context_id": "evpn-prefix-blue",
        "route_type": "evpn_ip_prefix",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "vrf_id": "blue",
        "eligible_roles": ("provider_edge", "provider_core"),
    },
    {
        "context_id": "evpn-prefix-red",
        "route_type": "evpn_ip_prefix",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "vrf_id": "red",
        "eligible_routing_groups": ("red_service_pe",),
    },
    {
        "context_id": "l3vpn-red",
        "route_type": "mpls_l3vpn",
        "route_family": "vpnv4_unicast",
        "address_family": "ipv4",
        "vrf_id": "red",
        "eligible_routing_groups": ("red_service_pe",),
    },
    {
        "context_id": "management-ipv4",
        "route_type": "ipv4_unicast",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "vrf_id": "management",
        "protocol": "ebgp",
        "eligible_roles": ("provider_edge",),
    },
    {
        "context_id": "global-srv6",
        "route_type": "srv6_policy",
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "vrf_id": "default",
        "eligible_roles": ("provider_edge", "provider_core"),
    },
    {
        "context_id": "blue-mpls-transport",
        "route_type": "mpls_transport",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
        "vrf_id": "blue",
        "eligible_roles": ("provider_edge", "provider_core"),
    },
)

SCENARIO_BY_ID = {
    str(item["scenario_id"]): item
    for item in ROUTE_TRACE_SCENARIOS
}
if len(SCENARIO_BY_ID) != len(ROUTE_TRACE_SCENARIOS):
    raise ValueError("demo scenario IDs must be unique")


def scenario_semantics(scenario_id: str) -> dict[str, Any]:
    """Return the canonical semantic declaration for *scenario_id*."""

    try:
        return SCENARIO_BY_ID[scenario_id]
    except KeyError as error:
        raise ValueError(f"unknown demo route scenario: {scenario_id}") from error


__all__ = [
    "BASE_ROUTE_TRACE_SCENARIOS",
    "PACKET_TRACE_SCENARIOS",
    "ROUTE_INVENTORY_CONTEXTS",
    "ROUTE_PROTOCOL_BY_TYPE",
    "ROUTE_RESOLUTION_LAYERS_BY_TYPE",
    "ROUTE_TRACE_SCENARIOS",
    "SCENARIO_BY_ID",
    "scenario_semantics",
]
