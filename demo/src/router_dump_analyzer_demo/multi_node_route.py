"""Cross-node route tracing over the heterogeneous topology demo.

This module is intentionally an orchestration example rather than a routing
implementation.  Node plug-ins provide local route-resolution decisions and
their explanatory strings; the federation linker provides inter-node boundary
identity.  The core aligns time, evaluates exact typed candidate constraints,
performs bounded traversal and cycle detection, orders the opaque explanatory
steps, retains every candidate, and records uncertainty or best-effort joins.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections import deque
from typing import Any

from .multi_node_topology import (
    MULTI_NODE_TOPOLOGY_ID,
    MultiNodeTopologyDemo,
    MultiNodeTopologyRequestError,
)
from router_dump_analyzer.route_trace_core import (
    EndpointReachabilityPairEvaluation,
    ForwardingPolicyEvaluation,
    ForwardingPacketTraceEvaluation,
    ForwardingPacketTransitionEvaluation,
    RouteTraceContractError,
    evaluate_endpoint_reachability_pair,
    evaluate_forwarding_packet_trace,
    evaluate_forwarding_policy,
    evaluate_forwarding_traversal,
)
from router_dump_analyzer.plugin_api import (
    Evidence,
    ForwardingCandidateConstraint,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
    ForwardingTraversalStateKey,
    ResourceKey,
    StatusPerspectiveRef,
    TopologyEndpointReference,
)
from router_dump_analyzer_demo_plugins.advanced_trace import (
    ADVANCED_TRACE_SCENARIO_IDS,
    ADVANCED_TRACE_SCENARIOS,
    STEERING_PROFILES,
    build_packet_transitions,
    forced_node_sequence,
    preferred_node_sequence,
)


class MultiNodeRouteRequestError(MultiNodeTopologyRequestError):
    """A route-trace request cannot be executed by the advertised resolvers."""


_SCENARIOS = (
    {
        "scenario_id": "single-active-primary",
        "label": "Single-active primary with eligible standby",
        "description": (
            "Alpha selects one programmed path while retaining the alternate "
            "ambiguous boundary candidate as an inspectable inactive standby."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
    },
    {
        "scenario_id": "all-active-ecmp",
        "label": "All-active ECMP",
        "description": (
            "Both plug-in-declared next-hop candidates are active members of one "
            "ECMP set; neither is presented as a singular primary."
        ),
        "multipath_mode": "all_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
    },
    {
        "scenario_id": "cross-layer-inconsistent",
        "label": "Control/forwarding path mismatch",
        "description": (
            "The EVPN control resolver expects an overlay peer while observed "
            "forwarding traverses P1. Both views are retained and linked to issues."
        ),
        "multipath_mode": "single_active",
        "route_type": "evpn_service",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
    },
    {
        "scenario_id": "incomplete-node-resolution",
        "label": "Incomplete node-local resolution",
        "description": (
            "The Beta next-hop row is absent. Strict tracing stops at the gap; "
            "best effort may bridge it from topology and current resource status."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
    },
    {
        "scenario_id": "router-to-router",
        "label": "Any router to any router",
        "description": (
            "A plug-in-owned route catalog resolves every ordered pair in the sparse "
            "seven-router physical topology."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv4_unicast",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "supports_arbitrary_endpoints": True,
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    {
        "scenario_id": "transit-start-endpoint-reachability",
        "label": "Transit observation with endpoint return validation",
        "description": (
            "The packet source is PE-A, but forward observation begins at P1. "
            "Return traffic is validated from PE-B to the PE-A source endpoint "
            "and is not required to revisit P1."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv4_unicast",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "supports_explicit_start": True,
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-b-loopback",
        "default_start": "start:transit-p-1",
    },
    {
        "scenario_id": "site-a-site-c-asymmetric",
        "label": "PE-A / PE-C asymmetric service",
        "description": (
            "Forward SRv6 resolution uses P2 directly; reverse MPLS resolution uses "
            "P2 and P1, so both directions work but do not mirror each other."
        ),
        "multipath_mode": "single_active",
        "route_type": "srv6_policy",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "directional_routing_contexts": {
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
        "pair_id": "pair:pe-a-pe-c-asymmetric",
    },
    {
        "scenario_id": "site-b-site-c-one-way",
        "label": "PE-B / PE-C one-way service drop",
        "description": (
            "PE-B to PE-C succeeds through P2. The reverse trace reaches P2 but a "
            "directional forwarding decision drops the packet toward PE-B."
        ),
        "multipath_mode": "single_active",
        "route_type": "evpn_service",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "pair_id": "pair:pe-b-pe-c-one-way",
    },
    {
        "scenario_id": "evpn-mh-all-active",
        "label": "EVPN multihoming all-active",
        "description": (
            "The east Ethernet segment is reachable through independently resolved "
            "PE-B and PE-E VTEPs. Both plug-in-declared members remain active and "
            "neither is promoted to a singular primary."
        ),
        "multipath_mode": "all_active",
        "route_type": "evpn_mac_ip",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:east-evpn-multihomed-service",
    },
    {
        "scenario_id": "evpn-es-withdraw-failover",
        "label": "EVPN ES withdraw and failover",
        "description": (
            "PE-E is selected after the PE-B Ethernet-segment advertisement is "
            "withdrawn. The withdrawn candidate is retained as a focusable dead path."
        ),
        "multipath_mode": "single_active",
        "route_type": "evpn_mac_ip",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:east-evpn-multihomed-service",
    },
    {
        "scenario_id": "evpn-stale-fib-after-withdraw",
        "label": "EVPN control/FIB lag after ES withdraw",
        "description": (
            "EVPN control has moved the service to PE-E while the observed FIB still "
            "uses the withdrawn PE-B VTEP and stale encapsulation."
        ),
        "multipath_mode": "single_active",
        "route_type": "evpn_mac_ip",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:east-evpn-multihomed-service",
    },
    {
        "scenario_id": "srv6-all-active",
        "label": "SRv6 all-active policies",
        "description": (
            "Two independently programmed SRv6 policies reach PE-E through P1 and "
            "P2 with different plug-in-declared SID lists."
        ),
        "multipath_mode": "all_active",
        "route_type": "srv6_policy",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:node-e-loopback",
    },
    {
        "scenario_id": "recursive-static-to-external",
        "label": "Recursive static route to an external subnet",
        "description": (
            "A tenant static route recursively resolves a BGP next hop, an IS-IS "
            "transport path, and PE-E's external attachment."
        ),
        "multipath_mode": "single_active",
        "route_type": "static_recursive",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:eta-external-subnet",
    },
    {
        "scenario_id": "recursive-resolution-cycle",
        "label": "Recursive next-hop cycle",
        "description": (
            "Two plug-in-declared recursive lookups return to the same canonical "
            "forwarding state. The core reports the repeated state instead of "
            "silently discarding the candidate."
        ),
        "multipath_mode": "single_active",
        "route_type": "static_recursive",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:blue-service-prefix",
    },
    {
        "scenario_id": "cross-node-forwarding-loop",
        "label": "Cross-node forwarding loop",
        "description": (
            "PE-B sends the service route back toward P1, returning to the same "
            "canonical P1 forwarding state. Every router occurrence and the "
            "loop-closing boundary remain inspectable."
        ),
        "multipath_mode": "single_active",
        "route_type": "ipv4_unicast",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:pe-a-loopback",
        "default_destination": "destination:blue-service-prefix",
    },
    {
        "scenario_id": "evpn-split-horizon-block",
        "label": "EVPN split-horizon policy block",
        "description": (
            "An EVPN frame received from the east Ethernet segment reaches the "
            "remote PE, whose plug-in rejects egress back into the same normalized "
            "split-horizon scope. The rejected candidate is retained."
        ),
        "multipath_mode": "single_active",
        "route_type": "evpn_mac_ip",
        "vrf_id": "blue",
        "vrf": "blue",
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "default_source": "source:node-b-loopback",
        "default_destination": "destination:east-evpn-multihomed-service",
    },
    {
        "scenario_id": "connected-external-subnet",
        "label": "PE-E connected external subnet",
        "description": (
            "The connected route terminates on PE-E's external attachment and subnet "
            "without fabricating a remote router."
        ),
        "multipath_mode": "single_active",
        "route_type": "connected",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "default_source": "source:node-e-loopback",
        "default_destination": "destination:eta-external-subnet",
    },
    {
        "scenario_id": "incomplete-intermediate-resolution",
        "label": "Missing P2 intermediate resolution",
        "description": (
            "The P2 node-local decision between PE-D and PE-B is missing. Strict "
            "tracing preserves the gap; best effort may bridge it with explicit "
            "topology and status evidence."
        ),
        "multipath_mode": "single_active",
        "route_type": "mpls_transport",
        "vrf_id": "default",
        "vrf": "default",
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
        "default_source": "source:node-d-loopback",
        "default_destination": "destination:node-b-loopback",
    },
    *ADVANCED_TRACE_SCENARIOS,
)


_SCENARIO_DESTINATION_IDS: dict[str, set[str]] = {
    "single-active-primary": {"destination:blue-service-prefix"},
    "all-active-ecmp": {"destination:blue-service-prefix"},
    "cross-layer-inconsistent": {"destination:blue-service-prefix"},
    "incomplete-node-resolution": {"destination:blue-service-prefix"},
    "transit-start-endpoint-reachability": {
        "destination:node-b-loopback"
    },
    "site-a-site-c-asymmetric": {
        "destination:node-a-loopback",
        "destination:node-c-loopback",
    },
    "site-b-site-c-one-way": {
        "destination:node-b-loopback",
        "destination:node-c-loopback",
    },
    "evpn-mh-all-active": {"destination:east-evpn-multihomed-service"},
    "evpn-es-withdraw-failover": {
        "destination:east-evpn-multihomed-service"
    },
    "evpn-stale-fib-after-withdraw": {
        "destination:east-evpn-multihomed-service"
    },
    "srv6-all-active": {"destination:node-e-loopback"},
    "recursive-static-to-external": {"destination:eta-external-subnet"},
    "recursive-resolution-cycle": {"destination:blue-service-prefix"},
    "cross-node-forwarding-loop": {"destination:blue-service-prefix"},
    "evpn-split-horizon-block": {
        "destination:east-evpn-multihomed-service"
    },
    "connected-external-subnet": {"destination:eta-external-subnet"},
    "incomplete-intermediate-resolution": {
        "destination:node-b-loopback",
        "destination:node-d-loopback",
    },
    **{
        scenario_id: {"destination:node-b-loopback"}
        for scenario_id in ADVANCED_TRACE_SCENARIO_IDS
    },
}

_BLUE_SERVICE_SCENARIOS = {
    "single-active-primary",
    "all-active-ecmp",
    "cross-layer-inconsistent",
    "incomplete-node-resolution",
    "recursive-resolution-cycle",
    "cross-node-forwarding-loop",
}

_EXTERNAL_SUBNET_SCENARIOS = {
    "recursive-static-to-external",
    "connected-external-subnet",
}


_ROUTERS: tuple[dict[str, Any], ...] = (
    {
        "node_id": "node-a",
        "source_id": "source:pe-a-loopback",
        "destination_id": "destination:node-a-loopback",
        "label": "PE-A loopback",
        "site": "toronto-west",
        "role": "provider_edge",
        "loopback_resource_id": "node-a/LOOPBACK/lo0",
        "prefix": "10.255.0.1/32",
    },
    {
        "node_id": "node-b",
        "source_id": "source:node-b-loopback",
        "destination_id": "destination:node-b-loopback",
        "label": "PE-B loopback",
        "site": "montreal-east",
        "role": "provider_edge",
        "loopback_resource_id": "node-b/LOOPBACK/1",
        "prefix": "10.255.0.2/32",
    },
    {
        "node_id": "transit-p-1",
        "source_id": "source:transit-p-1-loopback",
        "destination_id": "destination:transit-p-1-loopback",
        "label": "P1 router ID",
        "site": "core-west",
        "role": "core_transit",
        "loopback_resource_id": "transit-p-1/LOOPBACK/0",
        "prefix": "10.255.0.11/32",
    },
    {
        "node_id": "transit-p-2",
        "source_id": "source:transit-p-2-loopback",
        "destination_id": "destination:transit-p-2-loopback",
        "label": "P2 router ID",
        "site": "core-east",
        "role": "core_transit",
        "loopback_resource_id": "transit-p-2/ROUTER_ID/10.255.0.12",
        "prefix": "10.255.0.12/32",
    },
    {
        "node_id": "node-c",
        "source_id": "source:node-c-loopback",
        "destination_id": "destination:node-c-loopback",
        "label": "PE-C service loopback",
        "site": "ottawa-edge",
        "role": "provider_edge",
        "loopback_resource_id": "node-c/LOOPBACK/100",
        "prefix": "10.255.0.3/32",
    },
    {
        "node_id": "node-d",
        "source_id": "source:node-d-loopback",
        "destination_id": "destination:node-d-loopback",
        "label": "PE-D / Zeta EVPN NOS",
        "site": "toronto-west",
        "role": "provider_edge",
        "loopback_resource_id": "node-d/LOOPBACK/lo0",
        "prefix": "10.255.0.4/32",
    },
    {
        "node_id": "node-e",
        "source_id": "source:node-e-loopback",
        "destination_id": "destination:node-e-loopback",
        "label": "PE-E / Eta border NOS",
        "site": "montreal-east",
        "role": "provider_edge",
        "loopback_resource_id": "node-e/LOOPBACK/lo0",
        "external_interface_resource_id": "node-e/INTERFACE/et-0-0-20",
        "prefix": "10.255.0.5/32",
    },
)


_BOUNDARIES: dict[tuple[str, str], dict[str, Any]] = {
    ("node-a", "transit-p-1"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-101:node-a:transit-p-1",
        "resources": {
            "node-a": "node-a/INTERFACE/xe-0-0-0",
            "transit-p-1": "transit-p-1/ADJACENCY/pe-a",
        },
    },
    ("node-b", "transit-p-1"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-102:node-b:transit-p-1",
        "resources": {
            "node-b": "node-b/PORT/17",
            "transit-p-1": "transit-p-1/ADJACENCY/pe-b",
        },
    },
    ("node-a", "transit-p-2"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-201:node-a:transit-p-2",
        "resources": {
            "node-a": "node-a/INTERFACE/xe-0-0-1",
            "transit-p-2": "transit-p-2/ADJACENCY/pe-a",
        },
    },
    ("node-b", "transit-p-2"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-202:node-b:transit-p-2",
        "resources": {
            "node-b": "node-b/PORT/18",
            "transit-p-2": "transit-p-2/ADJACENCY/pe-b",
        },
    },
    ("transit-p-2", "node-c"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-203:transit-p-2:node-c",
        "resources": {
            "transit-p-2": "transit-p-2/ADJACENCY/pe-c",
            "node-c": "node-c/PORT/7",
        },
    },
    ("transit-p-1", "transit-p-2"): {
        "link_id": "demo.connector-key.exact.v1:underlay:core-p1-p2:transit-p-1:transit-p-2",
        "resources": {
            "transit-p-1": "transit-p-1/ADJACENCY/p2",
            "transit-p-2": "transit-p-2/ADJACENCY/p1",
        },
    },
    ("node-d", "transit-p-1"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-301:node-d:transit-p-1",
        "resources": {
            "node-d": "node-d/INTERFACE/Ethernet1-1",
            "transit-p-1": "transit-p-1/INTERFACE/et-0-0-2",
        },
    },
    ("node-d", "transit-p-2"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-302:node-d:transit-p-2",
        "resources": {
            "node-d": "node-d/INTERFACE/Ethernet1-2",
            "transit-p-2": "transit-p-2/INTERFACE/TenGig0-0-5",
        },
    },
    ("node-e", "transit-p-1"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-401:node-e:transit-p-1",
        "resources": {
            "node-e": "node-e/INTERFACE/et-0-0-0",
            "transit-p-1": "transit-p-1/INTERFACE/et-0-0-3",
        },
    },
    ("node-e", "transit-p-2"): {
        "link_id": "demo.connector-key.exact.v1:underlay:circuit-402:node-e:transit-p-2",
        "resources": {
            "node-e": "node-e/INTERFACE/et-0-0-1",
            "transit-p-2": "transit-p-2/INTERFACE/TenGig0-0-6",
        },
    },
}


_ROUTE_TYPES = (
    {"route_type": "ipv4_unicast", "label": "IPv4 unicast"},
    {"route_type": "ipv6_unicast", "label": "IPv6 unicast"},
    {"route_type": "connected", "label": "Connected subnet"},
    {"route_type": "static_recursive", "label": "Recursive static route"},
    {"route_type": "isis_underlay", "label": "IS-IS underlay"},
    {"route_type": "mpls_transport", "label": "MPLS label switched path"},
    {"route_type": "mpls_l3vpn", "label": "MPLS L3VPN"},
    {"route_type": "srv6_policy", "label": "SRv6 policy"},
    {"route_type": "evpn_service", "label": "EVPN service resolution"},
    {"route_type": "evpn_mac_ip", "label": "EVPN MAC/IP route (Type 2)"},
    {"route_type": "evpn_ip_prefix", "label": "EVPN IP prefix route (Type 5)"},
)


# Demo plug-in policy, not core protocol inference.  A production plug-in emits
# the same generic presentation descriptors after interpreting its own route,
# VRF, encapsulation, and service state.  The core only validates and renders
# the declared roles.
_DEMO_SERVICE_PRESENTATION: dict[str, dict[str, str]] = {
    "mpls_l3vpn": {
        "technology": "MPLS L3VPN",
        "description": "Tenant routing and VPN-label context",
    },
    "evpn_service": {
        "technology": "EVPN service",
        "description": "EVPN control and service context",
    },
    "evpn_mac_ip": {
        "technology": "EVPN MAC/IP",
        "description": "EVPN Type-2 service and Ethernet-segment context",
    },
    "evpn_ip_prefix": {
        "technology": "EVPN IP prefix",
        "description": "EVPN Type-5 service and IP-prefix context",
    },
}

_DEMO_VPN_SEGMENT_KEYS = {
    "blue": "vpn:blue:ipv4:10.20.0.0-24",
    "red": "vpn:red:ipv6:2001-db8-30--64",
}


_ROUTE_FAMILIES: tuple[dict[str, Any], ...] = (
    {
        "route_family": "ipv4_unicast",
        "address_family": "ipv4",
        "safi": "unicast",
        "label": "IPv4 unicast",
        "supported_route_types": [
            "ipv4_unicast",
            "connected",
            "static_recursive",
            "isis_underlay",
        ],
    },
    {
        "route_family": "mpls_labeled_unicast",
        "address_family": "mpls",
        "safi": "labeled_unicast",
        "label": "MPLS labeled unicast",
        "supported_route_types": ["mpls_transport"],
    },
    {
        "route_family": "ipv6_unicast",
        "address_family": "ipv6",
        "safi": "unicast",
        "label": "IPv6 unicast / SRv6",
        "supported_route_types": ["ipv6_unicast", "srv6_policy"],
    },
    {
        "route_family": "vpnv4_unicast",
        "address_family": "ipv4",
        "safi": "mpls_vpn",
        "label": "VPNv4 MPLS L3VPN",
        "supported_route_types": ["mpls_l3vpn"],
    },
    {
        "route_family": "l2vpn_evpn",
        "address_family": "l2vpn",
        "safi": "evpn",
        "label": "L2VPN EVPN",
        "supported_route_types": [
            "evpn_service",
            "evpn_mac_ip",
            "evpn_ip_prefix",
        ],
    },
)


_VRFS: tuple[dict[str, Any], ...] = (
    {
        "vrf_id": "default",
        "vrf": "default",
        "label": "Global / default routing table",
        "description": "Underlay, transport, and global SRv6 reachability.",
        "route_families": [
            "ipv4_unicast",
            "mpls_labeled_unicast",
            "ipv6_unicast",
        ],
        "supported_route_types": [
            "ipv4_unicast",
            "ipv6_unicast",
            "connected",
            "isis_underlay",
            "mpls_transport",
            "srv6_policy",
        ],
        "node_ids": [
            "node-a",
            "node-b",
            "transit-p-1",
            "transit-p-2",
            "node-c",
            "node-d",
            "node-e",
        ],
    },
    {
        "vrf_id": "blue",
        "vrf": "blue",
        "label": "Tenant Blue",
        "description": "EVPN tenant and service-chain reachability.",
        "route_families": [
            "ipv4_unicast",
            "mpls_labeled_unicast",
            "ipv6_unicast",
            "vpnv4_unicast",
            "l2vpn_evpn",
        ],
        "supported_route_types": [
            "ipv4_unicast",
            "static_recursive",
            "mpls_transport",
            "mpls_l3vpn",
            "srv6_policy",
            "evpn_service",
            "evpn_mac_ip",
            "evpn_ip_prefix",
        ],
        "node_ids": [
            "node-a",
            "node-b",
            "transit-p-1",
            "transit-p-2",
            "node-c",
            "node-d",
            "node-e",
        ],
    },
    {
        "vrf_id": "red",
        "vrf": "red",
        "label": "Tenant Red",
        "description": "EVPN and L3VPN reachability installed only on PE-D and PE-E.",
        "route_families": ["vpnv4_unicast", "l2vpn_evpn"],
        "supported_route_types": [
            "mpls_l3vpn",
            "evpn_ip_prefix",
        ],
        "node_ids": ["node-d", "node-e"],
    },
    {
        "vrf_id": "management",
        "vrf": "management",
        "label": "Out-of-band management",
        "description": "IPv4 management reachability only.",
        "route_families": ["ipv4_unicast"],
        "supported_route_types": ["ipv4_unicast"],
        "node_ids": ["node-a", "node-b", "node-c", "node-d", "node-e"],
    },
)


_ROUTE_TYPE_DEFAULT_CONTEXT = {
    "ipv4_unicast": ("default", "ipv4_unicast"),
    "ipv6_unicast": ("default", "ipv6_unicast"),
    "connected": ("default", "ipv4_unicast"),
    "static_recursive": ("blue", "ipv4_unicast"),
    "isis_underlay": ("default", "ipv4_unicast"),
    "mpls_transport": ("default", "mpls_labeled_unicast"),
    "mpls_l3vpn": ("blue", "vpnv4_unicast"),
    "srv6_policy": ("blue", "ipv6_unicast"),
    "evpn_service": ("blue", "l2vpn_evpn"),
    "evpn_mac_ip": ("blue", "l2vpn_evpn"),
    "evpn_ip_prefix": ("red", "l2vpn_evpn"),
}


_ROUTE_TABLE_CONTEXTS = (
    ("ipv4_unicast", "default", "ipv4_unicast"),
    ("ipv6_unicast", "default", "ipv6_unicast"),
    ("connected", "default", "ipv4_unicast"),
    ("static_recursive", "blue", "ipv4_unicast"),
    ("isis_underlay", "default", "ipv4_unicast"),
    ("mpls_transport", "default", "mpls_labeled_unicast"),
    ("mpls_l3vpn", "blue", "vpnv4_unicast"),
    ("srv6_policy", "blue", "ipv6_unicast"),
    ("evpn_service", "blue", "l2vpn_evpn"),
    ("evpn_mac_ip", "blue", "l2vpn_evpn"),
    ("evpn_ip_prefix", "red", "l2vpn_evpn"),
)


# These plug-in-owned rows fill supported VRF/family/type combinations that do
# not need a full all-pairs fixture.  Keeping them explicit makes the demo
# comprehensive without manufacturing hundreds of identical-looking routes.
_ROUTE_TABLE_REPRESENTATIVE_CONTEXTS = (
    ("node-a", "node-e", "srv6_policy", "default", "ipv6_unicast"),
    ("node-a", "node-b", "ipv4_unicast", "blue", "ipv4_unicast"),
    ("node-a", "node-b", "mpls_transport", "blue", "mpls_labeled_unicast"),
    ("node-a", "node-e", "evpn_ip_prefix", "blue", "l2vpn_evpn"),
    ("node-d", "node-e", "mpls_l3vpn", "red", "vpnv4_unicast"),
    ("node-a", "node-b", "ipv4_unicast", "management", "ipv4_unicast"),
)


_ROUTE_PLUGIN_BY_NODE: dict[str, dict[str, str]] = {
    "node-a": {
        "plugin_id": "demo.alpha.platform",
        "plugin_run_id": "run:node-a/alpha-platform:2.4.0",
        "plugin_set_id": "node-a.alpha-evpn.v1",
        "status_perspective_id": "alpha.hardware-observed",
    },
    "node-b": {
        "plugin_id": "demo.beta.forwarding",
        "plugin_run_id": "run:node-b/beta-forwarding:5.1.2",
        "plugin_set_id": "node-b.beta-evpn.v2",
        "status_perspective_id": "beta.asic-observed",
    },
    "transit-p-1": {
        "plugin_id": "demo.gamma.isis",
        "plugin_run_id": "run:transit-p-1/gamma-isis:3.0.1",
        "plugin_set_id": "transit-p-1.gamma.v1",
        "status_perspective_id": "gamma.isis-observed",
    },
    "transit-p-2": {
        "plugin_id": "demo.delta.sr-isis",
        "plugin_run_id": "run:transit-p-2/delta-sr-isis:4.2.0",
        "plugin_set_id": "transit-p-2.delta-sr.v1",
        "status_perspective_id": "delta.sr-observed",
    },
    "node-c": {
        "plugin_id": "demo.epsilon.forwarding",
        "plugin_run_id": "run:node-c/epsilon-forwarding:7.0.3",
        "plugin_set_id": "node-c.epsilon-edge.v1",
        "status_perspective_id": "epsilon.forwarding-observed",
    },
    "node-d": {
        "plugin_id": "demo.zeta.fabric",
        "plugin_run_id": "run:node-d/zeta-fabric:6.2.1",
        "plugin_set_id": "node-d.zeta-evpn.v1",
        "status_perspective_id": "zeta.hardware-observed",
    },
    "node-e": {
        "plugin_id": "demo.eta.border",
        "plugin_run_id": "run:node-e/eta-border:8.3.2",
        "plugin_set_id": "node-e.eta-evpn.v1",
        "status_perspective_id": "eta.forwarding-observed",
    },
}


_UNDERLAY_PATH_FACTS: dict[str, dict[str, Any]] = {
    "transit-p-1": {
        "plugin_display_name": "Gamma",
        "source_interface": "xe-0/0/0",
        "transport_label": 16002,
        "metric": 20,
    },
    "transit-p-2": {
        "plugin_display_name": "Delta SR",
        "source_interface": "xe-0/0/1",
        "transport_label": 16012,
        "metric": 30,
    },
}


_ROUTE_PROTOCOL_BY_TYPE = {
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


class MultiNodeRouteDemo:
    """Compose plug-in-owned local decisions into bounded cross-node paths."""

    def __init__(self, topology: MultiNodeTopologyDemo) -> None:
        self.topology = topology
        self._route_table_contexts: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _router(node_id: str) -> dict[str, Any]:
        router = next((item for item in _ROUTERS if item["node_id"] == node_id), None)
        if router is None:
            raise MultiNodeRouteRequestError(f"unknown routed node: {node_id}")
        return router

    @staticmethod
    def _router_endpoint_id(node_id: str) -> str:
        return f"endpoint:{node_id}:loopback"

    @staticmethod
    def _endpoint_attachment_id(
        endpoint_id: str,
        node_id: str,
        resource_id: str,
    ) -> str:
        """Return the plug-in-declared identity of one endpoint attachment."""

        material = json.dumps(
            [endpoint_id, node_id, resource_id],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return "attachment1-" + hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()[:24]

    @classmethod
    def _endpoint_attachment(
        cls,
        *,
        endpoint_id: str,
        node_id: str,
        member_id: str,
        resource_id: str,
    ) -> dict[str, Any]:
        return {
            "attachment_id": cls._endpoint_attachment_id(
                endpoint_id,
                node_id,
                resource_id,
            ),
            "endpoint_id": endpoint_id,
            "node_id": node_id,
            "member_id": member_id,
            "resource_id": resource_id,
            "can_originate": True,
            "can_terminate": True,
            "state": "available",
            "semantic_owner": "node_plugin",
        }

    @staticmethod
    def _shortest_nodes(source_node_id: str, destination_node_id: str) -> list[str]:
        if source_node_id == destination_node_id:
            raise MultiNodeRouteRequestError("source and destination must be different routers")
        adjacency: dict[str, list[str]] = {item["node_id"]: [] for item in _ROUTERS}
        for left, right in _BOUNDARIES:
            adjacency[left].append(right)
            adjacency[right].append(left)
        # Stable plug-in-declared tie breaking; the core does not derive metric meaning.
        preference = {
            "node-a": ["transit-p-1", "transit-p-2"],
            "node-b": ["transit-p-2", "transit-p-1"],
            "transit-p-1": [
                "node-a",
                "node-b",
                "node-d",
                "node-e",
                "transit-p-2",
            ],
            "transit-p-2": [
                "node-c",
                "node-b",
                "node-a",
                "node-d",
                "node-e",
                "transit-p-1",
            ],
            "node-c": ["transit-p-2"],
            "node-d": ["transit-p-1", "transit-p-2"],
            "node-e": ["transit-p-2", "transit-p-1"],
        }
        queue: deque[list[str]] = deque([[source_node_id]])
        visited = {source_node_id}
        while queue:
            path = queue.popleft()
            current = path[-1]
            ordered = sorted(
                adjacency[current],
                key=lambda item: (
                    preference.get(current, []).index(item)
                    if item in preference.get(current, [])
                    else 999,
                    item,
                ),
            )
            for neighbor in ordered:
                if neighbor in visited:
                    continue
                candidate = [*path, neighbor]
                if neighbor == destination_node_id:
                    return candidate
                visited.add(neighbor)
                queue.append(candidate)
        raise MultiNodeRouteRequestError(
            f"no plug-in-declared route from {source_node_id} to {destination_node_id}"
        )

    @staticmethod
    def _path_id(node_sequence: list[str], route_type: str) -> str:
        via = "-".join(node_sequence[1:-1]) or "direct"
        return (
            f"route-path:{node_sequence[0]}:{node_sequence[-1]}:"
            f"{route_type}:via-{via}"
        )

    @staticmethod
    def _family(route_family: str) -> dict[str, Any]:
        descriptor = next(
            (
                item
                for item in _ROUTE_FAMILIES
                if item["route_family"] == route_family
            ),
            None,
        )
        if descriptor is None:
            raise MultiNodeRouteRequestError(
                f"unknown route_family: {route_family}"
            )
        return descriptor

    @staticmethod
    def _vrf(vrf_id: str) -> dict[str, Any]:
        aliases = {
            "global": "default",
            "master": "default",
            "tenant-blue": "blue",
            "tenant_blue": "blue",
            "mgmt": "management",
        }
        canonical = aliases.get(vrf_id.casefold(), vrf_id.casefold())
        descriptor = next(
            (item for item in _VRFS if item["vrf_id"] == canonical), None
        )
        if descriptor is None:
            raise MultiNodeRouteRequestError(f"unknown vrf: {vrf_id}")
        return descriptor

    def _route_table_entries(self) -> list[dict[str, Any]]:
        """Return synthetic rows emitted by the installed demo node plug-ins.

        Production core code receives these envelopes from plug-ins; it does not
        derive metrics, protocols, preference, VRF membership, or next hops.
        """

        entries: list[dict[str, Any]] = []
        for source in _ROUTERS:
            for destination in _ROUTERS:
                if source["node_id"] == destination["node_id"]:
                    continue
                sequence = self._shortest_nodes(
                    source["node_id"], destination["node_id"]
                )
                for route_type, vrf_id, route_family in _ROUTE_TABLE_CONTEXTS:
                    vrf_node_ids = set(self._vrf(vrf_id)["node_ids"])
                    if route_type == "connected":
                        # Connected routes are local interface/subnet state, not
                        # an all-pairs route to every remote loopback.
                        continue
                    if (
                        source["node_id"] not in vrf_node_ids
                        or destination["node_id"] not in vrf_node_ids
                    ):
                        continue
                    entries.append(
                        self._route_table_entry(
                            source,
                            destination,
                            sequence,
                            route_type,
                            vrf_id,
                            route_family,
                            installed=not (
                                source["role"] == "core_transit"
                                and route_type == "evpn_service"
                            ),
                        )
                    )

        # One real local connected route is enough to demonstrate the schema.
        # It terminates on PE-E's external attachment and deliberately has no
        # remote neighbor or multi-hop node sequence.
        entries.append(
            self._route_table_entry(
                self._router("node-e"),
                self._router("node-e"),
                ["node-e"],
                "connected",
                "default",
                "ipv4_unicast",
                suffix="external-subnet",
            )
        )

        for (
            source_node_id,
            destination_node_id,
            route_type,
            vrf_id,
            route_family,
        ) in _ROUTE_TABLE_REPRESENTATIVE_CONTEXTS:
            source = self._router(source_node_id)
            destination = self._router(destination_node_id)
            entries.append(
                self._route_table_entry(
                    source,
                    destination,
                    self._shortest_nodes(source_node_id, destination_node_id),
                    route_type,
                    vrf_id,
                    route_family,
                    suffix="representative",
                )
            )

        # The reverse asymmetric service deliberately uses a non-shortest MPLS
        # candidate. The installed scenario row and its inactive standby variant
        # let traces correlate by opaque references rather than parsing path IDs.
        entries.append(
            self._route_table_entry(
                self._router("node-c"),
                self._router("node-a"),
                ["node-c", "transit-p-2", "transit-p-1", "node-a"],
                "mpls_transport",
                "default",
                "mpls_labeled_unicast",
                suffix="asymmetric-scenario-active",
            )
        )
        entries.append(
            self._route_table_entry(
                self._router("node-c"),
                self._router("node-a"),
                ["node-c", "transit-p-2", "transit-p-1", "node-a"],
                "mpls_transport",
                "default",
                "mpls_labeled_unicast",
                active=False,
                backup=True,
                suffix="asymmetric-backup",
            )
        )
        return entries

    def _route_table_entry(
        self,
        source: dict[str, Any],
        destination: dict[str, Any],
        node_sequence: list[str],
        route_type: str,
        vrf_id: str,
        route_family: str,
        *,
        active: bool = True,
        backup: bool = False,
        installed: bool | None = None,
        suffix: str | None = None,
    ) -> dict[str, Any]:
        """Build one opaque demo plug-in row, not a core routing decision."""

        family = self._family(route_family)
        plugin = dict(_ROUTE_PLUGIN_BY_NODE[source["node_id"]])
        control_plane_only = source["role"] == "core_transit" and route_type in {
            "evpn_service",
            "evpn_mac_ip",
            "evpn_ip_prefix",
        }
        if control_plane_only:
            plugin.update(
                {
                    "plugin_id": "demo.fabric.evpn-route-reflector",
                    "plugin_run_id": (
                        f"run:{source['node_id']}/evpn-route-reflector:1.3.0"
                    ),
                    "status_perspective_id": "evpn.control-observed",
                }
            )
        installed = active if installed is None else installed
        local_connected = route_type == "connected" and len(node_sequence) == 1
        if local_connected:
            egress_resource_id = source.get("external_interface_resource_id")
            if not egress_resource_id:
                raise MultiNodeRouteRequestError(
                    "the demo connected route requires a plug-in-declared "
                    "external interface"
                )
            next_node = None
            path_id = (
                "route-path:node-e:external-subnet:connected:candidate-on-link"
            )
            catalog_id = f"route:connected:{source['node_id']}:external-subnet"
            destination_identity = "external-subnet"
        else:
            next_node = node_sequence[1]
            boundary = self._boundary_descriptor(source["node_id"], next_node)
            egress_resource_id = boundary["resources"][source["node_id"]]
            path_id = self._path_id(node_sequence, route_type)
            catalog_id = f"route:mesh:{source['node_id']}:{destination['node_id']}"
            destination_identity = destination["node_id"]
        discriminator = suffix or "selected"
        route_entry_id = (
            f"route-entry:{source['node_id']}:{vrf_id}:{route_family}:"
            f"{route_type}:{destination_identity}:{discriminator}"
        )
        table_id = f"route-table:{source['node_id']}:{vrf_id}:{route_family}"
        route_entry_ref = {
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "node_id": source["node_id"],
            "member_id": f"member:{source['node_id']}",
            "plugin_id": plugin["plugin_id"],
            "table_id": table_id,
            "route_entry_id": route_entry_id,
        }
        protocol = _ROUTE_PROTOCOL_BY_TYPE[route_type]
        if route_type in {"ipv4_unicast", "ipv6_unicast"} and source[
            "node_id"
        ] == "node-e":
            protocol = "ebgp"
        metric = 0 if local_connected else max(1, (len(node_sequence) - 1) * 10)
        preference = {
            "ibgp": 170,
            "ebgp": 20,
            "connected": 0,
            "static": 5,
            "isis-l2": 18,
            "segment-routing-mpls": 12,
            "bgp-vpnv4": 170,
            "bgp-sr-policy": 100,
            "bgp-evpn": 170,
        }[protocol]
        egress_name = egress_resource_id.rsplit("/", 1)[-1]
        next_hop_value = (
            "on-link"
            if local_connected
            else self._router(str(next_node))["prefix"].split("/", 1)[0]
        )
        if family["address_family"] == "ipv6" and next_node is not None:
            next_hop_value = (
                f"2001:db8:ffff::{list(item['node_id'] for item in _ROUTERS).index(self._router(next_node)['node_id']) + 1}"
            )
        next_hop = {
            "next_hop_id": (
                f"next-hop:{source['node_id']}:{destination_identity}:"
                f"{route_type}:{next_node or 'on-link'}"
            ),
            "kind": (
                "on_link"
                if route_type == "connected"
                else "recursive_ip"
                if route_type == "static_recursive"
                else "neighbor_router"
            ),
            "value": next_hop_value,
            "neighbor_node_id": next_node,
            "egress_interface_resource_id": egress_resource_id,
            "active": active,
            "backup": backup,
            "weight": 1,
        }
        destination_value = (
            "203.0.113.0/24" if local_connected else destination["prefix"]
        )
        attributes: dict[str, Any] = {
            "node_sequence": list(node_sequence),
            "origin_node_id": destination["node_id"],
        }
        if route_type == "connected":
            attributes.update(
                {
                    "resolution_phases": ["local_lookup", "adjacency_egress"],
                    "connected_interface_resource_id": egress_resource_id,
                    "connected_subnet": destination_value,
                    "external": True,
                    "has_remote_router": False,
                }
            )
        elif route_type == "static_recursive":
            attributes.update(
                {
                    "resolution_phases": [
                        "local_lookup",
                        "recursive_lookup",
                        "next_hop",
                        "tunnel_action",
                    ],
                    "recursive_next_hop": next_hop_value,
                    "resolution_chain": ["static", "ibgp", "isis-l2"],
                }
            )
        elif route_type in {"mpls_transport", "mpls_l3vpn"}:
            attributes["outgoing_label_stack"] = [
                16000 + list(item["node_id"] for item in _ROUTERS).index(
                    destination["node_id"]
                )
            ]
            attributes["resolution_phases"] = [
                "local_lookup",
                "candidate_selection",
                "tunnel_action",
                "adjacency_egress",
            ]
            if route_type == "mpls_l3vpn":
                attributes.update(
                    {
                        "route_distinguisher": f"65000:{200 + list(_ROUTERS).index(destination)}",
                        "route_targets": [f"target:65000:{200 if vrf_id == 'blue' else 300}"],
                        "vpn_label": 24000 + list(_ROUTERS).index(destination),
                    }
                )
                attributes["outgoing_label_stack"].append(
                    attributes["vpn_label"]
                )
        elif route_type in {"srv6_policy", "ipv6_unicast"}:
            if route_type == "srv6_policy":
                attributes["segment_list"] = [
                    f"2001:db8:{index + 1:x}::{index + 10}"
                    for index, _node_id in enumerate(node_sequence[1:])
                ]
            attributes["resolution_phases"] = [
                "local_lookup",
                "candidate_selection",
                "tunnel_action",
                "adjacency_egress",
            ]
            destination_value = (
                f"2001:db8:{list(item['node_id'] for item in _ROUTERS).index(destination['node_id']) + 1:x}::/128"
            )
        elif route_type in {"evpn_service", "evpn_mac_ip", "evpn_ip_prefix"}:
            attributes.update(
                {
                    "route_distinguisher": f"65000:{100 + list(_ROUTERS).index(destination)}",
                    "route_targets": ["target:65000:100"],
                    "vni": 10100,
                    "esi": (
                        "00:11:22:33:44:55:66:77:88:99"
                        if destination["role"] == "provider_edge"
                        else None
                    ),
                    "resolution_phases": [
                        "local_lookup",
                        "candidate_selection",
                        "recursive_lookup",
                        "tunnel_action",
                    ],
                }
            )
            if route_type == "evpn_mac_ip":
                attributes.update(
                    {
                        "evpn_route_type": 2,
                        "mac_address": (
                            f"02:00:00:00:00:{list(_ROUTERS).index(destination) + 1:02x}"
                        ),
                        "ip_address": destination["prefix"].split("/", 1)[0],
                        "ethernet_tag_id": 320,
                    }
                )
                destination_value = (
                    f"{attributes['mac_address']} / {attributes['ip_address']}"
                )
            elif route_type == "evpn_ip_prefix":
                attributes.update(
                    {
                        "evpn_route_type": 5,
                        "ip_prefix": f"198.18.{list(_ROUTERS).index(destination)}.0/24",
                        "gateway_ip": next_hop_value,
                    }
                )
                destination_value = attributes["ip_prefix"]
        elif route_type == "isis_underlay":
            attributes.update(
                {
                    "isis_level": 2,
                    "resolution_phases": [
                        "local_lookup",
                        "next_hop",
                        "adjacency_egress",
                    ],
                }
            )
        else:
            attributes["resolution_phases"] = [
                "local_lookup",
                "next_hop",
                "adjacency_egress",
            ]
        status = (
            "control_plane_only"
            if control_plane_only
            else "backup"
            if backup
            else "active"
            if active
            else "inactive"
        )
        attributes["installation_scope"] = (
            "control_plane_only" if control_plane_only else "routing_and_forwarding"
        )
        if control_plane_only:
            attributes["route_reflector_client_route"] = True
        forwarding_actions: list[dict[str, Any]] = []
        label_stack = attributes.get("outgoing_label_stack")
        if isinstance(label_stack, list) and label_stack:
            value_roles = ["transport"]
            if route_type == "mpls_l3vpn":
                value_roles.append("vpn")
            forwarding_actions.append(
                {
                    "action_id": f"{route_entry_id}:mpls-label-stack",
                    "kind": "mpls_label_stack",
                    "label": "MPLS label stack",
                    "operation": "push",
                    "order": "outer_to_inner",
                    "applies_to_next_hop_id": next_hop["next_hop_id"],
                    "values": [
                        {
                            "value": value,
                            "display": str(value),
                            "kind": (
                                "sr_mpls_sid"
                                if index == 0
                                else "mpls_label"
                            ),
                            "value_type": "integer",
                            "role": (
                                value_roles[index]
                                if index < len(value_roles)
                                else f"label_{index + 1}"
                            ),
                            "position": index,
                        }
                        for index, value in enumerate(label_stack)
                    ],
                }
            )
        segment_list = attributes.get("segment_list")
        if isinstance(segment_list, list) and segment_list:
            forwarding_actions.append(
                {
                    "action_id": f"{route_entry_id}:srv6-segment-list",
                    "kind": "srv6_sid_list",
                    "label": "SRv6 SID list",
                    "operation": "encapsulate",
                    "order": "first_segment_to_last",
                    "applies_to_next_hop_id": next_hop["next_hop_id"],
                    "values": [
                        {
                            "value": value,
                            "display": str(value),
                            "kind": "srv6_sid",
                            "value_type": "ipv6_address",
                            "role": f"segment_{index + 1}",
                            "position": index,
                        }
                        for index, value in enumerate(segment_list)
                    ],
                }
            )
        trace_query = {
            "scenario_id": (
                "connected-external-subnet"
                if local_connected
                else "router-to-router"
            ),
            "direction": "both",
            "source_id": source["source_id"],
            "destination_id": (
                "destination:eta-external-subnet"
                if local_connected
                else destination["destination_id"]
            ),
            "vrf": vrf_id,
            "vrf_id": vrf_id,
            "route_family": route_family,
            "address_family": family["address_family"],
            "route_type": route_type,
            "route_entry_ref": route_entry_ref,
        }
        return {
            "route_entry_id": route_entry_id,
            "row_id": route_entry_id,
            "route_entry_ref": route_entry_ref,
            "node_id": source["node_id"],
            "member_id": f"member:{source['node_id']}",
            "node_label": source["label"],
            "table_id": table_id,
            "vrf_id": vrf_id,
            "vrf": vrf_id,
            "address_family": family["address_family"],
            "safi": family["safi"],
            "route_family": route_family,
            "route_type": route_type,
            "prefix": destination_value,
            "destination": {
                "destination_id": (
                    "destination:eta-external-subnet"
                    if local_connected
                    else destination["destination_id"]
                ),
                "node_id": destination["node_id"],
                "kind": "ip_prefix" if local_connected else "router_loopback",
                "value": destination_value,
                "label": (
                    "PE-E external subnet"
                    if local_connected
                    else destination["label"]
                ),
            },
            "source": protocol,
            "source_protocol": protocol,
            "protocol": protocol,
            "owner": "node_route_plugin",
            "next_hops": [next_hop],
            # Plug-ins own the forwarding meaning, order, and display label.
            # The core treats these as bounded declarative values and never
            # derives label/SID semantics from the route type or attributes.
            "forwarding_actions": forwarding_actions,
            "egress_interface": {
                "resource_id": egress_resource_id,
                "name": egress_name,
                "node_id": source["node_id"],
            },
            "metric": metric,
            "preference": preference,
            "selected": active and not backup,
            "installed": installed,
            "active": active,
            "backup": backup,
            "status": status,
            "install_state": (
                "control_plane_only"
                if control_plane_only
                else "installed"
                if installed
                else "eligible_not_installed"
            ),
            "path_id": path_id,
            "candidate_path_ids": [path_id],
            "route_catalog_id": catalog_id,
            "correlation_ids": [catalog_id, path_id, route_entry_id],
            "resource_refs": [
                {
                    "member_id": f"member:{source['node_id']}",
                    "node_id": source["node_id"],
                    "local_resource_id": egress_resource_id,
                }
            ],
            "trace_query": trace_query,
            "status_perspective_id": plugin["status_perspective_id"],
            "plugin_provenance": {
                **plugin,
                "decision_owner": "node_route_plugin",
                "data_kind": "route_table_row",
            },
            "attributes": attributes,
            "plugin_details": attributes,
            "valid_from_ns": str(self.topology.start_ns),
            "valid_to_ns": None,
        }

    def _route_catalog(self) -> list[dict[str, Any]]:
        return [
            {
                "route_id": f"route:mesh:{source['node_id']}:{destination['node_id']}",
                "route_type": "ipv4_unicast",
                "supported_route_types": [
                    item["route_type"] for item in _ROUTE_TYPES
                ],
                "source_id": source["source_id"],
                "destination_id": destination["destination_id"],
                "source_node_id": source["node_id"],
                "destination_node_id": destination["node_id"],
                "node_sequence": self._shortest_nodes(
                    source["node_id"], destination["node_id"]
                ),
                "directional": True,
                "decision_owner": "node_route_plugins",
            }
            for source in _ROUTERS
            for destination in _ROUTERS
            if source["node_id"] != destination["node_id"]
        ]

    def capabilities(self) -> dict[str, Any]:
        topology_capabilities = self.topology.capabilities()
        return {
            "api_version": "v1",
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "label": "Heterogeneous cross-node route trace",
            "description": (
                "Retains active and inactive candidates, cross-layer disagreements, "
                "exact-state cycles, policy exclusions, and explicitly sourced "
                "best-effort continuations."
            ),
            "default_request": {
                "scenario_id": "single-active-primary",
                "direction": "forward",
                "route_type": "mpls_transport",
                "route_family": "mpls_labeled_unicast",
                "address_family": "mpls",
                "vrf": "default",
                "vrf_id": "default",
                "resolution_mode": "best_effort",
                "steering_profile_id": "observed",
                "max_hops": 64,
                "max_recursion": 16,
                "source_id": "source:pe-a-loopback",
                "destination_id": "destination:blue-service-prefix",
                "clock_policy": "best_effort",
                "basis": {"kind": "relative_to_watermark", "offset_ns": "0"},
                "source": {
                    "endpoint_id": self._router_endpoint_id("node-a"),
                    "node_id": "node-a",
                    "resource_id": "node-a/LOOPBACK/lo0",
                },
                "destination": {
                    "endpoint_id": "endpoint:blue-service-prefix",
                    "destination_id": "destination:blue-service-prefix",
                    "kind": "ip_prefix",
                    "value": "203.0.113.0/24",
                    "node_id": "node-b",
                },
                "flow": {
                    "source": {
                        "endpoint_id": self._router_endpoint_id("node-a"),
                        "node_id": "node-a",
                        "resource_id": "node-a/LOOPBACK/lo0",
                    },
                    "destination": {
                        "endpoint_id": "endpoint:blue-service-prefix",
                        "destination_id": "destination:blue-service-prefix",
                        "kind": "ip_prefix",
                        "value": "203.0.113.0/24",
                        "node_id": "node-b",
                    },
                },
                "ingress": {
                    "start_id": "start:node-a",
                    "node_id": "node-a",
                    "member_id": "member:node-a",
                },
            },
            "sources": [
                {
                    "endpoint_id": self._router_endpoint_id(item["node_id"]),
                    "source_id": item["source_id"],
                    "label": item["label"],
                    "node_id": item["node_id"],
                    "member_id": f"member:{item['node_id']}",
                    "resource_id": item["loopback_resource_id"],
                    "site": item["site"],
                    "role": item["role"],
                    "route_participant": True,
                }
                for item in _ROUTERS
            ],
            "start_points": [
                {
                    "start_id": f"start:{item['node_id']}",
                    "label": f"{item['label']} - trace observation",
                    "node_id": item["node_id"],
                    "member_id": f"member:{item['node_id']}",
                    "resource_id": item["loopback_resource_id"],
                    "site": item["site"],
                    "role": item["role"],
                    "semantic_role": "traversal_seed",
                }
                for item in _ROUTERS
            ],
            "destinations": [
                {
                    "endpoint_id": "endpoint:blue-service-prefix",
                    "destination_id": "destination:blue-service-prefix",
                    "label": "Blue service · 203.0.113.0/24",
                    "kind": "ip_prefix",
                    "value": "203.0.113.0/24",
                    "node_id": "node-b",
                    "member_id": "member:node-b",
                    "terminating_resource_id": "node-b/LOOPBACK/1",
                    "supported_scenario_ids": [item["scenario_id"] for item in _SCENARIOS],
                    "route_participant": False,
                },
                {
                    "endpoint_id": "endpoint:east-evpn-multihomed-service",
                    "destination_id": "destination:east-evpn-multihomed-service",
                    "label": "East EVPN multihomed service - ESI east / VLAN 320",
                    "kind": "evpn_ethernet_segment",
                    "value": "esi-east:vlan-320",
                    "node_id": "node-e",
                    "terminating_node_ids": ["node-b", "node-e"],
                    "member_id": "member:node-e",
                    "terminating_resource_id": "node-e/ETHERNET_SEGMENT/esi-east",
                    "supported_scenario_ids": [
                        "evpn-mh-all-active",
                        "evpn-es-withdraw-failover",
                        "evpn-stale-fib-after-withdraw",
                        "evpn-split-horizon-block",
                    ],
                    "route_participant": False,
                },
                {
                    "endpoint_id": "endpoint:eta-external-subnet",
                    "destination_id": "destination:eta-external-subnet",
                    "label": "PE-E external subnet - 203.0.113.0/24",
                    "kind": "ip_prefix",
                    "value": "203.0.113.0/24",
                    "node_id": "node-e",
                    "member_id": "member:node-e",
                    "terminating_resource_id": "node-e/INTERFACE/et-0-0-20",
                    "supported_scenario_ids": [
                        "recursive-static-to-external",
                        "connected-external-subnet",
                    ],
                    "route_participant": False,
                },
                *[
                    {
                        "endpoint_id": self._router_endpoint_id(item["node_id"]),
                        "destination_id": item["destination_id"],
                        "label": f"{item['label']} - {item['prefix']}",
                        "kind": "router_loopback",
                        "value": item["prefix"],
                        "node_id": item["node_id"],
                        "member_id": f"member:{item['node_id']}",
                        "terminating_resource_id": item["loopback_resource_id"],
                        "site": item["site"],
                        "role": item["role"],
                        "route_participant": True,
                        "supported_scenario_ids": [
                            "router-to-router",
                            *(
                                sorted(ADVANCED_TRACE_SCENARIO_IDS)
                                if item["node_id"] == "node-b"
                                else []
                            ),
                        ],
                    }
                    for item in _ROUTERS
                ],
            ],
            "route_types": [dict(item) for item in _ROUTE_TYPES],
            "route_families": [dict(item) for item in _ROUTE_FAMILIES],
            "vrfs": [
                {
                    **item,
                    "node_ids": list(item["node_ids"]),
                }
                for item in _VRFS
            ],
            "route_tables": {
                "schema_version": "demo.route-table.v1",
                "state_location": "time_bound_query_only",
                "available_node_ids": [item["node_id"] for item in _ROUTERS],
                "entry_count_at_demo_snapshot": len(self._route_table_entries()),
                "columns": [
                    "node_id",
                    "vrf_id",
                    "address_family",
                    "route_family",
                    "prefix",
                    "route_type",
                    "source_protocol",
                    "next_hops",
                    "forwarding_actions",
                    "egress_interface",
                    "metric",
                    "preference",
                    "active",
                    "backup",
                    "install_state",
                    "plugin_provenance",
                ],
                "query_href": (
                    f"/v1/topology-assemblies/{MULTI_NODE_TOPOLOGY_ID}/"
                    "routes/tables/query"
                ),
                "alias_query_href": "/v1/topologies/routes/tables/query",
                "max_page_size": 500,
            },
            "network_model": {
                "router_count": len(_ROUTERS),
                "physical_link_count": len(_BOUNDARIES),
                "full_mesh_physical_link_count": len(_ROUTERS) * (len(_ROUTERS) - 1) // 2,
                "physical_topology": "connected_non_full_mesh",
                "is_full_physical_mesh": False,
                "reachable_directed_pair_count": len(_ROUTERS) * (len(_ROUTERS) - 1),
                "expected_directed_pair_count": len(_ROUTERS) * (len(_ROUTERS) - 1),
                "all_router_pairs_reachable": True,
                "physical_links": [
                    {
                        "endpoint_a_node_id": left,
                        "endpoint_b_node_id": right,
                        "topology_link_id": descriptor["link_id"],
                    }
                    for (left, right), descriptor in _BOUNDARIES.items()
                ],
            },
            "route_catalog": self._route_catalog(),
            "directional_pairs": [
                {
                    "pair_id": "pair:pe-a-pe-c-asymmetric",
                    "label": "PE-A / PE-C asymmetric service",
                    "scenario_id": "site-a-site-c-asymmetric",
                    "forward": {
                        "source_id": "source:pe-a-loopback",
                        "destination_id": "destination:node-c-loopback",
                        "route_type": "srv6_policy",
                    },
                    "reverse": {
                        "source_id": "source:node-c-loopback",
                        "destination_id": "destination:node-a-loopback",
                        "route_type": "mpls_transport",
                    },
                    "expected_comparison": "asymmetric_reachable",
                },
                {
                    "pair_id": "pair:pe-b-pe-c-one-way",
                    "label": "PE-B / PE-C one-way forwarding fault",
                    "scenario_id": "site-b-site-c-one-way",
                    "forward": {
                        "source_id": "source:node-b-loopback",
                        "destination_id": "destination:node-c-loopback",
                        "route_type": "evpn_service",
                    },
                    "reverse": {
                        "source_id": "source:node-c-loopback",
                        "destination_id": "destination:node-b-loopback",
                        "route_type": "evpn_service",
                    },
                    "expected_comparison": "one_way_reachable",
                },
            ],
            "resolution_modes": [
                {
                    "mode": "strict",
                    "semantics": "Do not cross a missing node-local or boundary decision.",
                },
                {
                    "mode": "best_effort",
                    "semantics": (
                        "Core may join plug-in output through the reconstructed topology "
                        "and contemporaneous node status, with explicit provenance and "
                        "reduced confidence."
                    ),
                },
            ],
            "scenarios": [dict(item) for item in _SCENARIOS],
            "packet_trace": {
                "schema_version": "demo.forwarding-packet-trace.v1",
                "layer_order": "outermost_to_innermost",
                "maximum_layers": 256,
                "maximum_transitions": 256,
                "continuity_owner": "core",
                "packet_action_owner": "node_plugins",
                "mtu_semantics_owner": "node_plugins",
                "mtu_comparison_owner": "core_exact_basis_only",
                "federation_boundary_behavior": (
                    "preserve_or_explicitly_map_packet_contract"
                ),
                "user_forced_results_are_counterfactual": True,
                "steering_profiles": [dict(item) for item in STEERING_PROFILES],
            },
            "steering_profiles": [dict(item) for item in STEERING_PROFILES],
            "route_resolvers": [
                {
                    "node_id": "node-a",
                    "member_id": "member:node-a",
                    "plugin_set_id": "node-a.alpha-evpn.v1",
                    "plugin_id": "demo.alpha.platform",
                    "plugin_run_id": "run:node-a/alpha-platform:2.4.0",
                    "roles": ["local_resolution", "candidate_selection"],
                },
                {
                    "node_id": "node-b",
                    "member_id": "member:node-b",
                    "plugin_set_id": "node-b.beta-evpn.v2",
                    "plugin_id": "demo.beta.forwarding",
                    "plugin_run_id": "run:node-b/beta-forwarding:5.1.2",
                    "roles": [
                        "local_resolution",
                        "forwarding_observation",
                        "ingress_dependent_policy",
                    ],
                },
                {
                    "node_id": "transit-p-1",
                    "member_id": "member:transit-p-1",
                    "plugin_set_id": "transit-p-1.gamma.v1",
                    "plugin_id": "demo.gamma.isis",
                    "plugin_run_id": "run:transit-p-1/gamma-isis:3.0.1",
                    "roles": ["local_resolution", "route_metric"],
                },
                {
                    "node_id": "transit-p-2",
                    "member_id": "member:transit-p-2",
                    "plugin_set_id": "transit-p-2.delta-sr.v1",
                    "plugin_id": "demo.delta.sr-isis",
                    "plugin_run_id": "run:transit-p-2/delta-sr-isis:4.2.0",
                    "roles": ["local_resolution", "segment_routing_policy"],
                },
                {
                    "node_id": "node-c",
                    "member_id": "member:node-c",
                    "plugin_set_id": "node-c.epsilon-edge.v1",
                    "plugin_id": "demo.epsilon.forwarding",
                    "plugin_run_id": "run:node-c/epsilon-forwarding:7.0.3",
                    "roles": ["local_resolution", "directional_policy"],
                },
                {
                    "node_id": "node-d",
                    "member_id": "member:node-d",
                    "plugin_set_id": "node-d.zeta-evpn.v1",
                    "plugin_id": "demo.zeta.fabric",
                    "plugin_run_id": "run:node-d/zeta-fabric:6.2.1",
                    "roles": [
                        "local_resolution",
                        "evpn_multihoming",
                        "candidate_selection",
                        "ingress_dependent_policy",
                    ],
                },
                {
                    "node_id": "node-e",
                    "member_id": "member:node-e",
                    "plugin_set_id": "node-e.eta-evpn.v1",
                    "plugin_id": "demo.eta.border",
                    "plugin_run_id": "run:node-e/eta-border:8.3.2",
                    "roles": [
                        "local_resolution",
                        "evpn_multihoming",
                        "external_prefix_resolution",
                        "ingress_dependent_policy",
                    ],
                },
                {
                    "node_id": "node-a,node-b",
                    "member_id": "member:node-a,member:node-b",
                    "plugin_set_id": "node-specific",
                    "plugin_id": "demo.evpn.control",
                    "plugin_run_id": "node-specific",
                    "roles": ["control_plane_resolution"],
                },
                {
                    "node_id": "transit-p-1,transit-p-2",
                    "member_id": "member:transit-p-1,member:transit-p-2",
                    "plugin_set_id": "node-specific",
                    "plugin_id": "demo.fabric.evpn-route-reflector",
                    "plugin_run_id": "node-specific",
                    "roles": [
                        "control_plane_resolution",
                        "route_reflector",
                        "no_tenant_fib_installation",
                    ],
                },
            ],
            "federation_resolver": topology_capabilities["federation_plugin"],
            "request_contract": {
                "scenario_id": "one advertised scenario_id",
                "flow": (
                    "immutable traffic source and destination endpoints; "
                    "top-level source/destination remain compatibility aliases"
                ),
                "ingress": (
                    "forward traversal/observation start, independent from the "
                    "traffic source"
                ),
                "trace_starts": (
                    "optional per-direction start points; reverse otherwise "
                    "starts from a destination endpoint attachment"
                ),
                "resolution_mode": "strict or best_effort",
                "resolution_policy": "compatibility alias for resolution_mode",
                "completeness_policy": "documentation compatibility alias for resolution_mode",
                "destination_id": "one advertised destinations[].destination_id",
                "source_id": "one advertised sources[].source_id",
                "direction": "forward, reverse, or both",
                "route_type": "one advertised route_types[].route_type",
                "route_family": (
                    "one advertised route_families[].route_family; address_family "
                    "is a compatibility selector"
                ),
                "vrf_id": (
                    "one advertised vrfs[].vrf_id; vrf is a compatibility alias"
                ),
                "routing_context": (
                    "structured form of vrf_id, route_family/address_family, "
                    "route_type, table_id, and opaque constraints"
                ),
                "route_entry_ref": (
                    "optional opaque reference returned by the route-table query"
                ),
                "focus_path_id": (
                    "optional stable path_id; inactive and inconsistent candidates are valid"
                ),
                "max_hops": (
                    "bounded maximum inter-node transitions, integer 1 through 128"
                ),
                "max_recursion": (
                    "bounded maximum recursive lookup depth, integer 0 through 64"
                ),
                "basis": topology_capabilities["time_bases"],
                "clock_policy": topology_capabilities["clock_policies"],
                "node_queries": (
                    "optional heterogeneous per-node selections accepted by topology query"
                ),
                "bidirectional_criterion": (
                    "forward reaches the traffic destination and reverse reaches "
                    "the traffic source; reverse need not revisit forward ingress"
                ),
            },
            "response_contract": {
                "paths": "all candidate paths, never only the selected or active path",
                "route_resolution_sequence": (
                    "ordered plug-in-provided text objects for the focused path"
                ),
                "interaction_targets": (
                    "stable bidirectional targets shared by text parts and topology objects"
                ),
                "highlight_target_ids": (
                    "exact typed topology-node or topology-link targets selected by plug-ins; "
                    "the core preserves the IDs without interpreting route text"
                ),
                "path_graph_target_ids": (
                    "ordered exact graph targets aggregated from each path's structured segments"
                ),
                "path_outcome": (
                    "normalized role, result, eligibility, and terminal_reason on "
                    "every candidate, including cycle and policy_blocked"
                ),
                "cycle": (
                    "typed repeated canonical traversal state with first and closing steps"
                ),
                "policy_decisions": (
                    "core-evaluated verdicts retaining plug-in constraints, scope "
                    "completeness, reasons, and evidence on each candidate"
                ),
                "node_occurrences": (
                    "ordered path-local router occurrences; repeated nodes are not deduplicated"
                ),
                "issues": "cross-layer, boundary, incompleteness, and inference findings",
                "endpoint_reachability": (
                    "typed terminal endpoint matching for each direction"
                ),
                "path_relation": (
                    "symmetric, asymmetric, or not_comparable descriptive path "
                    "shape; it does not determine consistency"
                ),
            },
            "semantic_ownership": {
                "core": [
                    "time alignment",
                    "ordering and joining plug-in-provided resolution steps",
                    "candidate retention and focus selection",
                    "bounded traversal and canonical-state cycle detection",
                    "exact typed policy comparison, decision validation, and "
                    "aggregate verdict handling",
                    "uncertainty, completeness, and best-effort evidence accounting",
                    "immutable flow direction, endpoint-goal matching, and "
                    "bidirectional reachability aggregation",
                ],
                "node_plugins": [
                    "local route resolution and candidate activity",
                    "route_resolution text and resource references",
                    "layer-specific reachability and forwarding semantics",
                    "route-table keys, VRF/family semantics, preference, and next hops",
                    "policy constraints, scope construction/completeness, reasons, "
                    "and evidence",
                    "endpoint attachment and local terminal/delivery classification",
                ],
                "federation_linker": [
                    "inter-node endpoint identity and boundary candidates"
                ],
            },
            "limits": {
                "max_candidate_paths": 64,
                "max_segments_per_path": 128,
                "default_max_hops": 64,
                "maximum_max_hops": 128,
                "default_max_recursion": 16,
                "maximum_max_recursion": 64,
            },
            "topology_capabilities_href": (
                f"/v1/topology-assemblies/{MULTI_NODE_TOPOLOGY_ID}/capabilities"
            ),
            "trace_href": (
                f"/v1/topology-assemblies/{MULTI_NODE_TOPOLOGY_ID}/routes/trace"
            ),
            "route_table_query_href": (
                f"/v1/topology-assemblies/{MULTI_NODE_TOPOLOGY_ID}/"
                "routes/tables/query"
            ),
            "demo_disclosure": (
                "Route decisions are synthetic plug-in fixtures. The core contract is "
                "designed for independently supplied device resolvers."
            ),
        }

    def route_tables(self, body: dict[str, Any]) -> dict[str, Any]:
        """Federate opaque plug-in route rows at one topology time context."""

        if not isinstance(body, dict):
            raise MultiNodeRouteRequestError("request body must be an object")
        context_aliases = {
            str(body[field])
            for field in ("topology_context_id", "context_id")
            if body.get(field) is not None
        }
        if len(context_aliases) > 1:
            raise MultiNodeRouteRequestError(
                "context_id and topology_context_id disagree"
            )
        requested_context_id = next(iter(context_aliases), None)
        if requested_context_id is not None:
            snapshot = self.topology._contexts.get(requested_context_id)
            if snapshot is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired topology context"
                )
            effective_basis = snapshot["resolved_basis"]["requested"]
            effective_clock_policy = snapshot["resolved_basis"]["clock_policy"]
            if (
                body.get("basis") is not None
                and self.topology.normalize_basis(body["basis"])
                != self.topology.normalize_basis(effective_basis)
            ):
                raise MultiNodeRouteRequestError(
                    "basis disagrees with the selected topology context"
                )
            if (
                body.get("clock_policy") is not None
                and str(body["clock_policy"]) != effective_clock_policy
            ):
                raise MultiNodeRouteRequestError(
                    "clock_policy disagrees with the selected topology context"
                )
            self._validate_context_node_selection(body, snapshot)
        else:
            requested_basis = (
                self.topology.normalize_basis(body["basis"])
                if body.get("basis") is not None
                else {"kind": "relative_to_watermark", "offset_ns": "0"}
            )
            topology_request: dict[str, Any] = {
                "basis": requested_basis,
                "clock_policy": body.get("clock_policy", "best_effort"),
                "resource_limit": 500,
                "inter_node_link_limit": 1000,
            }
            selected_nodes = body.get("node_ids")
            if selected_nodes is None and "node_queries" not in body:
                selected_nodes = [item["node_id"] for item in _ROUTERS]
            if selected_nodes is not None:
                topology_request["node_ids"] = selected_nodes
            if "node_queries" in body:
                topology_request["node_queries"] = body["node_queries"]
            snapshot = self.topology.query(topology_request)
            effective_basis = snapshot["resolved_basis"]["requested"]
            effective_clock_policy = snapshot["resolved_basis"]["clock_policy"]

        filters = self._optional_object(body, "filters")
        page_request = self._optional_object(body, "page")
        limit = self._bounded_page_integer(
            page_request.get("limit", body.get("limit", 250)),
            "page.limit",
            minimum=1,
            maximum=500,
        )
        cursor = page_request.get("cursor")
        if cursor is None:
            offset = self._bounded_page_integer(
                page_request.get("offset", body.get("offset", 0)),
                "page.offset",
                minimum=0,
                maximum=100_000,
            )
        else:
            # Decoded only after the query-bound route-table context digest is
            # known.  A cursor can never be reused against another filter set.
            offset = 0

        selected_node_ids = {
            str(item["node_id"])
            for item in snapshot["nodes"]
            if item.get("available", True)
        }
        node_filter = self._filter_values(
            filters,
            plural=("node_ids",),
            singular=("node_id",),
        )
        if node_filter:
            unknown = node_filter - {item["node_id"] for item in _ROUTERS}
            if unknown:
                raise MultiNodeRouteRequestError(
                    f"unknown route-table node_ids: {sorted(unknown)}"
                )
            selected_node_ids &= node_filter
        vrf_filter = self._filter_values(
            filters,
            plural=("vrf_ids", "vrfs"),
            singular=("vrf_id", "vrf"),
        )
        vrf_filter = {
            self._vrf(value)["vrf_id"] for value in vrf_filter
        }
        family_filter = self._filter_values(
            filters,
            plural=("route_families",),
            singular=("route_family",),
        )
        for value in family_filter:
            self._family(value)
        address_filter = self._filter_values(
            filters,
            plural=("address_families",),
            singular=("address_family",),
        )
        known_address_families = {
            item["address_family"] for item in _ROUTE_FAMILIES
        }
        unknown_addresses = address_filter - known_address_families
        if unknown_addresses:
            raise MultiNodeRouteRequestError(
                f"unknown address_families: {sorted(unknown_addresses)}"
            )
        type_filter = self._filter_values(
            filters,
            plural=("route_types",),
            singular=("route_type",),
        )
        known_types = {item["route_type"] for item in _ROUTE_TYPES}
        unknown_types = type_filter - known_types
        if unknown_types:
            raise MultiNodeRouteRequestError(
                f"unknown route_types: {sorted(unknown_types)}"
            )
        protocol_filter = self._filter_values(
            filters,
            plural=("protocols",),
            singular=("protocol", "source_protocol"),
        )
        active_filter = self._optional_boolean(filters, "active")
        installed_filter = self._optional_boolean(filters, "installed")
        text_filter = str(filters.get("text", "")).strip().casefold()
        destination_filter = filters.get("destination")
        if destination_filter is not None and not isinstance(
            destination_filter, (str, dict)
        ):
            raise MultiNodeRouteRequestError(
                "filters.destination must be a string or object"
            )
        destination_value = (
            str(destination_filter.get("value", "")).strip()
            if isinstance(destination_filter, dict)
            else str(destination_filter or "").strip()
        )
        destination_match = (
            str(destination_filter.get("match", "exact"))
            if isinstance(destination_filter, dict)
            else "exact"
        )
        if destination_match not in {"exact", "text"}:
            raise MultiNodeRouteRequestError(
                "filters.destination.match must be exact or text; prefix-match "
                "semantics belong to the node plug-in"
            )

        nodes_by_id = {str(item["node_id"]): item for item in snapshot["nodes"]}
        rows: list[dict[str, Any]] = []
        for row in self._route_table_entries():
            if row["node_id"] not in selected_node_ids:
                continue
            if vrf_filter and row["vrf_id"] not in vrf_filter:
                continue
            if family_filter and row["route_family"] not in family_filter:
                continue
            if address_filter and row["address_family"] not in address_filter:
                continue
            if type_filter and row["route_type"] not in type_filter:
                continue
            if protocol_filter and row["source_protocol"] not in protocol_filter:
                continue
            if active_filter is not None and row["active"] is not active_filter:
                continue
            if installed_filter is not None and row["installed"] is not installed_filter:
                continue
            if destination_value:
                candidate_values = {
                    str(row["prefix"]),
                    str(row["destination"]["value"]),
                    str(row["destination"]["destination_id"]),
                    str(row["destination"]["node_id"]),
                }
                matches = (
                    destination_value in candidate_values
                    if destination_match == "exact"
                    else any(
                        destination_value.casefold() in value.casefold()
                        for value in candidate_values
                    )
                )
                if not matches:
                    continue
            if text_filter and text_filter not in json.dumps(
                row, sort_keys=True, default=str
            ).casefold():
                continue
            node = nodes_by_id[row["node_id"]]
            resolved_time = node.get("resolved_time") or {}
            basis_time_ns = resolved_time.get("query_time_ns")
            if basis_time_ns is not None:
                timestamp_ns = int(basis_time_ns)
                if timestamp_ns < self.topology.start_ns:
                    continue
            rows.append(
                {
                    **row,
                    "basis_time_ns": basis_time_ns,
                    "quality": (
                        "exact"
                        if resolved_time.get("resolution") == "exact"
                        else "best_effort"
                    ),
                    "resolved_time": resolved_time,
                    "topology_context_id": snapshot["context_id"],
                }
            )

        rows.sort(
            key=lambda item: (
                item["node_id"],
                item["vrf_id"],
                item["route_family"],
                item["prefix"],
                item["route_type"],
                item["backup"],
            )
        )
        context_material = {
            "topology_context_id": snapshot["context_id"],
            "filters": filters,
            "route_entry_ids": [item["route_entry_id"] for item in rows],
        }
        context_digest = hashlib.sha256(
            json.dumps(
                context_material,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:24]
        route_table_context_id = f"rtctx1-{context_digest}"
        if cursor is not None:
            offset = self._decode_route_table_cursor(
                cursor, route_table_context_id
            )
        for row in rows:
            row["route_table_context_id"] = route_table_context_id
            row["trace_query"] = {
                **row["trace_query"],
                "topology_context_id": snapshot["context_id"],
                "route_table_context_id": route_table_context_id,
            }
        total = len(rows)
        returned = rows[offset : offset + limit]
        next_offset = offset + len(returned)
        truncated = next_offset < total
        next_cursor = (
            self._encode_route_table_cursor(
                route_table_context_id, next_offset
            )
            if truncated
            else None
        )
        returned_ids = {item["route_entry_id"] for item in returned}
        node_summaries = []
        for node in snapshot["nodes"]:
            node_rows = [item for item in rows if item["node_id"] == node["node_id"]]
            node_summaries.append(
                {
                    "node_id": node["node_id"],
                    "member_id": node["member_id"],
                    "label": node["label"],
                    "plugin_set_id": node["plugin_set_id"],
                    "resolved_time": node.get("resolved_time"),
                    "available": node.get("available", True),
                    "complete": node.get("complete", False),
                    "entry_count": len(node_rows),
                    "returned_count": sum(
                        item["route_entry_id"] in returned_ids for item in node_rows
                    ),
                    "plugin_provenance": _ROUTE_PLUGIN_BY_NODE.get(node["node_id"]),
                }
            )
        response = {
            "api_version": "v1",
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "schema_version": "demo.route-table.v1",
            "route_table_context_id": route_table_context_id,
            "topology_context_id": snapshot["context_id"],
            "request": {
                "topology_context_id": requested_context_id,
                "basis": effective_basis,
                "clock_policy": effective_clock_policy,
                "filters": filters,
                "page": {"limit": limit, "cursor": cursor, "offset": offset},
            },
            "resolved_basis": snapshot["resolved_basis"],
            "capture_vector": [
                {
                    "node_id": item["node_id"],
                    "member_id": item["member_id"],
                    "resolved_time": item.get("resolved_time"),
                    "complete": item.get("complete", False),
                }
                for item in snapshot["nodes"]
            ],
            "items": returned,
            "node_summaries": node_summaries,
            "counts": {
                "total": total,
                "returned": len(returned),
                "nodes": len({item["node_id"] for item in rows}),
            },
            "facets": {
                "node_ids": self._facet_counts(rows, "node_id"),
                "vrf_ids": self._facet_counts(rows, "vrf_id"),
                "route_families": self._facet_counts(rows, "route_family"),
                "route_types": self._facet_counts(rows, "route_type"),
                "protocols": self._facet_counts(rows, "source_protocol"),
            },
            "page": {
                "offset": offset,
                "limit": limit,
                "returned": len(returned),
                "total": total,
                "truncated": truncated,
                "next_cursor": next_cursor,
            },
            "completeness": {
                "complete": snapshot["complete"] and not truncated,
                "topology_complete": snapshot["complete"],
                "rows_truncated": truncated,
                "clock_alignment": snapshot["completeness"]["clock_alignment"],
                "simultaneity": snapshot["resolved_basis"]["simultaneity"],
                "relative_capture_vector_is_not_simultaneous": (
                    snapshot["resolved_basis"]["simultaneity"] == "not_implied"
                ),
            },
            "semantic_ownership": {
                "route_rows_and_keys": "node_plugins",
                "prefix_match_and_preference": "node_plugins",
                "vrf_family_and_next_hop_semantics": "node_plugins",
                "time_context_filtering_and_pagination": "core",
                "opaque_row_trace_correlation": "core",
            },
        }
        self._route_table_contexts[route_table_context_id] = {
            "topology_context_id": snapshot["context_id"],
            "route_entry_ids": {item["route_entry_id"] for item in rows},
        }
        while len(self._route_table_contexts) > 32:
            self._route_table_contexts.pop(next(iter(self._route_table_contexts)))
        return response

    @staticmethod
    def _bounded_page_integer(
        value: Any,
        field: str,
        *,
        minimum: int,
        maximum: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, str))
            or (
                isinstance(value, str)
                and not (
                    value.isdigit()
                    or (value.startswith("-") and value[1:].isdigit())
                )
            )
        ):
            raise MultiNodeRouteRequestError(f"{field} must be an integer")
        try:
            parsed = int(value)
        except (ValueError, OverflowError) as error:
            raise MultiNodeRouteRequestError(
                f"{field} must be an integer"
            ) from error
        if parsed < minimum or parsed > maximum:
            raise MultiNodeRouteRequestError(
                f"{field} must be between {minimum} and {maximum}"
            )
        return parsed

    def _validate_context_node_selection(
        self,
        body: dict[str, Any],
        snapshot: dict[str, Any],
    ) -> None:
        """Reject a route request that reinterprets a cached topology context."""

        has_node_ids = "node_ids" in body
        has_node_queries = "node_queries" in body
        if not has_node_ids and not has_node_queries:
            return
        selection_body = {
            field: body[field]
            for field in ("node_ids", "node_queries")
            if field in body
        }
        requested = self.topology._node_queries(selection_body)
        cached_nodes = {
            str(item["node_id"]): item for item in snapshot.get("nodes", [])
        }
        requested_ids = [str(item["node_id"]) for item in requested]
        if set(requested_ids) != set(cached_nodes):
            raise MultiNodeRouteRequestError(
                "node selection disagrees with the selected topology context"
            )

        # node_ids only selects scope. Projection identity is explicit only in
        # node_queries, so do not reinterpret a custom context as defaults when
        # a caller merely repeats its node membership.
        if not has_node_queries:
            return

        for request in requested:
            node_id = str(request["node_id"])
            cached = cached_nodes[node_id]
            node = self.topology._node(node_id)
            for field in ("member_id", "revision_id"):
                if (
                    request.get(field) is not None
                    and str(request[field]) != str(cached.get(field))
                ):
                    raise MultiNodeRouteRequestError(
                        f"{field} for node {node_id} disagrees with the selected "
                        "topology context"
                    )

            plugin_set_id = str(
                request.get("plugin_set_id", node["active_plugin_set_id"])
            )
            if plugin_set_id != str(cached.get("plugin_set_id")):
                raise MultiNodeRouteRequestError(
                    f"plugin_set_id for node {node_id} disagrees with the selected "
                    "topology context"
                )
            plugin_set = next(
                (
                    item
                    for item in node["plugin_sets"]
                    if item["plugin_set_id"] == plugin_set_id
                ),
                None,
            )
            if plugin_set is None:
                raise MultiNodeRouteRequestError(
                    f"unknown plugin_set_id {plugin_set_id} for node {node_id}"
                )
            requested_selections = self.topology._projection_selections(
                node,
                plugin_set,
                request,
            )
            requested_projection_ids = [
                (
                    str(item["plugin"]["plugin_id"]),
                    str(item["projection"]["projection_id"]),
                    str(item["status_perspective_id"]),
                )
                for item in requested_selections
            ]
            cached_projection_ids = [
                (
                    str(item["plugin_id"]),
                    str(item["projection_id"]),
                    str(item["status_perspective_id"]),
                )
                for item in cached.get("selected_plugins", [])
            ]
            if requested_projection_ids != cached_projection_ids:
                raise MultiNodeRouteRequestError(
                    f"projection selection for node {node_id} disagrees with the "
                    "selected topology context"
                )

            if "basis" not in request:
                continue
            requested_basis = self.topology.normalize_basis(
                request["basis"],
                f"basis for node {node_id}",
            )
            resolved_times = cached.get("resolved_times", [])
            if requested_basis["kind"] == "absolute_time":
                comparable_times = [
                    item
                    for item in resolved_times
                    if item.get("query_time_ns") is not None
                ]
                agrees = all(
                    str(item.get("query_time_ns"))
                    == str(requested_basis["time_ns"])
                    for item in comparable_times
                )
            else:
                comparable_times = [
                    item
                    for item in resolved_times
                    if item.get("relative_offset_ns") is not None
                ]
                agrees = all(
                    str(item.get("relative_offset_ns"))
                    == str(requested_basis["offset_ns"])
                    for item in comparable_times
                )
            if not agrees:
                raise MultiNodeRouteRequestError(
                    f"basis for node {node_id} disagrees with the selected "
                    "topology context"
                )

    @staticmethod
    def _filter_values(
        filters: dict[str, Any],
        *,
        plural: tuple[str, ...],
        singular: tuple[str, ...],
    ) -> set[str]:
        values: list[Any] = []
        for field in plural:
            if field not in filters:
                continue
            supplied = filters[field]
            if not isinstance(supplied, list):
                raise MultiNodeRouteRequestError(f"filters.{field} must be an array")
            values.extend(supplied)
        for field in singular:
            if filters.get(field) is not None:
                values.append(filters[field])
        return {str(value) for value in values}

    @staticmethod
    def _optional_boolean(filters: dict[str, Any], field: str) -> bool | None:
        if field not in filters:
            return None
        value = filters[field]
        if not isinstance(value, bool):
            raise MultiNodeRouteRequestError(f"filters.{field} must be boolean")
        return value

    @staticmethod
    def _facet_counts(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
        values: dict[str, int] = {}
        for row in rows:
            value = str(row[field])
            values[value] = values.get(value, 0) + 1
        return [
            {"value": value, "count": count}
            for value, count in sorted(values.items())
        ]

    @staticmethod
    def _optional_object(
        container: dict[str, Any], field: str, *, label: str | None = None
    ) -> dict[str, Any]:
        if field not in container or container[field] is None:
            return {}
        value = container[field]
        if not isinstance(value, dict):
            raise MultiNodeRouteRequestError(
                f"{label or field} must be an object"
            )
        return value

    @staticmethod
    def _scenario_routing_context(
        scenario: dict[str, Any], direction: str
    ) -> dict[str, str]:
        directional = scenario.get("directional_routing_contexts", {}).get(
            direction, {}
        )
        return {
            field: str(directional.get(field, scenario[field]))
            for field in (
                "route_type",
                "vrf_id",
                "route_family",
                "address_family",
            )
        }

    @staticmethod
    def _encode_route_table_cursor(
        route_table_context_id: str, offset: int
    ) -> str:
        material = json.dumps(
            {"context": route_table_context_id, "offset": offset},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        token = base64.urlsafe_b64encode(material).decode("ascii").rstrip("=")
        return f"rtcursor2-{token}"

    def _decode_route_table_cursor(
        self, cursor: Any, route_table_context_id: str
    ) -> int:
        cursor_text = str(cursor)
        if not cursor_text.startswith("rtcursor2-"):
            raise MultiNodeRouteRequestError("invalid route-table cursor")
        token = cursor_text.removeprefix("rtcursor2-")
        try:
            padding = "=" * (-len(token) % 4)
            decoded = json.loads(
                base64.urlsafe_b64decode(token + padding).decode("utf-8")
            )
        except (
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            binascii.Error,
        ) as error:
            raise MultiNodeRouteRequestError(
                "invalid route-table cursor"
            ) from error
        if not isinstance(decoded, dict) or set(decoded) != {"context", "offset"}:
            raise MultiNodeRouteRequestError("invalid route-table cursor")
        if decoded["context"] != route_table_context_id:
            raise MultiNodeRouteRequestError(
                "route-table cursor belongs to a different query or context"
            )
        return self._bounded_page_integer(
            decoded["offset"],
            "page.cursor",
            minimum=0,
            maximum=100_000,
        )

    def _resolve_routing_context(
        self,
        body: dict[str, Any],
        scenario: dict[str, Any],
        direction: str,
    ) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
        routing = self._optional_object(body, "routing_context")
        route_entry_ref = (
            body["route_entry_ref"]
            if body.get("route_entry_ref") is not None
            else routing.get("route_entry_ref")
        )
        referenced_row: dict[str, Any] | None = None
        if route_entry_ref is not None:
            if not isinstance(route_entry_ref, dict):
                raise MultiNodeRouteRequestError(
                    "route_entry_ref must be an object"
                )
            entry_id = route_entry_ref.get("route_entry_id")
            if not entry_id:
                raise MultiNodeRouteRequestError(
                    "route_entry_ref requires route_entry_id"
                )
            referenced_row = next(
                (
                    item
                    for item in self._route_table_entries()
                    if item["route_entry_id"] == str(entry_id)
                ),
                None,
            )
            if referenced_row is None:
                raise MultiNodeRouteRequestError(
                    f"unknown route_entry_ref: {entry_id}"
                )
            for field in ("node_id", "member_id", "plugin_id", "table_id"):
                expected = referenced_row["route_entry_ref"].get(field)
                supplied = route_entry_ref.get(field)
                if supplied is not None and str(supplied) != str(expected):
                    raise MultiNodeRouteRequestError(
                        f"route_entry_ref.{field} does not match the advertised row"
                    )

        route_table_context_id = body.get("route_table_context_id") or routing.get(
            "route_table_context_id"
        )
        if route_table_context_id is not None:
            route_table_context_id = str(route_table_context_id)
            table_context = self._route_table_contexts.get(route_table_context_id)
            if table_context is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired route_table_context_id"
                )
            if referenced_row and referenced_row["route_entry_id"] not in table_context[
                "route_entry_ids"
            ]:
                raise MultiNodeRouteRequestError(
                    "route_entry_ref is not present in the selected route-table context"
                )
            topology_context_values = {
                str(value)
                for value in (
                    body.get("topology_context_id"),
                    body.get("context_id"),
                )
                if value is not None
            }
            if len(topology_context_values) > 1:
                raise MultiNodeRouteRequestError(
                    "context_id and topology_context_id disagree"
                )
            if topology_context_values and next(
                iter(topology_context_values)
            ) != table_context["topology_context_id"]:
                raise MultiNodeRouteRequestError(
                    "route_table_context_id belongs to a different topology context"
                )

        type_values = {
            str(value)
            for value in (
                body.get("route_type"),
                routing.get("route_type"),
                referenced_row.get("route_type") if referenced_row else None,
            )
            if value is not None
        }
        if len(type_values) > 1:
            raise MultiNodeRouteRequestError(
                "route_type and the selected route-table row disagree"
            )
        explicit_route_type = next(iter(type_values), None)

        family_values = {
            str(value)
            for value in (
                body.get("route_family"),
                routing.get("route_family"),
                referenced_row.get("route_family") if referenced_row else None,
            )
            if value is not None
        }
        if len(family_values) > 1:
            raise MultiNodeRouteRequestError(
                "route_family and the selected route-table row disagree"
            )
        requested_family = next(iter(family_values), None)
        if requested_family is not None:
            family = self._family(requested_family)
        else:
            family = None

        address_values = {
            str(value)
            for value in (
                body.get("address_family"),
                routing.get("address_family"),
                referenced_row.get("address_family") if referenced_row else None,
            )
            if value is not None
        }
        if len(address_values) > 1:
            raise MultiNodeRouteRequestError(
                "address_family and the selected route-table row disagree"
            )
        requested_address = next(iter(address_values), None)

        scenario_context = self._scenario_routing_context(scenario, direction)
        fixed_context = not bool(scenario.get("supports_arbitrary_endpoints"))
        default_type = scenario_context["route_type"]
        if fixed_context and explicit_route_type not in {None, default_type}:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires route_type "
                f"{default_type} for {direction} direction"
            )
        if (
            fixed_context
            and requested_family not in {None, scenario_context["route_family"]}
        ):
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires route_family "
                f"{scenario_context['route_family']} for {direction} direction"
            )
        if explicit_route_type is not None:
            route_type = explicit_route_type
        elif family is not None and default_type not in family["supported_route_types"]:
            route_type = str(family["supported_route_types"][0])
        else:
            route_type = default_type
        known_types = {item["route_type"] for item in _ROUTE_TYPES}
        if route_type not in known_types:
            raise MultiNodeRouteRequestError(f"unknown route_type: {route_type}")
        default_vrf_id, derived_family_id = _ROUTE_TYPE_DEFAULT_CONTEXT[route_type]
        if family is None:
            family = self._family(
                scenario_context["route_family"]
                if fixed_context
                else derived_family_id
            )
        if route_type not in family["supported_route_types"]:
            raise MultiNodeRouteRequestError(
                f"route_type {route_type} is incompatible with route_family "
                f"{family['route_family']}"
            )
        if requested_address is not None:
            address_family_id = requested_address
            if requested_address in {
                item["route_family"] for item in _ROUTE_FAMILIES
            }:
                address_family_id = self._family(requested_address)[
                    "address_family"
                ]
            if address_family_id != family["address_family"]:
                raise MultiNodeRouteRequestError(
                    f"address_family {requested_address} is incompatible with "
                    f"route_family {family['route_family']}"
                )
            if (
                fixed_context
                and address_family_id != scenario_context["address_family"]
            ):
                raise MultiNodeRouteRequestError(
                    f"scenario {scenario['scenario_id']} requires address_family "
                    f"{scenario_context['address_family']} for {direction} direction"
                )

        source_request = body.get("source") or {}
        destination_request = body.get("destination") or {}
        vrf_values = {
            str(value)
            for value in (
                body.get("vrf_id"),
                body.get("vrf"),
                routing.get("vrf_id"),
                routing.get("vrf"),
                source_request.get("vrf_id") if isinstance(source_request, dict) else None,
                source_request.get("vrf") if isinstance(source_request, dict) else None,
                destination_request.get("vrf_id")
                if isinstance(destination_request, dict)
                else None,
                destination_request.get("vrf")
                if isinstance(destination_request, dict)
                else None,
                referenced_row.get("vrf_id") if referenced_row else None,
            )
            if value is not None
        }
        canonical_vrfs = {self._vrf(value)["vrf_id"] for value in vrf_values}
        if len(canonical_vrfs) > 1:
            raise MultiNodeRouteRequestError(
                "VRF selectors and the selected route-table row disagree"
            )
        expected_vrf_id = (
            scenario_context["vrf_id"] if fixed_context else default_vrf_id
        )
        vrf = self._vrf(next(iter(canonical_vrfs), expected_vrf_id))
        if fixed_context and vrf["vrf_id"] != scenario_context["vrf_id"]:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires VRF "
                f"{scenario_context['vrf_id']} for {direction} direction"
            )
        if family["route_family"] not in vrf["route_families"]:
            raise MultiNodeRouteRequestError(
                f"route_family {family['route_family']} is not available in VRF "
                f"{vrf['vrf_id']}"
            )
        if route_type not in vrf["supported_route_types"]:
            raise MultiNodeRouteRequestError(
                f"route_type {route_type} is not available in VRF {vrf['vrf_id']}"
            )

        table_values = {
            str(value)
            for value in (
                body.get("table_id"),
                routing.get("table_id"),
                referenced_row.get("table_id") if referenced_row else None,
            )
            if value is not None
        }
        if len(table_values) > 1:
            raise MultiNodeRouteRequestError(
                "table_id and the selected route-table row disagree"
            )
        constraints = self._optional_object(
            routing, "constraints", label="routing_context.constraints"
        )
        context = {
            "vrf_id": vrf["vrf_id"],
            "vrf": vrf["vrf"],
            "route_family": family["route_family"],
            "address_family": family["address_family"],
            "safi": family["safi"],
            "route_type": route_type,
            "table_id": next(iter(table_values), None),
            "constraints": constraints,
            "route_table_context_id": route_table_context_id,
            "route_entry_ref": (
                referenced_row["route_entry_ref"] if referenced_row else None
            ),
            "semantic_owner": "node_route_plugins",
        }
        return route_type, context, referenced_row

    def trace(self, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise MultiNodeRouteRequestError("request body must be an object")
        scenario_id = str(body.get("scenario_id", "single-active-primary"))
        scenario = next(
            (item for item in _SCENARIOS if item["scenario_id"] == scenario_id),
            None,
        )
        if scenario is None:
            raise MultiNodeRouteRequestError(f"unknown scenario_id: {scenario_id}")
        supplied_policies = {
            str(body[field])
            for field in ("resolution_mode", "resolution_policy", "completeness_policy")
            if body.get(field) is not None
        }
        if len(supplied_policies) > 1:
            raise MultiNodeRouteRequestError(
                "resolution_mode, resolution_policy, and completeness_policy disagree"
            )
        resolution_mode = next(iter(supplied_policies), "best_effort")
        if resolution_mode not in {"strict", "best_effort"}:
            raise MultiNodeRouteRequestError(
                "resolution_mode must be strict or best_effort"
            )
        steering_profile_id = str(
            body.get("steering_profile_id", "observed")
        )
        advertised_steering_ids = {
            str(item["profile_id"]) for item in STEERING_PROFILES
        }
        if steering_profile_id not in advertised_steering_ids:
            raise MultiNodeRouteRequestError(
                f"unknown steering_profile_id: {steering_profile_id}"
            )
        scenario_steering_ids = {
            str(item)
            for item in scenario.get("steering_profiles", ("observed",))
        }
        if steering_profile_id not in scenario_steering_ids:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario_id} does not support steering profile "
                f"{steering_profile_id}"
            )
        direction = str(body.get("direction", "forward"))
        if direction not in {"forward", "reverse", "both"}:
            raise MultiNodeRouteRequestError(
                "direction must be forward, reverse, or both"
            )
        max_hops = self._bounded_page_integer(
            body.get("max_hops", 64),
            "max_hops",
            minimum=1,
            maximum=128,
        )
        max_recursion = self._bounded_page_integer(
            body.get("max_recursion", 16),
            "max_recursion",
            minimum=0,
            maximum=64,
        )
        normalized_body = dict(body)
        flow = self._optional_object(body, "flow")
        for field in ("source", "destination"):
            flow_endpoint = flow.get(field)
            if flow_endpoint is not None and not isinstance(
                flow_endpoint, (dict, str)
            ):
                raise MultiNodeRouteRequestError(
                    f"flow.{field} must be an object or advertised value"
                )
            if (
                flow_endpoint is not None
                and field in normalized_body
                and normalized_body[field] not in (None, {}, flow_endpoint)
            ):
                raise MultiNodeRouteRequestError(
                    f"flow.{field} and top-level {field} disagree"
                )
            if flow_endpoint is not None:
                normalized_body[field] = flow_endpoint
        for field in ("source", "destination"):
            endpoint = normalized_body.get(field)
            if endpoint is None:
                normalized_body[field] = {}
            elif isinstance(endpoint, str):
                normalized_body[field] = {"value": endpoint}
            elif not isinstance(endpoint, dict):
                raise MultiNodeRouteRequestError(
                    f"{field} must be an object or advertised value"
                )
        route_type, routing_context, referenced_row = self._resolve_routing_context(
            normalized_body, scenario, direction
        )
        if referenced_row is not None:
            normalized_body.setdefault(
                "source_id", referenced_row["trace_query"]["source_id"]
            )
            normalized_body.setdefault(
                "destination_id",
                referenced_row["trace_query"]["destination_id"],
            )
            if not any(
                normalized_body.get(field)
                for field in ("ingress", "starting_point", "trace_starts")
            ):
                normalized_body["ingress"] = {
                    "start_id": f"start:{referenced_row['node_id']}",
                    "node_id": referenced_row["node_id"],
                    "member_id": referenced_row["member_id"],
                    "resource_id": self._router(
                        referenced_row["node_id"]
                    )["loopback_resource_id"],
                    "derivation": "selected_route_table_row",
                }
        if direction == "both":
            forward_request = dict(normalized_body)
            reverse_request = dict(normalized_body)
            forward_request["direction"] = "forward"
            reverse_request["direction"] = "reverse"
            if body.get("directional_routing_contexts") is not None:
                directional_contexts = body["directional_routing_contexts"]
            else:
                directional_contexts = scenario.get(
                    "directional_routing_contexts", {}
                )
            if not isinstance(directional_contexts, dict):
                raise MultiNodeRouteRequestError(
                    "directional_routing_contexts must be an object"
                )
            for requested_direction, request in (
                ("forward", forward_request),
                ("reverse", reverse_request),
            ):
                directional_context = directional_contexts.get(
                    requested_direction
                )
                if directional_context is None:
                    continue
                if not isinstance(directional_context, dict):
                    raise MultiNodeRouteRequestError(
                        "each directional routing context must be an object"
                    )
                for field in (
                    "route_type",
                    "route_family",
                    "address_family",
                    "vrf",
                    "vrf_id",
                ):
                    request.pop(field, None)
                nested_context = dict(request.get("routing_context") or {})
                for field in (
                    "route_type",
                    "route_family",
                    "address_family",
                    "vrf",
                    "vrf_id",
                ):
                    nested_context.pop(field, None)
                nested_context.update(directional_context)
                request["routing_context"] = nested_context
            forward_request.pop("focus_path_id", None)
            reverse_request.pop("focus_path_id", None)
            # A route-entry reference identifies the forward source RIB row. The
            # reverse trace resolves and reports its own contemporaneous rows.
            reverse_request.pop("route_entry_ref", None)
            if isinstance(reverse_request.get("routing_context"), dict):
                reverse_request["routing_context"] = {
                    key: value
                    for key, value in reverse_request["routing_context"].items()
                    if key != "route_entry_ref"
                }
            forward = self.trace(forward_request)
            reverse = self.trace(reverse_request)
            self._validate_pair_reverse_start(
                forward["flow"]["destination"],
                reverse["trace_start"],
            )
            return self._bidirectional_response(
                scenario, route_type, resolution_mode, forward, reverse
            )
        flow_source, flow_destination = self._resolve_endpoints(
            normalized_body, scenario_id, "forward"
        )
        source, destination = self._resolve_endpoints(
            normalized_body, scenario_id, direction
        )
        trace_start = self._resolve_trace_start(
            normalized_body,
            scenario,
            direction,
            flow_source if direction == "forward" else flow_destination,
        )
        target_endpoint = (
            flow_destination if direction == "forward" else flow_source
        )
        vrf_node_ids = set(self._vrf(routing_context["vrf_id"])["node_ids"])
        outside_vrf = [
            endpoint["node_id"]
            for endpoint in (source, destination, trace_start)
            if endpoint["node_id"] not in vrf_node_ids
        ]
        if outside_vrf:
            raise MultiNodeRouteRequestError(
                f"source, destination, and trace start must belong to VRF "
                f"{routing_context['vrf_id']}; outside scope: "
                f"{sorted(set(outside_vrf))}"
            )
        self._validate_referenced_route_row(
            referenced_row, trace_start, destination, routing_context
        )
        source_id = source["source_id"]
        destination_id = destination["destination_id"]
        context_aliases = {
            str(body[field])
            for field in ("context_id", "topology_context_id")
            if body.get(field) is not None
        }
        if len(context_aliases) > 1:
            raise MultiNodeRouteRequestError(
                "context_id and topology_context_id disagree"
            )
        requested_context_id = next(iter(context_aliases), None)
        if requested_context_id and not requested_context_id.startswith("tctx1-"):
            raise MultiNodeRouteRequestError("invalid topology context identifier")

        requested_basis = (
            self.topology.normalize_basis(body["basis"])
            if body.get("basis") is not None
            else {"kind": "relative_to_watermark", "offset_ns": "0"}
        )
        topology_request = {
            "basis": requested_basis,
            "clock_policy": body.get("clock_policy", "best_effort"),
            "resource_limit": 500,
            "inter_node_link_limit": 1000,
        }
        for field in ("node_queries", "node_ids"):
            if field in body:
                topology_request[field] = body[field]
        if requested_context_id:
            snapshot = self.topology._contexts.get(requested_context_id)
            if snapshot is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired topology context"
                )
            cached_basis = snapshot["resolved_basis"]["requested"]
            cached_clock_policy = snapshot["resolved_basis"]["clock_policy"]
            if (
                body.get("basis") is not None
                and self.topology.normalize_basis(body["basis"])
                != self.topology.normalize_basis(cached_basis)
            ):
                raise MultiNodeRouteRequestError(
                    "basis disagrees with the selected topology context"
                )
            if (
                body.get("clock_policy") is not None
                and str(body["clock_policy"]) != cached_clock_policy
            ):
                raise MultiNodeRouteRequestError(
                    "clock_policy disagrees with the selected topology context"
                )
            self._validate_context_node_selection(body, snapshot)
            topology_request["basis"] = cached_basis
            topology_request["clock_policy"] = cached_clock_policy
        else:
            snapshot = self.topology.query(topology_request)

        # The selected topology snapshot remains the trace's authoritative context.
        # Route resolvers can, however, require evidence from another default-enabled
        # projection in the same installed plug-in set (for example EVPN control state
        # when the visible topology is filtered to underlay only).  Re-run the same
        # selected nodes, basis, and clock policy without projection filters.  This is
        # an auxiliary evidence snapshot, not a replacement topology context.
        requested_node_queries = {
            str(item["node_id"]): item
            for item in body.get("node_queries", [])
            if isinstance(item, dict) and item.get("node_id")
        }
        route_node_queries: list[dict[str, Any]] = []
        for node in snapshot["nodes"]:
            original = requested_node_queries.get(str(node["node_id"]), {})
            route_node_query = {
                "node_id": node["node_id"],
                "plugin_set_id": node["plugin_set_id"],
            }
            if "basis" in original:
                route_node_query["basis"] = original["basis"]
            route_node_queries.append(route_node_query)
        route_evidence_request = {
            "basis": topology_request["basis"],
            "clock_policy": topology_request["clock_policy"],
            "resource_limit": topology_request["resource_limit"],
            "inter_node_link_limit": topology_request["inter_node_link_limit"],
            "node_queries": route_node_queries,
        }
        route_evidence = self.topology.query(route_evidence_request)
        resources = {
            item["resource_id"]: item
            for node in route_evidence["nodes"]
            for item in node.get("resources", [])
        }
        links: dict[str, list[dict[str, Any]]] = {}
        for link in route_evidence.get("inter_node_links", []):
            links.setdefault(str(link["link_id"]), []).append(link)

        targets: dict[str, dict[str, Any]] = {}
        issues: list[dict[str, Any]] = []
        if scenario_id in {
            "router-to-router",
            "transit-start-endpoint-reachability",
        }:
            selected_sequence = self._shortest_nodes(
                trace_start["node_id"], destination["node_id"]
            )
            if (
                referenced_row is not None
                and referenced_row["active"]
                and not referenced_row["backup"]
                and referenced_row["install_state"] != "control_plane_only"
            ):
                # The row is the plug-in's selected decision.  It may be a
                # deliberate non-shortest policy path, so do not replace it
                # with the demo graph's generic shortest-path fallback.
                selected_sequence = list(
                    referenced_row["attributes"]["node_sequence"]
                )
            if (
                referenced_row is not None
                and referenced_row["install_state"] == "control_plane_only"
            ):
                issue_id = (
                    "issue:route-table:control-plane-only:"
                    f"{referenced_row['route_entry_id']}"
                )
                control_path = self._generic_path(
                    list(referenced_row["attributes"]["node_sequence"]),
                    route_type,
                    resources,
                    links,
                    targets,
                    active=False,
                    primary=False,
                    alternative_state="control_plane_only",
                    issue_refs=[issue_id],
                )
                control_path.update(
                    {
                        "label": (
                            f"{control_path['label']} - control-plane evidence only"
                        ),
                        "perspective": "control_plane_observed",
                        "forwarding_capable": False,
                        "route_table_install_state": "control_plane_only",
                    }
                )
                paths = [control_path]
                issues.append(
                    {
                        "issue_id": issue_id,
                        "category": "forwarding",
                        "severity": "warning",
                        "summary": (
                            "Selected EVPN route is not installed for forwarding"
                        ),
                        "detail": (
                            "The P-router route-reflector plug-in retains this EVPN "
                            "route as control-plane evidence only. Core keeps the row "
                            "inspectable but does not treat it as a forwarding path."
                        ),
                        "path_refs": [control_path["path_id"]],
                        "segment_refs": [
                            item["segment_id"] for item in control_path["segments"]
                        ],
                        "route_entry_refs": [
                            referenced_row["route_entry_ref"]
                        ],
                        "interaction_target_ids": [],
                        "ownership": "node_plugin_install_state_core_reachability_guard",
                    }
                )
                consistency_state = "control_plane_only_not_forwarding"
            else:
                paths = [
                    self._generic_path(
                        selected_sequence,
                        route_type,
                        resources,
                        links,
                        targets,
                        active=True,
                        primary=True,
                        alternative_state="selected_primary",
                    )
                ]
            if (
                referenced_row is not None
                and referenced_row["backup"]
                and referenced_row["install_state"] != "control_plane_only"
            ):
                backup_sequence = list(
                    referenced_row["attributes"]["node_sequence"]
                )
                if backup_sequence != selected_sequence:
                    paths.append(
                        self._generic_path(
                            backup_sequence,
                            route_type,
                            resources,
                            links,
                            targets,
                            active=False,
                            primary=False,
                            alternative_state="eligible_standby",
                        )
                    )
            if not (
                referenced_row is not None
                and referenced_row["install_state"] == "control_plane_only"
            ):
                consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "site-a-site-c-asymmetric":
            node_sequence = (
                ["node-a", "transit-p-2", "node-c"]
                if direction == "forward"
                else ["node-c", "transit-p-2", "transit-p-1", "node-a"]
            )
            paths = [
                self._generic_path(
                    node_sequence,
                    "srv6_policy" if direction == "forward" else "mpls_transport",
                    resources,
                    links,
                    targets,
                    active=True,
                    primary=True,
                    alternative_state="selected_primary",
                )
            ]
            # This direction is internally consistent.  Forward/return path
            # asymmetry is a pair-level comparison produced by
            # _bidirectional_response(), not a fault on either valid path.
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "site-b-site-c-one-way" and direction == "reverse":
            paths = self._one_way_drop_paths(
                resources, links, targets, issues, resolution_mode
            )
            consistency_state = "inconsistent_one_way_drop"
        elif scenario_id == "site-b-site-c-one-way":
            paths = [
                self._generic_path(
                    ["node-b", "transit-p-2", "node-c"],
                    "evpn_service",
                    resources,
                    links,
                    targets,
                    active=True,
                    primary=True,
                    alternative_state="selected_primary",
                )
            ]
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id in ADVANCED_TRACE_SCENARIO_IDS:
            packet_profile_id = str(scenario["packet_profile_id"])
            node_sequence = (
                forced_node_sequence(direction, steering_profile_id)
                or preferred_node_sequence(packet_profile_id, direction)
            )
            paths = [
                self._generic_path(
                    node_sequence,
                    route_type,
                    resources,
                    links,
                    targets,
                    active=True,
                    primary=True,
                    alternative_state="selected_primary",
                )
            ]
            self._attach_packet_trace(
                paths[0],
                profile_id=packet_profile_id,
                direction=direction,
                steering_profile_id=steering_profile_id,
                issues=issues,
            )
            consistency_state = (
                "consistent_counterfactual_user_forced"
                if steering_profile_id != "observed"
                else "consistent_with_selected_observations"
            )
        elif direction == "reverse" and scenario_id != "connected-external-subnet":
            paths = [
                self._generic_path(
                    self._shortest_nodes(
                        trace_start["node_id"],
                        destination["node_id"],
                    ),
                    route_type,
                    resources,
                    links,
                    targets,
                    active=True,
                    primary=True,
                    alternative_state="selected_primary",
                )
            ]
            # The remaining scenario builders below model forward, plug-in-owned
            # demonstrations.  Reverse traversal is rebuilt from its own start
            # and endpoint goal instead of reusing their forward geometry.
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "evpn-mh-all-active":
            paths = self._evpn_multihoming_paths(
                resources,
                links,
                targets,
                issues,
                mode="all_active",
            )
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "evpn-es-withdraw-failover":
            paths = self._evpn_multihoming_paths(
                resources,
                links,
                targets,
                issues,
                mode="withdraw_failover",
            )
            consistency_state = "consistent_after_failover"
        elif scenario_id == "evpn-stale-fib-after-withdraw":
            paths = self._evpn_stale_fib_paths(
                resources, links, targets, issues
            )
            consistency_state = "inconsistent"
        elif scenario_id == "srv6-all-active":
            paths = self._srv6_all_active_paths(resources, links, targets)
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "recursive-static-to-external":
            paths = [
                self._recursive_static_external_path(
                    resources, links, targets
                )
            ]
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "recursive-resolution-cycle":
            paths = self._recursive_cycle_paths(
                source,
                destination,
                routing_context,
                resources,
                targets,
                issues,
                max_recursion=max_recursion,
            )
            consistency_state = (
                "consistent_cycle_detected"
                if paths[0]["result"] == "cycle"
                else "consistent_resolution_budget_exhausted"
            )
        elif scenario_id == "cross-node-forwarding-loop":
            paths = self._forwarding_loop_paths(
                source,
                destination,
                routing_context,
                resources,
                links,
                targets,
                issues,
                max_hops=max_hops,
            )
            consistency_state = (
                "consistent_cycle_detected"
                if paths[0]["result"] == "cycle"
                else "consistent_resolution_budget_exhausted"
            )
        elif scenario_id == "evpn-split-horizon-block":
            paths = self._split_horizon_paths(
                source,
                destination,
                resources,
                links,
                targets,
                issues,
            )
            consistency_state = "consistent_policy_blocked"
        elif scenario_id == "connected-external-subnet":
            paths = [self._connected_external_path(resources, targets)]
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "incomplete-intermediate-resolution":
            paths = self._incomplete_intermediate_paths(
                resources, links, targets, issues, resolution_mode
            )
            consistency_state = (
                "best_effort_with_gap"
                if resolution_mode == "best_effort"
                else "incomplete"
            )
        elif scenario_id == "single-active-primary":
            paths = self._underlay_paths(
                resources, links, targets, "single_active", issues
            )
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "all-active-ecmp":
            paths = self._underlay_paths(
                resources, links, targets, "all_active", issues
            )
            consistency_state = "consistent_with_selected_observations"
        elif scenario_id == "cross-layer-inconsistent":
            paths = self._inconsistent_paths(resources, links, targets, issues)
            consistency_state = "inconsistent"
        elif scenario_id == "incomplete-node-resolution":
            paths = self._incomplete_paths(
                resources, links, targets, issues, resolution_mode
            )
            consistency_state = (
                "best_effort_with_gap" if resolution_mode == "best_effort" else "incomplete"
            )
        else:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario_id} is not executable for direction {direction}"
            )

        self._declare_demo_terminal_evidence(paths, target_endpoint)
        endpoint_reachability = self._annotate_endpoint_reachability(
            paths,
            target_endpoint,
            trace_start,
        )
        route_entry_refs = self._attach_route_entry_refs(
            paths,
            destination,
            routing_context,
            referenced_row,
            targets,
        )
        self._decorate_route_presentations(paths, routing_context)
        route_entry_correlations = list(
            {
                item["route_entry_id"]: item
                for path in paths
                for item in path.get("route_entry_correlations", [])
            }.values()
        )
        path_ids = {item["path_id"] for item in paths}
        requested_focus = body.get("focus_path_id") or (
            referenced_row["path_id"] if referenced_row is not None else None
        )
        if requested_focus is not None and str(requested_focus) not in path_ids:
            raise MultiNodeRouteRequestError(
                f"focus_path_id is not a candidate in this trace: {requested_focus}"
            )
        focused_path_id = str(requested_focus) if requested_focus else self._default_focus(paths)
        for path in paths:
            path["focused"] = path["path_id"] == focused_path_id

        focused = next(item for item in paths if item["path_id"] == focused_path_id)
        issue_by_id = {item["issue_id"]: item for item in issues}
        active_paths = [item for item in paths if item["active"]]
        primary = next((item for item in paths if item["primary"]), None)
        trace_material = {
            "context_id": snapshot["context_id"],
            "route_evidence_context_id": route_evidence["context_id"],
            "scenario_id": scenario_id,
            "resolution_mode": resolution_mode,
            "steering_profile_id": steering_profile_id,
            "direction": direction,
            "route_type": route_type,
            "max_hops": max_hops,
            "max_recursion": max_recursion,
            "flow_source_endpoint_id": flow_source["endpoint_id"],
            "flow_destination_endpoint_id": flow_destination["endpoint_id"],
            "trace_start_node_id": trace_start["node_id"],
            "source_node_id": source["node_id"],
            "destination_node_id": destination["node_id"],
            "source_id": source_id,
            "destination_id": destination_id,
            "routing_context": routing_context,
            "requested_context_id": requested_context_id,
        }
        trace_id = "rtrace1-" + hashlib.sha256(
            json.dumps(trace_material, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:24]
        all_end_to_end = all(
            item["completeness"]["end_to_end_resolved"] for item in paths
        )
        exact = all(
            item["completeness"]["state"] == "complete" for item in paths
        )
        reachable = endpoint_reachability["reaches_target"] is True
        directional_pair = self._directional_pair(
            scenario_id, direction, flow_source, flow_destination
        )
        counterpart_direction = (
            "reverse" if direction == "forward" else "forward"
        )
        counterpart_context = self._scenario_routing_context(
            scenario, counterpart_direction
        )
        if scenario.get("supports_arbitrary_endpoints"):
            counterpart_source_id = self._router(
                directional_pair["base_source_node_id"]
            )["source_id"]
            counterpart_destination_id = self._router(
                directional_pair["base_destination_node_id"]
            )["destination_id"]
            counterpart_context = {
                "route_type": route_type,
                "route_family": routing_context["route_family"],
                "address_family": routing_context["address_family"],
                "vrf_id": routing_context["vrf_id"],
            }
        else:
            counterpart_source_id = scenario.get("default_source") or self._router(
                directional_pair["base_source_node_id"]
            )["source_id"]
            counterpart_destination_id = scenario.get("default_destination")
            if counterpart_destination_id is None:
                counterpart_destination_id = (
                    "destination:blue-service-prefix"
                    if scenario_id in _BLUE_SERVICE_SCENARIOS
                    else self._router(
                        directional_pair["base_destination_node_id"]
                    )["destination_id"]
                )
        return {
            "api_version": "v1",
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "trace_id": trace_id,
            "trace_mode": "single_direction",
            "direction": direction,
            "steering_profile_id": steering_profile_id,
            "counterfactual": steering_profile_id != "observed",
            "direction_id": (
                f"direction:{direction}:{trace_start['node_id']}:"
                f"{target_endpoint['endpoint_id']}"
            ),
            "route_type": route_type,
            "route_family": routing_context["route_family"],
            "address_family": routing_context["address_family"],
            "vrf": routing_context["vrf"],
            "vrf_id": routing_context["vrf_id"],
            "routing_context": routing_context,
            "source": source,
            "destination": destination,
            "flow": {
                "source": flow_source,
                "destination": flow_destination,
            },
            "traffic_endpoints": {
                "source": flow_source,
                "destination": flow_destination,
            },
            "trace_start": trace_start,
            "starting_point": trace_start,
            "target_endpoint": target_endpoint,
            "goal_endpoint": target_endpoint,
            "endpoint_reachability": endpoint_reachability,
            "directional_pair": directional_pair,
            "reachable": reachable,
            "context_id": snapshot["context_id"],
            "topology_context_id": snapshot["context_id"],
            "requested_context_id": requested_context_id,
            "context_consistency": {
                "state": (
                    "not_supplied"
                    if requested_context_id is None
                    else "same_reconstruction"
                    if requested_context_id == snapshot["context_id"]
                    else "derived_from_valid_context"
                ),
                "requested_context_id": requested_context_id,
                "resolved_context_id": snapshot["context_id"],
                "validated": requested_context_id is None
                or requested_context_id == snapshot["context_id"]
                or requested_context_id in self.topology._contexts,
            },
            "scenario": dict(scenario),
            "request": {
                "scenario_id": scenario_id,
                "direction": direction,
                "route_type": route_type,
                "route_family": routing_context["route_family"],
                "address_family": routing_context["address_family"],
                "vrf": routing_context["vrf"],
                "vrf_id": routing_context["vrf_id"],
                "routing_context": routing_context,
                "source_id": source_id,
                "resolution_mode": resolution_mode,
                "resolution_policy": resolution_mode,
                "completeness_policy": resolution_mode,
                "steering_profile_id": steering_profile_id,
                "max_hops": max_hops,
                "max_recursion": max_recursion,
                "destination_id": destination_id,
                "route_table_context_id": routing_context[
                    "route_table_context_id"
                ],
                "route_entry_ref": routing_context["route_entry_ref"],
                "clock_policy": topology_request["clock_policy"],
                "basis": topology_request["basis"],
                "source": source,
                "destination": destination,
                "flow": {
                    "source": flow_source,
                    "destination": flow_destination,
                },
                "trace_starts": {direction: trace_start},
            },
            "counterpart_request": {
                "scenario_id": scenario_id,
                "direction": counterpart_direction,
                "source_id": counterpart_source_id,
                "destination_id": counterpart_destination_id,
                "route_type": counterpart_context["route_type"],
                "route_family": counterpart_context["route_family"],
                "address_family": counterpart_context["address_family"],
                "vrf": counterpart_context["vrf_id"],
                "vrf_id": counterpart_context["vrf_id"],
                "resolution_mode": resolution_mode,
                "steering_profile_id": steering_profile_id,
                "max_hops": max_hops,
                "max_recursion": max_recursion,
                "basis": topology_request["basis"],
                "clock_policy": topology_request["clock_policy"],
                "flow": {
                    "source": flow_source,
                    "destination": flow_destination,
                },
            },
            "resolution_mode": resolution_mode,
            "resolution_policy": resolution_mode,
            "completeness_policy": resolution_mode,
            "max_hops": max_hops,
            "max_recursion": max_recursion,
            "resolved_basis": snapshot["resolved_basis"],
            "multipath": {
                "mode": scenario["multipath_mode"],
                "selection_owner": "node_plugins",
                "candidate_count": len(paths),
                "active_path_count": len(active_paths),
                "active_path_ids": [item["path_id"] for item in active_paths],
                "primary_path_id": primary["path_id"] if primary else None,
                "all_candidates_retained": True,
            },
            "paths": paths,
            "route_table_entry_refs": route_entry_refs,
            "matched_route_entry_refs": route_entry_refs,
            "route_table_entry_correlations": route_entry_correlations,
            "route_table_entry_ids": [
                item["route_entry_id"] for item in route_entry_refs
            ],
            "focused_path_id": focused_path_id,
            "focus": {
                "path_id": focused_path_id,
                "active": focused["active"],
                "primary": focused["primary"],
                "alternative_state": focused["alternative_state"],
                "role": focused["role"],
                "result": focused["result"],
                "eligibility": focused["eligibility"],
                "terminal_reason": focused["terminal_reason"],
                "graph_target_ids": focused["graph_target_ids"],
            },
            "route_resolution_sequence": focused["route_resolution_sequence"],
            "interaction_targets": list(targets.values()),
            "issues": issues,
            "consistency": {
                "state": consistency_state,
                "consistent": consistency_state.startswith("consistent"),
                "issue_refs": [
                    item["issue_id"]
                    for item in issues
                    if item["category"]
                    in {"cross_layer", "boundary", "directional", "forwarding"}
                    and item.get("affects_consistency", True) is not False
                ],
                "compared_status_perspectives": sorted(
                    {
                        provider.get("status_perspective_id")
                        for path in paths
                        for provider in path["plugin_provenance"]
                        if provider.get("status_perspective_id")
                    }
                ),
            },
            "complete": all_end_to_end,
            "completeness": {
                "end_to_end_resolved": all_end_to_end,
                "reachable": reachable,
                "endpoint_reachability_state": endpoint_reachability["state"],
                "observationally_complete": exact,
                "state": "complete" if exact else "partial",
                "inferred_segment_count": sum(
                    1
                    for path in paths
                    for segment in path["segments"]
                    if segment["completeness"]["state"] == "best_effort_inferred"
                ),
                "unresolved_segment_count": sum(
                    1
                    for path in paths
                    for segment in path["segments"]
                    if segment["completeness"]["state"] == "unresolved"
                ),
            },
            "topology_snapshot": {
                "context_id": snapshot["context_id"],
                "resolved_basis": snapshot["resolved_basis"],
                "node_count": snapshot["counts"]["nodes"],
                "inter_node_link_count": snapshot["counts"]["inter_node_links"],
                "complete": snapshot["complete"],
                "deep_link": snapshot["deep_links"]["self"],
            },
            "route_resolution_evidence": {
                "context_id": route_evidence["context_id"],
                "topology_context_id": snapshot["context_id"],
                "scope": "default_enabled_projections_for_selected_node_plugin_sets",
                "auxiliary": True,
                "replaces_topology_context": False,
                "explicit_projection_filters_removed": any(
                    "projections" in item
                    or any(
                        field in item
                        for field in (
                            "plugin_id",
                            "projection_id",
                            "status_perspective_id",
                        )
                    )
                    for item in requested_node_queries.values()
                ),
                "node_queries": route_node_queries,
                "resolved_basis": route_evidence["resolved_basis"],
            },
            "issue_index": issue_by_id,
            "semantic_ownership": {
                "route_resolution_text": "node_or_federation_plugin",
                "local_resolution": "node_plugin",
                "boundary_resolution": "federation_linker_plugin",
                "route_presentation_roles_and_content": "node_or_federation_plugin",
                "presentation_reference_validation_and_rendering": "core",
                "route_table_rows_and_selection": "node_plugin",
                "route_table_time_context_and_correlation": "core",
                "time_path_join_and_uncertainty": "core",
                "flow_endpoint_identity_and_direction_swap": "core",
                "trace_start_selection": "caller_and_core",
                "terminal_endpoint_classification": "node_plugin",
                "terminal_endpoint_exact_match_and_pair_aggregation": "core",
                "reverse_must_revisit_forward_start": False,
                "core_does_not_interpret_route_resolution_text": True,
                "core_does_not_infer_overlay_from_protocol_or_address_fields": True,
            },
            "deep_links": {
                "topology": snapshot["deep_links"]["self"],
                "individual_nodes": snapshot["deep_links"]["individual_nodes"],
            },
        }

    @staticmethod
    def _attachment_identity(
        attachment: dict[str, Any],
        *,
        label: str,
    ) -> tuple[str, str, str, str]:
        values = tuple(
            attachment.get(field)
            for field in (
                "attachment_id",
                "node_id",
                "member_id",
                "resource_id",
            )
        )
        if any(not isinstance(value, str) or not value for value in values):
            raise MultiNodeRouteRequestError(
                f"{label} must declare non-empty attachment_id, node_id, "
                "member_id, and resource_id"
            )
        return values  # type: ignore[return-value]

    @staticmethod
    def _packet_value_json(value: Any) -> Any:
        """Serialize one already-validated opaque forwarding value for the demo."""

        if isinstance(value, tuple):
            return [
                MultiNodeRouteDemo._packet_value_json(item) for item in value
            ]
        if isinstance(value, bytes):
            return {"encoding": "hex", "value": value.hex()}
        if isinstance(value, (str, int)) or value is None:
            return value
        return str(value)

    @classmethod
    def _packet_resource_key_json(
        cls,
        resource: ResourceKey,
    ) -> dict[str, Any]:
        """Preserve one typed resource identity without interpreting its parts."""

        return {
            "namespace": resource.namespace,
            "node": resource.node,
            "layer": resource.layer,
            "kind": resource.kind,
            "parts": [
                {
                    "name": name,
                    "value": cls._packet_value_json(value),
                }
                for name, value in resource.parts
            ],
        }

    @classmethod
    def _packet_topology_reference_json(
        cls,
        reference: TopologyEndpointReference,
    ) -> dict[str, Any]:
        """Serialize the exact resource-or-matcher topology reference."""

        if reference.resource is not None:
            return {
                "resource": cls._packet_resource_key_json(reference.resource),
            }
        assert reference.match is not None
        return {
            "match": {
                "matcher_id": reference.match.matcher_id,
                "arguments": {
                    name: cls._packet_value_json(value)
                    for name, value in reference.match.arguments.items()
                },
                "resolved_candidates": [
                    cls._packet_resource_key_json(candidate)
                    for candidate in reference.match.resolved_candidates
                ],
            },
        }

    @staticmethod
    def _packet_evidence_json(evidence: Evidence) -> dict[str, Any]:
        """Serialize retained evidence without exposing any undeclared payload."""

        return {
            "artifact_id": str(evidence.artifact_id),
            "locator": evidence.locator,
            "raw_timestamp_ns": evidence.raw_timestamp_ns,
            "clock_domain": evidence.clock_domain,
            "excerpt_sha256": evidence.excerpt_sha256,
        }

    @staticmethod
    def _packet_boundary_continuity(
        expected: ForwardingPacketState,
        actual: ForwardingPacketState,
    ) -> bool | None:
        """Return exact boundary continuity, or unknown for incomplete identity."""

        if not expected.identity_complete or not actual.identity_complete:
            return None
        return expected == actual

    @classmethod
    def _packet_layer_json(
        cls,
        layer: ForwardingPacketLayer,
    ) -> dict[str, Any]:
        return {
            "layer_id": layer.layer_id,
            "contract_id": layer.contract_id,
            "label": layer.label,
            "fields": {
                name: cls._packet_value_json(value)
                for name, value in layer.fields
            },
            "size_bytes": layer.size_bytes,
            "complete": layer.complete,
        }

    @classmethod
    def _packet_state_json(
        cls,
        state: ForwardingPacketState,
    ) -> dict[str, Any]:
        return {
            "layers": [
                cls._packet_layer_json(layer) for layer in state.layers
            ],
            "size": (
                {
                    "basis_contract_id": state.size.basis_contract_id,
                    "size_bytes": state.size.size_bytes,
                    "complete": state.size.complete,
                }
                if state.size is not None
                else None
            ),
            "complete": state.complete,
            "identity_complete": state.identity_complete,
        }

    @classmethod
    def _packet_transition_json(
        cls,
        evaluation: ForwardingPacketTransitionEvaluation,
        *,
        segment: dict[str, Any],
    ) -> dict[str, Any]:
        transition = evaluation.transition
        mtu_constraint = transition.mtu
        return {
            "transition": {
                "transition_id": transition.transition_id,
                "step_id": transition.step_id,
                "before": cls._packet_state_json(transition.before),
                "after": cls._packet_state_json(transition.after),
                "action_contract_id": transition.action_contract_id,
                "action_label": transition.action_label,
                "disposition": transition.disposition.value,
                "origin": transition.origin.value,
                "actor_id": transition.actor_id,
                "forced_rule_id": transition.forced_rule_id,
                "mtu_constraint": (
                    {
                        "basis_contract_id": (
                            mtu_constraint.basis_contract_id
                        ),
                        "limit_bytes": mtu_constraint.limit_bytes,
                        "complete": mtu_constraint.complete,
                        "resource": (
                            cls._packet_resource_key_json(
                                mtu_constraint.resource
                            )
                            if mtu_constraint.resource is not None
                            else None
                        ),
                    }
                    if mtu_constraint is not None
                    else None
                ),
                "contributions": [
                    {
                        "phase": item.phase,
                        "text": item.text,
                        "quality": item.quality.value,
                        "resource_references": [
                            cls._packet_resource_key_json(reference)
                            for reference in item.resource_references
                        ],
                        "topology_references": [
                            cls._packet_topology_reference_json(reference)
                            for reference in item.topology_references
                        ],
                        "evidence": [
                            cls._packet_evidence_json(evidence)
                            for evidence in item.evidence
                        ],
                    }
                    for item in transition.contributions
                ],
            },
            "diff": {
                "added_layer_ids": list(evaluation.diff.added_layer_ids),
                "removed_layer_ids": list(
                    evaluation.diff.removed_layer_ids
                ),
                "changed_layer_ids": list(
                    evaluation.diff.changed_layer_ids
                ),
                "moved_layer_ids": list(evaluation.diff.moved_layer_ids),
                "complete": evaluation.diff.complete,
            },
            "mtu": {
                "outcome": evaluation.mtu.outcome,
                "size_bytes": evaluation.mtu.size_bytes,
                "limit_bytes": evaluation.mtu.limit_bytes,
                "excess_bytes": evaluation.mtu.excess_bytes,
                "basis_contract_id": evaluation.mtu.basis_contract_id,
            },
            "counterfactual": evaluation.counterfactual,
            "segment_id": segment["segment_id"],
            "node_id": segment.get("node_id"),
            "highlight_target_ids": list(
                segment.get("highlight_target_ids", [])
            ),
            "interaction_target_ids": list(
                segment.get("interaction_target_ids", [])
            ),
        }

    @classmethod
    def _attach_packet_trace(
        cls,
        path: dict[str, Any],
        *,
        profile_id: str,
        direction: str,
        steering_profile_id: str,
        issues: list[dict[str, Any]],
    ) -> None:
        """Validate demo plug-in transitions and attach protocol-neutral JSON."""

        local_segments = [
            item
            for item in sorted(
                path["segments"], key=lambda candidate: candidate["ordinal"]
            )
            if item["segment_kind"] == "node_resolution"
        ]
        initial_state, transitions = build_packet_transitions(
            profile_id=profile_id,
            step_ids=[
                str(item["segment_id"]) for item in local_segments
            ],
            node_ids=[str(item["node_id"]) for item in local_segments],
            direction=direction,
            steering_profile_id=steering_profile_id,
        )
        trace: ForwardingPacketTraceEvaluation = (
            evaluate_forwarding_packet_trace(
                initial_state,
                transitions,
                max_steps=256,
            )
        )
        segment_by_id = {
            str(item["segment_id"]): item for item in local_segments
        }
        serialized_transitions: list[dict[str, Any]] = []
        expected_packet_state = initial_state
        for evaluation in trace.transitions:
            segment = segment_by_id[evaluation.transition.step_id]
            serialized = cls._packet_transition_json(
                evaluation,
                segment=segment,
            )
            serialized["continuity_valid"] = (
                cls._packet_boundary_continuity(
                    expected_packet_state,
                    evaluation.transition.before,
                )
            )
            serialized_transitions.append(serialized)
            segment["packet_transition"] = serialized
            segment["route_resolution"]["packet_transition"] = serialized
            expected_packet_state = evaluation.transition.after

        counterfactual = any(
            item.counterfactual for item in trace.transitions
        )
        path["packet_profile_id"] = profile_id
        path["counterfactual"] = counterfactual
        path["observed"] = not counterfactual
        path["packet_trace"] = {
            "schema_version": "demo.forwarding-packet-trace.v1",
            "layer_order": "outermost_to_innermost",
            "initial_state": cls._packet_state_json(initial_state),
            "outcome": trace.outcome,
            "stop_step": trace.stop_step,
            "continuity": trace.continuity,
            "continuity_complete": trace.continuity == "complete",
            "terminal_disposition": (
                trace.terminal_disposition.value
                if trace.terminal_disposition is not None
                else None
            ),
            "counterfactual": counterfactual,
            "steering_profile_id": steering_profile_id,
            "transitions": serialized_transitions,
            "validation_owner": "core",
            "semantics_owner": "node_plugins",
        }

        if trace.outcome != "drop" or not trace.transitions:
            return
        dropped = trace.transitions[-1]
        terminal = segment_by_id[dropped.transition.step_id]
        drop_index = path["segments"].index(terminal)
        terminal.update(
            {
                "segment_kind": "packet_mtu_drop",
                "active": False,
                "confidence": 1.0,
                "completeness": {
                    "state": "terminal_drop",
                    "end_to_end_resolved": False,
                    "observed": True,
                },
            }
        )
        terminal["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": True,
                "operational": "unusable",
                "terminal": "mtu_exceeded",
                "reason_code": "mtu_exceeded_after_encapsulation",
                "terminal_disposition": "dropped",
            }
        )
        terminal["route_resolution"]["phase"] = "packet_mtu_decision"
        terminal["phase"] = "packet_mtu_decision"
        path["segments"] = path["segments"][: drop_index + 1]
        path["node_sequence"] = [
            str(item["node_id"])
            for item in path["segments"]
            if item.get("node_id")
            and item["segment_kind"] != "inter_node_boundary"
        ]
        issue_id = (
            f"issue:packet-mtu:{direction}:{terminal['segment_id']}"
        )
        terminal["issue_refs"] = list(
            dict.fromkeys([*terminal.get("issue_refs", []), issue_id])
        )
        path["issue_refs"] = list(
            dict.fromkeys([*path.get("issue_refs", []), issue_id])
        )
        issues.append(
            {
                "issue_id": issue_id,
                "category": "forwarding",
                "severity": "error",
                "summary": "Plug-in-declared MTU policy drops the packet",
                "detail": (
                    "Core confirmed that the plug-in-declared packet size "
                    "exceeds an exactly comparable MTU. The node plug-in, not "
                    "core, declared the DF/drop disposition."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [terminal["segment_id"]],
                "interaction_target_ids": list(
                    terminal.get("interaction_target_ids", [])
                ),
                "ownership": (
                    "core_size_comparison_node_plugin_disposition"
                ),
            }
        )
        cls._refresh_path(path)

    def _declare_demo_terminal_evidence(
        self,
        paths: list[dict[str, Any]],
        target_endpoint: dict[str, Any],
    ) -> None:
        """Project demo plug-in delivery decisions before core exact matching.

        This method stands in for the participating node plug-ins.  The core
        annotator below consumes only this normalized declaration; it does not
        infer endpoint delivery from a path's final node.
        """

        attachments_by_node = {
            str(item["node_id"]): dict(item)
            for item in target_endpoint.get("attachments", [])
            if item.get("can_terminate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
            and item.get("node_id")
        }
        for path in paths:
            sequence = [
                str(item) for item in path.get("node_sequence", []) if item
            ]
            terminal_node_id = sequence[-1] if sequence else None
            target_attachment = attachments_by_node.get(
                str(terminal_node_id)
            )
            resolved = bool(
                path.get("completeness", {}).get("end_to_end_resolved")
            )
            forwarding_capable = path.get("forwarding_capable", True) is not False
            result = str(path.get("result", "unknown"))
            if (
                resolved
                and forwarding_capable
                and result == "resolved"
                and target_attachment is not None
            ):
                declaration = {
                    "classification": "delivered",
                    "classification_complete": True,
                    "endpoint_id": target_endpoint["endpoint_id"],
                    "attachment": target_attachment,
                }
            elif (
                resolved
                and forwarding_capable
                and result == "resolved"
                and terminal_node_id is not None
            ):
                terminal_router = self._router(terminal_node_id)
                terminal_endpoint_id = self._router_endpoint_id(
                    terminal_node_id
                )
                declaration = {
                    "classification": "delivered",
                    "classification_complete": True,
                    "endpoint_id": terminal_endpoint_id,
                    "attachment": self._endpoint_attachment(
                        endpoint_id=terminal_endpoint_id,
                        node_id=terminal_node_id,
                        member_id=f"member:{terminal_node_id}",
                        resource_id=terminal_router["loopback_resource_id"],
                    ),
                }
            elif result in {
                "dropped",
                "discarded",
                "unusable",
                "cycle",
                "policy_blocked",
                "hop_limit_exceeded",
                "recursion_limit_exceeded",
            } or not forwarding_capable:
                declaration = {
                    "classification": "not_delivered",
                    "classification_complete": True,
                    "endpoint_id": None,
                    "attachment": None,
                }
            else:
                declaration = {
                    "classification": "unknown",
                    "classification_complete": False,
                    "endpoint_id": None,
                    "attachment": None,
                }
            declaration.update(
                {
                    "terminal_node_id": terminal_node_id,
                    "semantic_owner": "node_plugin",
                    "evidence_kind": "normalized_terminal_attachment",
                }
            )
            path["plugin_terminal"] = declaration

    @classmethod
    def _annotate_endpoint_reachability(
        cls,
        paths: list[dict[str, Any]],
        target_endpoint: dict[str, Any],
        trace_start: dict[str, Any],
    ) -> dict[str, Any]:
        """Match plug-in-declared path terminals to the requested endpoint."""

        target_endpoint_id = target_endpoint.get("endpoint_id")
        if not isinstance(target_endpoint_id, str) or not target_endpoint_id:
            raise MultiNodeRouteRequestError(
                "target endpoint must declare a non-empty endpoint_id"
            )
        target_attachments = [
            dict(item)
            for item in target_endpoint.get("attachments", [])
            if item.get("can_terminate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        ]
        target_attachment_identities = {
            cls._attachment_identity(
                item,
                label="target endpoint attachment",
            )
            for item in target_attachments
        }
        attachments_complete = target_endpoint.get(
            "attachments_complete", False
        )
        if not isinstance(attachments_complete, bool):
            raise MultiNodeRouteRequestError(
                "target endpoint attachments_complete must be a boolean"
            )
        active_branch_count = 0
        reached_active_branch_count = 0
        unresolved_active_branch_count = 0
        failed_active_branch_count = 0
        selected_results: list[bool | None] = []
        for path in paths:
            sequence = [
                str(item) for item in path.get("node_sequence", []) if item
            ]
            if not sequence or sequence[0] != str(trace_start.get("node_id")):
                raise MultiNodeRouteRequestError(
                    "plug-in route path must begin at the declared trace_start"
                )
            terminal_node_id = sequence[-1] if sequence else None
            end_to_end_resolved = bool(
                path.get("completeness", {}).get("end_to_end_resolved")
            )
            declaration = path.get("plugin_terminal")
            if not isinstance(declaration, dict):
                raise MultiNodeRouteRequestError(
                    "plug-in route path must declare plugin_terminal evidence"
                )
            classification = declaration.get("classification")
            if classification not in {"delivered", "not_delivered", "unknown"}:
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.classification must be delivered, "
                    "not_delivered, or unknown"
                )
            classification_complete = declaration.get(
                "classification_complete"
            )
            if not isinstance(classification_complete, bool):
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.classification_complete must be a boolean"
                )
            terminal_attachment = declaration.get("attachment")
            if terminal_attachment is not None and not isinstance(
                terminal_attachment, dict
            ):
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.attachment must be an object or null"
                )
            terminal_attachment_identity = (
                cls._attachment_identity(
                    terminal_attachment,
                    label="plug-in terminal attachment",
                )
                if terminal_attachment is not None
                else None
            )
            endpoint_matches = (
                declaration.get("endpoint_id") == target_endpoint_id
            )
            attachment_matches = (
                terminal_attachment_identity
                in target_attachment_identities
                if terminal_attachment_identity is not None
                else False
            )
            exact_match = endpoint_matches and attachment_matches
            if classification == "delivered":
                if exact_match and end_to_end_resolved:
                    reaches_target: bool | None = True
                elif classification_complete and attachments_complete:
                    reaches_target = False
                else:
                    reaches_target = None
            elif classification == "not_delivered":
                reaches_target = False if classification_complete else None
            else:
                reaches_target = None
            state = (
                "reached"
                if reaches_target is True
                else "not_reached"
                if reaches_target is False
                else "unknown"
            )
            path["target_endpoint_id"] = target_endpoint_id
            path["terminal_endpoint_id"] = declaration.get("endpoint_id")
            path["terminal_reachability"] = {
                "state": state,
                "reached": reaches_target,
                "target_endpoint_id": target_endpoint_id,
                "terminal_endpoint_id": declaration.get("endpoint_id"),
                "terminal_node_id": terminal_node_id,
                "terminal_attachment": terminal_attachment,
                "exact_endpoint_match": endpoint_matches,
                "exact_attachment_match": attachment_matches,
                "exact_match": exact_match,
                "classification_complete": classification_complete,
                "end_to_end_resolved": end_to_end_resolved,
                "classification_owner": "node_plugin",
                "exact_match_owner": "core",
            }
            selected_active = bool(
                path.get(
                    "selected_active_by_plugin",
                    path.get("active"),
                )
            )
            if selected_active:
                active_branch_count += 1
                selected_results.append(reaches_target)
                if reaches_target is True:
                    reached_active_branch_count += 1
                elif reaches_target is None:
                    unresolved_active_branch_count += 1
                else:
                    failed_active_branch_count += 1

        no_selected_active_path = not selected_results
        explicitly_nonforwarding = bool(paths) and all(
            item["plugin_terminal"]["classification"] == "not_delivered"
            and item["plugin_terminal"]["classification_complete"] is True
            for item in paths
        )
        if no_selected_active_path and explicitly_nonforwarding:
            state = "not_reached"
            reaches_target: bool | None = False
        elif no_selected_active_path:
            # Standby, rejected, or merely retained candidates are not
            # forwarding truth.  Do not promote the primary or first row.
            state = "unknown_no_selected_active_path"
            reaches_target = None
        elif all(item is True for item in selected_results):
            state = "reached"
            reaches_target = True
        elif any(item is None for item in selected_results):
            state = "unknown"
            reaches_target = None
        elif any(item is True for item in selected_results):
            state = "partial_active_reachability"
            reaches_target = None
        else:
            state = "not_reached"
            reaches_target = False
        all_active_branches_reach: bool | None = (
            None
            if not selected_results or any(
                item is None for item in selected_results
            )
            else all(item is True for item in selected_results)
        )
        return {
            "state": state,
            "reaches_target": reaches_target,
            "target_endpoint_id": target_endpoint_id,
            "target_attachment_ids": sorted(
                item[0] for item in target_attachment_identities
            ),
            "target_attachment_node_ids": sorted(
                item[1] for item in target_attachment_identities
            ),
            "attachments_complete": attachments_complete,
            "trace_start_node_id": trace_start["node_id"],
            "active_branch_count": active_branch_count,
            "reached_active_branch_count": reached_active_branch_count,
            "unresolved_active_branch_count": unresolved_active_branch_count,
            "failed_active_branch_count": failed_active_branch_count,
            "all_active_branches_reach": all_active_branches_reach,
            "selection_complete": not no_selected_active_path
            or explicitly_nonforwarding,
            "no_selected_active_path": no_selected_active_path,
            "criterion": "exact_normalized_endpoint_attachment",
            "terminal_classification_owner": "node_plugin",
            "aggregation_owner": "core",
        }

    @staticmethod
    def _validate_referenced_route_row(
        row: dict[str, Any] | None,
        trace_start: dict[str, Any],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
    ) -> None:
        if row is None:
            return
        expected = {
            "node_id": trace_start["node_id"],
            "destination_node_id": destination["node_id"],
            "vrf_id": routing_context["vrf_id"],
            "route_family": routing_context["route_family"],
            "route_type": routing_context["route_type"],
        }
        actual = {
            "node_id": row["node_id"],
            "destination_node_id": row["destination"]["node_id"],
            "vrf_id": row["vrf_id"],
            "route_family": row["route_family"],
            "route_type": row["route_type"],
        }
        if actual != expected:
            raise MultiNodeRouteRequestError(
                "route_entry_ref does not match the requested trace start, destination, "
                "VRF, family, and route type"
            )

    @staticmethod
    def _decorate_route_presentations(
        paths: list[dict[str, Any]],
        routing_context: dict[str, Any],
    ) -> None:
        """Attach plug-in-declared graph context without changing path geometry.

        These descriptors deliberately use protocol-neutral roles.  The demo
        plug-in decides which route types represent a tenant service; the core
        renderer must not infer that from a VRF name, VNI, label, SID, or text.
        """

        def node_topology_reference(node_id: str) -> dict[str, Any]:
            return {
                "match": {
                    "matcher_id": "demo.node-id.exact.v1",
                    "arguments": {"node_id": node_id},
                }
            }

        def target_topology_reference(
            target: dict[str, Any],
        ) -> dict[str, Any] | None:
            if target.get("kind") == "topology_link" and target.get("topology_link_id"):
                return {
                    "match": {
                        "matcher_id": "demo.topology-link-id.exact.v1",
                        "arguments": {"topology_link_id": target["topology_link_id"]},
                    }
                }
            if target.get("kind") == "topology_match" and target.get("matcher_id"):
                return {
                    "match": {
                        "matcher_id": target["matcher_id"],
                        "arguments": {"match_key": target.get("match_key")},
                    }
                }
            return None

        for path in paths:
            path_id = str(path["path_id"])
            node_sequence = [str(item) for item in path.get("node_sequence", [])]
            endpoint_refs = [
                {"node_id": node_id}
                for node_id in (
                    [node_sequence[0], node_sequence[-1]]
                    if len(node_sequence) >= 2
                    else node_sequence
                )
            ]
            topology_references = [
                node_topology_reference(item["node_id"])
                for item in endpoint_refs
            ]
            provenance = [dict(item) for item in path.get("plugin_provenance", [])]
            provided_by = next(
                (
                    item
                    for item in provenance
                    if item.get("ownership") == "node_plugin"
                    or item.get("decision_owner") == "node_route_plugin"
                ),
                provenance[0] if provenance else {"plugin_id": "unknown-plugin"},
            )
            boundary_segments = [
                item
                for item in path.get("segments", [])
                if item.get("segment_kind") == "inter_node_boundary"
                and item.get("participates_in_forwarding_geometry", True)
            ]
            principal = {
                "presentation_id": f"presentation:{path_id}:outer-l1-l3",
                "role": "principal",
                "scope": "path",
                "style": "path",
                "label": "Outer L1-L3 forwarding",
                "description": (
                    "Device cards are L3 resolution points; arrows are the "
                    "plug-in-resolved outer L1/L2 boundaries between them."
                ),
                "geometry_role": "forwarding",
                "participates_in_forwarding_geometry": True,
                "topology_references": topology_references,
                "anchor_resources": [],
                # Temporary response aliases consumed by older demo clients.
                "endpoint_refs": endpoint_refs,
                "segment_ids": [item["segment_id"] for item in boundary_segments],
                "topology_link_ids": [
                    item["topology_link_id"]
                    for item in boundary_segments
                    if item.get("topology_link_id")
                ],
                "facts": {
                    "layers": ["L1", "L2", "L3"],
                    "physical_boundaries": len(boundary_segments),
                },
                "semantic_owner": "plugin",
                "provided_by": dict(provided_by),
                "plugin_provenance": provenance,
            }
            layers = [principal]
            route_type = str(path.get("route_type") or routing_context.get("route_type") or "")
            service = _DEMO_SERVICE_PRESENTATION.get(route_type)
            encapsulation = dict(path.get("encapsulation") or {})
            if service:
                vrf_id = str(routing_context.get("vrf_id") or routing_context.get("vrf") or "default")
                facts: dict[str, Any] = {
                    "routing_context": vrf_id,
                    "route_family": routing_context.get("route_family"),
                    "protocol_chain": list(path.get("protocol_chain") or []),
                    "encapsulation": encapsulation,
                }
                evpn = dict(path.get("evpn") or {})
                if evpn:
                    facts["service_attributes"] = evpn
                topology_targets = list(path.get("presentation_topology_targets") or [])
                segment_key = _DEMO_VPN_SEGMENT_KEYS.get(vrf_id)
                if segment_key:
                    topology_targets.append(
                        {
                            "kind": "topology_match",
                            "matcher_id": "demo.connectivity-domain-key.exact.v1",
                            "match_key": segment_key,
                            "semantic_owner": "topology_plugin",
                        }
                    )
                alternative_state = str(path.get("alternative_state") or "")
                status = (
                    "withdrawn"
                    if alternative_state == "withdrawn_dead"
                    else "expected"
                    if alternative_state == "control_expected_not_observed"
                    else "active"
                    if path.get("active")
                    else "inactive"
                )
                overlay_topology_references = list(topology_references)
                overlay_topology_references.extend(
                    reference
                    for item in topology_targets
                    if (reference := target_topology_reference(item)) is not None
                )
                layers.append(
                    {
                        "presentation_id": f"presentation:{path_id}:service-overlay",
                        "group_id": (
                            f"service:{vrf_id}:{routing_context.get('route_family', route_type)}"
                        ),
                        "role": "overlay",
                        "scope": "path",
                        "style": "band",
                        "label": f"{vrf_id.title()} VPN overlay · {service['technology']}",
                        "description": (
                            f"{service['description']}. This encloses the outer path as "
                            "service context; it is not an extra forwarding hop."
                        ),
                        "geometry_role": "context",
                        "participates_in_forwarding_geometry": False,
                        "topology_references": overlay_topology_references,
                        "anchor_resources": [],
                        # Resolved targets and aliases are response extensions;
                        # the declarative contract remains authoritative above.
                        "endpoint_refs": endpoint_refs,
                        "topology_targets": topology_targets,
                        "interaction_target_ids": [
                            item["interaction_target_id"]
                            for item in topology_targets
                            if isinstance(item, dict) and item.get("interaction_target_id")
                        ],
                        "facts": {
                            key: value
                            for key, value in facts.items()
                            if value not in (None, [], {})
                        },
                        "status": status,
                        "semantic_owner": "plugin",
                        "provided_by": dict(provided_by),
                        "plugin_provenance": provenance,
                    }
                )
            elif encapsulation:
                layers.append(
                    {
                        "presentation_id": f"presentation:{path_id}:encapsulation",
                        "role": "annotation",
                        "scope": "path",
                        "style": "badge",
                        "label": "Encapsulation context",
                        "description": "Plug-in-declared encapsulation applied to the outer path.",
                        "geometry_role": "context",
                        "participates_in_forwarding_geometry": False,
                        "topology_references": topology_references,
                        "anchor_resources": [],
                        "endpoint_refs": endpoint_refs,
                        "facts": {"encapsulation": encapsulation},
                        "semantic_owner": "plugin",
                        "provided_by": dict(provided_by),
                        "plugin_provenance": provenance,
                    }
                )
            path["presentations"] = layers
            # Compatibility alias used by the current demo client while the
            # generalized API contract names this collection `presentations`.
            path["presentation_layers"] = layers

    def _attach_route_entry_refs(
        self,
        paths: list[dict[str, Any]],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
        referenced_row: dict[str, Any] | None,
        targets: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        entries = self._route_table_entries()
        all_refs: dict[str, dict[str, Any]] = {}
        for path in paths:
            sequence = list(path.get("node_sequence") or [])
            path_destination_node_id = str(
                path.get("destination_node_id") or destination["node_id"]
            )
            local_rows: list[dict[str, Any]] = []
            resolution_nodes = sequence if len(sequence) == 1 else sequence[:-1]
            for node_id in resolution_nodes:
                candidates = [
                    item
                    for item in entries
                    if item["node_id"] == node_id
                    and item["destination"]["node_id"]
                    == path_destination_node_id
                    and item["vrf_id"] == routing_context["vrf_id"]
                    and item["route_family"] == routing_context["route_family"]
                    and item["route_type"] == path.get("route_type")
                    and item["installed"]
                ]
                if (
                    node_id == sequence[0]
                    and referenced_row is not None
                    and referenced_row["path_id"] == path.get("path_id")
                ):
                    candidates = [referenced_row]
                elif candidates:
                    exact = next(
                        (
                            item
                            for item in candidates
                            if item["path_id"] == path.get("path_id")
                        ),
                        None,
                    )
                    candidates = [exact or candidates[0]]
                local_rows.extend(candidates[:1])
            refs = [item["route_entry_ref"] for item in local_rows]
            correlations = [
                {
                    "route_entry_ref": item["route_entry_ref"],
                    "route_entry_id": item["route_entry_id"],
                    "install_state": item["install_state"],
                    "installed": item["installed"],
                    "correlation_role": (
                        "control_plane_evidence"
                        if item["install_state"] == "control_plane_only"
                        else "forwarding_route"
                    ),
                }
                for item in local_rows
            ]
            path["route_entry_refs"] = refs
            path["matched_route_entry_refs"] = refs
            path["route_entry_correlations"] = correlations
            for row in local_rows:
                entry_id = row["route_entry_id"]
                all_refs[entry_id] = row["route_entry_ref"]
                target_id = self._target_id("route_table_row", entry_id)
                targets.setdefault(
                    target_id,
                    {
                        "target_id": target_id,
                        "kind": "route_table_row",
                        "label": (
                            f"{row['node_label']} {row['vrf_id']} "
                            f"{row['prefix']}"
                        ),
                        "node_id": row["node_id"],
                        "member_id": row["member_id"],
                        "route_entry_id": entry_id,
                        "route_entry_ref": row["route_entry_ref"],
                        "installed": row["installed"],
                        "install_state": row["install_state"],
                        "correlation_role": (
                            "control_plane_evidence"
                            if row["install_state"] == "control_plane_only"
                            else "forwarding_route"
                        ),
                        "trace_query": row["trace_query"],
                    },
                )
            refs_by_node = {
                item["node_id"]: item["route_entry_ref"] for item in local_rows
            }
            correlations_by_node = {
                item["node_id"]: correlation
                for item, correlation in zip(local_rows, correlations)
            }
            for segment in path.get("segments", []):
                node_id = segment.get("node_id")
                segment_refs = [refs_by_node[node_id]] if node_id in refs_by_node else []
                segment["route_entry_refs"] = segment_refs
                segment["route_entry_correlations"] = (
                    [correlations_by_node[node_id]]
                    if node_id in correlations_by_node
                    else []
                )
        return list(all_refs.values())

    def _resolve_trace_start(
        self,
        body: dict[str, Any],
        scenario: dict[str, Any],
        direction: str,
        directional_source: dict[str, Any],
    ) -> dict[str, Any]:
        """Resolve a traversal seed without changing the packet source.

        ``ingress`` is the forward observation point.  The reverse direction
        deliberately ignores it and defaults to the destination-side endpoint
        attachment unless ``trace_starts.reverse``/``reverse_ingress`` is
        explicitly supplied.
        """

        trace_starts = self._optional_object(body, "trace_starts")
        candidates: list[tuple[str, Any]] = []
        if trace_starts.get(direction) is not None:
            candidates.append((f"trace_starts.{direction}", trace_starts[direction]))
        if direction == "forward":
            for field in ("ingress", "starting_point", "start"):
                if body.get(field) is not None:
                    candidates.append((field, body[field]))
            if body.get("start_id") is not None:
                candidates.append(("start_id", body["start_id"]))
        elif body.get("reverse_ingress") is not None:
            candidates.append(("reverse_ingress", body["reverse_ingress"]))
        normalized_candidates = [
            (
                label,
                {"start_id": value} if isinstance(value, str) else value,
            )
            for label, value in candidates
        ]
        if any(not isinstance(value, dict) for _label, value in normalized_candidates):
            label = next(
                label
                for label, value in normalized_candidates
                if not isinstance(value, dict)
            )
            raise MultiNodeRouteRequestError(f"{label} must be an object or start ID")
        if len(normalized_candidates) > 1:
            encoded = {
                json.dumps(value, sort_keys=True, default=str)
                for _label, value in normalized_candidates
            }
            if len(encoded) > 1:
                raise MultiNodeRouteRequestError(
                    "trace start selectors for the requested direction disagree"
                )
        request = (
            dict(normalized_candidates[0][1])
            if normalized_candidates
            else {}
        )
        if (
            not request
            and direction == "forward"
            and scenario.get("default_start")
        ):
            request = {"start_id": scenario["default_start"]}

        derivation = str(
            request.get("derivation")
            or (
                "explicit_observation"
                if request
                else "source_endpoint_attachment"
                if direction == "forward"
                else "destination_endpoint_attachment"
            )
        )
        available_attachments = [
            dict(item)
            for item in directional_source.get("attachments", [])
            if item.get("state") not in {"withdrawn", "unavailable"}
            and item.get("can_originate", True)
        ]
        selected_attachment: dict[str, Any] | None = None
        if not request:
            router = self._router(str(directional_source["node_id"]))
            matching_attachments = [
                item
                for item in available_attachments
                if str(item.get("node_id")) == router["node_id"]
            ]
            if len(matching_attachments) == 1:
                selected_attachment = matching_attachments[0]
        else:
            ingress_ref = request.get("ingress_resource_ref")
            if ingress_ref is not None and not isinstance(ingress_ref, dict):
                raise MultiNodeRouteRequestError(
                    "ingress_resource_ref must be an object"
                )
            resource_id = request.get("resource_id") or (
                ingress_ref.get("resource_id") if ingress_ref else None
            )
            start_id = request.get("start_id")
            node_selectors = {
                str(value)
                for value in (
                    request.get("node_id"),
                    str(request["member_id"]).removeprefix("member:")
                    if request.get("member_id")
                    else None,
                    str(start_id).removeprefix("start:")
                    if start_id
                    else None,
                )
                if value is not None
            }
            if resource_id is not None:
                endpoint_attachment = next(
                    (
                        item
                        for item in available_attachments
                        if str(item.get("resource_id")) == str(resource_id)
                    ),
                    None,
                )
                resource_router = (
                    self._router(str(endpoint_attachment["node_id"]))
                    if endpoint_attachment is not None
                    else next(
                        (
                            item
                            for item in _ROUTERS
                            if item["loopback_resource_id"]
                            == str(resource_id)
                        ),
                        None,
                    )
                )
                if resource_router is None:
                    for boundary in _BOUNDARIES.values():
                        node_id = next(
                            (
                                candidate_node_id
                                for candidate_node_id, candidate_resource_id
                                in boundary["resources"].items()
                                if candidate_resource_id == str(resource_id)
                            ),
                            None,
                        )
                        if node_id:
                            resource_router = self._router(node_id)
                            break
                if resource_router is None:
                    raise MultiNodeRouteRequestError(
                        f"unknown trace start resource_id: {resource_id}"
                    )
                node_selectors.add(resource_router["node_id"])
            value = request.get("value") or request.get("label")
            if value is not None:
                normalized = str(value).strip().casefold()
                matches = [
                    item
                    for item in _ROUTERS
                    if normalized
                    in {
                        item["node_id"].casefold(),
                        item["label"].casefold(),
                        item["prefix"].casefold(),
                        item["prefix"].split("/", 1)[0].casefold(),
                    }
                ]
                if len(matches) != 1:
                    raise MultiNodeRouteRequestError(
                        f"unknown or ambiguous trace start value: {value}"
                    )
                node_selectors.add(matches[0]["node_id"])
            if not node_selectors:
                raise MultiNodeRouteRequestError(
                    "trace start requires start_id, node_id, member_id, "
                    "resource_id, or value"
                )
            if len(node_selectors) != 1:
                raise MultiNodeRouteRequestError(
                    "trace start identifiers disagree"
                )
            router = self._router(next(iter(node_selectors)))
            matching_attachments = [
                item
                for item in available_attachments
                if str(item.get("node_id")) == router["node_id"]
                and (
                    resource_id is None
                    or str(item.get("resource_id")) == str(resource_id)
                )
            ]
            if len(matching_attachments) == 1:
                selected_attachment = matching_attachments[0]
            elif len(matching_attachments) > 1:
                raise MultiNodeRouteRequestError(
                    "trace start matches multiple endpoint attachments; "
                    "supply resource_id"
                )

        if (
            router["node_id"] != directional_source["node_id"]
            and not scenario.get("supports_explicit_start")
            and not scenario.get("supports_arbitrary_endpoints")
        ):
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} does not advertise a "
                "transit trace start"
            )
        return {
            "start_id": f"start:{router['node_id']}",
            "node_id": router["node_id"],
            "member_id": (
                selected_attachment.get("member_id")
                if selected_attachment is not None
                else f"member:{router['node_id']}"
            ),
            "resource_id": (
                selected_attachment.get("resource_id")
                if selected_attachment is not None
                else request.get("resource_id") or router["loopback_resource_id"]
            ),
            "attachment_id": (
                selected_attachment.get("attachment_id")
                if selected_attachment is not None
                else None
            ),
            "label": router["label"],
            "site": router["site"],
            "role": router["role"],
            "derivation": derivation,
            "semantic_role": "traversal_seed",
        }

    def _resolve_endpoints(
        self, body: dict[str, Any], scenario_id: str, direction: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        source_request = self._optional_object(body, "source")
        destination_request = self._optional_object(body, "destination")
        routers_by_source = {item["source_id"]: item for item in _ROUTERS}
        routers_by_source.update(
            {
                self._router_endpoint_id(item["node_id"]): item
                for item in _ROUTERS
            }
        )
        routers_by_destination = {
            item["destination_id"]: item for item in _ROUTERS
        }
        routers_by_destination.update(
            {
                self._router_endpoint_id(item["node_id"]): item
                for item in _ROUTERS
            }
        )
        routers_by_destination["destination:blue-service-prefix"] = self._router(
            "node-b"
        )
        routers_by_destination["endpoint:blue-service-prefix"] = self._router(
            "node-b"
        )
        routers_by_destination[
            "destination:east-evpn-multihomed-service"
        ] = self._router("node-e")
        routers_by_destination[
            "endpoint:east-evpn-multihomed-service"
        ] = self._router("node-e")
        routers_by_destination["destination:eta-external-subnet"] = self._router(
            "node-e"
        )
        routers_by_destination["endpoint:eta-external-subnet"] = self._router(
            "node-e"
        )
        routers_by_resource = {
            item["loopback_resource_id"]: item for item in _ROUTERS
        }
        routers_by_resource["node-e/INTERFACE/et-0-0-20"] = self._router(
            "node-e"
        )
        routers_by_resource["node-e/ETHERNET_SEGMENT/esi-east"] = self._router(
            "node-e"
        )
        for boundary in _BOUNDARIES.values():
            for node_id, resource_id in boundary["resources"].items():
                routers_by_resource[resource_id] = self._router(node_id)

        def router_from_value(value: Any, field: str) -> dict[str, Any] | None:
            if value is None:
                return None
            text = str(value).strip()
            normalized = text.casefold()
            if text in routers_by_resource:
                return routers_by_resource[text]
            candidates = [
                item
                for item in _ROUTERS
                if normalized
                in {
                    item["node_id"].casefold(),
                    item["label"].casefold(),
                    item["prefix"].casefold(),
                    item["prefix"].split("/", 1)[0].casefold(),
                }
            ]
            for index, router in enumerate(_ROUTERS, start=1):
                srv6_values = {
                    f"2001:db8:{index:x}::/128",
                    f"2001:db8:{index:x}::",
                }
                if normalized in {item.casefold() for item in srv6_values}:
                    candidates = [router]
                    break
            if normalized in {"203.0.113.0/24", "203.0.113.0"}:
                if field != "destination":
                    raise MultiNodeRouteRequestError(
                        f"ambiguous {field} value: {value}"
                    )
                if scenario_id in _EXTERNAL_SUBNET_SCENARIOS:
                    candidates = [self._router("node-e")]
                elif scenario_id in _BLUE_SERVICE_SCENARIOS:
                    candidates = [self._router("node-b")]
                else:
                    raise MultiNodeRouteRequestError(
                        f"ambiguous {field} value: {value}; use an advertised "
                        "destination_id"
                    )
            if normalized == "blue service":
                candidates = [self._router("node-b")]
            if normalized in {"eta external", "external subnet"}:
                candidates = [self._router("node-e")]
            if normalized in {
                "east evpn service",
                "esi-east:vlan-320",
                "east ethernet segment",
            }:
                candidates = [self._router("node-e")]
            if not candidates:
                raise MultiNodeRouteRequestError(
                    f"unknown {field} value: {value}"
                )
            if len(candidates) > 1:
                raise MultiNodeRouteRequestError(
                    f"ambiguous {field} value: {value}"
                )
            return candidates[0]

        source_id = (
            body.get("source_id")
            or source_request.get("source_id")
            or source_request.get("endpoint_id")
        )
        source_node_id = source_request.get("node_id")
        source_value = body.get("source_value") or source_request.get("value")
        if source_value is not None:
            value_router = router_from_value(source_value, "source")
            if source_node_id and value_router["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError(
                    "source value and source.node_id disagree"
                )
            source_node_id = value_router["node_id"]
        if source_request.get("resource_id"):
            record = routers_by_resource.get(str(source_request["resource_id"]))
            if record is None:
                raise MultiNodeRouteRequestError(
                    f"unknown source resource_id: {source_request['resource_id']}"
                )
            if source_node_id and record["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError(
                    "source.resource_id and source.node_id disagree"
                )
            source_node_id = record["node_id"]
        if source_id is not None:
            source_router = routers_by_source.get(str(source_id))
            if source_router is None:
                source_router = router_from_value(source_id, "source")
            if source_node_id and source_router["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError("source_id and source.node_id disagree")
            source_node_id = source_router["node_id"]

        destination_id = (
            body.get("destination_id")
            or destination_request.get("destination_id")
            or destination_request.get("endpoint_id")
        )
        destination_node_id = destination_request.get("node_id")
        if destination_request.get("resource_id"):
            record = routers_by_resource.get(
                str(destination_request["resource_id"])
            )
            if record is None:
                raise MultiNodeRouteRequestError(
                    "unknown destination resource_id: "
                    f"{destination_request['resource_id']}"
                )
            if destination_node_id and record["node_id"] != str(
                destination_node_id
            ):
                raise MultiNodeRouteRequestError(
                    "destination.resource_id and destination.node_id disagree"
                )
            destination_node_id = record["node_id"]
        destination_value = body.get("destination_value") or destination_request.get(
            "value"
        )
        destination_value_text = str(destination_value or "").casefold()
        destination_is_blue_service = destination_value_text == "blue service" or (
            destination_value_text in {"203.0.113.0/24", "203.0.113.0"}
            and scenario_id in _BLUE_SERVICE_SCENARIOS
        )
        destination_is_east_evpn = str(destination_value or "").casefold() in {
            "east evpn service",
            "esi-east:vlan-320",
            "east ethernet segment",
        }
        destination_is_external = destination_value_text in {
            "eta external",
            "external subnet",
        } or (
            destination_value_text in {"203.0.113.0/24", "203.0.113.0"}
            and scenario_id in _EXTERNAL_SUBNET_SCENARIOS
        )
        if destination_value is not None:
            value_router = router_from_value(destination_value, "destination")
            if (
                destination_node_id
                and value_router["node_id"] != str(destination_node_id)
            ):
                raise MultiNodeRouteRequestError(
                    "destination value and destination.node_id disagree"
                )
            destination_node_id = value_router["node_id"]
        if destination_id is not None:
            destination_id_text = str(destination_id)
            allowed_destination_ids = _SCENARIO_DESTINATION_IDS.get(scenario_id)
            if (
                allowed_destination_ids is not None
                and destination_id_text.startswith("destination:")
                and destination_id_text not in allowed_destination_ids
            ):
                raise MultiNodeRouteRequestError(
                    f"destination_id {destination_id_text} is not supported by "
                    f"scenario {scenario_id}"
                )
            destination_router = routers_by_destination.get(str(destination_id))
            if destination_router is None:
                destination_router = router_from_value(
                    destination_id, "destination"
                )
                destination_is_blue_service = str(destination_id).casefold() in {
                    "203.0.113.0/24",
                    "203.0.113.0",
                    "blue service",
                }
            destination_is_blue_service = destination_is_blue_service or (
                destination_id_text == "destination:blue-service-prefix"
            )
            destination_is_east_evpn = destination_is_east_evpn or str(
                destination_id
            ) == "destination:east-evpn-multihomed-service"
            destination_is_external = destination_is_external or str(
                destination_id
            ) == "destination:eta-external-subnet"
            if (
                destination_node_id
                and destination_router["node_id"] != str(destination_node_id)
            ):
                raise MultiNodeRouteRequestError(
                    "destination_id and destination.node_id disagree"
                )
            destination_node_id = destination_router["node_id"]

        fixed_pairs = {
            "single-active-primary": ("node-a", "node-b"),
            "all-active-ecmp": ("node-a", "node-b"),
            "cross-layer-inconsistent": ("node-a", "node-b"),
            "incomplete-node-resolution": ("node-a", "node-b"),
            "transit-start-endpoint-reachability": ("node-a", "node-b"),
            "site-a-site-c-asymmetric": ("node-a", "node-c"),
            "site-b-site-c-one-way": ("node-b", "node-c"),
            "evpn-mh-all-active": ("node-a", "node-e"),
            "evpn-es-withdraw-failover": ("node-a", "node-e"),
            "evpn-stale-fib-after-withdraw": ("node-a", "node-e"),
            "srv6-all-active": ("node-a", "node-e"),
            "recursive-static-to-external": ("node-a", "node-e"),
            "recursive-resolution-cycle": ("node-a", "node-b"),
            "cross-node-forwarding-loop": ("node-a", "node-b"),
            "evpn-split-horizon-block": ("node-b", "node-e"),
            "connected-external-subnet": ("node-e", "node-e"),
            "incomplete-intermediate-resolution": ("node-d", "node-b"),
            **{
                scenario_id: ("node-a", "node-b")
                for scenario_id in ADVANCED_TRACE_SCENARIO_IDS
            },
        }
        if scenario_id in fixed_pairs:
            base_source, base_destination = fixed_pairs[scenario_id]
            supplied_pair = (
                str(source_node_id or base_source),
                str(destination_node_id or base_destination),
            )
            allowed_pairs = {(base_source, base_destination)}
            if base_source != base_destination:
                allowed_pairs.add((base_destination, base_source))
            if supplied_pair not in allowed_pairs:
                raise MultiNodeRouteRequestError(
                    f"scenario {scenario_id} is scoped to {base_source}/{base_destination}"
                )
        else:
            base_source = str(source_node_id or "node-a")
            base_destination = str(destination_node_id or "node-b")
            self._router(base_source)
            self._router(base_destination)
        actual_source, actual_destination = (
            (base_destination, base_source)
            if direction == "reverse"
            else (base_source, base_destination)
        )
        if actual_source == actual_destination and scenario_id != "connected-external-subnet":
            raise MultiNodeRouteRequestError(
                "source and destination must be different routers"
            )
        source_router = self._router(actual_source)
        destination_router = self._router(actual_destination)
        resolved_source = {
            "endpoint_id": self._router_endpoint_id(source_router["node_id"]),
            "source_id": source_router["source_id"],
            "node_id": source_router["node_id"],
            "member_id": f"member:{source_router['node_id']}",
            "resource_id": source_router["loopback_resource_id"],
            "label": source_router["label"],
            "site": source_router["site"],
            "role": source_router["role"],
        }
        if direction == "forward" and scenario_id in {
            "evpn-mh-all-active",
            "evpn-es-withdraw-failover",
            "evpn-stale-fib-after-withdraw",
            "evpn-split-horizon-block",
        }:
            destination_is_east_evpn = True
        if (
            direction == "forward"
            or scenario_id == "connected-external-subnet"
        ) and scenario_id in {
            "recursive-static-to-external",
            "connected-external-subnet",
        }:
            destination_is_external = True
        if direction == "forward" and scenario_id in _BLUE_SERVICE_SCENARIOS:
            destination_is_blue_service = True
        if direction == "reverse" and scenario_id != "connected-external-subnet":
            # Destination selectors describe the base forward pair.  In the
            # reverse trace the service/subnet is the source-side endpoint and
            # the resolved destination is the opposite router loopback.
            destination_is_blue_service = False
            destination_is_east_evpn = False
            destination_is_external = False
        resolved_destination = {
            "endpoint_id": (
                "endpoint:east-evpn-multihomed-service"
                if destination_is_east_evpn
                else "endpoint:eta-external-subnet"
                if destination_is_external
                else "endpoint:blue-service-prefix"
                if direction == "forward"
                and (
                    destination_is_blue_service
                    or destination_id
                    in {
                        "destination:blue-service-prefix",
                        "endpoint:blue-service-prefix",
                    }
                    or scenario_id in _BLUE_SERVICE_SCENARIOS
                )
                else self._router_endpoint_id(destination_router["node_id"])
            ),
            "destination_id": (
                "destination:east-evpn-multihomed-service"
                if destination_is_east_evpn
                else "destination:eta-external-subnet"
                if destination_is_external
                else
                "destination:blue-service-prefix"
                if direction == "forward"
                and (
                    destination_is_blue_service
                    or destination_id == "destination:blue-service-prefix"
                    or scenario_id
                    in {
                        "single-active-primary",
                        "all-active-ecmp",
                        "cross-layer-inconsistent",
                        "incomplete-node-resolution",
                    }
                )
                else destination_router["destination_id"]
            ),
            "node_id": destination_router["node_id"],
            "member_id": f"member:{destination_router['node_id']}",
            "resource_id": (
                destination_router.get("external_interface_resource_id")
                if destination_is_external
                else "node-e/ETHERNET_SEGMENT/esi-east"
                if destination_is_east_evpn
                else destination_router["loopback_resource_id"]
            ),
            "kind": (
                "evpn_ethernet_segment"
                if destination_is_east_evpn
                else "ip_prefix"
                if destination_is_blue_service or destination_is_external
                else "router_loopback"
            ),
            "value": (
                "esi-east:vlan-320"
                if destination_is_east_evpn
                else "203.0.113.0/24"
                if destination_is_blue_service or destination_is_external
                else destination_router["prefix"]
            ),
            "label": (
                "East EVPN multihomed service"
                if destination_is_east_evpn
                else "PE-E external subnet"
                if destination_is_external
                else destination_router["label"]
            ),
            "site": destination_router["site"],
            "role": destination_router["role"],
        }
        if destination_is_east_evpn:
            resolved_destination["terminating_node_ids"] = ["node-b", "node-e"]
        resolved_destination["attachments"] = [
            self._endpoint_attachment(
                endpoint_id=resolved_destination["endpoint_id"],
                node_id=node_id,
                member_id=f"member:{node_id}",
                resource_id=(
                    f"{node_id}/ETHERNET_SEGMENT/esi-east"
                    if destination_is_east_evpn
                    else resolved_destination["resource_id"]
                ),
            )
            for node_id in resolved_destination.get(
                "terminating_node_ids", [resolved_destination["node_id"]]
            )
        ]
        resolved_destination["attachments_complete"] = True
        resolved_source["attachments"] = [
            self._endpoint_attachment(
                endpoint_id=resolved_source["endpoint_id"],
                node_id=resolved_source["node_id"],
                member_id=resolved_source["member_id"],
                resource_id=resolved_source["resource_id"],
            )
        ]
        resolved_source["attachments_complete"] = True
        return resolved_source, resolved_destination

    @staticmethod
    def _directional_pair(
        scenario_id: str,
        direction: str,
        source: dict[str, Any],
        destination: dict[str, Any],
    ) -> dict[str, Any]:
        fixed = {
            "site-a-site-c-asymmetric": (
                "pair:pe-a-pe-c-asymmetric",
                "node-a",
                "node-c",
            ),
            "site-b-site-c-one-way": (
                "pair:pe-b-pe-c-one-way",
                "node-b",
                "node-c",
            ),
        }
        if scenario_id in fixed:
            pair_id, base_source, base_destination = fixed[scenario_id]
        else:
            base_source = source["node_id"]
            base_destination = destination["node_id"]
            pair_id = (
                f"pair:{source.get('endpoint_id', base_source)}:"
                f"{destination.get('endpoint_id', base_destination)}"
            )
        return {
            "pair_id": pair_id,
            "scenario_id": scenario_id,
            "base_source_node_id": base_source,
            "base_destination_node_id": base_destination,
            "source_endpoint_id": source.get("endpoint_id"),
            "destination_endpoint_id": destination.get("endpoint_id"),
            "requested_direction": direction,
        }

    @classmethod
    def _validate_pair_reverse_start(
        cls,
        flow_destination: dict[str, Any],
        reverse_start: dict[str, Any],
    ) -> None:
        """Require a pair's return observation to start at its destination."""

        allowed = {
            cls._attachment_identity(
                item,
                label="traffic destination attachment",
            )
            for item in flow_destination.get("attachments", [])
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        observed = (
            reverse_start.get("attachment_id"),
            reverse_start.get("node_id"),
            reverse_start.get("member_id"),
            reverse_start.get("resource_id"),
        )
        if observed not in allowed:
            raise MultiNodeRouteRequestError(
                "bidirectional reverse trace start must resolve to an "
                "available attachment of flow.destination"
            )

    def _bidirectional_response(
        self,
        scenario: dict[str, Any],
        route_type: str,
        resolution_mode: str,
        forward: dict[str, Any],
        reverse: dict[str, Any],
    ) -> dict[str, Any]:
        forward_active_paths = [
            item for item in forward["paths"] if item.get("active")
        ]
        reverse_active_paths = [
            item for item in reverse["paths"] if item.get("active")
        ]
        forward_path = (
            forward_active_paths[0]
            if forward_active_paths
            else forward["paths"][0]
        )
        reverse_path = (
            reverse_active_paths[0]
            if reverse_active_paths
            else reverse["paths"][0]
        )
        forward_start_attachment = (
            forward["trace_start"].get("attachment_id"),
            forward["trace_start"].get("node_id"),
            forward["trace_start"].get("member_id"),
            forward["trace_start"].get("resource_id"),
        )
        forward_source_attachments = {
            self._attachment_identity(
                item,
                label="traffic source attachment",
            )
            for item in forward["flow"]["source"].get("attachments", [])
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        reverse_start_attachment = (
            reverse["trace_start"].get("attachment_id"),
            reverse["trace_start"].get("node_id"),
            reverse["trace_start"].get("member_id"),
            reverse["trace_start"].get("resource_id"),
        )
        reverse_destination_attachments = {
            self._attachment_identity(
                item,
                label="traffic destination attachment",
            )
            for item in forward["flow"]["destination"].get(
                "attachments", []
            )
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        forward_sequence = list(forward_path.get("node_sequence", []))
        reverse_sequence = list(reverse_path.get("node_sequence", []))
        multipath = (
            str(scenario.get("multipath_mode")) == "all_active"
            or len(forward_active_paths) > 1
            or len(reverse_active_paths) > 1
        )

        def directional_state(trace: dict[str, Any]) -> str:
            state = str(
                trace.get("endpoint_reachability", {}).get(
                    "state", "unknown"
                )
            )
            return (
                state
                if state
                in {
                    "reached",
                    "not_reached",
                    "unknown",
                    "partial_active_reachability",
                }
                else "unknown"
            )

        evaluation: EndpointReachabilityPairEvaluation = (
            evaluate_endpoint_reachability_pair(
                forward_reaches_destination=forward.get(
                    "endpoint_reachability", {}
                ).get("reaches_target"),
                reverse_reaches_source=reverse.get(
                    "endpoint_reachability", {}
                ).get("reaches_target"),
                forward_complete=bool(forward["complete"]),
                reverse_complete=bool(reverse["complete"]),
                forward_node_sequence=tuple(forward_sequence),
                reverse_node_sequence=tuple(reverse_sequence),
                forward_start_node_id=forward["trace_start"]["node_id"],
                traffic_source_node_id=forward["flow"]["source"]["node_id"],
                forward_starts_at_source_endpoint=(
                    forward_start_attachment in forward_source_attachments
                ),
                reverse_starts_at_destination_endpoint=(
                    reverse_start_attachment
                    in reverse_destination_attachments
                ),
                forward_reachability_state=directional_state(forward),
                reverse_reachability_state=directional_state(reverse),
                forward_branch_node_sequences=(
                    tuple(
                        tuple(str(node_id) for node_id in path["node_sequence"])
                        for path in forward_active_paths
                    )
                    if multipath
                    else None
                ),
                reverse_branch_node_sequences=(
                    tuple(
                        tuple(str(node_id) for node_id in path["node_sequence"])
                        for path in reverse_active_paths
                    )
                    if multipath
                    else None
                ),
                multipath=multipath,
            )
        )
        comparison = evaluation.comparison_state
        issue_refs = list(
            dict.fromkeys(
                item["issue_id"]
                for trace in (forward, reverse)
                for item in trace.get("issues", [])
            )
        )
        combined_issues = list(
            {
                item["issue_id"]: item
                for trace in (forward, reverse)
                for item in trace.get("issues", [])
            }.values()
        )
        directional_consistent = all(
            bool(trace.get("consistency", {}).get("consistent"))
            for trace in (forward, reverse)
        )
        endpoint_consistent = evaluation.consistent
        overall_consistent = directional_consistent and endpoint_consistent
        directional_inconsistent_state = next(
            (
                str(trace.get("consistency", {}).get("state"))
                for trace in (forward, reverse)
                if not trace.get("consistency", {}).get("consistent")
            ),
            None,
        )
        overall_consistency_state = (
            directional_inconsistent_state
            if directional_inconsistent_state
            else evaluation.endpoint_state
        )
        trace_id = "rtrace-pair1-" + hashlib.sha256(
            f"{forward['trace_id']}:{reverse['trace_id']}".encode("utf-8")
        ).hexdigest()[:24]
        response = dict(forward)
        response.update(
            {
                "trace_id": trace_id,
                "trace_mode": "bidirectional",
                "direction": "both",
                "scenario": dict(scenario),
                "route_type": route_type,
                "resolution_mode": resolution_mode,
                "resolution_policy": resolution_mode,
                "completeness_policy": resolution_mode,
                "traces": {"forward": forward, "reverse": reverse},
                "directional_traces": {"forward": forward, "reverse": reverse},
                "forward_trace": forward,
                "reverse_trace": reverse,
                "routing_contexts": {
                    "forward": forward["routing_context"],
                    "reverse": reverse["routing_context"],
                },
                "bidirectional_validation": {
                    "state": comparison,
                    "criterion": "source_destination_endpoint_reachability",
                    "endpoint_state": evaluation.endpoint_state,
                    "consistent": evaluation.consistent,
                    "forward_reaches_destination": (
                        evaluation.forward_reaches_destination
                    ),
                    "reverse_reaches_source": evaluation.reverse_reaches_source,
                    "forward_reachability_state": (
                        evaluation.forward_reachability_state
                    ),
                    "reverse_reachability_state": (
                        evaluation.reverse_reachability_state
                    ),
                    # Compatibility aliases are endpoint-goal results, not
                    # merely continuous line/segment results.
                    "forward_reachable": evaluation.forward_reaches_destination,
                    "reverse_reachable": evaluation.reverse_reaches_source,
                    "one_way": evaluation.endpoint_state
                    == "one_way_reachable",
                    "symmetric_node_sequence": evaluation.path_relation
                    == "symmetric",
                    "forward_node_sequence": forward_sequence,
                    "reverse_node_sequence": reverse_sequence,
                    "path_relation": {
                        "state": evaluation.path_relation,
                        "reason": evaluation.path_relation_reason,
                        "basis": evaluation.path_relation_basis,
                        "comparison_affects_consistency": False,
                    },
                    "forward_start": forward["trace_start"],
                    "reverse_start": reverse["trace_start"],
                    "reverse_must_visit_forward_start": (
                        evaluation.reverse_must_visit_forward_start
                    ),
                    "reverse_visits_forward_start": (
                        evaluation.reverse_visits_forward_start
                    ),
                    "issue_refs": issue_refs,
                    "ownership": (
                        "core matches typed terminal endpoints and aggregates "
                        "directional goals; plugins own each next-hop and local "
                        "terminal classification"
                    ),
                },
                "endpoint_reachability": {
                    "criterion": "source_destination_endpoint_reachability",
                    "state": evaluation.endpoint_state,
                    "consistent": evaluation.consistent,
                    "forward_reaches_destination": (
                        evaluation.forward_reaches_destination
                    ),
                    "reverse_reaches_source": evaluation.reverse_reaches_source,
                    "forward_state": evaluation.forward_reachability_state,
                    "reverse_state": evaluation.reverse_reachability_state,
                    "flow": forward["flow"],
                    "reverse_must_visit_forward_start": False,
                },
                "path_relation": {
                    "state": evaluation.path_relation,
                    "reason": evaluation.path_relation_reason,
                    "basis": evaluation.path_relation_basis,
                    "forward_node_sequence": forward_sequence,
                    "reverse_node_sequence": reverse_sequence,
                    "reverse_visits_forward_start": (
                        evaluation.reverse_visits_forward_start
                    ),
                    "affects_consistency": False,
                },
                "issues": combined_issues,
                "issue_index": {
                    item["issue_id"]: item for item in combined_issues
                },
                "consistency": {
                    "state": overall_consistency_state,
                    "comparison_state": comparison,
                    "endpoint_state": evaluation.endpoint_state,
                    "criterion": (
                        "directional_findings_and_source_destination_"
                        "endpoint_reachability"
                    ),
                    "consistent": overall_consistent,
                    "endpoint_consistent": endpoint_consistent,
                    "directional_consistent": directional_consistent,
                    "issue_refs": issue_refs,
                    "directional": True,
                },
                "complete": forward["complete"] and reverse["complete"],
                "reachable": evaluation.consistent,
                "completeness": {
                    "state": (
                        "complete"
                        if forward["complete"] and reverse["complete"]
                        else "partial"
                    ),
                    "forward_complete": forward["complete"],
                    "reverse_complete": reverse["complete"],
                    "forward_reachable": forward["reachable"],
                    "reverse_reachable": reverse["reachable"],
                },
            }
        )
        return response

    @staticmethod
    def _default_focus(paths: list[dict[str, Any]]) -> str:
        primary = next((item for item in paths if item["primary"]), None)
        if primary:
            return str(primary["path_id"])
        active = next((item for item in paths if item["active"]), None)
        return str((active or paths[0])["path_id"])

    @staticmethod
    def _boundary_descriptor(left: str, right: str) -> dict[str, Any]:
        descriptor = _BOUNDARIES.get((left, right)) or _BOUNDARIES.get((right, left))
        if descriptor is None:
            raise MultiNodeRouteRequestError(
                f"plug-in route references a non-existent physical boundary: {left}/{right}"
            )
        return descriptor

    def _generic_path(
        self,
        node_sequence: list[str],
        route_type: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        *,
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str] | None = None,
        candidate_id: str | None = None,
        allow_repeated_nodes: bool = False,
        destination_node_id: str | None = None,
        terminal_next_hop_node_id: str | None = None,
    ) -> dict[str, Any]:
        if len(node_sequence) < 2:
            raise MultiNodeRouteRequestError(
                "plug-in route node_sequence must contain at least two routers"
            )
        has_repeated_nodes = len(set(node_sequence)) != len(node_sequence)
        if has_repeated_nodes and not allow_repeated_nodes:
            raise MultiNodeRouteRequestError(
                "plug-in route node_sequence repeats a router without explicit "
                "diagnostic-loop retention"
            )
        issue_refs = list(issue_refs or [])
        destination = self._router(destination_node_id or node_sequence[-1])
        via = "-".join(node_sequence[1:-1]) or "direct"
        path_id = (
            f"route-path:{node_sequence[0]}:{destination['node_id']}:"
            f"{route_type}:via-{via}"
        )
        if candidate_id:
            path_id = f"{path_id}:candidate-{candidate_id}"
        segments: list[dict[str, Any]] = []
        ordinal = 1
        first_boundary = self._boundary_descriptor(
            node_sequence[0], node_sequence[1]
        )
        source_router = self._router(node_sequence[0])
        segments.append(
            self._local_segment(
                f"segment:{path_id}:source",
                ordinal,
                node_sequence[0],
                [
                    source_router["loopback_resource_id"],
                    first_boundary["resources"][node_sequence[0]],
                ],
                (
                    f"The {node_sequence[0]} route plug-in resolves {destination['prefix']} "
                    f"as {route_type} toward {node_sequence[1]}."
                ),
                resources,
                targets,
                active,
                primary,
                alternative_state,
                issue_refs,
            )
        )
        ordinal += 1
        for index, (left, right) in enumerate(
            zip(node_sequence, node_sequence[1:])
        ):
            boundary = self._boundary_descriptor(left, right)
            segments.append(
                self._boundary_segment(
                    f"segment:{path_id}:boundary:{index + 1}",
                    ordinal,
                    [
                        boundary["resources"][left],
                        boundary["resources"][right],
                    ],
                    boundary["link_id"],
                    (
                        f"The federation linker maps the plug-in-declared {left} "
                        f"egress to the {right} ingress without interpreting route semantics."
                    ),
                    resources,
                    links,
                    targets,
                    active,
                    primary,
                    alternative_state,
                    issue_refs,
                )
            )
            ordinal += 1
            at_last_occurrence = index == len(node_sequence) - 2
            if at_last_occurrence and terminal_next_hop_node_id is not None:
                next_boundary = self._boundary_descriptor(
                    right, terminal_next_hop_node_id
                )
                end_ids = [
                    boundary["resources"][right],
                    next_boundary["resources"][right],
                ]
                text = (
                    f"The {right} route plug-in resolves {destination['prefix']} "
                    f"from {left} back toward {terminal_next_hop_node_id} for "
                    f"{route_type}."
                )
            elif at_last_occurrence:
                end_ids = [
                    boundary["resources"][right],
                    destination["loopback_resource_id"],
                ]
                text = (
                    f"The {right} route plug-in terminates {route_type} resolution "
                    f"at {destination['prefix']}."
                )
            else:
                next_boundary = self._boundary_descriptor(
                    right, node_sequence[index + 2]
                )
                end_ids = [
                    boundary["resources"][right],
                    next_boundary["resources"][right],
                ]
                text = (
                    f"The {right} route plug-in resolves {destination['prefix']} "
                    f"from {left} toward {node_sequence[index + 2]} for {route_type}."
                )
            segments.append(
                self._local_segment(
                    (
                        f"segment:{path_id}:node:{index + 1}:{right}"
                        if has_repeated_nodes
                        else f"segment:{path_id}:node:{right}"
                    ),
                    ordinal,
                    right,
                    end_ids,
                    text,
                    resources,
                    targets,
                    active,
                    primary,
                    alternative_state,
                    issue_refs,
                )
            )
            ordinal += 1
        path = self._path(
            path_id,
            (
                f"{route_type.replace('_', ' ').upper()} "
                + (
                    f"via {' -> '.join(node_sequence[1:-1])}"
                    if node_sequence[1:-1]
                    else "direct"
                )
            ),
            segments,
            active,
            primary,
            alternative_state,
            "forwarding_observed",
            issue_refs,
        )
        path["node_sequence"] = list(node_sequence)
        path["destination_node_id"] = destination["node_id"]
        path["route_type"] = route_type
        path["candidate_id"] = candidate_id or path_id
        local_segments = [
            item for item in segments if item["segment_kind"] == "node_resolution"
        ]
        for index, segment in enumerate(local_segments):
            phase = (
                "local_lookup"
                if index == 0
                else "remote_ingress"
                if index == len(local_segments) - 1
                else "next_hop"
            )
            if route_type == "static_recursive" and index == 1:
                phase = "recursive_lookup"
            segment["phase"] = phase
            segment["route_resolution"]["phase"] = phase
        for segment in segments:
            if segment["segment_kind"] == "inter_node_boundary":
                segment["phase"] = "federation_boundary"
                segment["route_resolution"]["phase"] = "federation_boundary"
        semantic_profiles: dict[str, dict[str, Any]] = {
            "ipv4_unicast": {
                "protocol_chain": ["ibgp", "isis-l2"],
                "encapsulation": {"kind": "ip"},
            },
            "ipv6_unicast": {
                "protocol_chain": ["ibgp", "isis-l2"],
                "encapsulation": {"kind": "ipv6"},
            },
            "connected": {
                "protocol_chain": ["connected"],
                "encapsulation": {"kind": "native"},
            },
            "static_recursive": {
                "protocol_chain": ["static", "ibgp", "isis-l2"],
                "encapsulation": {"kind": "recursive_ip_transport"},
            },
            "isis_underlay": {
                "protocol_chain": ["isis-l2"],
                "encapsulation": {"kind": "ip"},
            },
            "mpls_transport": {
                "protocol_chain": ["isis-l2", "segment-routing-mpls"],
                "encapsulation": {"kind": "mpls", "actions": ["push", "swap", "pop"]},
            },
            "mpls_l3vpn": {
                "protocol_chain": ["bgp-vpnv4", "segment-routing-mpls"],
                "encapsulation": {
                    "kind": "mpls_l3vpn",
                    "actions": ["push_transport_and_vpn", "swap", "pop"],
                },
            },
            "srv6_policy": {
                "protocol_chain": ["bgp-sr-policy", "isis-l2"],
                "encapsulation": {"kind": "srv6", "actions": ["encap", "end", "decap"]},
            },
            "evpn_service": {
                "protocol_chain": ["bgp-evpn", "isis-l2"],
                "encapsulation": {"kind": "vxlan", "vni": 10100},
            },
            "evpn_mac_ip": {
                "protocol_chain": ["bgp-evpn", "isis-l2"],
                "encapsulation": {"kind": "vxlan", "vni": 10320, "evpn_route_type": 2},
            },
            "evpn_ip_prefix": {
                "protocol_chain": ["bgp-evpn", "isis-l2"],
                "encapsulation": {"kind": "vxlan", "vni": 10330, "evpn_route_type": 5},
            },
        }
        path.update(semantic_profiles.get(route_type, {}))
        source_text_by_type = {
            "ipv4_unicast": (
                f"The {node_sequence[0]} BGP resolver selects an IPv4 unicast next "
                f"hop toward {node_sequence[1]} for {destination['prefix']}."
            ),
            "ipv6_unicast": (
                f"The {node_sequence[0]} BGP resolver selects an IPv6 next hop "
                f"toward {node_sequence[1]} for {destination['prefix']}."
            ),
            "connected": (
                f"The {node_sequence[0]} connected-route resolver selects its "
                f"on-link attachment toward {node_sequence[1]}."
            ),
            "static_recursive": (
                f"The {node_sequence[0]} static route recursively resolves a BGP "
                f"next hop toward {node_sequence[1]}; IS-IS owns transport reachability."
            ),
            "isis_underlay": (
                f"The {node_sequence[0]} IS-IS Level-2 resolver selects adjacency "
                f"{node_sequence[1]} for {destination['prefix']}."
            ),
            "mpls_transport": (
                f"The {node_sequence[0]} SR-MPLS resolver selects a transport-label "
                f"action toward {node_sequence[1]} for {destination['prefix']}."
            ),
            "mpls_l3vpn": (
                f"The {node_sequence[0]} VPNv4 resolver selects transport and VPN "
                f"labels toward {node_sequence[1]} for {destination['prefix']}."
            ),
            "srv6_policy": (
                f"The {node_sequence[0]} SR policy resolver selects an SRv6 SID "
                f"list toward {node_sequence[1]} for {destination['prefix']}."
            ),
            "evpn_service": (
                f"The {node_sequence[0]} EVPN resolver selects a VTEP and VNI "
                f"toward {node_sequence[1]} for the requested service."
            ),
            "evpn_mac_ip": (
                f"The {node_sequence[0]} EVPN Type-2 resolver selects a MAC/IP VTEP "
                f"toward {node_sequence[1]}."
            ),
            "evpn_ip_prefix": (
                f"The {node_sequence[0]} EVPN Type-5 resolver selects an IP-prefix "
                f"gateway and VTEP toward {node_sequence[1]}."
            ),
        }
        source_phase = (
            "recursive_lookup"
            if route_type == "static_recursive"
            else "candidate_selection"
            if route_type
            in {
                "mpls_transport",
                "mpls_l3vpn",
                "srv6_policy",
                "evpn_service",
                "evpn_mac_ip",
                "evpn_ip_prefix",
            }
            else "local_lookup"
        )
        self._set_segment_resolution(
            local_segments[0],
            source_text_by_type.get(
                route_type, local_segments[0]["route_resolution_text"]
            ),
            source_phase,
        )
        path["resolution_phases"] = [
            segment["phase"] for segment in sorted(segments, key=lambda item: item["ordinal"])
        ]
        return path

    @classmethod
    def _canonical_traversal_state(
        cls,
        state: dict[str, Any],
    ) -> tuple[ForwardingTraversalStateKey, dict[str, Any]]:
        """Return the typed cycle identity and its safe demo projection."""

        try:
            typed = cls._typed_traversal_state(state)
        except (KeyError, TypeError, ValueError) as error:
            raise MultiNodeRouteRequestError(str(error)) from error
        canonical = {
            "member_id": typed.member_id,
            "status_perspective": {
                "perspective_id": typed.status_perspective.perspective_id,
                "plugin_instance_id": typed.status_perspective.plugin_instance_id,
            },
            "vrf_id": str(state["vrf_id"]),
            "forwarding_object_key": state["forwarding_object_key"],
            "lookup_target_key": state["lookup_target_key"],
            "ingress_scope": state.get("ingress_scope"),
            "encapsulation_state": state.get("encapsulation_state"),
            "policy_scopes_complete": typed.policy_scopes_complete,
        }
        return typed, canonical

    @staticmethod
    def _typed_traversal_state(
        state: dict[str, Any],
    ) -> ForwardingTraversalStateKey:
        node_id = str(state["node_id"])
        provider = _ROUTE_PLUGIN_BY_NODE[node_id]
        forwarding_object = state["forwarding_object_key"]
        object_kind = str(
            forwarding_object.get("resource_type", "FORWARDING_OBJECT")
            if isinstance(forwarding_object, dict)
            else "FORWARDING_OBJECT"
        )
        object_value = json.dumps(
            forwarding_object,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        ingress_scope = ForwardingPolicyScope(
            contract_id="demo.forwarding.ingress-scope.v1",
            arguments=(
                (
                    "opaque_scope",
                    json.dumps(
                        state.get("ingress_scope"),
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                ),
            ),
        )
        return ForwardingTraversalStateKey(
            member_id=str(state["member_id"]),
            status_perspective=StatusPerspectiveRef(
                perspective_id=provider["status_perspective_id"],
                plugin_instance_id=provider["plugin_run_id"],
            ),
            forwarding_object=ResourceKey(
                namespace="demo",
                node=node_id,
                layer="forwarding",
                kind=object_kind,
                parts=(("opaque_key", object_value),),
            ),
            forwarding_domain=ResourceKey(
                namespace="demo",
                node=node_id,
                layer="forwarding",
                kind="VRF",
                parts=(("vrf_id", str(state["vrf_id"])),),
            ),
            lookup_context=(
                (
                    "lookup_target",
                    json.dumps(
                        state["lookup_target_key"],
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                ),
            ),
            packet_context=(
                (
                    "encapsulation",
                    json.dumps(
                        state.get("encapsulation_state"),
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                ),
            ),
            policy_scopes=frozenset({ingress_scope}),
            policy_scopes_complete=state.get("policy_scopes_complete", True),
        )

    @classmethod
    def _classify_traversal_states(
        cls,
        states: list[dict[str, Any]],
        *,
        max_hops: int,
        max_recursion: int,
        cycle_reason: str,
    ) -> dict[str, Any]:
        try:
            evaluation = evaluate_forwarding_traversal(
                tuple(cls._typed_traversal_state(item) for item in states),
                max_hops=max_hops,
                max_recursion=max_recursion,
                hop_indices=tuple(
                    int(item.get("hop_index", index))
                    for index, item in enumerate(states)
                ),
                recursion_depths=tuple(
                    int(item.get("recursion_depth", 0)) for item in states
                ),
                cycle_reason=cycle_reason,
            )
        except (RouteTraceContractError, ValueError) as error:
            raise MultiNodeRouteRequestError(str(error)) from error
        result: dict[str, Any] = {
            "outcome": evaluation.outcome,
            "terminal_reason": evaluation.terminal_reason,
            "stop_step": evaluation.stop_step + 1,
        }
        if evaluation.cycle is not None:
            report = evaluation.cycle
            result["cycle"] = {
                "kind": cycle_reason,
                "repeated_state": cls._canonical_traversal_state(
                    states[report.first_seen_step]
                )[1],
                "first_step": report.first_seen_step + 1,
                "closing_step": report.repeated_at_step + 1,
            }
        if evaluation.budget_kind is not None:
            result["budget"] = {
                "kind": evaluation.budget_kind,
                "limit": evaluation.budget_limit,
                "observed": evaluation.budget_observed,
            }
        return result

    def _apply_traversal_outcome(
        self,
        path: dict[str, Any],
        states: list[dict[str, Any]],
        state_segment_ids: list[str],
        classification: dict[str, Any],
    ) -> None:
        if len(states) != len(state_segment_ids):
            raise MultiNodeRouteRequestError(
                "each traversal state must identify one resolution segment"
            )
        stop_step = int(classification["stop_step"])
        retained_states = states[:stop_step]
        retained_segment_ids = state_segment_ids[:stop_step]
        terminal_id = retained_segment_ids[-1]
        terminal = next(
            item for item in path["segments"] if item["segment_id"] == terminal_id
        )
        path["segments"] = [
            item
            for item in path["segments"]
            if int(item["ordinal"]) <= int(terminal["ordinal"])
        ]
        path["node_sequence"] = [
            str(item["node_id"]) for item in retained_states
        ]

        occurrences: list[dict[str, Any]] = []
        occurrence_by_segment: dict[str, str] = {}
        first_occurrence_by_identity: dict[ForwardingTraversalStateKey, str] = {}
        for step, (state, segment_id) in enumerate(
            zip(retained_states, retained_segment_ids), start=1
        ):
            identity, canonical = self._canonical_traversal_state(state)
            occurrence_id = f"{path['path_id']}:node-occurrence:{step}"
            occurrence = {
                "occurrence_id": occurrence_id,
                "ordinal": step,
                "node_id": str(state["node_id"]),
                "member_id": str(state["member_id"]),
                "canonical_state": canonical,
                "repeated": identity in first_occurrence_by_identity,
                "repeats_occurrence_id": first_occurrence_by_identity.get(identity),
            }
            first_occurrence_by_identity.setdefault(identity, occurrence_id)
            occurrences.append(occurrence)
            occurrence_by_segment[segment_id] = occurrence_id
        path["node_occurrences"] = occurrences
        path["traversal_states"] = [
            {
                **self._canonical_traversal_state(item)[1],
                "node_id": str(item["node_id"]),
                "hop_index": int(item.get("hop_index", 0)),
                "recursion_depth": int(item.get("recursion_depth", 0)),
            }
            for item in retained_states
        ]

        sorted_segments = sorted(
            path["segments"], key=lambda item: int(item["ordinal"])
        )
        local_positions = {
            segment_id: index
            for index, segment_id in enumerate(retained_segment_ids)
        }
        for segment in sorted_segments:
            occurrence_id = occurrence_by_segment.get(str(segment["segment_id"]))
            if occurrence_id is not None:
                segment["node_occurrence_id"] = occurrence_id
        for left_id, right_id in zip(
            retained_segment_ids, retained_segment_ids[1:]
        ):
            left = next(
                item for item in sorted_segments if item["segment_id"] == left_id
            )
            right = next(
                item for item in sorted_segments if item["segment_id"] == right_id
            )
            for segment in sorted_segments:
                if (
                    int(left["ordinal"])
                    < int(segment["ordinal"])
                    < int(right["ordinal"])
                    and segment["segment_kind"] == "inter_node_boundary"
                ):
                    segment["source_occurrence_id"] = occurrence_by_segment[left_id]
                    segment["target_occurrence_id"] = occurrence_by_segment[right_id]
        # Keep this local variable assertion useful when this helper is changed:
        # duplicate state-segment IDs would otherwise corrupt occurrence mapping.
        if len(local_positions) != len(retained_segment_ids):
            raise MultiNodeRouteRequestError(
                "traversal state segment identifiers must be unique"
            )

        outcome = str(classification["outcome"])
        if outcome == "resolved":
            self._refresh_path(path)
            return
        terminal_reason = str(classification["terminal_reason"])
        cycle_detected = outcome == "cycle"
        terminal["active"] = False
        terminal["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": True,
                "operational": (
                    "loop_detected" if cycle_detected else "budget_exhausted"
                ),
                "terminal": terminal_reason,
                "reason_code": terminal_reason,
                "terminal_disposition": outcome,
            }
        )
        terminal["completeness"] = {
            "state": "bounded_cycle" if cycle_detected else "bounded_limit",
            "end_to_end_resolved": False,
            "observed": True,
        }
        phase = "cycle_detection" if cycle_detected else "budget_guard"
        explanation = (
            "The core encountered the same canonical traversal state again and "
            "stopped before following the loop further."
            if outcome == "cycle"
            else (
                f"The core stopped this retained candidate because "
                f"{classification['budget']['kind']}="
                f"{classification['budget']['limit']} was exceeded."
            )
        )
        self._set_segment_resolution(terminal, explanation, phase)
        path["active"] = False
        self._refresh_path(path)
        if classification.get("cycle"):
            cycle = dict(classification["cycle"])
            cycle["first_occurrence_id"] = occurrences[
                int(cycle["first_step"]) - 1
            ]["occurrence_id"]
            cycle["closing_occurrence_id"] = occurrences[
                int(cycle["closing_step"]) - 1
            ]["occurrence_id"]
            path["cycle"] = cycle
        if classification.get("budget"):
            path["resolution_budget"] = dict(classification["budget"])

    def _recursive_cycle_paths(
        self,
        source: dict[str, Any],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        *,
        max_recursion: int,
    ) -> list[dict[str, Any]]:
        node_id = str(source["node_id"])
        destination_value = str(destination["value"])
        issue_id = f"issue:recursive-cycle:{node_id}:{destination_value}"
        states = [
            {
                "node_id": node_id,
                "member_id": source["member_id"],
                "vrf_id": routing_context["vrf_id"],
                "forwarding_object_key": {
                    "resource_type": "STATIC_ROUTE",
                    "key": destination_value,
                },
                "lookup_target_key": "192.0.2.44/32",
                "ingress_scope": {"kind": "vrf", "id": routing_context["vrf_id"]},
                "encapsulation_state": {"kind": "ip", "labels": []},
                "hop_index": 0,
                "recursion_depth": 0,
            },
            {
                "node_id": node_id,
                "member_id": source["member_id"],
                "vrf_id": routing_context["vrf_id"],
                "forwarding_object_key": {
                    "resource_type": "BGP_ROUTE",
                    "key": "192.0.2.44/32",
                },
                "lookup_target_key": destination_value,
                "ingress_scope": {"kind": "vrf", "id": routing_context["vrf_id"]},
                "encapsulation_state": {"kind": "ip", "labels": []},
                "hop_index": 0,
                "recursion_depth": 1,
            },
            {
                "node_id": node_id,
                "member_id": source["member_id"],
                "vrf_id": routing_context["vrf_id"],
                "forwarding_object_key": {
                    "resource_type": "STATIC_ROUTE",
                    "key": destination_value,
                },
                "lookup_target_key": "192.0.2.44/32",
                "ingress_scope": {"kind": "vrf", "id": routing_context["vrf_id"]},
                "encapsulation_state": {"kind": "ip", "labels": []},
                "hop_index": 0,
                "recursion_depth": 2,
            },
        ]
        texts = [
            (
                f"The {node_id} static-route plug-in resolves {destination_value} "
                "through recursive next hop 192.0.2.44/32."
            ),
            (
                f"The {node_id} BGP plug-in resolves 192.0.2.44/32 back through "
                f"{destination_value} in the same VRF."
            ),
            (
                f"The {node_id} static-route lookup returns to the original "
                "forwarding object and packet state."
            ),
        ]
        path_id = (
            f"route-path:{node_id}:{destination['node_id']}:"
            "static_recursive:candidate-recursive-cycle"
        )
        segments = [
            self._local_segment(
                f"segment:{path_id}:recursive:{index}",
                index,
                node_id,
                [str(source["resource_id"])],
                text,
                resources,
                targets,
                True,
                True,
                "selected_primary",
                [issue_id],
            )
            for index, text in enumerate(texts, start=1)
        ]
        for segment in segments:
            self._set_segment_resolution(
                segment, segment["route_resolution_text"], "recursive_lookup"
            )
        path = self._path(
            path_id,
            "Recursive static candidate with a next-hop cycle",
            segments,
            True,
            True,
            "selected_primary",
            "control_plane_observed",
            [issue_id],
        )
        path.update(
            {
                "candidate_id": "recursive-cycle",
                "node_sequence": [node_id, node_id, node_id],
                "destination_node_id": destination["node_id"],
                "destination_endpoint_id": destination["destination_id"],
                "route_type": "static_recursive",
                "protocol_chain": ["static", "bgp", "static"],
                "encapsulation": {"kind": "ip"},
            }
        )
        classification = self._classify_traversal_states(
            states,
            max_hops=64,
            max_recursion=max_recursion,
            cycle_reason="recursive_resolution_cycle",
        )
        self._apply_traversal_outcome(
            path,
            states,
            [item["segment_id"] for item in segments],
            classification,
        )
        terminal_segment = path["segments"][-1]
        issues.append(
            {
                "issue_id": issue_id,
                "category": "forwarding",
                "severity": "error",
                "finding_type": classification["outcome"],
                "summary": (
                    "Recursive next-hop resolution revisits an identical state"
                    if classification["outcome"] == "cycle"
                    else "Recursive next-hop resolution exhausted its budget"
                ),
                "detail": (
                    "The core compares the plug-in-declared member, VRF, forwarding "
                    "object, lookup target, ingress scope, and encapsulation state."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [terminal_segment["segment_id"]],
                "interaction_target_ids": terminal_segment[
                    "interaction_target_ids"
                ],
                "affects_consistency": False,
                "ownership": "plugin_resolution_state_core_cycle_and_budget_guard",
            }
        )
        return [path]

    def _forwarding_loop_paths(
        self,
        source: dict[str, Any],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        *,
        max_hops: int,
    ) -> list[dict[str, Any]]:
        if source["node_id"] == "node-a":
            node_sequence = ["node-a", "transit-p-1", "node-b", "transit-p-1"]
        else:
            node_sequence = ["node-b", "transit-p-2", "node-a", "transit-p-2"]
        repeated_transit = node_sequence[1]
        bounce_node = node_sequence[-2]
        issue_id = (
            f"issue:forwarding-loop:{source['node_id']}:"
            f"{destination['node_id']}:{repeated_transit}"
        )
        path = self._generic_path(
            node_sequence,
            "ipv4_unicast",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            issue_refs=[issue_id],
            candidate_id="selected-forwarding-loop",
            allow_repeated_nodes=True,
            destination_node_id=destination["node_id"],
            terminal_next_hop_node_id=bounce_node,
        )
        path["label"] = (
            f"Selected forwarding loop through {repeated_transit} and {bounce_node}"
        )
        states: list[dict[str, Any]] = []
        for hop_index, node_id in enumerate(node_sequence):
            is_repeated_transit = node_id == repeated_transit
            states.append(
                {
                    "node_id": node_id,
                    "member_id": f"member:{node_id}",
                    "vrf_id": routing_context["vrf_id"],
                    "forwarding_object_key": {
                        "resource_type": "FIB_ENTRY",
                        "key": (
                            f"{repeated_transit}:{destination['value']}"
                            if is_repeated_transit
                            else f"{node_id}:{destination['value']}"
                        ),
                    },
                    "lookup_target_key": destination["value"],
                    "ingress_scope": {
                        "kind": "forwarding_domain",
                        "id": f"vrf:{routing_context['vrf_id']}",
                    },
                    "encapsulation_state": {"kind": "ip", "labels": []},
                    "hop_index": hop_index,
                    "recursion_depth": 0,
                }
            )
        local_segments = [
            item
            for item in sorted(path["segments"], key=lambda item: item["ordinal"])
            if item["segment_kind"] == "node_resolution"
        ]
        classification = self._classify_traversal_states(
            states,
            max_hops=max_hops,
            max_recursion=16,
            cycle_reason="forwarding_loop",
        )
        self._apply_traversal_outcome(
            path,
            states,
            [item["segment_id"] for item in local_segments],
            classification,
        )
        terminal_segment = path["segments"][-1]
        issues.append(
            {
                "issue_id": issue_id,
                "category": "forwarding",
                "severity": "error",
                "finding_type": classification["outcome"],
                "summary": (
                    f"Forwarding returns to the same {repeated_transit} state"
                    if classification["outcome"] == "cycle"
                    else "Forwarding stopped at the configured hop budget"
                ),
                "detail": (
                    "Repeated router IDs alone are not considered a loop. This "
                    "candidate is terminal only because its complete canonical "
                    "forwarding state repeats."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [terminal_segment["segment_id"]],
                "interaction_target_ids": terminal_segment[
                    "interaction_target_ids"
                ],
                "affects_consistency": False,
                "ownership": "plugin_forwarding_state_core_cycle_and_budget_guard",
            }
        )
        return [path]

    def _apply_policy_decisions(
        self,
        path: dict[str, Any],
        evaluation: ForwardingPolicyEvaluation,
        decisions: list[dict[str, Any]],
        terminal_segment: dict[str, Any],
    ) -> None:
        if len(decisions) != len(evaluation.decisions):
            raise MultiNodeRouteRequestError(
                "serialized policy decisions must match the core evaluation"
            )
        for record, typed_decision in zip(decisions, evaluation.decisions):
            if record.get("core_verdict") != typed_decision.verdict.value:
                raise MultiNodeRouteRequestError(
                    "serialized policy decision disagrees with the core verdict"
                )
        path["policy_decisions"] = [dict(item) for item in decisions]
        if evaluation.verdict in {
            ForwardingPolicyVerdict.PERMITTED,
            ForwardingPolicyVerdict.NOT_APPLICABLE,
        }:
            self._refresh_path(path)
            return
        blocked = evaluation.verdict is ForwardingPolicyVerdict.BLOCKED
        verdict_value = evaluation.verdict.value
        decision = next(
            (
                item
                for item in decisions
                if item.get("core_verdict") == verdict_value
            ),
            None,
        )
        if decision is None:
            raise MultiNodeRouteRequestError(
                "terminal policy evaluation requires a matching serialized decision"
            )
        reason = str(
            decision.get("reason")
            or (
                "policy_evidence_incomplete"
                if evaluation.verdict is ForwardingPolicyVerdict.UNKNOWN
                else ""
            )
        )
        if not reason:
            raise MultiNodeRouteRequestError(
                "a blocked policy decision must provide a reason"
            )
        terminal_disposition = "policy_blocked" if blocked else "unresolved"
        operational = "policy_blocked" if blocked else "policy_unknown"
        terminal_segment["policy_decision_refs"] = [
            str(decision["decision_id"])
        ]
        terminal_segment["active"] = False
        terminal_segment["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": False,
                "operational": operational,
                "terminal": reason,
                "reason_code": reason,
                "terminal_disposition": terminal_disposition,
            }
        )
        terminal_segment["completeness"] = {
            "state": (
                "bounded_policy_decision"
                if blocked
                else "policy_evidence_incomplete"
            ),
            "end_to_end_resolved": False,
            "observed": blocked,
        }
        path["active"] = False
        path["alternative_state"] = (
            "policy_rejected" if blocked else "policy_unknown"
        )
        self._refresh_path(path)

    def _split_horizon_paths(
        self,
        source: dict[str, Any],
        destination: dict[str, Any],
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        source_node_id = str(source["node_id"])
        destination_node_id = str(destination["node_id"])
        node_sequence = [source_node_id, "transit-p-2", destination_node_id]
        issue_id = (
            f"issue:evpn-split-horizon:{source_node_id}:{destination_node_id}"
        )
        path = self._generic_path(
            node_sequence,
            "evpn_mac_ip",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            issue_refs=[issue_id],
            candidate_id="same-es-suppressed",
        )
        ingress_resource_id = (
            f"{source_node_id}/ETHERNET_SEGMENT/esi-east"
        )
        egress_resource_id = (
            f"{destination_node_id}/ETHERNET_SEGMENT/esi-east"
        )
        ordinal = max(item["ordinal"] for item in path["segments"]) + 1
        policy_segment = self._local_segment(
            f"segment:{path['path_id']}:split-horizon-policy",
            ordinal,
            destination_node_id,
            [egress_resource_id],
            (
                f"The {destination_node_id} EVPN plug-in rejects egress to "
                "esi-east/VLAN 320 because the normalized ingress and egress "
                "split-horizon scopes are identical."
            ),
            resources,
            targets,
            True,
            True,
            "selected_primary",
            [issue_id],
        )
        policy_segment["segment_kind"] = "policy_decision"
        self._set_segment_resolution(
            policy_segment,
            policy_segment["route_resolution_text"],
            "policy_evaluation",
        )
        path["segments"].append(policy_segment)
        path["active"] = True
        typed_scope = ForwardingPolicyScope(
            contract_id="demo.evpn.split-horizon.v1",
            arguments=(
                ("ethernet_segment", "esi-east"),
                ("vlan", 320),
            ),
        )
        typed_candidate = ResourceKey(
            namespace="demo",
            node=destination_node_id,
            layer="data_bridge",
            kind="EVPN_EGRESS",
            parts=(
                ("ethernet_segment", "esi-east"),
                ("vlan", 320),
            ),
        )
        typed_constraint = ForwardingCandidateConstraint(
            constraint_id=(
                f"split-horizon:{source_node_id}:{destination_node_id}:"
                "esi-east:vlan-320"
            ),
            kind="exclude_exact_scope",  # type: ignore[arg-type]
            candidate_scope=typed_scope,
            traffic_classes=frozenset({"ethernet.bum"}),
        )
        typed_evaluation = evaluate_forwarding_policy(
            candidate=typed_candidate,
            constraints=(typed_constraint,),
            ingress_scopes=frozenset({typed_scope}),
            traffic_class="ethernet.bum",
        )
        typed_decision = typed_evaluation.decisions[0]
        if typed_evaluation.verdict is not ForwardingPolicyVerdict.BLOCKED:
            raise MultiNodeRouteRequestError(
                "the split-horizon fixture must produce a blocked typed verdict"
            )
        decision = {
            "decision_id": f"policy-decision:{path['path_id']}:split-horizon",
            "ordinal": 1,
            "policy_kind": "split_horizon",
            "outcome": (
                "reject"
                if typed_decision.verdict is ForwardingPolicyVerdict.BLOCKED
                else "accept"
            ),
            "core_verdict": typed_decision.verdict.value,
            "ingress_scopes_complete": typed_decision.ingress_scopes_complete,
            "reason": "split_horizon_same_scope",
            "constraint_id": typed_constraint.constraint_id,
            "provided_by": dict(
                policy_segment["route_resolution"]["provided_by"]
            ),
            "scope_refs": [
                {
                    "scope_type": "split_horizon_group",
                    "scope_id": "shg:esi-east:vlan-320",
                },
                {
                    "scope_type": "ethernet_segment",
                    "scope_id": "esi-east",
                },
                {"scope_type": "vlan", "scope_id": "320"},
            ],
            "evidence": [
                {
                    "kind": "ingress_attachment",
                    "resource_id": ingress_resource_id,
                    "normalized_scope": "shg:esi-east:vlan-320",
                },
                {
                    "kind": "egress_attachment",
                    "resource_id": egress_resource_id,
                    "normalized_scope": "shg:esi-east:vlan-320",
                },
                {
                    "kind": "encapsulation",
                    "field": "vni",
                    "value": 10320,
                },
            ],
            "semantic_owner": "node_plugin",
        }
        self._apply_policy_decisions(
            path,
            typed_evaluation,
            [decision],
            policy_segment,
        )
        path.update(
            {
                "candidate_id": "same-es-suppressed",
                "service_endpoint_id": destination["destination_id"],
                "ingress_context": {
                    "resource_id": ingress_resource_id,
                    "split_horizon_scope": "shg:esi-east:vlan-320",
                },
                "egress_resource_id": egress_resource_id,
            }
        )
        issues.append(
            {
                "issue_id": issue_id,
                "category": "forwarding",
                "severity": "info",
                "finding_type": "policy_blocked",
                "summary": "EVPN split horizon intentionally rejects same-ES egress",
                "detail": (
                    "The node plug-in declares the ingress and egress scope plus "
                    "the reject decision. The core retains the candidate and "
                    "normalizes its terminal outcome without implementing EVPN."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [policy_segment["segment_id"]],
                "interaction_target_ids": policy_segment[
                    "interaction_target_ids"
                ],
                "policy_decision_refs": [decision["decision_id"]],
                "affects_consistency": False,
                "ownership": "node_plugin_policy_core_outcome_normalization",
            }
        )
        return [path]

    @staticmethod
    def _set_segment_resolution(
        segment: dict[str, Any], text: str, phase: str
    ) -> None:
        segment["phase"] = phase
        segment["route_resolution"]["phase"] = phase
        segment["route_resolution"]["text"] = text
        segment["route_resolution_text"] = text
        if segment.get("graph_presentation", {}).get("role") == "l3-resolution":
            segment["graph_presentation"]["detail"] = text
        if segment["route_resolution"].get("parts"):
            segment["route_resolution"]["parts"][-1]["text"] = text

    def _mark_path_terminal(
        self,
        path: dict[str, Any],
        *,
        reason_code: str,
        text: str,
        disposition: str = "unusable",
        phase: str = "failover",
    ) -> None:
        terminal = path["segments"][-1]
        terminal["active"] = False
        terminal["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": False,
                "operational": "unusable",
                "terminal": reason_code,
                "reason_code": reason_code,
                # Normalized by the node plug-in.  The route coordinator must
                # not parse the human reason code to decide drop semantics.
                "terminal_disposition": disposition,
            }
        )
        terminal["completeness"] = {
            "state": "terminal_failure",
            "end_to_end_resolved": False,
            "observed": True,
        }
        self._set_segment_resolution(terminal, text, phase)
        path["active"] = False
        self._refresh_path(path)

    def _evpn_multihoming_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        *,
        mode: str,
    ) -> list[dict[str, Any]]:
        all_active = mode == "all_active"
        via_b = self._generic_path(
            ["node-a", "transit-p-1", "node-b"],
            "evpn_mac_ip",
            resources,
            links,
            targets,
            active=all_active,
            primary=False,
            alternative_state="ecmp_member" if all_active else "withdrawn_dead",
            candidate_id="east-es-via-pe-b",
        )
        via_e = self._generic_path(
            ["node-a", "transit-p-2", "node-e"],
            "evpn_mac_ip",
            resources,
            links,
            targets,
            active=True,
            primary=not all_active,
            alternative_state="ecmp_member" if all_active else "selected_primary",
            candidate_id="east-es-via-pe-e",
        )
        for path, vtep, egress in (
            (via_b, "10.0.0.2", "node-b/ETHERNET_SEGMENT/esi-east"),
            (via_e, "10.0.0.5", "node-e/ETHERNET_SEGMENT/esi-east"),
        ):
            path.update(
                {
                    "service_endpoint_id": "destination:east-evpn-multihomed-service",
                    "evpn": {
                        "route_type": 2,
                        "esi": "00:11:22:33:44:55:66:77:88:ee",
                        "ethernet_tag_id": 320,
                        "vni": 10320,
                        "remote_vtep": vtep,
                    },
                    "egress_resource_id": egress,
                }
            )
            path["encapsulation"] = {
                "kind": "vxlan",
                "vni": 10320,
                "remote_vtep": vtep,
                "evpn_route_type": 2,
            }
            self._set_segment_resolution(
                path["segments"][0],
                (
                    "Alpha EVPN Type-2 resolution selects the east multihomed "
                    f"Ethernet segment through VTEP {vtep} and VNI 10320."
                ),
                "candidate_selection",
            )
        if not all_active:
            issue_id = "issue:evpn:east-es:pe-b-withdrawn"
            via_b["issue_refs"] = [issue_id]
            for segment in via_b["segments"]:
                segment["issue_refs"] = [issue_id]
            self._mark_path_terminal(
                via_b,
                reason_code="evpn_es_withdrawn",
                text=(
                    "The PE-B EVPN plug-in reports the east Ethernet-segment "
                    "advertisement withdrawn; this historical candidate is retained "
                    "but cannot forward traffic."
                ),
            )
            issues.append(
                {
                    "issue_id": issue_id,
                    "category": "forwarding",
                    "severity": "warning",
                    "finding_type": "reachability",
                    "summary": "PE-B Ethernet-segment candidate was withdrawn",
                    "detail": (
                        "PE-E is selected after failover. Core retains PE-B's dead "
                        "candidate and its plug-in-provided terminal reason."
                    ),
                    "path_refs": [via_b["path_id"], via_e["path_id"]],
                    "segment_refs": [via_b["segments"][-1]["segment_id"]],
                    "interaction_target_ids": via_b["interaction_target_ids"],
                    "ownership": "evpn_plugin_state_core_candidate_retention",
                }
            )
        return [via_b, via_e]

    def _evpn_stale_fib_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        issue_ids = [
            "issue:evpn-stale-fib:next-hop",
            "issue:evpn-stale-fib:egress-interface",
            "issue:evpn-stale-fib:encapsulation",
            "issue:evpn-stale-fib:update-lag",
        ]
        observed = self._generic_path(
            ["node-a", "transit-p-1", "node-b"],
            "evpn_mac_ip",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            issue_refs=issue_ids,
            candidate_id="stale-hardware-via-pe-b",
        )
        observed["perspective"] = "forwarding_observed"
        observed["encapsulation"] = {
            "kind": "vxlan",
            "vni": 10320,
            "remote_vtep": "10.0.0.2",
            "programmed_at_offset_ms": -780,
        }
        observed["egress_resource_id"] = "node-a/INTERFACE/xe-0-0-0"
        self._mark_path_terminal(
            observed,
            reason_code="stale_fib_to_withdrawn_es",
            text=(
                "The hardware FIB still sends VNI 10320 to PE-B after its Ethernet "
                "segment was withdrawn, so the selected observed path terminates."
            ),
        )
        control = self._generic_path(
            ["node-a", "transit-p-2", "node-e"],
            "evpn_mac_ip",
            resources,
            links,
            targets,
            active=False,
            primary=False,
            alternative_state="control_expected_not_observed",
            issue_refs=issue_ids,
            candidate_id="fresh-control-via-pe-e",
        )
        control["perspective"] = "control_expected"
        control["encapsulation"] = {
            "kind": "vxlan",
            "vni": 10320,
            "remote_vtep": "10.0.0.5",
            "resolved_at_offset_ms": -20,
        }
        control["egress_resource_id"] = "node-a/INTERFACE/xe-0-0-1"
        finding_specs = (
            (
                issue_ids[0],
                "next_hop",
                "Control and hardware select different remote VTEPs",
                "Control selects PE-E 10.0.0.5 while the hardware FIB retains PE-B 10.0.0.2.",
            ),
            (
                issue_ids[1],
                "egress_interface",
                "Control and hardware select different egress interfaces",
                "Control resolves xe-0-0-1 while observed hardware uses xe-0-0-0.",
            ),
            (
                issue_ids[2],
                "encapsulation",
                "The programmed VXLAN destination is stale",
                "Both views use VNI 10320, but their remote VTEP encapsulation destinations differ.",
            ),
            (
                issue_ids[3],
                "update_lag",
                "Forwarding has not caught up with the EVPN withdrawal",
                "The control observation is 20 ms old and the hardware programming observation is 780 ms old.",
            ),
        )
        for issue_id, finding_type, summary, detail in finding_specs:
            issues.append(
                {
                    "issue_id": issue_id,
                    "category": "cross_layer",
                    "severity": "error" if finding_type == "next_hop" else "warning",
                    "finding_type": finding_type,
                    "summary": summary,
                    "detail": detail,
                    "path_refs": [observed["path_id"], control["path_id"]],
                    "segment_refs": [],
                    "interaction_target_ids": sorted(
                        set(
                            observed["interaction_target_ids"]
                            + control["interaction_target_ids"]
                        )
                    ),
                    "ownership": "core_cross_perspective_comparison",
                }
            )
        return [observed, control]

    def _srv6_all_active_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        paths = []
        for transit_node_id, candidate_id, segment_list in (
            (
                "transit-p-1",
                "srv6-policy-color-100-via-p1",
                ["2001:db8:100:1::a", "2001:db8:100:5::e"],
            ),
            (
                "transit-p-2",
                "srv6-policy-color-100-via-p2",
                ["2001:db8:100:2::a", "2001:db8:100:5::e"],
            ),
        ):
            path = self._generic_path(
                ["node-a", transit_node_id, "node-e"],
                "srv6_policy",
                resources,
                links,
                targets,
                active=True,
                primary=False,
                alternative_state="ecmp_member",
                candidate_id=candidate_id,
            )
            path["encapsulation"] = {
                "kind": "srv6",
                "policy_color": 100,
                "segment_list": segment_list,
            }
            self._set_segment_resolution(
                path["segments"][0],
                (
                    "Alpha's SR policy plug-in selects color 100 and encapsulates "
                    f"with SID list {' -> '.join(segment_list)}."
                ),
                "tunnel_action",
            )
            paths.append(path)
        return paths

    def _recursive_static_external_path(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        path = self._generic_path(
            ["node-a", "transit-p-1", "node-e"],
            "static_recursive",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            candidate_id="static-blue-external-via-p1",
        )
        local_segments = [
            item for item in path["segments"] if item["segment_kind"] == "node_resolution"
        ]
        self._set_segment_resolution(
            local_segments[0],
            (
                "Alpha VRF blue matches static 203.0.113.0/24 and recursively "
                "resolves the BGP next hop at PE-E."
            ),
            "local_lookup",
        )
        self._set_segment_resolution(
            local_segments[1],
            (
                "Gamma IS-IS resolves PE-E's BGP next-hop loopback and applies the "
                "plug-in-declared transport action toward circuit-401."
            ),
            "recursive_lookup",
        )
        self._set_segment_resolution(
            local_segments[-1],
            (
                "Eta terminates the recursive transport lookup and resolves the "
                "connected external subnet through et-0-0-20."
            ),
            "adjacency_egress",
        )
        path.update(
            {
                "destination_endpoint_id": "destination:eta-external-subnet",
                "protocol_chain": ["static", "ibgp", "isis-l2", "connected"],
                "resolution_phases": [
                    "local_lookup",
                    "recursive_lookup",
                    "tunnel_action",
                    "adjacency_egress",
                ],
                "egress_resource_id": "node-e/INTERFACE/et-0-0-20",
            }
        )
        return path

    def _connected_external_path(
        self,
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        resource_id = "node-e/INTERFACE/et-0-0-20"
        segment = self._local_segment(
            "segment:connected:node-e:external-203-0-113",
            1,
            "node-e",
            [resource_id],
            (
                "Eta's connected-route plug-in terminates 203.0.113.0/24 on "
                "et-0-0-20; the subnet is external and no remote router is invented."
            ),
            resources,
            targets,
            True,
            True,
            "selected_primary",
            [],
        )
        self._set_segment_resolution(
            segment,
            segment["route_resolution_text"],
            "adjacency_egress",
        )
        path = self._path(
            "route-path:node-e:external-subnet:connected:candidate-on-link",
            "Connected external subnet on PE-E",
            [segment],
            True,
            True,
            "selected_primary",
            "forwarding_observed",
            [],
        )
        path.update(
            {
                "candidate_id": "connected-node-e-external",
                "node_sequence": ["node-e"],
                "destination_node_id": "node-e",
                "destination_endpoint_id": "destination:eta-external-subnet",
                "route_type": "connected",
                "protocol_chain": ["connected"],
                "egress_resource_id": resource_id,
                "encapsulation": {"kind": "native", "subnet": "203.0.113.0/24"},
            }
        )
        return path

    def _incomplete_intermediate_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        mode: str,
    ) -> list[dict[str, Any]]:
        issue_id = "issue:missing-p2-intermediate-resolution"
        path = self._generic_path(
            ["node-d", "transit-p-2", "node-b"],
            "mpls_transport",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            issue_refs=[issue_id],
            candidate_id=f"p2-intermediate-{mode}",
        )
        middle = next(
            item
            for item in path["segments"]
            if item.get("node_id") == "transit-p-2"
            and item["segment_kind"] == "node_resolution"
        )
        if mode == "best_effort":
            middle["confidence"] = 0.56
            middle["completeness"] = {
                "state": "best_effort_inferred",
                "end_to_end_resolved": True,
                "observed": False,
            }
            middle["inference"] = {
                "performed_by": "core",
                "rule_owner": "demo.delta.sr-isis",
                "method": "join_topology_with_contemporaneous_resource_status",
                "assumption_reason_codes": [
                    "missing_intermediate_next_hop",
                    "usable_incident_attachments",
                ],
            }
            self._set_segment_resolution(
                middle,
                (
                    "P2's local next-hop observation is missing. Best effort joins "
                    "the D/P2 and P2/B attachments using Delta's declared policy."
                ),
                "best_effort",
            )
        else:
            middle["active"] = False
            middle["state"].update(
                {"active": False, "operational": "unknown"}
            )
            middle["completeness"] = {
                "state": "unresolved",
                "end_to_end_resolved": False,
                "observed": False,
            }
            middle["confidence"] = 0.18
            self._set_segment_resolution(
                middle,
                "P2 has no node-local next-hop observation from PE-D toward PE-B.",
                "unresolved",
            )
        self._refresh_path(path)
        issues.append(
            {
                "issue_id": issue_id,
                "category": "incomplete",
                "severity": "warning" if mode == "best_effort" else "error",
                "finding_type": "missing_intermediate_resolution",
                "summary": "P2 intermediate next-hop state is missing",
                "detail": (
                    "Best effort continues with explicit assumptions."
                    if mode == "best_effort"
                    else "Strict mode stops at P2 and preserves the unresolved path prefix."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [middle["segment_id"]],
                "interaction_target_ids": middle["interaction_target_ids"],
                "ownership": "core_completeness_accounting",
            }
        )
        return [path]

    def _one_way_drop_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        resolution_mode: str,
    ) -> list[dict[str, Any]]:
        issue_id = "issue:directional:node-c:node-b:p2-egress-drop"
        observed = self._generic_path(
            ["node-c", "transit-p-2", "node-b"],
            "evpn_service",
            resources,
            links,
            targets,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            issue_refs=[issue_id],
        )
        drop_index = next(
            index
            for index, segment in enumerate(observed["segments"])
            if segment.get("node_id") == "transit-p-2"
            and segment["segment_kind"] == "node_resolution"
        )
        drop = observed["segments"][drop_index]
        drop.update(
            {
                "segment_kind": "directional_drop",
                "active": False,
                "confidence": 0.99,
                "issue_refs": [issue_id],
                "completeness": {
                    "state": "terminal_drop",
                    "end_to_end_resolved": False,
                    "observed": True,
                },
            }
        )
        drop["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": True,
                "operational": "unusable",
                "terminal": "dropped",
                "terminal_disposition": "dropped",
            }
        )
        drop_text = (
            "The Delta SR forwarding plug-in observes a directional policy drop "
            "toward PE-B even though the P2/PE-B physical boundary is usable."
        )
        drop["route_resolution"]["text"] = drop_text
        drop["route_resolution"]["parts"][-1]["text"] = drop_text
        drop["route_resolution_text"] = drop_text
        observed["segments"] = observed["segments"][: drop_index + 1]
        observed["label"] = "Observed reverse path - dropped at P2"
        observed["issue_refs"] = [issue_id]
        observed["node_sequence"] = ["node-c", "transit-p-2"]
        self._refresh_path(observed)

        paths = [observed]
        if resolution_mode == "best_effort":
            inferred = self._generic_path(
                ["node-c", "transit-p-2", "transit-p-1", "node-b"],
                "evpn_service",
                resources,
                links,
                targets,
                active=False,
                primary=False,
                alternative_state="best_effort_possible",
                issue_refs=[issue_id],
            )
            inferred["label"] = "Inactive best-effort continuation via P1"
            inferred["inference"] = {
                "performed_by": "core",
                "rule_owner": "node_plugins",
                "method": "join_topology_with_contemporaneous_resource_status",
                "does_not_override_observed_drop": True,
            }
            for segment in inferred["segments"]:
                segment["confidence"] = min(segment["confidence"], 0.62)
                segment["completeness"] = {
                    "state": "best_effort_inferred",
                    "end_to_end_resolved": True,
                    "observed": False,
                }
            self._refresh_path(inferred)
            paths.append(inferred)
        issues.append(
            {
                "issue_id": issue_id,
                "category": "directional",
                "severity": "error",
                "summary": "PE-C to PE-B drops while PE-B to PE-C remains reachable",
                "detail": (
                    "The P2 route plug-in reports a one-direction forwarding policy "
                    "failure. The federation boundary remains usable; core retains the "
                    "observed drop and never promotes its best-effort continuation."
                ),
                "path_refs": [item["path_id"] for item in paths],
                "segment_refs": [drop["segment_id"]],
                "interaction_target_ids": drop["interaction_target_ids"],
                "ownership": "node_plugin_observation_core_directional_comparison",
            }
        )
        return paths

    def _underlay_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        mode: str,
        issues: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        primary_active = True
        alternate_active = mode == "all_active"
        primary_label = (
            "Primary through P1"
            if mode == "single_active"
            else "ECMP member A through P1"
        )
        alternate_label = (
            "Eligible standby through P2"
            if mode == "single_active"
            else "ECMP member B through P2"
        )
        primary = self._underlay_path(
            "route-path:underlay:pe-a-primary",
            primary_label,
            "transit-p-1",
            resources,
            links,
            targets,
            issues,
            active=primary_active,
            primary=mode == "single_active",
            alternative_state=("selected_primary" if mode == "single_active" else "ecmp_member"),
        )
        alternate = self._underlay_path(
            "route-path:underlay:pe-a-alternate",
            alternate_label,
            "transit-p-2",
            resources,
            links,
            targets,
            issues,
            active=alternate_active,
            primary=False,
            alternative_state=("ecmp_member" if mode == "all_active" else "eligible_standby"),
        )
        return [primary, alternate]

    def _underlay_path(
        self,
        path_id: str,
        label: str,
        transit_node_id: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        *,
        active: bool,
        primary: bool,
        alternative_state: str,
        inherited_issue_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        inherited_issue_refs = inherited_issue_refs or []
        path_slug = path_id.rsplit(":", 1)[-1]
        try:
            path_facts = _UNDERLAY_PATH_FACTS[transit_node_id]
        except KeyError as exc:
            raise MultiNodeRouteRequestError(
                f"no plug-in underlay path facts for transit node: {transit_node_id}"
            ) from exc
        ingress_boundary = self._boundary_descriptor("node-a", transit_node_id)
        egress_boundary = self._boundary_descriptor(transit_node_id, "node-b")
        source_interface_id = ingress_boundary["resources"]["node-a"]
        ingress_adjacency = ingress_boundary["resources"][transit_node_id]
        egress_adjacency = egress_boundary["resources"][transit_node_id]
        destination_port_id = egress_boundary["resources"]["node-b"]
        circuit_a = str(ingress_boundary["link_id"])
        circuit_b = str(egress_boundary["link_id"])
        circuit_a_name = circuit_a.split(":")[2]
        circuit_b_name = circuit_b.split(":")[2]
        plugin_name = str(path_facts["plugin_display_name"])
        source_interface = str(path_facts["source_interface"])
        transport_label = int(path_facts["transport_label"])
        metric = int(path_facts["metric"])
        route_prefix = "203.0.113.0/24"
        destination_port = destination_port_id.rsplit("/", 1)[-1]
        segments = [
            self._local_segment(
                f"segment:{path_slug}:001-alpha",
                1,
                "node-a",
                ["node-a/LOOPBACK/lo0", source_interface_id],
                (
                    f"Alpha FIB resolves {route_prefix} through {source_interface} "
                    f"with transport label {transport_label}."
                ),
                resources,
                targets,
                active,
                primary,
                alternative_state,
                inherited_issue_refs,
            ),
            self._boundary_segment(
                f"segment:{path_slug}:002-boundary-a",
                2,
                [source_interface_id, ingress_adjacency],
                circuit_a,
                (
                    f"The federation linker maps Alpha {circuit_a_name} to the "
                    f"selected {plugin_name} PE-A adjacency claim."
                ),
                resources,
                links,
                targets,
                active,
                primary,
                alternative_state,
                inherited_issue_refs,
            ),
            self._local_segment(
                f"segment:{path_slug}:003-transit",
                3,
                transit_node_id,
                [ingress_adjacency, egress_adjacency],
                (
                    f"{plugin_name} IS-IS resolves {route_prefix} toward PE-B "
                    f"at metric {metric}."
                ),
                resources,
                targets,
                active,
                primary,
                alternative_state,
                inherited_issue_refs,
            ),
            self._boundary_segment(
                f"segment:{path_slug}:004-boundary-b",
                4,
                [egress_adjacency, destination_port_id],
                circuit_b,
                (
                    f"The federation linker maps {plugin_name} {circuit_b_name} "
                    f"to Beta port {destination_port}."
                ),
                resources,
                links,
                targets,
                active,
                primary,
                alternative_state,
                inherited_issue_refs,
            ),
            self._local_segment(
                f"segment:{path_slug}:005-beta",
                5,
                "node-b",
                [destination_port_id, "node-b/LOOPBACK/1"],
                (
                    f"Beta forwarding removes transport label {transport_label} and "
                    f"resolves {route_prefix} through its local route table."
                ),
                resources,
                targets,
                active,
                primary,
                alternative_state,
                inherited_issue_refs,
            ),
        ]
        path = self._path(
            path_id,
            label,
            segments,
            active,
            primary,
            alternative_state,
            "forwarding_observed",
            inherited_issue_refs,
        )
        path["node_sequence"] = ["node-a", transit_node_id, "node-b"]
        path["route_type"] = "mpls_transport"
        return path

    def _inconsistent_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        mismatch_id = "issue:cross-layer-egress-mismatch"
        boundary_id = "issue:boundary-path-disagreement"
        issue_refs = [mismatch_id, boundary_id]
        observed = self._underlay_path(
            "route-path:inconsistent:forwarding-observed",
            "Observed forwarding path",
            "transit-p-1",
            resources,
            links,
            targets,
            issues,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            inherited_issue_refs=issue_refs,
        )
        overlay_link_id = (
            "demo.evpn-peer-key.exact.v1:evpn:blue:pe-pair:node-a:node-b"
        )
        # The EVPN peer is a service/control correlation, not a physical hop.
        # The plug-in resolves its outer transport independently and attaches
        # the peer claim as presentation metadata below.
        control = self._generic_path(
            ["node-a", "transit-p-2", "node-b"],
            "evpn_service",
            resources,
            links,
            targets,
            active=False,
            primary=False,
            alternative_state="control_expected_not_observed",
            issue_refs=issue_refs,
            candidate_id="control-expected-via-p2",
        )
        control["path_id"] = "route-path:inconsistent:control-expected"
        control["label"] = "Control-plane expected path"
        control["perspective"] = "control_expected"
        overlay_link = next(iter(links.get(overlay_link_id, [])), None)
        overlay_target_id = (
            self._link_target(overlay_link, targets) if overlay_link else None
        )
        control["presentation_topology_targets"] = [
            {
                "kind": "topology_link",
                "topology_link_id": overlay_link_id,
                "interaction_target_id": overlay_target_id,
                "semantic_owner": "federation_linker_plugin",
            }
        ]
        self._set_segment_resolution(
            control["segments"][0],
            (
                "EVPN control resolution selects VTEP 10.0.0.2 while the "
                "underlay resolver selects the outer L1-L3 transport through P2."
            ),
            "candidate_selection",
        )
        issues.extend(
            [
                {
                    "issue_id": mismatch_id,
                    "category": "cross_layer",
                    "severity": "error",
                    "summary": "Control and forwarding layers resolve different egress paths",
                    "detail": (
                        "EVPN control selects the direct VTEP peer while observed Alpha/Gamma/Beta "
                        "forwarding traverses P1. The core reports both opaque plug-in results."
                    ),
                    "path_refs": [observed["path_id"], control["path_id"]],
                    "interaction_target_ids": sorted(
                        set(observed["interaction_target_ids"] + control["interaction_target_ids"])
                    ),
                    "ownership": "reported_by_core_from_plugin_comparison",
                },
                {
                    "issue_id": boundary_id,
                    "category": "boundary",
                    "severity": "warning",
                    "summary": "Expected overlay and observed underlay cross different boundaries",
                    "detail": (
                        "The federation linker resolved both boundary families; it does not decide "
                        "which layer is ground truth."
                    ),
                    "path_refs": [observed["path_id"], control["path_id"]],
                    "interaction_target_ids": sorted(
                        set(observed["interaction_target_ids"] + control["interaction_target_ids"])
                    ),
                    "ownership": "federation_linker_evidence_core_comparison",
                },
            ]
        )
        return [observed, control]

    def _incomplete_paths(
        self,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        issues: list[dict[str, Any]],
        mode: str,
    ) -> list[dict[str, Any]]:
        gap_id = "issue:missing-beta-next-hop"
        base = self._underlay_path(
            "route-path:incomplete:best-effort" if mode == "best_effort" else "route-path:incomplete:strict",
            "Best-effort reconstructed path" if mode == "best_effort" else "Strict path with unresolved tail",
            "transit-p-1",
            resources,
            links,
            targets,
            issues,
            active=True,
            primary=True,
            alternative_state="selected_primary",
            inherited_issue_refs=[gap_id],
        )
        base["segments"].pop()
        if mode == "best_effort":
            tail = self._best_effort_segment(
                "segment:incomplete:005-beta-inferred",
                5,
                resources,
                targets,
                [gap_id],
            )
        else:
            tail = self._unresolved_segment(
                "segment:incomplete:005-beta-gap",
                5,
                resources,
                targets,
                [gap_id],
            )
        base["segments"].append(tail)
        self._refresh_path(base)
        issues.append(
            {
                "issue_id": gap_id,
                "category": "incomplete",
                "severity": "warning" if mode == "best_effort" else "error",
                "summary": "Beta node-local next-hop observation is missing",
                "detail": (
                    "Best effort joins the circuit-102 boundary, Beta port status, and the "
                    "plug-in-declared local topology with reduced confidence."
                    if mode == "best_effort"
                    else "Strict mode preserves the unresolved tail and performs no inferred join."
                ),
                "path_refs": [base["path_id"]],
                "segment_refs": [tail["segment_id"]],
                "interaction_target_ids": tail["interaction_target_ids"],
                "ownership": "core_completeness_accounting",
            }
        )
        return [base]

    def _local_segment(
        self,
        segment_id: str,
        ordinal: int,
        node_id: str,
        resource_ids: list[str],
        text: str,
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        records = [resources[item] for item in resource_ids if item in resources]
        provider = self._provider_for_records(records, node_id)
        target_ids = [self._resource_target(item, targets) for item in records]
        member_id = (
            str(records[0]["member_id"])
            if records
            else f"member:{node_id}"
        )
        node_target_id = self._node_target(node_id, member_id, targets)
        operational = self._resource_operational(records, len(resource_ids))
        confidence = 0.96 if operational == "usable" else 0.68
        segment = self._segment(
            segment_id,
            ordinal,
            "node_resolution",
            records,
            target_ids,
            text,
            provider,
            active,
            primary,
            alternative_state,
            operational,
            "complete" if len(records) == len(resource_ids) else "unresolved",
            confidence,
            issue_refs,
            highlight_target_ids=[node_target_id],
        )
        segment["graph_presentation"] = {
            "role": "l3-resolution",
            "label": "L3 resolution",
            "detail": text,
            "semantic_owner": "plugin",
            "provided_by": provider,
        }
        return segment

    def _boundary_segment(
        self,
        segment_id: str,
        ordinal: int,
        resource_ids: list[str],
        link_id: str,
        text: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        records = [resources[item] for item in resource_ids if item in resources]
        link = self._matching_link(links.get(link_id, []), set(resource_ids))
        target_ids = [self._resource_target(item, targets) for item in records]
        link_target_id = None
        if link:
            link_target_id = self._link_target(link, targets)
            target_ids.append(link_target_id)
        linker = dict(self.topology.contract["federation_plugin"])
        provider = {
            "ownership": "federation_linker_plugin",
            "plugin_id": linker["plugin_id"],
            "plugin_run_id": linker["plugin_run_id"],
            "plugin_version": linker["plugin_version"],
        }
        operational = (
            str(link.get("operational_status", "unknown")) if link else "unknown"
        )
        segment = self._segment(
            segment_id,
            ordinal,
            "inter_node_boundary",
            records,
            target_ids,
            text,
            provider,
            active,
            primary,
            alternative_state,
            operational,
            "complete" if link else "unresolved",
            0.82 if link and link.get("resolution") == "ambiguous" else 0.95 if link else 0.35,
            issue_refs,
            topology_link_id=link_id,
            extra_provenance=(link.get("plugin_provenance", []) if link else []),
            highlight_target_ids=([link_target_id] if link_target_id else []),
        )
        attachment_labels = [
            str(item.get("label") or item["resource_id"]) for item in records
        ]
        segment["graph_presentation"] = {
            "role": "outer-boundary",
            "label": "L1/L2 boundary",
            "detail": " ↔ ".join(attachment_labels),
            "semantic_owner": "federation_linker_plugin",
            "provided_by": provider,
        }
        return segment

    def _best_effort_segment(
        self,
        segment_id: str,
        ordinal: int,
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        issue_refs: list[str],
    ) -> dict[str, Any]:
        ids = ["node-b/PORT/17", "node-b/LOOPBACK/1"]
        records = [resources[item] for item in ids if item in resources]
        target_ids = [self._resource_target(item, targets) for item in records]
        node_target_id = self._node_target("node-b", "member:node-b", targets)
        provider = self._provider_for_records(records, "node-b")
        segment = self._segment(
            segment_id,
            ordinal,
            "best_effort_bridge",
            records,
            target_ids,
            (
                "Beta's plug-in policy permits a topology-backed continuation from port 17 "
                "when both endpoint resources are usable, but marks the next hop inferred."
            ),
            provider,
            True,
            True,
            "selected_primary",
            self._resource_operational(records, len(ids)),
            "best_effort_inferred",
            0.58,
            issue_refs,
            highlight_target_ids=[node_target_id],
        )
        segment["inference"] = {
            "performed_by": "core",
            "rule_owner": "node_plugin",
            "method": "join_topology_with_contemporaneous_resource_status",
            "evidence": [
                {
                    "kind": "plugin_declared_local_topology",
                    "link_id": "node-b:loopback-to-port",
                    "direction_assumption": "reverse_direction_not_observed",
                },
                {
                    "kind": "node_resource_status",
                    "resource_refs": [item["resource_ref"] for item in records],
                },
            ],
            "confidence_penalty": 0.38,
        }
        return segment

    def _unresolved_segment(
        self,
        segment_id: str,
        ordinal: int,
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        issue_refs: list[str],
    ) -> dict[str, Any]:
        records = [resources[item] for item in ["node-b/PORT/17"] if item in resources]
        target_ids = [self._resource_target(item, targets) for item in records]
        node_target_id = self._node_target("node-b", "member:node-b", targets)
        provider = self._provider_for_records(records, "node-b")
        return self._segment(
            segment_id,
            ordinal,
            "unresolved",
            records,
            target_ids,
            "Beta's resolver has no node-local next-hop observation after ingress port 17.",
            provider,
            False,
            True,
            "selected_primary",
            "unknown",
            "unresolved",
            0.20,
            issue_refs,
            highlight_target_ids=[node_target_id],
        )

    def _segment(
        self,
        segment_id: str,
        ordinal: int,
        kind: str,
        records: list[dict[str, Any]],
        target_ids: list[str],
        text: str,
        provider: dict[str, Any],
        selected_active: bool,
        primary: bool,
        alternative_state: str,
        operational: str,
        completeness_state: str,
        confidence: float,
        issue_refs: list[str],
        *,
        topology_link_id: str | None = None,
        extra_provenance: list[dict[str, Any]] | None = None,
        highlight_target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        plugin_provenance = self._dedupe_provenance(
            [
                *(item.get("plugin_provenance", {}) for item in records),
                *(extra_provenance or []),
                provider,
            ]
        )
        node_ids = list(dict.fromkeys(item["node_id"] for item in records))
        member_ids = list(dict.fromkeys(item["member_id"] for item in records))
        exact_highlight_target_ids = list(dict.fromkeys(highlight_target_ids or []))
        resolution_parts = []
        labels = [str(item.get("label", item["resource_id"])) for item in records]
        if labels:
            resolution_parts.append(
                {
                    "part_id": f"{segment_id}:part:resources",
                    "text": " / ".join(labels),
                    "interactive": True,
                    "interaction_target_ids": target_ids,
                    "highlight_target_ids": exact_highlight_target_ids,
                }
            )
        resolution_parts.append(
            {
                "part_id": f"{segment_id}:part:explanation",
                "text": text,
                "interactive": True,
                "interaction_target_ids": target_ids,
                "highlight_target_ids": exact_highlight_target_ids,
            }
        )
        end_to_end = completeness_state != "unresolved"
        active = selected_active and operational != "unusable" and end_to_end
        result = {
            "segment_id": segment_id,
            "ordinal": ordinal,
            "segment_kind": kind,
            "geometry_role": "forwarding",
            "participates_in_forwarding_geometry": True,
            "phase": (
                "federation_boundary"
                if kind == "inter_node_boundary"
                else "best_effort"
                if kind == "best_effort_bridge"
                else "unresolved"
                if kind == "unresolved"
                else "local_lookup"
            ),
            "node_id": node_ids[0] if len(node_ids) == 1 else None,
            "node_ids": node_ids,
            "member_id": member_ids[0] if len(member_ids) == 1 else None,
            "member_ids": member_ids,
            "plugin_provenance": plugin_provenance,
            "route_resolution": {
                "resolution_id": f"resolution:{segment_id}",
                "ordinal": ordinal,
                "phase": (
                    "federation_boundary"
                    if kind == "inter_node_boundary"
                    else "best_effort"
                    if kind == "best_effort_bridge"
                    else "unresolved"
                    if kind == "unresolved"
                    else "local_lookup"
                ),
                "text": text,
                "text_source": "plugin_provided",
                "provided_by": provider,
                "core_role": "orders_and_joins_plugin_steps_only",
                "parts": resolution_parts,
                "interaction_target_ids": target_ids,
                "highlight_target_ids": exact_highlight_target_ids,
            },
            "route_resolution_text": text,
            "resource_refs": [item["resource_ref"] for item in records],
            "topology_link_id": topology_link_id,
            "active": active,
            "primary": primary,
            "alternative_state": alternative_state,
            "state": {
                "active": active,
                "selected_active_by_plugin": selected_active,
                "primary": primary,
                "alternative_state": alternative_state,
                "operational": operational,
            },
            "completeness": {
                "state": completeness_state,
                "end_to_end_resolved": end_to_end,
                "observed": completeness_state == "complete",
            },
            "confidence": confidence,
            "issue_refs": list(issue_refs),
            "interaction_target_ids": target_ids,
            "highlight_target_ids": exact_highlight_target_ids,
        }
        return result

    def _path(
        self,
        path_id: str,
        label: str,
        segments: list[dict[str, Any]],
        selected_active: bool,
        primary: bool,
        alternative_state: str,
        perspective: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        result = {
            "path_id": path_id,
            "label": label,
            "perspective": perspective,
            "selected_active_by_plugin": selected_active,
            "active": selected_active and all(item["active"] for item in segments),
            "primary": primary,
            "alternative_state": alternative_state,
            "segments": segments,
            "issue_refs": list(issue_refs),
        }
        self._refresh_path(result)
        return result

    @staticmethod
    def _refresh_path(path: dict[str, Any]) -> None:
        segments = path["segments"]
        path["active"] = bool(path.get("active")) and all(
            item["active"] for item in segments
        )
        path["confidence"] = round(
            min((item["confidence"] for item in segments), default=0.0), 3
        )
        unresolved = [
            item for item in segments if not item["completeness"]["end_to_end_resolved"]
        ]
        inferred = [
            item
            for item in segments
            if item["completeness"]["state"] == "best_effort_inferred"
        ]
        path["completeness"] = {
            "state": (
                "incomplete" if unresolved else "best_effort_resolved" if inferred else "complete"
            ),
            "end_to_end_resolved": not unresolved,
            "observationally_complete": not unresolved and not inferred,
            "inferred_segment_count": len(inferred),
            "unresolved_segment_count": len(unresolved),
        }
        alternative_state = str(path.get("alternative_state", ""))
        if path.get("primary") or alternative_state == "selected_primary":
            role = "primary"
        elif alternative_state == "ecmp_member":
            role = "ecmp"
        elif alternative_state == "eligible_standby":
            role = "standby"
        else:
            role = "alternative"

        terminal_segment = next(
            (
                item
                for item in segments
                if isinstance(item.get("state"), dict)
                and item["state"].get("terminal")
            ),
            None,
        )
        unusable_segment = next(
            (
                item
                for item in segments
                if isinstance(item.get("state"), dict)
                and item["state"].get("operational") == "unusable"
            ),
            None,
        )
        if terminal_segment is not None:
            terminal_state = terminal_segment["state"]
            terminal_reason = str(
                terminal_state.get("reason_code") or terminal_state["terminal"]
            )
            declared_disposition = str(
                terminal_state.get("terminal_disposition") or "unusable"
            )
            result = (
                declared_disposition
                if declared_disposition
                in {
                    "dropped",
                    "discarded",
                    "unusable",
                    "cycle",
                    "policy_blocked",
                    "hop_limit_exceeded",
                    "recursion_limit_exceeded",
                }
                else "unusable"
            )
        elif unresolved:
            terminal_reason = "unresolved_resolution"
            result = "unresolved"
        elif unusable_segment is not None:
            terminal_reason = str(
                unusable_segment["state"].get("reason_code")
                or "resource_unusable"
            )
            result = "unusable"
        elif path["completeness"]["end_to_end_resolved"]:
            terminal_reason = None
            result = "resolved"
        else:
            terminal_reason = "incomplete_resolution"
            result = "incomplete"

        eligibility_by_alternative = {
            "eligible_standby": "eligible_standby",
            "best_effort_possible": "best_effort_candidate",
            "control_expected_not_observed": "comparison_only",
            "control_plane_only": "control_plane_only",
            "withdrawn_dead": "ineligible_dead",
            "policy_rejected": "ineligible_policy",
        }
        eligibility = eligibility_by_alternative.get(alternative_state)
        if eligibility is None:
            eligibility = (
                "selected"
                if role in {"primary", "ecmp"} or path.get("active")
                else "inactive_candidate"
            )

        path["role"] = role
        path["result"] = result
        path["eligibility"] = eligibility
        path["terminal_reason"] = terminal_reason
        path["graph_target_ids"] = [
            str(target_id)
            for item in sorted(segments, key=lambda candidate: candidate["ordinal"])
            for target_id in item.get("highlight_target_ids", [])
        ]
        path["route_resolution_sequence"] = [
            {
                "sequence": item["ordinal"],
                "segment_id": item["segment_id"],
                "route_resolution": item["route_resolution"],
            }
            for item in segments
        ]
        path["interaction_target_ids"] = list(
            dict.fromkeys(
                target
                for item in segments
                for target in item["interaction_target_ids"]
            )
        )
        path["plugin_provenance"] = MultiNodeRouteDemo._dedupe_provenance(
            [
                provider
                for item in segments
                for provider in item["plugin_provenance"]
            ]
        )

    @staticmethod
    def _provider_for_records(
        records: list[dict[str, Any]], node_id: str
    ) -> dict[str, Any]:
        if records:
            provider = dict(records[0].get("plugin_provenance", {}))
            provider["ownership"] = "node_plugin"
            return provider
        fallbacks = {
            "node-a": ("demo.alpha.platform", "run:node-a/alpha-platform:2.4.0"),
            "node-b": ("demo.beta.forwarding", "run:node-b/beta-forwarding:5.1.2"),
            "transit-p-1": ("demo.gamma.isis", "run:transit-p-1/gamma-isis:3.0.1"),
            "transit-p-2": (
                "demo.delta.sr-isis",
                "run:transit-p-2/delta-sr-isis:4.2.0",
            ),
            "node-c": (
                "demo.epsilon.forwarding",
                "run:node-c/epsilon-forwarding:7.0.3",
            ),
            "node-d": (
                "demo.zeta.fabric",
                "run:node-d/zeta-fabric:6.2.1",
            ),
            "node-e": (
                "demo.eta.border",
                "run:node-e/eta-border:8.3.2",
            ),
        }
        plugin_id, run_id = fallbacks[node_id]
        return {
            "ownership": "node_plugin",
            "plugin_id": plugin_id,
            "plugin_run_id": run_id,
        }

    @staticmethod
    def _resource_operational(
        records: list[dict[str, Any]], expected_count: int
    ) -> str:
        if len(records) != expected_count:
            return "unknown"
        classes = {item.get("status_class") for item in records}
        if "unusable" in classes:
            return "unusable"
        if classes == {"usable"}:
            return "usable"
        return "unknown"

    @staticmethod
    def _matching_link(
        candidates: list[dict[str, Any]], required_resource_ids: set[str]
    ) -> dict[str, Any] | None:
        for item in candidates:
            endpoint_ids = {
                item["endpoint_a"]["resource_id"],
                item["endpoint_b"]["resource_id"],
            }
            if endpoint_ids == required_resource_ids:
                return item
        # A topology link identifier is not sufficient evidence when a
        # federation result contains several scoped candidates.  Choosing the
        # first candidate can silently attach a route segment to the wrong
        # endpoints; leave it unresolved unless the exact endpoint set matches.
        return None

    @staticmethod
    def _dedupe_provenance(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for raw in values:
            if not raw:
                continue
            item = dict(raw)
            key = (str(item.get("plugin_id")), str(item.get("plugin_run_id")))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _target_id(kind: str, material: str) -> str:
        digest = hashlib.sha256(f"{kind}:{material}".encode("utf-8")).hexdigest()[:16]
        return f"target:{kind}:{digest}"

    def _resource_target(
        self, resource: dict[str, Any], targets: dict[str, dict[str, Any]]
    ) -> str:
        ref = resource["resource_ref"]
        target_id = self._target_id(
            "resource",
            f"{ref['member_id']}:{ref['revision_id']}:{ref['local_resource_id']}",
        )
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "resource",
                "label": resource.get("label", resource["resource_id"]),
                "node_id": resource["node_id"],
                "member_id": resource["member_id"],
                "resource_ref": ref,
                "status": resource.get("status"),
                "status_class": resource.get("status_class"),
                "deep_link": resource.get("deep_link"),
            },
        )
        return target_id

    def _node_target(
        self,
        node_id: str,
        member_id: str,
        targets: dict[str, dict[str, Any]],
    ) -> str:
        """Register a stable graph-level target without folding in resource identity."""
        target_id = self._target_id("topology-node", f"{member_id}:{node_id}")
        router = next((item for item in _ROUTERS if item["node_id"] == node_id), None)
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "topology_node",
                "label": (router or {}).get("label", node_id),
                "node_id": node_id,
                "member_id": member_id,
                "semantic_owner": "plugin",
            },
        )
        return target_id

    def _link_target(
        self, link: dict[str, Any], targets: dict[str, dict[str, Any]]
    ) -> str:
        target_id = self._target_id(
            "topology-link",
            f"{link['link_id']}:{link['endpoint_a']['resource_id']}:{link['endpoint_b']['resource_id']}",
        )
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "topology_link",
                "label": link["link_type"],
                "topology_link_id": link["link_id"],
                "resolution": link["resolution"],
                "operational_status": link["operational_status"],
                "endpoint_a": link["endpoint_a"],
                "endpoint_b": link["endpoint_b"],
                "deep_link": link.get("deep_links", {}).get("topology"),
            },
        )
        return target_id
