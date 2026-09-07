"""Example plug-in route semantics supplied to the core service."""

from __future__ import annotations

from typing import Any

from router_dump_analyzer.multi_node_route import (
    RouteProjectionSet,
    RouteServicePolicy,
)

from .advanced_trace import STEERING_PROFILES, build_packet_transitions
from .assembly_store import DemoAssemblyStore
from .cross_node_consistency import revalidate_boundary_coverage
from .scenario_registry import SCENARIO_BY_ID
from .vpn_topology import vpn_domain_key

_SERVICE_PRESENTATIONS: dict[str, dict[str, Any]] = {
    "mpls_l3vpn": {
        "technology": "MPLS L3VPN",
        "label": "{vrf} VPN overlay · {technology}",
        "description": (
            "Tenant routing and VPN-label context encloses the outer path; "
            "it is not an additional forwarding hop."
        ),
        "fact_fields": {},
        "connectivity_domain_keys": {
            "blue": vpn_domain_key("mpls_l3vpn", "blue", "65000:100"),
            "red": vpn_domain_key("mpls_l3vpn", "red", "65000:200"),
        },
    },
    "evpn_service": {
        "technology": "EVPN service",
        "label": "{vrf} VPN overlay · {technology}",
        "description": (
            "EVPN control and service context encloses the outer path; "
            "it is not an additional forwarding hop."
        ),
        "fact_fields": {"evpn": "service_attributes"},
        "connectivity_domain_keys": {
            "blue": vpn_domain_key("evpn_vxlan", "blue", "65000:50100", 50100),
        },
    },
    "evpn_mac_ip": {
        "technology": "EVPN MAC/IP",
        "label": "{vrf} VPN overlay · {technology}",
        "description": (
            "EVPN Type-2 and Ethernet-segment context encloses the outer "
            "path; it is not an additional forwarding hop."
        ),
        "fact_fields": {"evpn": "service_attributes"},
        "connectivity_domain_keys": {
            "blue": vpn_domain_key("evpn_vxlan", "blue", "65000:50100", 50100),
        },
    },
    "evpn_ip_prefix": {
        "technology": "EVPN IP prefix",
        "label": "{vrf} VPN overlay · {technology}",
        "description": (
            "EVPN Type-5 and IP-prefix context encloses the outer path; "
            "it is not an additional forwarding hop."
        ),
        "fact_fields": {"evpn": "service_attributes"},
        "connectivity_domain_keys": {
            "blue": vpn_domain_key("evpn_vxlan", "blue", "65000:50100", 50100),
        },
    },
}


_ROUTE_TYPE_PROFILES: dict[str, dict[str, Any]] = {
    "ipv4_unicast": {
        "source_phase": "local_lookup",
        "path_attributes": {
            "protocol_chain": ["ibgp", "isis-l2"],
            "encapsulation": {"kind": "ip"},
        },
    },
    "ipv6_unicast": {
        "source_phase": "local_lookup",
        "path_attributes": {
            "protocol_chain": ["ibgp", "isis-l2"],
            "encapsulation": {"kind": "ipv6"},
        },
    },
    "connected": {
        "source_phase": "local_lookup",
        "path_attributes": {
            "protocol_chain": ["connected"],
            "encapsulation": {"kind": "native"},
        },
    },
    "static_recursive": {
        "source_phase": "recursive_lookup",
        "phase_by_visit_index": {"1": "recursive_lookup"},
        "path_attributes": {
            "protocol_chain": [
                "static",
                "ibgp",
                "isis-l2",
                "connected",
            ],
            "encapsulation": {"kind": "recursive_ip_transport"},
        },
    },
    "isis_underlay": {
        "source_phase": "local_lookup",
        "path_attributes": {
            "protocol_chain": ["isis-l2"],
            "encapsulation": {"kind": "ip"},
        },
    },
    "mpls_transport": {
        "source_phase": "candidate_selection",
        "path_attributes": {
            "protocol_chain": ["isis-l2", "segment-routing-mpls"],
            "encapsulation": {
                "kind": "mpls",
                "actions": ["push", "swap", "pop"],
            },
        },
    },
    "mpls_l3vpn": {
        "source_phase": "candidate_selection",
        "path_attributes": {
            "protocol_chain": ["bgp-vpnv4", "segment-routing-mpls"],
            "encapsulation": {
                "kind": "mpls_l3vpn",
                "actions": ["push_transport_and_vpn", "swap", "pop"],
            },
        },
        "service_presentation": _SERVICE_PRESENTATIONS["mpls_l3vpn"],
    },
    "srv6_policy": {
        "source_phase": "tunnel_action",
        "path_attributes": {
            "protocol_chain": ["bgp-sr-policy", "isis-l2"],
            "encapsulation": {
                "kind": "srv6",
                "actions": ["encap", "end", "decap"],
            },
        },
    },
    "evpn_service": {
        "source_phase": "candidate_selection",
        "path_attributes": {
            "protocol_chain": ["bgp-evpn", "isis-l2"],
            "encapsulation": {"kind": "vxlan", "vni": 10100},
        },
        "service_presentation": _SERVICE_PRESENTATIONS["evpn_service"],
    },
    "evpn_mac_ip": {
        "source_phase": "candidate_selection",
        "path_attributes": {
            "protocol_chain": ["bgp-evpn", "isis-l2"],
            "encapsulation": {
                "kind": "vxlan",
                "vni": 10320,
                "evpn_route_type": 2,
            },
        },
        "service_presentation": _SERVICE_PRESENTATIONS["evpn_mac_ip"],
    },
    "evpn_ip_prefix": {
        "source_phase": "candidate_selection",
        "path_attributes": {
            "protocol_chain": ["bgp-evpn", "isis-l2"],
            "encapsulation": {
                "kind": "vxlan",
                "vni": 10330,
                "evpn_route_type": 5,
            },
        },
        "service_presentation": _SERVICE_PRESENTATIONS["evpn_ip_prefix"],
    },
}


DEMO_ROUTE_POLICY: RouteServicePolicy = RouteServicePolicy(
    scenarios=SCENARIO_BY_ID,
    default_scenario_id="single-active-primary",
    steering_profiles=STEERING_PROFILES,
    packet_transition_builder=build_packet_transitions,
    endpoint_profiles={
        "blue_service": {
            "endpoint_id": "endpoint:blue-service-prefix",
            "destination_id": "destination:blue-service-prefix",
            "kind": "ip_prefix",
            "value": "203.0.113.0/24",
            "label": "Blue service prefix",
            "resource_mode": "router",
        },
        "evpn_service": {
            "endpoint_id": "endpoint:east-evpn-multihomed-service",
            "destination_id": "destination:east-evpn-multihomed-service",
            "kind": "evpn_ethernet_segment",
            "value": "esi-east:vlan-320",
            "label": "East EVPN multihomed service",
            "resource_mode": "scenario",
            "multi_attachment": True,
        },
        "external_subnet": {
            "endpoint_id": "endpoint:eta-external-subnet",
            "destination_id": "destination:eta-external-subnet",
            "kind": "ip_prefix",
            "value": "203.0.113.0/24",
            "label": "PE-E external subnet",
            "resource_mode": "scenario",
            "allow_same_node": True,
        },
    },
    route_type_profiles=_ROUTE_TYPE_PROFILES,
    route_family_presentations={
        "ipv4_unicast": {"safi": "unicast", "label": "IPv4 unicast"},
        "ipv6_unicast": {"safi": "unicast", "label": "IPv6 unicast"},
        "mpls_labeled_unicast": {
            "safi": "labeled_unicast",
            "label": "MPLS labeled unicast",
        },
        "vpnv4_unicast": {"safi": "mpls_vpn", "label": "VPNv4 unicast"},
        "l2vpn_evpn": {"safi": "evpn", "label": "L2VPN EVPN"},
    },
    vrf_aliases={
        "global": "default",
        "master": "default",
        "tenant-blue": "blue",
        "tenant_blue": "blue",
        "mgmt": "management",
    },
    router_value_aliases={
        "10.255.0.1/32": "node-a",
        "10.255.0.1": "node-a",
        "10.255.0.2/32": "node-b",
        "10.255.0.2": "node-b",
        "10.255.0.11/32": "transit-p-1",
        "10.255.0.11": "transit-p-1",
        "10.255.0.12/32": "transit-p-2",
        "10.255.0.12": "transit-p-2",
        "10.255.0.3/32": "node-c",
        "10.255.0.3": "node-c",
        "10.255.0.4/32": "node-d",
        "10.255.0.4": "node-d",
        "10.255.0.5/32": "node-e",
        "10.255.0.5": "node-e",
        "2001:db8:1::/128": "node-a",
        "2001:db8:1::": "node-a",
        "2001:db8:2::/128": "node-b",
        "2001:db8:2::": "node-b",
        "2001:db8:3::/128": "transit-p-1",
        "2001:db8:3::": "transit-p-1",
        "2001:db8:4::/128": "transit-p-2",
        "2001:db8:4::": "transit-p-2",
        "2001:db8:5::/128": "node-c",
        "2001:db8:5::": "node-c",
        "2001:db8:6::/128": "node-d",
        "2001:db8:6::": "node-d",
        "2001:db8:7::/128": "node-e",
        "2001:db8:7::": "node-e",
    },
    route_table_schema_version="demo.route-table.v1",
    packet_trace_schema_version="demo.forwarding-packet-trace.v1",
    node_matcher_id="demo.node-id.exact.v1",
    topology_link_matcher_id="demo.topology-link-id.exact.v1",
    connectivity_domain_matcher_id=(
        "demo.connectivity-domain-key.exact.v1"
    ),
    data_disclosure=(
        "All route, packet, topology, and status records are synthetic "
        "example plug-in output."
    ),
)


def build_route_projection_set(
    revision_store: DemoAssemblyStore,
) -> RouteProjectionSet:
    """Detach the example archive store from the core route service."""

    projections_by_node = {
        descriptor.node_id: revision_store.projection_for_node(
            descriptor.node_id
        )
        for descriptor in revision_store.assembly.revisions
    }
    revision_ids_by_node = {
        descriptor.node_id: descriptor.revision_id
        for descriptor in revision_store.assembly.revisions
    }
    return RouteProjectionSet(
        projections_by_node=projections_by_node,
        revision_ids_by_node=revision_ids_by_node,
        coverage=revalidate_boundary_coverage(
            revision_store.coverage,
            projections_by_node,
            revision_ids_by_node,
            SCENARIO_BY_ID,
        ),
    )


__all__ = [
    "DEMO_ROUTE_POLICY",
    "build_route_projection_set",
]
