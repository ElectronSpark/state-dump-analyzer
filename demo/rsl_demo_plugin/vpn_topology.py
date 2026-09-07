"""Demo-owned VPN semantics inferred from node-local service configuration.

This module consumes opaque authored resource properties, not generator media
or peer lists. VPN domains describe service membership, never physical hops.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from . import GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID


def vpn_domain_key(
    service_type: str,
    vrf: str,
    route_target: str,
    vni: int | None = None,
) -> str:
    """Keep tenant, technology and import/export scope in service identity."""

    key = (
        f"vpn:{quote(service_type, safe='')}:{quote(vrf, safe='')}"
        f":rt:{quote(route_target, safe='')}"
    )
    return f"{key}:vni:{vni}" if vni is not None else key


def project_vpn_topology_resource(
    *,
    node_id: str,
    revision_id: str,
    resource: Mapping[str, Any],
    valid_from_ns: int,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Project one supported local service as a separate connectivity domain."""

    properties = resource.get("properties", {})
    if not isinstance(properties, Mapping):
        return None
    service_type = properties.get("service_type")
    if service_type not in {"mpls_l3vpn", "evpn_vxlan"}:
        return None
    if resource.get("kind") != "VIRTUAL_INTERFACE":
        return None
    for field in ("service_id", "vrf", "route_target", "interface"):
        if not isinstance(properties.get(field), str) or not properties[field]:
            raise ValueError(f"demo VPN service requires local {field}")
    vni = properties.get("vni")
    if service_type == "evpn_vxlan" and (
        type(vni) is not int or not 1 <= vni <= 16_777_215
    ):
        raise ValueError("demo EVPN service requires a valid local VNI")
    if service_type == "mpls_l3vpn":
        vni = None
    vrf = str(properties["vrf"])
    route_target = str(properties["route_target"])
    prefix = properties.get("prefix")
    resource_id = str(resource["resource_id"])
    interface = str(properties["interface"])
    label = (
        f"{vrf} EVPN / VNI {vni}"
        if service_type == "evpn_vxlan"
        else f"{vrf} L3VPN / RT {route_target}"
    )
    key = vpn_domain_key(str(service_type), vrf, route_target, vni)
    projected_resource = {
        **dict(properties),
        "resource_id": resource_id,
        "kind": "VIRTUAL_INTERFACE",
        "label": interface,
        "status": str(resource.get("status") or "unknown"),
        "changes": list(resource.get("changes") or []),
    }
    claim = {
        "claim_id": f"{node_id}/topology/{properties['service_id']}",
        "node_id": node_id,
        "revision_id": revision_id,
        "interface_resource_id": resource_id,
        "interface_name": interface,
        "label": label,
        "attachment_kind": "logical",
        "components": {"logical_interface": interface},
        "segment_key": key,
        "matcher_id": GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
        "subnet": {
            "prefix": prefix,
            "classification": "vpn",
            "render_hint": "domain_node",
        },
        "plugin_semantics": {
            "network_kind": "vpn_service",
            "routing_scope": vrf,
            "address_family": (
                "l2vpn" if service_type == "evpn_vxlan"
                else "ipv6" if isinstance(prefix, str) and ":" in prefix
                else "ipv4"
            ),
            "presentation_group": "vpn",
            "service_type": service_type,
            "route_target": route_target,
            "vni": vni,
        },
        "topology_presentation": {
            "two_participant_shape": "domain_node",
            "reason": (
                "VPN membership is inferred from local service type, VRF, "
                "route target and VNI; it is not a physical adjacency."
            ),
        },
        "status": str(resource.get("status") or "unknown"),
        "valid_from_ns": str(valid_from_ns),
        "valid_to_ns": None,
        "confidence": "plugin_declared",
        "excluded_from_connectivity": True,
        "calculation": {
            "owner": "plugin",
            "basis": ["local VPN service configuration", "local interface state"],
            "summary": (
                f"{service_type}; VRF {vrf}; route target {route_target}"
                + (f"; VNI {vni}" if vni is not None else "")
                + ". Service membership does not create a forwarding hop."
            ),
        },
        "evidence_resource_ids": [resource_id],
    }
    return projected_resource, claim


__all__ = ["project_vpn_topology_resource", "vpn_domain_key"]
