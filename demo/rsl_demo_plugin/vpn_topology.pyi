from collections.abc import Mapping
from typing import Any

__all__ = ['vpn_domain_key', 'project_vpn_topology_resource']

def vpn_domain_key(service_type: str, vrf: str, route_target: str, vni: int | None = None) -> str: ...
def project_vpn_topology_resource(*, node_id: str, revision_id: str, resource: Mapping[str, Any], valid_from_ns: int) -> tuple[dict[str, Any], dict[str, Any]] | None: ...
