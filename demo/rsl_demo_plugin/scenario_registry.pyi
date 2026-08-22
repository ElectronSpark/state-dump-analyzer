from typing import Any

__all__ = ['BASE_ROUTE_TRACE_SCENARIOS', 'PACKET_TRACE_SCENARIOS', 'ROUTE_TRACE_SCENARIOS', 'ROUTE_PROTOCOL_BY_TYPE', 'ROUTE_RESOLUTION_LAYERS_BY_TYPE', 'ROUTE_INVENTORY_CONTEXTS', 'SCENARIO_BY_ID', 'scenario_semantics']

BASE_ROUTE_TRACE_SCENARIOS: tuple[dict[str, Any], ...]
PACKET_TRACE_SCENARIOS: tuple[dict[str, Any], ...]
ROUTE_TRACE_SCENARIOS: tuple[dict[str, Any], ...]
ROUTE_PROTOCOL_BY_TYPE: dict[str, str]
ROUTE_RESOLUTION_LAYERS_BY_TYPE: dict[str, tuple[str, ...]]
ROUTE_INVENTORY_CONTEXTS: tuple[dict[str, Any], ...]
SCENARIO_BY_ID: dict[str, dict[str, Any]]

def scenario_semantics(scenario_id: str) -> dict[str, Any]: ...
