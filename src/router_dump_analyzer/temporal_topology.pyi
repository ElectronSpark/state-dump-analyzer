from .normalized_data import contains_time as contains_time
from .process_control import PROCESS_CONTROL_EXCEPTIONS as PROCESS_CONTROL_EXCEPTIONS
from .temporal_core import RESOURCE_CREATION_OPERATIONS as RESOURCE_CREATION_OPERATIONS, RESOURCE_DELETION_OPERATIONS as RESOURCE_DELETION_OPERATIONS, TEMPORAL_ORDER_VERSION as TEMPORAL_ORDER_VERSION, checked_temporal_add as checked_temporal_add, checked_temporal_subtract as checked_temporal_subtract, distinct_temporal_states as distinct_temporal_states, temporal_integer as temporal_integer, temporal_order_key as temporal_order_key
from collections.abc import Callable
from typing import Any

StateReader = Callable[[str, int], dict[str, Any]]
RelationshipReader = Callable[[int], list[dict[str, Any]]]

class TemporalTopologyRequestError(ValueError): ...

class TemporalTopologyService:
    dataset: dict[str, Any]
    state_reader: StateReader | None
    relationship_reader: RelationshipReader
    contract: dict[str, Any]
    temporal_metadata: dict[str, Any]
    revision_id: str
    timeline_start_ns: int
    timeline_end_ns: int
    capture_ns: int
    default_node: str
    resource_by_id: dict[str, Any]
    runtime: Any
    def __init__(self, dataset: dict[str, Any], state_reader: StateReader | None, relationship_reader: RelationshipReader, *, contract: dict[str, Any], temporal_metadata: dict[str, Any]) -> None: ...
    def capabilities(self) -> dict[str, Any]: ...
    def query(self, body: dict[str, Any]) -> dict[str, Any]: ...
    def query_changes(self, body: dict[str, Any]) -> dict[str, Any]: ...
