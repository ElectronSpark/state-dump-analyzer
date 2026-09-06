from .contract_validation import strict_integer as strict_integer
from .normalized_data import active_interval as active_interval, state_intervals_for_perspective as state_intervals_for_perspective
from .plugin_api import StatusPerspectiveRef as StatusPerspectiveRef
from .process_control import PROCESS_CONTROL_EXCEPTIONS as PROCESS_CONTROL_EXCEPTIONS
from .temporal_core import MIN_TEMPORAL_NS as MIN_TEMPORAL_NS, RESOURCE_CREATION_OPERATIONS as RESOURCE_CREATION_OPERATIONS, RESOURCE_DELETION_OPERATIONS as RESOURCE_DELETION_OPERATIONS, TEMPORAL_ORDER_VERSION as TEMPORAL_ORDER_VERSION, checked_temporal_add as checked_temporal_add, checked_temporal_subtract as checked_temporal_subtract, contains_time as contains_time, distinct_temporal_states as distinct_temporal_states, possible_relationship_presence as possible_relationship_presence, relationship_presence as relationship_presence, temporal_integer as temporal_integer, temporal_order_key as temporal_order_key
from .value_core import MAX_JSON_SAFE_INTEGER as MAX_JSON_SAFE_INTEGER
from collections.abc import Callable
from typing import Any

StateReader = Callable[[str, int], dict[str, Any]]
PerspectiveStateReader = Callable[[str, int, StatusPerspectiveRef], dict[str, Any]]
RelationshipReader = Callable[[int], list[dict[str, Any]]]

class TemporalTopologyRequestError(ValueError): ...

class TemporalTopologyService:
    dataset: dict[str, Any]
    state_reader: StateReader | None
    perspective_state_reader: PerspectiveStateReader | None
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
    def __init__(self, dataset: dict[str, Any], state_reader: StateReader | None, relationship_reader: RelationshipReader, *, contract: dict[str, Any], temporal_metadata: dict[str, Any], perspective_state_reader: PerspectiveStateReader | None = None) -> None: ...
    def capabilities(self) -> dict[str, Any]: ...
    def query(self, body: dict[str, Any]) -> dict[str, Any]: ...
    def query_changes(self, body: dict[str, Any]) -> dict[str, Any]: ...
