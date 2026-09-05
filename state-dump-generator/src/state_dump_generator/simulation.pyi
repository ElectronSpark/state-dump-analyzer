from .model import ScenarioDocument
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ['reconstruct_scenario', 'compile_scenario']

@dataclass(frozen=True, slots=True)
class _ScheduledObservation:
    timestamp_ns: int
    order: int
    stable_id: str
    node_id: str
    resource_id: str
    resource_type: str
    operation: str
    outcome: str
    status: str | None
    properties: dict[str, Any]
    message: str
    update_snapshot: bool
    source: str

def reconstruct_scenario(value: ScenarioDocument | Mapping[str, Any], *, at_time_ns: int | str | None = None) -> dict[str, Any]: ...
def compile_scenario(value: ScenarioDocument | Mapping[str, Any]) -> dict[str, dict[str, Any]]: ...
