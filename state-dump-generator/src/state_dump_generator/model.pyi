from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ['SCHEMA_VERSION', 'SCHEMA_ID', 'MAX_NODES', 'MAX_MEDIA', 'MAX_EVENTS', 'ScenarioValidationError', 'ScenarioDocument', 'scenario_from_dict', 'load_scenario', 'new_scenario', 'validate_scenario']

SCHEMA_VERSION: int
SCHEMA_ID: str
MAX_NODES: int
MAX_MEDIA: int
MAX_EVENTS: int

class ScenarioValidationError(ValueError): ...

@dataclass(frozen=True, slots=True)
class ScenarioDocument:
    scenario_id: str
    name: str
    seed: int
    capture_time_ns: int
    nodes: tuple[dict[str, Any], ...]
    media: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]
    schema_version: int = ...
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScenarioDocument: ...

def scenario_from_dict(value: Mapping[str, Any]) -> ScenarioDocument: ...
def load_scenario(path: Path | str) -> ScenarioDocument: ...
def new_scenario() -> dict[str, Any]: ...
def validate_scenario(value: ScenarioDocument | Mapping[str, Any]) -> dict[str, Any]: ...
