from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping

__all__ = ['SCENARIO_SCHEMA_ID', 'DEFAULT_SCENARIO_PATH', 'ScenarioSourceError', 'SourceResource', 'NodeSpec', 'LinkSpec', 'GenerationDefaults', 'ExplicitObservation', 'PhysicalChange', 'DemoScenarioSource', 'load_scenario_source', 'load_default_scenario_source']

SCENARIO_SCHEMA_ID: str
DEFAULT_SCENARIO_PATH: Final[Path]

class ScenarioSourceError(ValueError): ...

@dataclass(frozen=True, slots=True)
class SourceResource:
    resource_id: str
    resource_type: str
    status: str
    properties_json: str
    updated_at_ns: int
    @property
    def properties(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class NodeSpec:
    node_id: str
    label: str
    role: str
    site: str
    clock_offset_ns: int = ...
    clock_uncertainty_ns: int = ...
    routing_groups: tuple[str, ...] = ...
    initial_resources: tuple[SourceResource, ...] = ...
    @property
    def revision_id(self) -> str: ...
    @property
    def identity_namespace(self) -> str: ...

@dataclass(frozen=True, slots=True)
class LinkSpec:
    segment_id: str
    label: str
    prefix: str
    participants: tuple[str, ...]
    attachment_resource_ids: tuple[str, ...]
    attachment_statuses: tuple[str, ...]
    attachment_kind: str
    vlan_id: int | None = ...
    lag_id: str | None = ...
    classification: str = ...
    confidence: str = ...
    def attachment_resource_id(self, node_id: str) -> str: ...
    def attachment_status(self, node_id: str) -> str: ...

@dataclass(frozen=True, slots=True)
class GenerationDefaults:
    assembly_id: str
    default_node_id: str
    events_per_node: int
    resources_per_node: int
    seed: int

@dataclass(frozen=True, slots=True)
class ExplicitObservation:
    event_id: str
    node_id: str
    relative_time_ns: int
    timestamp_ns: int
    order: int
    kind: str
    resource_id: str
    resource_type: str
    operation: str
    outcome: str
    status: str | None
    update_snapshot: bool
    message: str
    event_json: str
    def to_event(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class PhysicalChange:
    event_id: str
    relative_time_ns: int
    timestamp_ns: int
    order: int
    medium_id: str
    segment_id: str
    status: str

@dataclass(frozen=True, slots=True)
class DemoScenarioSource:
    path: Path
    sha256: str
    scenario_id: str
    base_time_ns: int
    capture_offset_ns: int
    capture_time_ns: int
    defaults: GenerationDefaults
    nodes: tuple[NodeSpec, ...]
    links: tuple[LinkSpec, ...]
    observations_by_node: Mapping[str, tuple[ExplicitObservation, ...]]
    physical_changes: tuple[PhysicalChange, ...]
    @property
    def observations(self) -> tuple[ExplicitObservation, ...]: ...
    def resources_at(self, node_id: str, *, timestamp_ns: int | None = None) -> tuple[SourceResource, ...]: ...

def load_scenario_source(path: Path | str = ..., *, fresh: bool = False) -> DemoScenarioSource: ...
def load_default_scenario_source(*, fresh: bool = False) -> DemoScenarioSource: ...
