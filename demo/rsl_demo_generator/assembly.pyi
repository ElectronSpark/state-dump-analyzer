import re
from .catalog import NodeSpec
from dataclasses import dataclass, field
from pathlib import Path
from rsl_demo_plugin import GENERATED_ASSEMBLY_FORMAT_VERSION
from rsl_demo_plugin.archive import ASSEMBLY_GENERATOR as ASSEMBLY_GENERATOR, ASSEMBLY_ROOT as ASSEMBLY_ROOT
from typing import Any, Final, Iterable, Mapping

__all__ = ['ASSEMBLY_GENERATOR', 'ASSEMBLY_ROOT', 'ASSEMBLY_FORMAT_VERSION', 'DEFAULT_ASSEMBLY_NAME', 'DEFAULT_ASSEMBLY_ID', 'DEFAULT_PLUGIN_ID', 'DEFAULT_PLUGIN_VERSION', 'DEFAULT_EVENT_COUNT', 'DEFAULT_RESOURCE_COUNT', 'DEFAULT_SEED', 'PROJECTION_ROOT', 'AssemblyConfig', 'ValidationReport', 'LaunchPreflightReport', 'EnsureLaunchReport', 'build_coverage', 'probe_demo_fixture_for_launch', 'build_demo_fixture', 'ensure_demo_fixture_for_launch', 'validate_demo_fixture', 'parse_node_selection']

ASSEMBLY_FORMAT_VERSION = GENERATED_ASSEMBLY_FORMAT_VERSION
DEFAULT_ASSEMBLY_NAME: str
DEFAULT_ASSEMBLY_ID: Final[str]
DEFAULT_PLUGIN_ID: Final[str]
DEFAULT_PLUGIN_VERSION: Final[str]
DEFAULT_EVENT_COUNT: Final[int]
DEFAULT_RESOURCE_COUNT: Final[int]
DEFAULT_SEED: Final[int]
PROJECTION_ROOT: Final[str]

@dataclass(frozen=True, slots=True)
class _JsonlRewritePlan:
    quoted_prefixes: tuple[bytes, ...]
    timestamp_pattern: re.Pattern[bytes]
    has_clock_domain: bool = ...
    has_burst_id: bool = ...

@dataclass(frozen=True, slots=True)
class AssemblyConfig:
    nodes: tuple[NodeSpec, ...] = ...
    events_per_node: int = ...
    resources_per_node: int = ...
    seed: int = ...
    allow_small: bool = ...
    assembly_id: str = ...
    default_node_id: str | None = ...
    def __post_init__(self) -> None: ...
    @property
    def selected_default_node_id(self) -> str: ...
    @property
    def full_scale(self) -> bool: ...

@dataclass(frozen=True, slots=True)
class ValidationReport:
    assembly_id: str
    node_ids: tuple[str, ...]
    coverage_case_count: int
    full_scale: bool
    deep: bool
    archive_sha256: str
    warnings: tuple[str, ...] = field(default_factory=tuple)

@dataclass(frozen=True, slots=True)
class LaunchPreflightReport:
    assembly_id: str
    node_ids: tuple[str, ...]
    coverage_case_count: int
    full_scale: bool

@dataclass(frozen=True, slots=True)
class EnsureLaunchReport:
    preferred_path: Path
    output_path: Path
    preflight: LaunchPreflightReport
    generated: bool
    used_recovery_path: bool = ...
    preserved_preferred: bool = ...
    rejection_reason: str | None = ...

@dataclass(frozen=True, slots=True)
class _PathSpec:
    suffix: str
    sequence: tuple[str, ...]
    selected: bool
    primary: bool
    alternative: str
    steering_profile_id: str | None = ...
    resolution_modes: tuple[str, ...] = ...
    inferred: bool = ...

def build_coverage(config: AssemblyConfig, *, _topology_projections: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]: ...
def probe_demo_fixture_for_launch(path: Path) -> LaunchPreflightReport: ...
def build_demo_fixture(output: Path, *, config: AssemblyConfig | None = None) -> Path: ...
def ensure_demo_fixture_for_launch(output: Path, *, force_rebuild: bool = False) -> EnsureLaunchReport: ...

@dataclass(frozen=True, slots=True)
class _JsonlScan:
    records: int
    sha256: str
    state_change_records: int

@dataclass(frozen=True, slots=True)
class _ResourceTableScan:
    records: int
    sha256: str

def validate_demo_fixture(path: Path, *, require_full_scale: bool | None = None, deep: bool = False) -> ValidationReport: ...
def parse_node_selection(node_ids: Iterable[str]) -> tuple[NodeSpec, ...]: ...
