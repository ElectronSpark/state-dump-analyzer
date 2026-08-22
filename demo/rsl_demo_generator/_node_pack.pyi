from ._archive import directory_members as _directory_members
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from rsl_demo_plugin.archive import NODE_PACK_GENERATOR, NODE_PACK_ROOT
from typing import Any, Final

__all__ = ['_directory_members', 'PACK_GENERATOR', 'PACK_ROOT', 'SCALE_FILES', 'CONTAINERS', '_write_status_files', '_write_event_files', '_write_container_manifests']

PACK_GENERATOR = NODE_PACK_GENERATOR
PACK_ROOT = NODE_PACK_ROOT
SCALE_FILES: Final[tuple[str, ...]]

@dataclass(frozen=True)
class ContainerDefinition:
    container_id: str
    label: str
    status_layout: str
    tables: tuple[str, ...]

CONTAINERS: Final[tuple[ContainerDefinition, ...]]

def _write_status_files(stage: Path, scale_dir: Path, scenario: dict[str, Any]) -> tuple[dict[tuple[str, str], int], dict[str, int]]: ...
def _write_event_files(stage: Path, scale_dir: Path, scenario: dict[str, Any]) -> tuple[dict[str, int], dict[str, Counter[str]]]: ...
def _write_container_manifests(stage: Path, scenario: dict[str, Any], row_counts: dict[tuple[str, str], int], container_resource_counts: dict[str, int], event_counts: dict[str, int], outcome_counts: dict[str, Counter[str]]) -> list[dict[str, Any]]: ...
