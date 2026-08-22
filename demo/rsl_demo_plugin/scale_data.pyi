from . import GENERATED_PROJECTION_POLICY as GENERATED_PROJECTION_POLICY
from .archive import MANIFEST_MEMBER_NAME as MANIFEST_MEMBER_NAME, NODE_PACK_GENERATOR as NODE_PACK_GENERATOR, NODE_PACK_MANIFEST_MEMBER as NODE_PACK_MANIFEST_MEMBER, NODE_PACK_ROOT as NODE_PACK_ROOT, NORMALIZED_SCALE_PREFIX as NORMALIZED_SCALE_PREFIX, RELATIONSHIP_MUTATIONS_MEMBER_NAME as RELATIONSHIP_MUTATIONS_MEMBER_NAME, normalize_archive_member_name as normalize_archive_member_name
from .scale import RESOURCE_TABLE_COLUMNS as RESOURCE_TABLE_COLUMNS, RESOURCE_TABLE_JSON_COLUMNS as RESOURCE_TABLE_JSON_COLUMNS
from .source_records import RECORD_LANE_PRESETS as RECORD_LANE_PRESETS, SOURCE_RECORD_DESCRIPTORS as SOURCE_RECORD_DESCRIPTORS, SOURCE_RECORD_GROUP_DESCRIPTORS as SOURCE_RECORD_GROUP_DESCRIPTORS, build_demo_source_records as build_demo_source_records
from collections.abc import Callable as Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from router_dump_analyzer.history_search_core import HistorySearchCorpus
from typing import Any, Final

PACK_ROOT = NODE_PACK_ROOT
SCALE_PREFIX = NORMALIZED_SCALE_PREFIX
MAX_SCALE_MEMBER_BYTES: Final[int]
HISTORY_SEARCH_PROJECTION_VERSION: bytes

class _ResourceSearchSnapshotCache:
    def __init__(self, max_snapshots: int = 2) -> None: ...
    def get_or_build(self, timestamp_ns: int, builder: Callable[[], dict[str, str]]) -> dict[str, str]: ...

@dataclass(slots=True)
class ScaleRuntime:
    resources: list[dict[str, Any]]
    resource_by_id: dict[str, dict[str, Any]]
    resources_by_kind: dict[str, list[dict[str, Any]]]
    resource_counts: dict[str, int]
    events: list[dict[str, Any]]
    event_by_uid: dict[str, dict[str, Any]]
    event_times: list[int]
    events_by_resource: dict[str, list[dict[str, Any]]]
    lifecycle_by_resource: Mapping[str, list[dict[str, Any]]]
    state_by_resource: Mapping[str, list[dict[str, Any]]]
    relationships: list[dict[str, Any]]
    relationships_by_endpoint: dict[str, list[dict[str, Any]]]
    mutations: list[dict[str, Any]]
    mutation_times: list[int]
    mutations_by_endpoint: dict[str, list[dict[str, Any]]]
    initial_resource_ids: list[str]
    failure_event_times: list[int] = field(default_factory=list)
    event_times_by_type: dict[str, list[int]] = field(default_factory=dict)
    event_index_by_uid: dict[str, int] = field(default_factory=dict)
    event_search: HistorySearchCorpus = field(default_factory=HistorySearchCorpus)
    event_redaction_policy: Any | None = ...
    resource_search: _ResourceSearchSnapshotCache = field(default_factory=_ResourceSearchSnapshotCache)

class _ScaleTemporalIndex:
    def __init__(self, resource_by_id: dict[str, dict[str, Any]], events_by_resource: dict[str, list[dict[str, Any]]]) -> None: ...
    def lifecycle_intervals(self, identifier: str) -> list[dict[str, Any]]: ...
    def state_intervals(self, identifier: str) -> list[dict[str, Any]]: ...

class _LazyIntervalMap(Mapping[str, list[dict[str, Any]]]):
    def __init__(self, resource_by_id: dict[str, dict[str, Any]], builder: Callable[[str], list[dict[str, Any]]]) -> None: ...
    def __getitem__(self, identifier: str) -> list[dict[str, Any]]: ...
    def __iter__(self) -> Iterator[str]: ...
    def __len__(self) -> int: ...
    def get(self, identifier: str, default: Any = None) -> list[dict[str, Any]] | Any: ...

def load_scale_dataset(archive_path: Path, *, revision_id: str, gaps: list[dict[str, Any]], review_prompts: list[str]) -> dict[str, Any]: ...
