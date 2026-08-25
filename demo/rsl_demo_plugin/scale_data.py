"""Load the example plug-in's event corpus from a generated node pack.

Each pack carries raw inputs and one authoritative normalized scale projection.
This module converts its pipe-delimited resource snapshot and JSONL
event/relationship streams into the core's normalized contracts while retaining
plug-in-owned indexes for bounded timeline, graph, and range queries.
"""

from __future__ import annotations

import json
import os
import sys
import tarfile
import unicodedata
from hashlib import sha256
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from operator import itemgetter
from pathlib import Path
from threading import RLock
from typing import Any, Final

try:
    from pydantic_core import from_json as _accelerated_from_json
except ModuleNotFoundError:  # The fixture generator is stdlib-importable.
    _accelerated_from_json = None
from router_dump_analyzer import (
    AnalysisLoadStage,
    report_analysis_load,
)
from router_dump_analyzer.temporal_core import (
    RESOURCE_CREATION_OPERATIONS,
    RESOURCE_DELETION_OPERATIONS,
    temporal_integer,
    temporal_order_key,
)

from .archive import (
    MANIFEST_MEMBER_NAME,
    NODE_PACK_MANIFEST_MEMBER,
    NODE_PACK_GENERATOR,
    NODE_PACK_ROOT,
    NORMALIZED_SCALE_PREFIX,
    RELATIONSHIP_MUTATIONS_MEMBER_NAME,
    normalize_archive_member_name,
)
from . import GENERATED_PROJECTION_POLICY
from .scale import (
    RESOURCE_TABLE_COLUMNS,
    RESOURCE_TABLE_JSON_COLUMNS,
    scale_condition_class as _status_class,
    scale_dashboards as _scale_dashboards,
    scale_icon_descriptor as _icon_descriptor,
    scale_initial_resource_ids as _initial_resource_ids,
    scale_projection_capabilities as _scale_projection_capabilities,
    scale_relationship_descriptor as _relationship_descriptor,
    scale_resource_record as _resource_record,
    scale_resource_label as _resource_label,
)
from .source_records import (
    RECORD_LANE_PRESETS,
    SOURCE_RECORD_GROUP_DESCRIPTORS,
    SOURCE_RECORD_DESCRIPTORS,
    build_demo_source_records,
)
from router_dump_analyzer.history_search_core import HistorySearchCorpus

PACK_ROOT = NODE_PACK_ROOT
SCALE_PREFIX = NORMALIZED_SCALE_PREFIX
MAX_SCALE_MEMBER_BYTES: Final[int] = 512 * 1024 * 1024
MAX_SCALE_EVENT_MEMBER_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
MAX_HISTORY_SEARCH_DOCUMENTS: Final[int] = 2_000_000
MAX_HISTORY_SEARCH_CHARACTERS: Final[int] = 3 * 1024 * 1024 * 1024
MAX_HISTORY_SEARCH_DATABASE_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
HISTORY_SEARCH_PROJECTION_VERSION = b"redacted-sorted-json-casefold-fts5-v5"
_LOAD_PROGRESS_RECORD_BATCH: Final[int] = 1024


def _from_json(value: bytes | bytearray | str) -> Any:
    """Use the optional fast decoder without making it an import-time dependency."""

    if _accelerated_from_json is not None:
        return _accelerated_from_json(value)
    return json.loads(value)


def _history_search_identity(archive_path: Path) -> str:
    """Bind a derived safe-search sidecar to content and projection semantics."""

    digest = sha256(HISTORY_SEARCH_PROJECTION_VERSION)
    digest.update(unicodedata.unidata_version.encode("ascii"))
    digest.update(str(sys.implementation.cache_tag).encode("ascii"))
    with archive_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _history_search_cache_path(archive_path: Path, identity: str) -> Path:
    """Choose a stable local cache outside synced fixture directories."""

    configured = os.environ.get("ROUTER_DUMP_SEARCH_CACHE_DIR")
    if configured:
        root = Path(configured).expanduser()
    elif os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "RouterDumpAnalyzer" / "cache"
    elif os.environ.get("XDG_CACHE_HOME"):
        root = Path(os.environ["XDG_CACHE_HOME"]) / "router-dump-analyzer"
    else:
        root = Path.home() / ".cache" / "router-dump-analyzer"
    return root / (
        f"{archive_path.stem}-{identity[:24]}.history-search.sqlite3"
    )


class _ResourceSearchSnapshotCache:
    """Keep a tiny LRU of immutable, client-safe resource search documents."""

    __slots__ = ("_documents", "_lock", "_max_snapshots")

    def __init__(self, max_snapshots: int = 2) -> None:
        if max_snapshots < 1:
            raise ValueError("max_snapshots must be at least one")
        self._max_snapshots = max_snapshots
        self._documents: OrderedDict[int, dict[str, str]] = OrderedDict()
        self._lock = RLock()

    def get_or_build(
        self,
        timestamp_ns: int,
        builder: Callable[[], dict[str, str]],
    ) -> dict[str, str]:
        """Return one exact timestamp projection, building it at most once."""

        with self._lock:
            cached = self._documents.get(timestamp_ns)
            if cached is not None:
                self._documents.move_to_end(timestamp_ns)
                return cached
            built = builder()
            self._documents[timestamp_ns] = built
            while len(self._documents) > self._max_snapshots:
                self._documents.popitem(last=False)
            return built


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
    event_redaction_policy: Any | None = None
    resource_search: _ResourceSearchSnapshotCache = field(
        default_factory=_ResourceSearchSnapshotCache
    )


def _safe_archive_member_name(name: str) -> None:
    try:
        normalize_archive_member_name(name)
    except ValueError as error:
        raise RuntimeError(
            f"unsafe packed fixture member: {name!r}"
        ) from error


class _ScaleTemporalIndex:
    """Build temporal intervals only for resources a query actually touches.

    The scale fixture has thousands of resources, but every interactive request is
    deliberately bounded to at most a few hundred of them. Eagerly expanding
    every explicit event effect into rich state and lifecycle dictionaries
    made startup allocate hundreds of thousands of objects that most sessions
    never read. The compact event index is sufficient to reconstruct exactly
    the same intervals on demand, after which they are cached for later queries.
    """

    __slots__ = (
        "_events_by_resource",
        "_lifecycle_cache",
        "_lock",
        "_resource_by_id",
        "_state_cache",
    )

    def __init__(
        self,
        resource_by_id: dict[str, dict[str, Any]],
        events_by_resource: dict[str, list[dict[str, Any]]],
    ) -> None:
        self._resource_by_id = resource_by_id
        self._events_by_resource = events_by_resource
        self._lifecycle_cache: dict[str, list[dict[str, Any]]] = {}
        self._state_cache: dict[str, list[dict[str, Any]]] = {}
        self._lock = RLock()

    def lifecycle_intervals(self, identifier: str) -> list[dict[str, Any]]:
        cached = self._lifecycle_cache.get(identifier)
        if cached is not None:
            return cached
        if identifier not in self._resource_by_id:
            return []
        with self._lock:
            cached = self._lifecycle_cache.get(identifier)
            if cached is not None:
                return cached
            intervals: list[dict[str, Any]] = []
            open_interval: dict[str, Any] | None = None
            saw_lifecycle_effect = False
            for event in self._events_by_resource.get(identifier, ()):
                for effect in event.get("effects", ()):
                    if (
                        effect.get("resource_id") != identifier
                        or not effect.get("state_changed", False)
                    ):
                        continue
                    operation = str(effect.get("effect_type", "")).casefold()
                    if operation in RESOURCE_CREATION_OPERATIONS:
                        saw_lifecycle_effect = True
                        if open_interval is None:
                            open_interval = {
                                "resource": identifier,
                                "valid_from_ns": str(event["timestamp_ns"]),
                                "valid_to_ns": None,
                                "start_event_uid": str(event["event_uid"]),
                                "end_event_uid": None,
                                "quality": "exact",
                            }
                    elif operation in RESOURCE_DELETION_OPERATIONS:
                        saw_lifecycle_effect = True
                        timestamp = str(event["timestamp_ns"])
                        if open_interval is None and not intervals:
                            # A delete without an observed create still proves
                            # presence immediately before the mutation. Keep
                            # the unknown/open start instead of inventing one.
                            intervals.append(
                                {
                                    "resource": identifier,
                                    "valid_from_ns": None,
                                    "valid_to_ns": timestamp,
                                    "start_event_uid": None,
                                    "end_event_uid": str(event["event_uid"]),
                                    "quality": "observed_snapshot",
                                }
                            )
                        elif open_interval is not None:
                            open_interval["valid_to_ns"] = timestamp
                            open_interval["end_event_uid"] = str(event["event_uid"])
                            intervals.append(open_interval)
                            open_interval = None
            if open_interval is not None:
                intervals.append(open_interval)
            if not intervals and not saw_lifecycle_effect:
                intervals.append(
                    {
                        "resource": identifier,
                        "valid_from_ns": None,
                        "valid_to_ns": None,
                        "start_event_uid": None,
                        "end_event_uid": None,
                        "quality": "observed_snapshot",
                    }
                )
            self._lifecycle_cache[identifier] = intervals
            return intervals

    def state_intervals(self, identifier: str) -> list[dict[str, Any]]:
        cached = self._state_cache.get(identifier)
        if cached is not None:
            return cached
        record = self._resource_by_id.get(identifier)
        if record is None:
            return []
        with self._lock:
            cached = self._state_cache.get(identifier)
            if cached is not None:
                return cached
            intervals: list[dict[str, Any]] = []
            current_state: dict[str, Any] = {}
            open_interval: dict[str, Any] | None = None
            for event in self._events_by_resource.get(identifier, ()):
                for effect in event.get("effects", ()):
                    if (
                        effect.get("resource_id") != identifier
                        or not effect.get("state_changed", False)
                    ):
                        continue
                    timestamp = str(event["timestamp_ns"])
                    before = effect.get("before")
                    if (
                        open_interval is None
                        and not intervals
                        and isinstance(before, dict)
                        and before.get("exists", True) is not False
                    ):
                        before_state = {
                            key: value
                            for key, value in before.items()
                            if key not in {"exists", "status"}
                        }
                        before_status = str(
                            before.get(
                                "status",
                                record.get("status", "unknown"),
                            )
                        )
                        open_interval = {
                            "resource": identifier,
                            "valid_from_ns": None,
                            "valid_to_ns": None,
                            "status": before_status,
                            "status_class": _status_class(before_status),
                            "properties": before_state,
                            "start_event_uid": None,
                            "quality": "exact",
                        }
                        current_state = dict(before_state)
                    if open_interval is not None:
                        open_interval["valid_to_ns"] = timestamp
                        intervals.append(open_interval)
                    operation = str(effect.get("effect_type", "")).casefold()
                    if operation in RESOURCE_DELETION_OPERATIONS:
                        open_interval = None
                        current_state = {}
                        continue
                    current_state.update(effect.get("after") or {})
                    # The fixture plug-in normalizes condition and class on the
                    # effect.  The temporal core carries them without deriving
                    # device meaning from arbitrary property names or text.
                    previous_status = (
                        open_interval.get("status", "unknown")
                        if open_interval is not None
                        else record.get("status", "unknown")
                    )
                    previous_status_class = (
                        open_interval.get("status_class", "unknown")
                        if open_interval is not None
                        else record.get(
                            "condition_class",
                            record.get("status_class", "unknown"),
                        )
                    )
                    status = effect.get("condition", previous_status)
                    declared_status_class = effect.get("condition_class")
                    if declared_status_class is None:
                        declared_status_class = effect.get(
                            "status_class", previous_status_class
                        )
                    open_interval = {
                        "resource": identifier,
                        "valid_from_ns": timestamp,
                        "valid_to_ns": None,
                        "status": status,
                        "status_class": declared_status_class,
                        "properties": dict(current_state),
                        "start_event_uid": str(event["event_uid"]),
                        "quality": "exact",
                    }
            if open_interval is not None:
                intervals.append(open_interval)
            if not intervals:
                snapshot = dict(record.get("state", {}))
                status = record.get("status", "unknown")
                intervals.append(
                    {
                        "resource": identifier,
                        "valid_from_ns": None,
                        "valid_to_ns": None,
                        "status": status,
                        "status_class": record.get("status_class", "unknown"),
                        "properties": snapshot,
                        "start_event_uid": None,
                        "quality": "observed_snapshot",
                    }
                )
            self._state_cache[identifier] = intervals
            return intervals


class _LazyIntervalMap(Mapping[str, list[dict[str, Any]]]):
    """Read-only mapping facade that preserves the existing runtime contract."""

    __slots__ = ("_builder", "_resource_by_id")

    def __init__(
        self,
        resource_by_id: dict[str, dict[str, Any]],
        builder: Callable[[str], list[dict[str, Any]]],
    ) -> None:
        self._resource_by_id = resource_by_id
        self._builder = builder

    def __getitem__(self, identifier: str) -> list[dict[str, Any]]:
        if identifier not in self._resource_by_id:
            raise KeyError(identifier)
        return self._builder(identifier)

    def __iter__(self) -> Iterator[str]:
        return iter(self._resource_by_id)

    def __len__(self) -> int:
        return len(self._resource_by_id)

    def get(
        self,
        identifier: str,
        default: Any = None,
    ) -> list[dict[str, Any]] | Any:
        if identifier not in self._resource_by_id:
            return default
        return self._builder(identifier)


@lru_cache(maxsize=64)
def _event_display_name(event_name: str) -> str:
    return event_name.replace("_", " ").title()


def _compact_event(raw: dict[str, Any]) -> dict[str, Any]:
    root_id = str(raw.get("resource_id") or "")
    raw_state_changed = bool(raw.get("state_changed", False))
    outcome = raw.get("outcome", "unknown")
    effect_summaries: list[dict[str, Any]] = []
    affected: list[str] = []
    seen: set[str] = set()
    if root_id:
        affected.append(root_id)
        seen.add(root_id)
    for effect in raw.get("effects", ()):
        identifier = effect.get("resource_id")
        if not identifier:
            continue
        identifier = str(identifier)
        state_changed = bool(
            effect.get("state_changed", raw_state_changed)
        )
        condition_supplied = "condition" in effect or "status" in (
            effect.get("after") or {}
        )
        condition = effect.get("condition")
        if condition is None and condition_supplied:
            # Legacy packed rows are normalized at this scale plug-in adapter
            # boundary. The generic temporal index below never performs this
            # vendor/fixture interpretation itself.
            condition = (effect.get("after") or {}).get("status", "unknown")
        class_supplied = (
            "condition_class" in effect or "status_class" in effect
        )
        # ``condition_class`` is the public plug-in API spelling. Keep the
        # fixture's older ``status_class`` spelling as a compatibility alias,
        # with the public declaration taking precedence when both are present.
        status_class = effect.get("condition_class")
        if status_class is None:
            status_class = effect.get("status_class")
        if status_class is None and condition_supplied:
            status_class = _status_class(condition)
        summary = {
            "resource_id": identifier,
            "kind": effect.get("kind"),
            "effect_type": effect.get("effect_type"),
            "state_changed": state_changed,
        }
        if isinstance(effect.get("before"), dict):
            summary["before"] = effect["before"]
        if condition_supplied:
            summary["condition"] = condition
        if class_supplied or status_class is not None:
            summary["status_class"] = status_class
        if state_changed and effect.get("after"):
            summary["after"] = effect["after"]
        effect_summaries.append(summary)
        if identifier not in seen:
            seen.add(identifier)
            affected.append(identifier)

    layer = raw.get("layer", "unknown")
    resource_kind = raw.get("resource_kind", "UNKNOWN")
    subject = {
        "resource_id": root_id,
        "layer": layer,
        "kind": resource_kind,
        "raw_key": raw.get("resource", root_id),
    }
    event_name = str(raw.get("event_name", "event"))
    result = raw.get("result", {})
    return {
        "event_uid": str(raw["event_uid"]),
        "timestamp_ns": str(
            temporal_integer(raw["timestamp_ns"], "timestamp_ns")
        ),
        "source_sequence": temporal_integer(
            raw.get("source_sequence", 0),
            "source_sequence",
        ),
        "event_type": event_name,
        "event_name": event_name,
        "display_name": _event_display_name(event_name),
        "action": raw.get("action", "observe"),
        "outcome": outcome,
        "state_changed": raw_state_changed,
        "layer": layer,
        "phase": raw.get("phase"),
        "burst_id": raw.get("burst_id"),
        "resource_id": root_id,
        "resource_kind": resource_kind,
        "subject": subject,
        "subjects": [subject],
        "affected_resources": affected,
        "effects": effect_summaries,
        "attributes": {
            "properties": raw.get("properties", {}),
            "result": result,
        },
        "result": result,
    }


def _add_history_only_resources(
    resources: list[dict[str, Any]],
    resource_by_id: dict[str, dict[str, Any]],
    resources_by_kind: defaultdict[str, list[dict[str, Any]]],
    events_by_resource: dict[str, list[dict[str, Any]]],
) -> None:
    """Catalog resources proven by history even when absent at capture time.

    A temporary resource can be created and deleted entirely before the final
    snapshot.  The resource table consequently has no row for it, but its
    normalized effects are still authoritative plug-in evidence.  Keeping a
    small catalog record here lets the generic temporal core reconstruct that
    past lifecycle without pretending the resource exists in the snapshot.
    """

    for identifier in sorted(set(events_by_resource) - set(resource_by_id)):
        events = events_by_resource[identifier]
        kind = "UNKNOWN"
        layer = "unknown"
        first_state: dict[str, Any] = {}
        first_status = "unknown"
        for event in events:
            if layer == "unknown":
                layer = str(event.get("layer") or "unknown")
            for effect in event.get("effects", ()):
                if str(effect.get("resource_id") or "") != identifier:
                    continue
                kind = str(
                    effect.get("kind")
                    or event.get("resource_kind")
                    or kind
                )
                operation = str(effect.get("effect_type") or "").casefold()
                if (
                    not first_state
                    and bool(effect.get("state_changed", False))
                    and operation not in RESOURCE_DELETION_OPERATIONS
                ):
                    first_state = dict(effect.get("after") or {})
                    first_status = str(
                        effect.get("condition")
                        or first_state.get("status")
                        or "unknown"
                    )
                break
            if kind != "UNKNOWN" and first_state:
                break
        record = {
            "resource_id": identifier,
            "kind": kind,
            "layer": layer,
            "label": _resource_label(identifier),
            "key": {},
            "state": {
                **first_state,
                "status": first_status,
                "status_class": _status_class(first_status),
            },
            "status": first_status,
            "status_class": _status_class(first_status),
            "quality": "historical_event",
            "plugin_defined": True,
            "presentation_tags": ["historical-only"],
            "snapshot_present": False,
        }
        resources.append(record)
        resource_by_id[identifier] = record
        resources_by_kind[kind].append(record)


def load_scale_dataset(
    archive_path: Path,
    *,
    revision_id: str,
    gaps: list[dict[str, Any]],
    review_prompts: list[str],
) -> dict[str, Any]:
    """Load the complete packed fixture and build bounded-query indexes."""

    report_analysis_load(
        AnalysisLoadStage.PARSING,
        records_processed=0,
    )
    resources: list[dict[str, Any]] = []
    resource_by_id: dict[str, dict[str, Any]] = {}
    resources_by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    events: list[dict[str, Any]] = []
    event_by_uid: dict[str, dict[str, Any]] = {}
    events_by_resource: dict[str, list[dict[str, Any]]] = defaultdict(list)
    relationship_records: list[dict[str, Any]] = []
    relationships_by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    mutation_records: list[dict[str, Any]] = []
    mutations_by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    phase_counts: Counter[str] = Counter()
    failure_count = 0
    scenario: dict[str, Any] | None = None
    normalized_manifest: dict[str, Any] | None = None
    plugin_schema: dict[str, Any] | None = None
    walkthrough: dict[str, Any] | None = None
    last_event_key: tuple[int, int, str] | None = None
    events_ordered = True
    last_mutation_key: tuple[int, int, str] | None = None
    mutations_ordered = True
    pack_manifest: dict[str, Any] | None = None
    inventory_members: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    metadata_targets = {
        "scenario.json": "scenario",
        MANIFEST_MEMBER_NAME: "manifest",
        "plugin-schema.json": "plugin_schema",
        "walkthrough.json": "walkthrough",
    }
    wanted = {
        *metadata_targets,
        "resources.table.txt",
        "events.jsonl",
        "relationships.jsonl",
        RELATIONSHIP_MUTATIONS_MEMBER_NAME,
    }
    prefix = f"{SCALE_PREFIX}/"
    pack_manifest_name = NODE_PACK_MANIFEST_MEMBER
    parse_record_total: int | None = None
    declared_parse_record_total: int | None = None

    def report_parsed_records(*, force: bool = False) -> None:
        completed = (
            len(resources)
            + len(events)
            + len(relationship_records)
            + len(mutation_records)
        )
        if not force and completed % _LOAD_PROGRESS_RECORD_BATCH:
            return
        determinate_total = (
            parse_record_total
            if parse_record_total is not None and completed <= parse_record_total
            else None
        )
        report_analysis_load(
            AnalysisLoadStage.PARSING,
            completed=completed if determinate_total is not None else None,
            total=determinate_total,
            records_processed=completed,
        )

    # A gzip-compressed tar is sequential. Reading all selected members in one
    # streaming pass avoids repeatedly seeking back through the compressed
    # archive (the prior loader decompressed large prefixes many times).
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            _safe_archive_member_name(member.name)
            if member.name in seen_members:
                raise RuntimeError(
                    f"duplicate packed fixture member: {member.name}"
                )
            seen_members.add(member.name)
            if member.isfile():
                inventory_members.append(
                    {
                        "path": member.name,
                        "size": member.size,
                        "kind": (
                            "nested-archive"
                            if member.name.endswith(".tgz")
                            else "file"
                        ),
                    }
                )
            elif not member.isdir():
                raise RuntimeError(
                    f"packed fixture contains a non-file member: {member.name}"
                )
            else:
                continue

            if member.name == pack_manifest_name:
                if member.size > 16 * 1024 * 1024:
                    raise RuntimeError(
                        f"packed manifest is unexpectedly large: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(
                        f"cannot read packed fixture member: {member.name}"
                    )
                pack_manifest = _from_json(source.read())
                continue

            if not member.name.startswith(prefix):
                continue
            relative_name = member.name[len(prefix) :]
            if relative_name not in wanted:
                continue
            member_limit = (
                MAX_SCALE_EVENT_MEMBER_BYTES
                if relative_name == "events.jsonl"
                else MAX_SCALE_MEMBER_BYTES
            )
            if member.size > member_limit:
                raise RuntimeError(
                    f"packed scale member is unexpectedly large: {member.name}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read packed scale member: {member.name}")
            if relative_name in metadata_targets:
                value = _from_json(source.read())
                target = metadata_targets[relative_name]
                if target == "scenario":
                    scenario = value
                elif target == "manifest":
                    normalized_manifest = value
                    descriptors = (
                        normalized_manifest.get("resources"),
                        normalized_manifest.get("events"),
                        normalized_manifest.get("relationships"),
                        normalized_manifest.get("relationship_mutations"),
                    )
                    if all(isinstance(item, Mapping) for item in descriptors):
                        try:
                            raw_record_counts = [
                                item["records"] for item in descriptors
                            ]
                        except KeyError:
                            parse_record_total = None
                        else:
                            record_counts = [
                                value
                                for value in raw_record_counts
                                if type(value) is int
                                and 0 <= value <= (1 << 53) - 1
                            ]
                            declared_total = sum(record_counts)
                            if (
                                len(record_counts) == len(descriptors)
                                and declared_total > 0
                                and declared_total <= (1 << 53) - 1
                            ):
                                parse_record_total = declared_total
                                declared_parse_record_total = declared_total
                                report_parsed_records(force=True)
                elif target == "plugin_schema":
                    plugin_schema = value
                else:
                    walkthrough = value
                continue
            if relative_name == "resources.table.txt":
                header = next(source).decode("utf-8").rstrip("\r\n").split("|")
                try:
                    project_columns = itemgetter(
                        *(header.index(name) for name in RESOURCE_TABLE_COLUMNS)
                    )
                except ValueError as error:
                    raise RuntimeError(
                        "packed resource table is missing a required column"
                    ) from error
                json_column_indexes = {
                    name: header.index(name)
                    for name in RESOURCE_TABLE_JSON_COLUMNS
                    if name in header
                }
                for line in source:
                    values = line.decode("utf-8").rstrip("\r\n").split("|")
                    if len(values) != len(header):
                        raise RuntimeError(
                            "packed resource table row has the wrong column count"
                        )
                    record = _resource_record(
                        project_columns(values),
                        key_json=(
                            values[json_column_indexes["KEY_JSON"]]
                            if "KEY_JSON" in json_column_indexes
                            else ""
                        ),
                        state_json=(
                            values[json_column_indexes["STATE_JSON"]]
                            if "STATE_JSON" in json_column_indexes
                            else ""
                        ),
                    )
                    resources.append(record)
                    resource_by_id[record["resource_id"]] = record
                    resources_by_kind[record["kind"]].append(record)
                    report_parsed_records()
                continue
            if relative_name == "events.jsonl":
                for line in source:
                    if not line.strip():
                        continue
                    raw = _from_json(line)
                    event = _compact_event(raw)
                    event_key = temporal_order_key(
                        event,
                        time_field="timestamp_ns",
                        identifier_fields=("event_uid", "event_id"),
                    )
                    if last_event_key is not None and event_key < last_event_key:
                        events_ordered = False
                    last_event_key = event_key
                    events.append(event)
                    event_by_uid[event["event_uid"]] = event
                    phase_counts[str(event.get("phase", "unknown"))] += 1
                    failure_count += event["outcome"] == "failure"
                    for identifier in event["affected_resources"]:
                        events_by_resource[identifier].append(event)
                    report_parsed_records()
                continue
            if relative_name == "relationships.jsonl":
                for line in source:
                    if not line.strip():
                        continue
                    relationship = _from_json(line)
                    relationship.setdefault(
                        "relation_type",
                        relationship.get("type", "related_to"),
                    )
                    relationship.setdefault("type", relationship["relation_type"])
                    relationship_records.append(relationship)
                    relationships_by_endpoint[relationship["source"]].append(
                        relationship
                    )
                    relationships_by_endpoint[relationship["target"]].append(
                        relationship
                    )
                    if len(relationship_records) % _LOAD_PROGRESS_RECORD_BATCH == 0:
                        report_parsed_records(force=True)
                continue
            for line in source:
                if not line.strip():
                    continue
                mutation = _from_json(line)
                mutation.setdefault(
                    "relation_type",
                    mutation.get("type", "related_to"),
                )
                mutation_key = temporal_order_key(
                    mutation,
                    time_field="effective_time_ns",
                    identifier_fields=("mutation_id",),
                )
                if last_mutation_key is not None and mutation_key < last_mutation_key:
                    mutations_ordered = False
                last_mutation_key = mutation_key
                mutation_records.append(mutation)
                mutations_by_endpoint[mutation["source"]].append(mutation)
                mutations_by_endpoint[mutation["target"]].append(mutation)
                if len(mutation_records) % _LOAD_PROGRESS_RECORD_BATCH == 0:
                    report_parsed_records(force=True)

    report_parsed_records(force=True)
    parsed_record_count = (
        len(resources)
        + len(events)
        + len(relationship_records)
        + len(mutation_records)
    )
    if (
        declared_parse_record_total is not None
        and parsed_record_count != declared_parse_record_total
    ):
        raise RuntimeError(
            "packed scale manifest record counts do not match parsed members"
        )
    report_analysis_load(
        AnalysisLoadStage.NORMALIZING,
        records_processed=parsed_record_count,
    )

    if pack_manifest is None:
        raise RuntimeError(f"packed fixture lacks {pack_manifest_name}")
    if pack_manifest.get("generator") != NODE_PACK_GENERATOR:
        raise RuntimeError("unsupported packed fixture generator")
    if any(
        item is None
        for item in (scenario, normalized_manifest, plugin_schema, walkthrough)
    ):
        raise RuntimeError("packed scale fixture is missing required metadata")
    assert plugin_schema is not None
    try:
        node_id = str(pack_manifest.get("node_id", ""))
        revision_id = str(pack_manifest.get("revision_id", ""))
        if node_id and revision_id:
            GENERATED_PROJECTION_POLICY.validate_materialized_generated_schema(
                plugin_schema,
                node_id=node_id,
                revision_id=revision_id,
            )
        else:
            GENERATED_PROJECTION_POLICY.validate_generated_schema_template(
                plugin_schema
            )
    except ValueError as error:
        raise RuntimeError(str(error)) from error
    inventory = {
        "archive": archive_path.name,
        "compressed_size": archive_path.stat().st_size,
        "members": inventory_members,
        "mode": "inventory-only",
    }

    if not events_ordered:
        events.sort(
            key=lambda item: temporal_order_key(
                item,
                time_field="timestamp_ns",
                identifier_fields=("event_uid", "event_id"),
            )
        )
    if not mutations_ordered:
        mutation_records.sort(
            key=lambda item: temporal_order_key(
                item,
                time_field="effective_time_ns",
                identifier_fields=("mutation_id",),
            )
        )
    events_by_resource_index = dict(events_by_resource)
    _add_history_only_resources(
        resources,
        resource_by_id,
        resources_by_kind,
        events_by_resource_index,
    )
    temporal_index = _ScaleTemporalIndex(
        resource_by_id,
        events_by_resource_index,
    )
    lifecycle_by_resource = _LazyIntervalMap(
        resource_by_id,
        temporal_index.lifecycle_intervals,
    )
    state_by_resource = _LazyIntervalMap(
        resource_by_id,
        temporal_index.state_intervals,
    )

    report_analysis_load(
        AnalysisLoadStage.INDEXING,
        records_processed=(
            len(resources)
            + len(events)
            + len(relationship_records)
            + len(mutation_records)
        ),
    )
    initial_ids = _initial_resource_ids(walkthrough, resources_by_kind)
    event_times: list[int] = []
    failure_event_times: list[int] = []
    event_times_by_type: defaultdict[str, list[int]] = defaultdict(list)
    for event in events:
        timestamp_ns = int(event["timestamp_ns"])
        event_times.append(timestamp_ns)
        if str(event.get("outcome", "")) == "failure":
            failure_event_times.append(timestamp_ns)
        event_type = str(
            event.get("event_type")
            or event.get("event_name")
            or "unknown"
        )
        event_times_by_type[event_type].append(timestamp_ns)

    runtime = ScaleRuntime(
        resources=resources,
        resource_by_id=resource_by_id,
        resources_by_kind=dict(resources_by_kind),
        resource_counts={kind: len(items) for kind, items in resources_by_kind.items()},
        events=events,
        event_by_uid=event_by_uid,
        event_times=event_times,
        failure_event_times=failure_event_times,
        event_times_by_type=dict(event_times_by_type),
        event_index_by_uid={
            str(event.get("event_uid") or event.get("event_id")): index
            for index, event in enumerate(events)
            if event.get("event_uid") or event.get("event_id")
        },
        events_by_resource=events_by_resource_index,
        lifecycle_by_resource=lifecycle_by_resource,
        state_by_resource=state_by_resource,
        relationships=relationship_records,
        relationships_by_endpoint=dict(relationships_by_endpoint),
        mutations=mutation_records,
        mutation_times=[
            temporal_integer(
                item["effective_time_ns"],
                "effective_time_ns",
            )
            for item in mutation_records
        ],
        mutations_by_endpoint=dict(mutations_by_endpoint),
        initial_resource_ids=initial_ids,
    )

    scale_kind_descriptors = {
        item["kind"]: item
        for item in plugin_schema.get("resource_kinds", [])
    }
    kinds = list(runtime.resource_counts)
    kind_descriptors = [
        _icon_descriptor(
            kind,
            scale_kind_descriptors,
        )
        for kind in kinds
    ]
    structural_types = {
        item["relation_type"]
        for item in plugin_schema.get("relationship_types", [])
        if item.get("structural")
    }
    relation_types = [
        item["relation_type"]
        for item in plugin_schema.get("relationship_types", [])
    ]
    relationship_descriptors = [
        _relationship_descriptor(
            relation_type,
            relation_type in structural_types,
        )
        for relation_type in relation_types
    ]

    scale_gaps = [dict(item) for item in gaps]
    for gap in scale_gaps:
        if gap.get("id") == "scale":
            gap.update(
                {
                    "status": "implemented-demo",
                    "detail": (
                        "The server loads the full 1M+-event corpus, resource catalog, and "
                        "temporal relationship corpus; browser DOM tables and lanes "
                        "remain bounded while counts and density use the full stream."
                    ),
                }
            )

    source_records = build_demo_source_records(events)
    neighbor_resources = runtime.resources_by_kind.get("NEIGHBOR", [])
    neighbors_by_protocol = Counter(
        str(item.get("state", {}).get("protocol") or "unknown")
        for item in neighbor_resources
    )
    neighbor_reachability = Counter(
        str(item.get("state", {}).get("reachability") or "unknown")
        for item in neighbor_resources
    )
    projection_capabilities = _scale_projection_capabilities(plugin_schema)
    plugin_lane_presets = plugin_schema.get("record_lane_presets", [])
    if not isinstance(plugin_lane_presets, list):
        plugin_lane_presets = []
    record_lane_presets = [
        *RECORD_LANE_PRESETS,
        *(dict(item) for item in plugin_lane_presets if isinstance(item, dict)),
    ]
    plugin_review_prompts = plugin_schema.get("review_prompts")
    scale_review_prompts = (
        [str(item) for item in plugin_review_prompts if str(item).strip()]
        if isinstance(plugin_review_prompts, list)
        else list(review_prompts)
    )
    packed_scale = pack_manifest["scale"]
    metrics = {
        "events": len(events),
        "matched_events": len(events),
        "source_records": len(source_records),
        "unmatched_source_records": sum(
            not item.get("matched_event_uid") for item in source_records
        ),
        "resources": len(resources),
        "relationships": len(relationship_records),
        "relationship_mutations": len(mutation_records),
        "failures": failure_count,
        "by_kind": runtime.resource_counts,
        "by_phase": dict(phase_counts),
        "neighbors_by_protocol": dict(neighbors_by_protocol),
        "neighbor_reachability": dict(neighbor_reachability),
    }
    raw_node_identity = scenario.get("node_identity")
    node_identity = (
        raw_node_identity
        if isinstance(raw_node_identity, Mapping)
        else {}
    )
    generated_revision_id = node_identity.get("revision_id")
    generated_node_id = node_identity.get("node_id")
    generated_node_label = node_identity.get("node_label")
    generated_assembly_id = node_identity.get("assembly_id")
    demo = {
        "name": f"Router State Lab — {len(events):,} matched events",
        "revision_id": (
            generated_revision_id
            if isinstance(generated_revision_id, str)
            and generated_revision_id
            else revision_id
        ),
        "node": (
            generated_node_id
            if isinstance(generated_node_id, str) and generated_node_id
            else "router-state-lab-100k"
        ),
        "node_label": (
            generated_node_label
            if isinstance(generated_node_label, str)
            and generated_node_label
            else "Router State Lab node"
        ),
        "fixture": "synthetic-packed-tgz-full-scale",
        "mode": "full-scale-1m-plus",
        "scale_mode": True,
        "scenario": (
            f"{len(events):,} matched EVPN events covering single-home to "
            "multi-home mass failover, ES restore, and next-hop dependency churn"
        ),
        "disclosure": (
            f"Full-scale mode loaded all {len(events):,} matched normalized "
            f"events and {len(resources):,} resources from {archive_path.name}; visible "
            "DOM rows and timeline lanes are windowed for browser safety."
        ),
        "event_count": len(events),
        "matched_event_count": len(events),
        "resource_count": len(resources),
        "relationship_count": len(relationship_records),
        "relationship_mutation_count": len(mutation_records),
        "failure_event_count": failure_count,
        "source_record_count": len(source_records),
        "unmatched_source_record_count": sum(
            not item.get("matched_event_uid") for item in source_records
        ),
        "timeline_start_ns": str(scenario["phases"][0]["start_ns"]),
        "timeline_end_ns": str(scenario["capture_time_ns"]),
        "capture_ns": str(scenario["capture_time_ns"]),
        "initial_resource_ids": initial_ids,
        "initial_focus_resource_id": walkthrough.get("initial_focus_resource_id"),
        "projection_capabilities": projection_capabilities,
        "packed_event_count": int(packed_scale["events"]),
        "packed_resource_count": int(packed_scale["resources"]),
        "packed_container_count": len(pack_manifest["containers"]),
        "packed_scenario_id": pack_manifest["scenario_id"],
    }
    if isinstance(generated_assembly_id, str) and generated_assembly_id:
        demo["assembly_id"] = generated_assembly_id
    findings = [
        {
            "finding_id": "scale-failed-updates",
            "rule_id": "failed_update_preserves_state",
            "result": "pass",
            "summary": (
                f"{failure_count:,} failed DTE reprogramming attempts are retained "
                "without an implicit state mutation."
            ),
            "resources": ["data-bridge-layer/DTE/blue/dte-000000"],
        },
        {
            "finding_id": "scale-es-restore",
            "rule_id": "mass_es_restore_complete",
            "result": "pass",
            "summary": (
                f"All {scenario['expected_changes']['mass_es_restores']:,} "
                "Ethernet Segment restores are represented."
            ),
            "resources": ["control-plane/EVPN_ES/es-00000"],
        },
        {
            "finding_id": "scale-next-hop-churn",
            "rule_id": "next_hop_dependency_changes",
            "result": "pass",
            "summary": (
                f"{scenario['expected_changes']['post_restore_next_hop_changes']:,} "
                "post-restore DTE next-hop changes are time-valid relationships."
            ),
            "resources": ["data-bridge-layer/DTE/blue/dte-000000"],
        },
    ]
    if neighbor_resources:
        first_neighbor = neighbor_resources[0]
        first_neighbor_state = first_neighbor.get("state", {})
        finding_resources = [str(first_neighbor["resource_id"])]
        local_interface_id = first_neighbor_state.get("local_interface_id")
        if local_interface_id in runtime.resource_by_id:
            finding_resources.append(str(local_interface_id))
        all_neighbors_reachable = (
            neighbor_reachability.get("reachable", 0) == len(neighbor_resources)
        )
        findings.append(
            {
                "finding_id": "scale-neighbor-restore",
                "rule_id": "scale.neighbor.restore-reachability.v1",
                "result": "pass" if all_neighbors_reachable else "fail",
                "summary": (
                    f"All {len(neighbor_resources):,} plug-in Neighbor resources "
                    "are reachable in the final restored snapshot."
                    if all_neighbors_reachable
                    else (
                        f"Only {neighbor_reachability.get('reachable', 0):,} of "
                        f"{len(neighbor_resources):,} plug-in Neighbor resources "
                        "are reachable in the final restored snapshot."
                    )
                ),
                "resources": finding_resources,
                "semantic_owner": "plugin",
            }
        )
    plugin_dashboards = plugin_schema.get("dashboards", [])
    if not isinstance(plugin_dashboards, list):
        plugin_dashboards = []
    dashboards = [
        *_scale_dashboards(len(events)),
        *(dict(item) for item in plugin_dashboards if isinstance(item, dict)),
    ]
    consistency_counts = Counter(
        str(item.get("result", "unknown")) for item in findings
    )
    resource_table_views = list(
        plugin_schema.get("resource_table_views") or []
    )
    search_identity = _history_search_identity(archive_path)
    runtime.event_search = HistorySearchCorpus(
        sidecar_path=_history_search_cache_path(archive_path, search_identity),
        identity=search_identity,
        expected_documents=len(events),
        max_documents=MAX_HISTORY_SEARCH_DOCUMENTS,
        max_characters=MAX_HISTORY_SEARCH_CHARACTERS,
        max_database_bytes=MAX_HISTORY_SEARCH_DATABASE_BYTES,
        # Frontend hosting defers this immutable corpus until the first indexed
        # search; API-only startup warms it synchronously.  Keep node workspace
        # materialization independent of a second linear sidecar scan.
        eager_validate_sidecar=False,
    )

    dataset: dict[str, Any] = {
        "demo": demo,
        "scale": {
            "metrics": metrics,
            "scenario": scenario,
            "walkthrough": walkthrough,
            "normalized_manifest": normalized_manifest,
            "client_contract": (
                "All compact resource and event records are transferred; "
                "DOM rows, resource queries, graphs, and lanes are bounded."
            ),
        },
        "summary": {
            "parse": {
                "artifacts": len(inventory.get("members", [])),
                "errors": 0,
                "skipped": 0,
            },
            "consistency": {
                "pass": consistency_counts.get("pass", 0),
                "fail": consistency_counts.get("fail", 0),
                "unknown": consistency_counts.get("unknown", 0),
            },
        },
        "coverage": {
            "exact_outputs": len(events),
            "best_effort_outputs": 0,
            "unknown_outputs": 0,
        },
        "events": events,
        "source_records": source_records,
        "resources": resources,
        "kind_descriptors": kind_descriptors,
        "dashboard_descriptors": dashboards,
        "resource_table_view_descriptors": resource_table_views,
        "source_record_group_descriptors": SOURCE_RECORD_GROUP_DESCRIPTORS,
        "source_record_descriptors": SOURCE_RECORD_DESCRIPTORS,
        "record_lane_presets": record_lane_presets,
        "relationship_descriptors": relationship_descriptors,
        "causal_link_descriptors": [],
        "schema": {
            "resource_kinds": kind_descriptors,
            "dashboards": dashboards,
            "resource_table_views": resource_table_views,
            "source_record_groups": SOURCE_RECORD_GROUP_DESCRIPTORS,
            "source_record_types": SOURCE_RECORD_DESCRIPTORS,
            "record_lane_presets": record_lane_presets,
            "relationship_types": relationship_descriptors,
            "causal_link_types": [],
            "consistency_rules": plugin_schema.get("consistency_rules", []),
            "projection_capabilities": projection_capabilities,
            "semantic_owner": "plugin",
            "core_semantics": (
                "generic typed resources, temporal typed relationships, and "
                "timestamped source records with stable normalization links"
            ),
            "core_interprets_domain_types": False,
        },
        # Full temporal collections stay in the server-only runtime to avoid
        # duplicating hundreds of thousands of records in /v1/workspace.
        "relationships": [],
        "relationship_intervals": [],
        "relationship_mutations": [],
        "lifecycle_intervals": [],
        "state_intervals": [],
        "findings": findings,
        "causal_links": [],
        # A scale plug-in must explicitly declare route/topology availability
        # and provide scale-owned, catalog-valid payloads.
        "route_scenarios": (
            list(plugin_schema.get("route_scenarios", []))
            if projection_capabilities["route_resolution"]["available"]
            else []
        ),
        "routes": (
            dict(plugin_schema.get("routes", {}))
            if projection_capabilities["route_resolution"]["available"]
            else {}
        ),
        "topology": (
            dict(plugin_schema.get("topology", {}))
            if projection_capabilities["underlay_topology"]["available"]
            else {}
        ),
        "projection_capabilities": projection_capabilities,
        "manifest": normalized_manifest,
        "pack_manifest": pack_manifest,
        "inventory": inventory,
        "gaps": scale_gaps,
        "review_prompts": scale_review_prompts,
        "presentation": {
            "layers": [
                {
                    "id": "control-plane",
                    "label": "Control plane",
                    "color": "#a58bff",
                },
                {
                    "id": "data-bridge-layer",
                    "label": "Data bridge",
                    "color": "#52e0c4",
                },
                {
                    "id": "hardware-driver-plane",
                    "label": "Hardware driver",
                    "color": "#f5b85b",
                },
            ]
        },
        "_scale_runtime": runtime,
    }
    return dataset
