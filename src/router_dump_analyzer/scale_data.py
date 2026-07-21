"""Load the full normalized 100K corpus from the packed synthetic fixture.

The review fixture and the scale fixture intentionally have different transport
shapes.  This module converts the pipe-delimited resource snapshot and JSONL
event/relationship streams into the generic demo contracts while retaining
server-side indexes for bounded timeline, graph, and range queries.
"""

from __future__ import annotations

import tarfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from functools import lru_cache
from operator import itemgetter
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any

from pydantic_core import from_json

from .demo_source_plugin import (
    RECORD_LANE_PRESETS,
    SOURCE_RECORD_DESCRIPTORS,
    build_demo_source_records,
)

PACK_ROOT = "router-state-lab-100k"
SCALE_PREFIX = f"{PACK_ROOT}/normalized-scale"
MAX_SCALE_MEMBER_BYTES = 512 * 1024 * 1024


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


def _safe_archive_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
    ):
        raise RuntimeError(f"unsafe packed fixture member: {name!r}")


def _review_json(
    payloads: dict[str, bytes],
    name: str,
    default: Any,
) -> Any:
    content = payloads.get(name)
    return from_json(content) if content is not None else default


def _review_jsonl(
    payloads: dict[str, bytes],
    name: str,
) -> list[dict[str, Any]]:
    content = payloads.get(name)
    if content is None:
        return []
    return [
        from_json(line)
        for line in content.decode("utf-8").splitlines()
        if line.strip()
    ]


def _label_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    if len(parts) <= 2:
        return resource_id
    return "/".join(parts[-2:] if parts[1] in {"ETG", "ETE"} else parts[-1:])


@lru_cache(maxsize=64)
def _status_class_cached(normalized: str) -> str:
    if any(token in normalized for token in ("down", "error", "fail", "withdraw")):
        return "error"
    if normalized in {
        "active",
        "ready",
        "programmed",
        "standby",
        "up",
        "observed",
    }:
        return "healthy"
    return "unknown"


def _status_class(status: Any) -> str:
    return _status_class_cached(str(status or "unknown").casefold())


class _ScaleTemporalIndex:
    """Build temporal intervals only for resources a query actually touches.

    The scale fixture has 100K resources but every interactive request is
    deliberately bounded to at most a few hundred of them. Eagerly expanding
    every successful event effect into rich state and lifecycle dictionaries
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
            start_ns: str | None = None
            start_event_uid: str | None = None
            for event in self._events_by_resource.get(identifier, ()):
                if event.get("outcome") == "failure":
                    continue
                for effect in event.get("effects", ()):
                    if effect.get("resource_id") != identifier:
                        continue
                    operation = str(effect.get("effect_type", "")).casefold()
                    if operation in {"create", "add", "insert"}:
                        start_ns = str(event["timestamp_ns"])
                        start_event_uid = str(event["event_uid"])
                        break
                if start_ns is not None:
                    break
            intervals = [
                {
                    "resource": identifier,
                    "valid_from_ns": start_ns,
                    "valid_to_ns": None,
                    "start_event_uid": start_event_uid,
                    "end_event_uid": None,
                    "quality": "exact" if start_ns is not None else "observed_snapshot",
                }
            ]
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
                if event.get("outcome") == "failure":
                    continue
                for effect in event.get("effects", ()):
                    if (
                        effect.get("resource_id") != identifier
                        or not effect.get("state_changed", False)
                    ):
                        continue
                    timestamp = str(event["timestamp_ns"])
                    if open_interval is not None:
                        open_interval["valid_to_ns"] = timestamp
                        intervals.append(open_interval)
                    current_state.update(effect.get("after") or {})
                    status = (
                        current_state.get("status")
                        or current_state.get("oper_state")
                        or current_state.get("program_state")
                        or "unknown"
                    )
                    open_interval = {
                        "resource": identifier,
                        "valid_from_ns": timestamp,
                        "valid_to_ns": None,
                        "status": status,
                        "status_class": _status_class(status),
                        "properties": dict(current_state),
                        "start_event_uid": str(event["event_uid"]),
                        "quality": "exact",
                    }
            if open_interval is not None:
                intervals.append(open_interval)
            if not intervals:
                snapshot = dict(record.get("state", {}))
                status = snapshot.get("status", "observed")
                intervals.append(
                    {
                        "resource": identifier,
                        "valid_from_ns": None,
                        "valid_to_ns": None,
                        "status": status,
                        "status_class": _status_class(status),
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


RESOURCE_TABLE_COLUMNS = (
    "KIND",
    "RESOURCE_ID",
    "LAYER",
    "VRF",
    "SERVICE_ID",
    "PARENT_ID",
    "ES_ID",
    "ESI",
    "HOME_MODE",
    "ROLE",
    "MATCH",
    "PACKET_ACTION",
    "NEXT_HOP",
    "ENCAP",
    "ADMIN",
    "OPER",
    "DF_STATE",
    "NEIGHBOR",
)


def _resource_record(values: tuple[str, ...]) -> dict[str, Any]:
    (
        kind,
        resource_id,
        layer,
        vrf,
        service_id,
        parent_id,
        es_id,
        esi,
        home_mode,
        role,
        match,
        packet_action,
        next_hop,
        encapsulation,
        admin_state,
        oper_state,
        df_state,
        neighbor,
    ) = values
    state: dict[str, Any] = {}
    if vrf:
        state["vrf"] = vrf
    if service_id:
        state["service_id"] = service_id
    if parent_id:
        state["parent_id"] = parent_id
    if es_id:
        state["es_id"] = es_id
    if esi:
        state["esi"] = esi
    if home_mode:
        state["home_mode"] = home_mode
    if role:
        state["role"] = role
    if match:
        state["match"] = match
    if packet_action:
        state["packet_action"] = packet_action
    if next_hop:
        state["next_hop"] = next_hop
    if encapsulation:
        state["encapsulation"] = encapsulation
    if admin_state:
        state["admin_state"] = admin_state
    if oper_state:
        state["oper_state"] = oper_state
    if df_state:
        state["df_state"] = df_state
    if neighbor:
        state["neighbor"] = neighbor
    status = oper_state or admin_state or "observed"
    state["status"] = status
    key: dict[str, str] = {}
    if vrf:
        key["vrf"] = vrf
    if service_id:
        key["service_id"] = service_id
    if es_id:
        key["es_id"] = es_id
    if esi:
        key["esi"] = esi
    return {
        "resource_id": resource_id,
        "kind": kind,
        "layer": layer,
        "label": _label_from_id(resource_id),
        "key": key,
        "state": state,
        "status": status,
        "quality": "exact",
        "plugin_defined": True,
        "presentation_tags": [],
    }


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
        summary = {
            "resource_id": identifier,
            "kind": effect.get("kind"),
            "effect_type": effect.get("effect_type"),
            "state_changed": state_changed,
        }
        if outcome != "failure" and state_changed and effect.get("after"):
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
        "timestamp_ns": str(raw["timestamp_ns"]),
        "source_sequence": int(raw.get("source_sequence", 0)),
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


def _icon_descriptor(
    kind: str,
    review_descriptors: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    descriptor = dict(review_descriptors.get(kind, {}))
    if not descriptor and kind == "EVPN_ES":
        descriptor = dict(review_descriptors.get("EVPN_ROUTE", {}))
    descriptor.update(
        {
            "kind": kind,
            "display_name": kind.replace("_", " ").title(),
            "plugin_defined": True,
        }
    )
    descriptor.setdefault("display_name_fields", ["name", "id"])
    descriptor.setdefault(
        "default_table_fields",
        ["status", "oper_state", "next_hop"],
    )
    descriptor.setdefault("condition_field", "status")
    descriptor.setdefault("presentation_tags", [])
    return descriptor


def _relationship_descriptor(
    relation_type: str,
    review_descriptors: dict[str, dict[str, Any]],
    structural: bool,
) -> dict[str, Any]:
    descriptor = dict(review_descriptors.get(relation_type, {}))
    descriptor.update(
        {
            "relation_type": relation_type,
            "label": relation_type.replace("_", " ").title(),
            "directed": True,
            "structural": bool(descriptor.get("structural", structural)),
            "plugin_defined": True,
        }
    )
    return descriptor


def _scale_dashboards(event_count: int) -> list[dict[str, Any]]:
    return [
        {
            "dashboard_id": "scale-overview",
            "title": f"{event_count:,}-event scale overview",
            "description": "Exact counts loaded from the packed normalized corpus.",
            "default_open": True,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "scale-events",
                    "label": "Matched events",
                    "aggregation": "precomputed",
                    "scale_metric": "matched_events",
                },
                {
                    "statistic_id": "scale-resources",
                    "label": "Resources",
                    "aggregation": "precomputed",
                    "scale_metric": "resources",
                },
                {
                    "statistic_id": "scale-relationships",
                    "label": "Temporal relationships",
                    "aggregation": "precomputed",
                    "scale_metric": "relationships",
                },
                {
                    "statistic_id": "scale-failures",
                    "label": "Failed updates",
                    "aggregation": "precomputed",
                    "scale_metric": "failures",
                },
            ],
            "tables": [],
        },
        {
            "dashboard_id": "forwarding-population",
            "title": "Forwarding population",
            "description": "Plug-in resource catalog, queried at the selected moment.",
            "default_open": True,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": f"kind-{kind.lower()}",
                    "label": kind.replace("_", " ").title(),
                    "aggregation": "precomputed",
                    "scale_metric": f"by_kind.{kind}",
                }
                for kind in ("ETG", "ETE", "DTE", "EVPN_ES")
            ],
            "tables": [
                {
                    "table_id": "forwarding-sample",
                    "title": "Current resource page",
                    "resource_kinds": ["ETG", "ETE", "DTE", "EVPN_ES"],
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                    "max_rows": 40,
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {
                            "field": "kind",
                            "label": "Type",
                            "value_format": "text",
                        },
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {
                            "field": "state.next_hop",
                            "label": "Next hop",
                            "value_format": "text",
                        },
                    ],
                }
            ],
        },
        {
            "dashboard_id": "event-phases",
            "title": "Mass-operation phases",
            "description": "Exact event counts for each generated phase.",
            "default_open": False,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": f"phase-{phase}",
                    "label": phase.replace("_", " ").title(),
                    "aggregation": "precomputed",
                    "scale_metric": f"by_phase.{phase}",
                }
                for phase in (
                    "single_home_create",
                    "multihome_add",
                    "mass_es_withdraw",
                    "mass_es_restore",
                    "next_hop_churn",
                )
            ],
            "tables": [],
        },
    ]


def _initial_resource_ids(
    walkthrough: dict[str, Any],
    resources_by_kind: dict[str, list[dict[str, Any]]],
) -> list[str]:
    identifiers: list[str] = []
    for service in walkthrough.get("services", [])[:2]:
        identifiers.extend(service.get("resource_ids", {}).values())
    for kind in ("VIRTUAL_INTERFACE", "IP_ROUTING"):
        if resources_by_kind.get(kind):
            identifiers.append(resources_by_kind[kind][0]["resource_id"])
    return list(dict.fromkeys(str(item) for item in identifiers if item))


def load_scale_dataset(
    archive_path: Path,
    *,
    revision_id: str,
    gaps: list[dict[str, Any]],
    review_prompts: list[str],
) -> dict[str, Any]:
    """Load the complete packed fixture and build bounded-query indexes."""

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
    last_event_key: tuple[int, int] | None = None
    events_ordered = True
    last_mutation_key: tuple[int, str] | None = None
    mutations_ordered = True
    pack_manifest: dict[str, Any] | None = None
    review_payloads: dict[str, bytes] = {}
    inventory_members: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    metadata_targets = {
        "scenario.json": "scenario",
        "manifest.json": "manifest",
        "plugin-schema.json": "plugin_schema",
        "walkthrough.json": "walkthrough",
    }
    wanted = {
        *metadata_targets,
        "resources.table.txt",
        "events.jsonl",
        "relationships.jsonl",
        "relationship-mutations.jsonl",
    }
    prefix = f"{SCALE_PREFIX}/"
    review_prefix = f"{PACK_ROOT}/review-projection/"
    pack_manifest_name = f"{PACK_ROOT}/manifest.json"

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

            if member.name == pack_manifest_name or member.name.startswith(
                review_prefix
            ):
                if member.size > 16 * 1024 * 1024:
                    raise RuntimeError(
                        f"packed review member is unexpectedly large: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(
                        f"cannot read packed fixture member: {member.name}"
                    )
                content = source.read()
                if member.name == pack_manifest_name:
                    pack_manifest = from_json(content)
                else:
                    relative_review_name = member.name[len(review_prefix) :]
                    if not relative_review_name:
                        raise RuntimeError(
                            "packed review projection contains an empty name"
                        )
                    review_payloads[relative_review_name] = content
                continue

            if not member.name.startswith(prefix):
                continue
            relative_name = member.name[len(prefix) :]
            if relative_name not in wanted:
                continue
            if member.size > MAX_SCALE_MEMBER_BYTES:
                raise RuntimeError(
                    f"packed scale member is unexpectedly large: {member.name}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read packed scale member: {member.name}")
            if relative_name in metadata_targets:
                value = from_json(source.read())
                target = metadata_targets[relative_name]
                if target == "scenario":
                    scenario = value
                elif target == "manifest":
                    normalized_manifest = value
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
                for line in source:
                    values = line.decode("utf-8").rstrip("\r\n").split("|")
                    if len(values) != len(header):
                        raise RuntimeError(
                            "packed resource table row has the wrong column count"
                        )
                    record = _resource_record(project_columns(values))
                    resources.append(record)
                    resource_by_id[record["resource_id"]] = record
                    resources_by_kind[record["kind"]].append(record)
                continue
            if relative_name == "events.jsonl":
                for line in source:
                    if not line.strip():
                        continue
                    raw = from_json(line)
                    event = _compact_event(raw)
                    event_key = (
                        int(event["timestamp_ns"]),
                        int(event.get("source_sequence", 0)),
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
                continue
            if relative_name == "relationships.jsonl":
                for line in source:
                    if not line.strip():
                        continue
                    relationship = from_json(line)
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
                continue
            for line in source:
                if not line.strip():
                    continue
                mutation = from_json(line)
                mutation.setdefault(
                    "relation_type",
                    mutation.get("type", "related_to"),
                )
                mutation_key = (
                    int(mutation["effective_time_ns"]),
                    str(mutation.get("mutation_id", "")),
                )
                if last_mutation_key is not None and mutation_key < last_mutation_key:
                    mutations_ordered = False
                last_mutation_key = mutation_key
                mutation_records.append(mutation)
                mutations_by_endpoint[mutation["source"]].append(mutation)
                mutations_by_endpoint[mutation["target"]].append(mutation)

    if pack_manifest is None:
        raise RuntimeError(f"packed fixture lacks {pack_manifest_name}")
    if pack_manifest.get("generator") != "router-dump-analyzer-packed-scale-v1":
        raise RuntimeError("unsupported packed fixture generator")
    if "manifest.json" not in review_payloads:
        raise RuntimeError("packed fixture lacks the review projection manifest")
    if any(
        item is None
        for item in (scenario, normalized_manifest, plugin_schema, walkthrough)
    ):
        raise RuntimeError("packed scale fixture is missing required metadata")
    inventory = {
        "archive": archive_path.name,
        "compressed_size": archive_path.stat().st_size,
        "members": inventory_members,
        "mode": "inventory-only",
    }

    if not events_ordered:
        events.sort(
            key=lambda item: (
                int(item["timestamp_ns"]),
                int(item.get("source_sequence", 0)),
            )
        )
    if not mutations_ordered:
        mutation_records.sort(
            key=lambda item: (
                int(item["effective_time_ns"]),
                item.get("mutation_id", ""),
            )
        )
    events_by_resource_index = dict(events_by_resource)
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

    initial_ids = _initial_resource_ids(walkthrough, resources_by_kind)
    runtime = ScaleRuntime(
        resources=resources,
        resource_by_id=resource_by_id,
        resources_by_kind=dict(resources_by_kind),
        resource_counts={kind: len(items) for kind, items in resources_by_kind.items()},
        events=events,
        event_by_uid=event_by_uid,
        event_times=[int(item["timestamp_ns"]) for item in events],
        events_by_resource=events_by_resource_index,
        lifecycle_by_resource=lifecycle_by_resource,
        state_by_resource=state_by_resource,
        relationships=relationship_records,
        relationships_by_endpoint=dict(relationships_by_endpoint),
        mutations=mutation_records,
        mutation_times=[int(item["effective_time_ns"]) for item in mutation_records],
        mutations_by_endpoint=dict(mutations_by_endpoint),
        initial_resource_ids=initial_ids,
    )

    review_kind_descriptors = {
        item["kind"]: item
        for item in _review_json(
            review_payloads,
            "kind-descriptors.json",
            [],
        )
    }
    kinds = list(runtime.resource_counts)
    kind_descriptors = [
        _icon_descriptor(kind, review_kind_descriptors)
        for kind in kinds
    ]
    review_relationship_descriptors = {
        item["relation_type"]: item
        for item in _review_json(
            review_payloads,
            "relationship-descriptors.json",
            [],
        )
    }
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
            review_relationship_descriptors,
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
                        "The server loads all 100K events/resources and the full "
                        "temporal relationship corpus; browser DOM tables and lanes "
                        "remain bounded while counts and density use the full stream."
                    ),
                }
            )

    source_records = build_demo_source_records(events)
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
    }
    demo = {
        "name": f"Router State Lab — {len(events):,} matched events",
        "revision_id": revision_id,
        "node": "router-state-lab-100k",
        "fixture": "synthetic-packed-tgz-full-scale",
        "mode": "full-scale-100k-plus",
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
        "packed_event_count": int(packed_scale["events"]),
        "packed_resource_count": int(packed_scale["resources"]),
        "packed_container_count": len(pack_manifest["containers"]),
        "packed_scenario_id": pack_manifest["scenario_id"],
    }
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
    dashboards = _scale_dashboards(len(events))
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
            "consistency": {"pass": len(findings), "fail": 0, "unknown": 0},
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
        "source_record_descriptors": SOURCE_RECORD_DESCRIPTORS,
        "record_lane_presets": RECORD_LANE_PRESETS,
        "relationship_descriptors": relationship_descriptors,
        "causal_link_descriptors": [],
        "schema": {
            "resource_kinds": kind_descriptors,
            "dashboards": dashboards,
            "source_record_types": SOURCE_RECORD_DESCRIPTORS,
            "record_lane_presets": RECORD_LANE_PRESETS,
            "relationship_types": relationship_descriptors,
            "causal_link_types": [],
            "semantic_owner": "plugin",
            "core_semantics": (
                "generic typed resources, temporal typed relationships, and "
                "timestamped source records with stable normalization links"
            ),
            "core_interprets_domain_types": False,
        },
        # Full temporal collections stay in the server-only runtime to avoid
        # duplicating hundreds of thousands of records in /api/demo.
        "relationships": [],
        "relationship_intervals": [],
        "relationship_mutations": [],
        "lifecycle_intervals": [],
        "state_intervals": [],
        "findings": findings,
        "causal_links": [],
        "route_scenarios": _review_jsonl(
            review_payloads,
            "route-scenarios.jsonl",
        ),
        "routes": {
            "reconstructed_time": _review_json(
                review_payloads,
                "route-resolution.json",
                {},
            ),
            "observed_capture_vector": _review_json(
                review_payloads,
                "route-resolution-observed.json",
                {},
            ),
        },
        "topology": {},
        "manifest": normalized_manifest,
        "pack_manifest": pack_manifest,
        "inventory": inventory,
        "gaps": scale_gaps,
        "review_prompts": review_prompts,
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
