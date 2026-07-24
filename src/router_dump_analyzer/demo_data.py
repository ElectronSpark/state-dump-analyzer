"""Load and query the comprehensive loose or packed illustrative dataset.

The server deliberately reads normalized, generated JSON rather than claiming to
be an ingestion pipeline.  The query helpers are nevertheless shaped like the
intended core projections: resource identity is stable, state and relationships
are temporal, and presentation metadata belongs to the fixture plugin.
"""

from __future__ import annotations

import json
import os
import tarfile
from hashlib import sha256
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .dashboard_core import evaluate_dashboards
from .demo_fixture_plugin import (
    fixture_causal_link_descriptor as _causal_link_descriptor,
    fixture_kind_descriptor as _kind_descriptor,
    fixture_relationship_descriptor as _relationship_descriptor,
    fixture_resource_label as _label_from_id,
)
from .demo_source_plugin import (
    RECORD_LANE_PRESETS,
    SOURCE_RECORD_GROUP_DESCRIPTORS,
    SOURCE_RECORD_DESCRIPTORS,
    build_demo_source_records,
)
from .scale_data import ScaleRuntime, load_scale_dataset


REVISION_ID = "illustrative-revision-node-a"
PACK_ROOT = "router-state-lab-100k"
PACK_ARCHIVE_ENV = "ROUTER_DUMP_DEMO_ARCHIVE"
_demo_archive_override: Path | None = None
_full_scale_enabled = False
MAX_RESOURCE_TABLE_TRAVERSAL_NODES = 5_000


def configure_demo_archive(path: Path | None) -> None:
    """Select one trusted local packed fixture before the server starts."""

    global _demo_archive_override
    if path is None:
        _demo_archive_override = None
    else:
        candidate = path.expanduser().resolve()
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(f"packed demo fixture is not a regular file: {candidate}")
        _demo_archive_override = candidate
    load_demo_dataset.cache_clear()


def configure_demo_scale(enabled: bool) -> None:
    """Choose whether a packed fixture is loaded at its full normalized scale."""

    global _full_scale_enabled
    _full_scale_enabled = bool(enabled)
    load_demo_dataset.cache_clear()


def _configured_demo_archive() -> Path | None:
    if _demo_archive_override is not None:
        return _demo_archive_override
    configured = os.environ.get(PACK_ARCHIVE_ENV)
    if not configured:
        return None
    candidate = Path(configured).expanduser().resolve()
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError(f"packed demo fixture is not a regular file: {candidate}")
    return candidate


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_optional_json(path: Path, default: Any) -> Any:
    return _read_json(path) if path.exists() else default


def _read_optional_jsonl(path: Path) -> list[dict[str, Any]]:
    return _read_jsonl(path) if path.exists() else []


def _safe_archive_member_name(name: str) -> PurePosixPath:
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
    return path


def _archive_inventory(path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            _safe_archive_member_name(member.name)
            if member.isfile():
                members.append(
                    {
                        "path": member.name,
                        "size": member.size,
                        "kind": (
                            "nested-archive" if member.name.endswith(".tgz") else "file"
                        ),
                    }
                )
            elif not member.isdir():
                raise RuntimeError(
                    f"packed fixture contains a non-file member: {member.name}"
                )
    return {
        "archive": path.name,
        "compressed_size": path.stat().st_size,
        "members": members,
        "mode": "inventory-only",
    }


def _read_packed_projection(
    archive_path: Path,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    prefix = f"{PACK_ROOT}/review-projection/"
    manifest_name = f"{PACK_ROOT}/manifest.json"
    payloads: dict[str, bytes] = {}
    pack_manifest: dict[str, Any] | None = None
    with tarfile.open(archive_path, mode="r:gz") as archive:
        seen: set[str] = set()
        for member in archive.getmembers():
            _safe_archive_member_name(member.name)
            if member.name in seen:
                raise RuntimeError(
                    f"duplicate packed fixture member: {member.name}"
                )
            seen.add(member.name)
            if not member.isfile():
                if not member.isdir():
                    raise RuntimeError(
                        f"packed fixture contains a non-file member: {member.name}"
                    )
                continue
            if member.name != manifest_name and not member.name.startswith(prefix):
                continue
            if member.size > 16 * 1024 * 1024:
                raise RuntimeError(
                    f"packed review member is unexpectedly large: {member.name}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read packed fixture member: {member.name}")
            content = source.read()
            if member.name == manifest_name:
                pack_manifest = json.loads(content)
            else:
                relative = member.name[len(prefix) :]
                if not relative:
                    raise RuntimeError("packed review projection contains an empty name")
                payloads[relative] = content
    if pack_manifest is None:
        raise RuntimeError(f"packed fixture lacks {manifest_name}")
    if pack_manifest.get("generator") != "router-dump-analyzer-packed-scale-v1":
        raise RuntimeError("unsupported packed fixture generator")
    if "manifest.json" not in payloads:
        raise RuntimeError("packed fixture lacks the review projection manifest")
    return payloads, pack_manifest


DEMO_GAPS = [
    {
        "id": "ingestion",
        "area": "Ingestion",
        "title": "Upload and safe nested-archive extraction",
        "status": "missing",
        "detail": (
            "The trusted outer TGZ review projection can be loaded directly, "
            "but arbitrary upload, safe extraction, and raw nested-container "
            "decoding are not implemented."
        ),
    },
    {
        "id": "ctf",
        "area": "Decoding",
        "title": "Production Babeltrace/CTF decoding worker",
        "status": "fixture-only",
        "detail": "The demo serves generated normalized records; production CTF decoding remains isolated work.",
    },
    {
        "id": "plugins",
        "area": "Extensibility",
        "title": "Concrete plugin discovery and sandboxing",
        "status": "contract-only",
        "detail": "Kinds and presentation are plugin-shaped, but no third-party plugin is loaded by the demo.",
    },
    {
        "id": "reconstruction",
        "area": "Temporal model",
        "title": "Runtime reconstruction from arbitrary dumps",
        "status": "fixture-only",
        "detail": "Intervals are deterministic generated expectations, not reconstructed during the request.",
    },
    {
        "id": "routing",
        "area": "Forwarding",
        "title": "General forwarding calculation",
        "status": "fixture-only",
        "detail": "Only the bundled explanation is available; general LPM and recursion are not executed.",
    },
    {
        "id": "source-context",
        "area": "Evidence",
        "title": "Jump to decoded source context",
        "status": "missing",
        "detail": "Evidence locators are returned, but raw bytes cannot yet be opened in context.",
    },
    {
        "id": "persistence",
        "area": "Operations",
        "title": "Jobs, persistence and exports",
        "status": "missing",
        "detail": "The process serves one immutable in-memory revision.",
    },
    {
        "id": "scale",
        "area": "Scale",
        "title": "100K+-event browser performance proof",
        "status": "partial",
        "detail": "A separate generator exists; the interactive fixture is intentionally review-sized.",
    },
    {
        "id": "security",
        "area": "Security",
        "title": "Authentication, redaction, quotas and audit",
        "status": "missing",
        "detail": "The local synthetic demo has no production data controls.",
    },
]


REVIEW_PROMPTS = [
    "Do these directional Forwarding Group, ETG, ETE and DTE correlations match the product model?",
    "Which plugin-defined status fields should drive lane color for each kind?",
    "Should Glue use a compact connector rendering everywhere or only in correlation views?",
    "Which raw evidence must be reachable from an event, interval, or relationship?",
    "Which endpoint-diff and event aggregates are most useful for a selected range?",
]


def resource_id(record: dict[str, Any]) -> str:
    """Return a stable resource identifier, including legacy fixture records."""

    explicit = (
        record.get("resource_id")
        or record.get("canonical_resource_id")
        or record.get("resource_uid")
    )
    if explicit:
        return str(explicit)
    # Compatibility-only identity for old fixtures.  Type-preserving canonical
    # JSON prevents integer/string and nested typed-key collisions; no device
    # meaning is inferred from ETG/ETE names or slash-delimited display text.
    identity = {
        "layer": record.get("layer"),
        "kind": record.get("kind"),
        "key": record.get("key", {}),
    }
    canonical = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=lambda value: {
            "python_type": f"{type(value).__module__}.{type(value).__qualname__}",
            "value": str(value),
        },
    ).encode("utf-8")
    return f"legacy-resource:{sha256(canonical).hexdigest()}"


def _contains(timestamp_ns: int, start: Any, end: Any) -> bool:
    return (start is None or timestamp_ns >= int(start)) and (
        end is None or timestamp_ns < int(end)
    )


@lru_cache(maxsize=1)
def load_demo_dataset() -> dict[str, Any]:
    root = repository_root()
    configured_archive = _configured_demo_archive()
    pack_manifest: dict[str, Any] | None = None
    if configured_archive is not None:
        archive = configured_archive
        if _full_scale_enabled:
            return load_scale_dataset(
                archive,
                revision_id=REVISION_ID,
                gaps=DEMO_GAPS,
                review_prompts=REVIEW_PROMPTS,
            )
        payloads, pack_manifest = _read_packed_projection(archive)

        def read_json_name(name: str) -> Any:
            try:
                return json.loads(payloads[name])
            except KeyError as error:
                raise RuntimeError(
                    f"packed review projection lacks {name}"
                ) from error

        def read_jsonl_name(name: str) -> list[dict[str, Any]]:
            try:
                content = payloads[name].decode("utf-8")
            except KeyError as error:
                raise RuntimeError(
                    f"packed review projection lacks {name}"
                ) from error
            return [
                json.loads(line)
                for line in content.splitlines()
                if line.strip()
            ]

        def read_optional_json_name(name: str, default: Any) -> Any:
            return json.loads(payloads[name]) if name in payloads else default

        def read_optional_jsonl_name(name: str) -> list[dict[str, Any]]:
            if name not in payloads:
                return []
            return [
                json.loads(line)
                for line in payloads[name].decode("utf-8").splitlines()
                if line.strip()
            ]

    else:
        data_dir = root / "samples" / "generated" / "illustrative"
        archive = root / "samples" / "generated" / "node-a.tgz"
        manifest_path = (
            root
            / "samples"
            / "generated"
            / "unpacked"
            / "node-a"
            / "manifest.json"
        )
        missing = [
            str(path)
            for path in (data_dir, archive, manifest_path)
            if not path.exists()
        ]
        if missing:
            raise RuntimeError(
                "Demo fixtures are missing. Run scripts/generate_sample_bundle.py "
                "first: " + ", ".join(missing)
            )

        def read_json_name(name: str) -> Any:
            if name == "manifest.json":
                return _read_json(manifest_path)
            return _read_json(data_dir / name)

        def read_jsonl_name(name: str) -> list[dict[str, Any]]:
            return _read_jsonl(data_dir / name)

        def read_optional_json_name(name: str, default: Any) -> Any:
            return _read_optional_json(data_dir / name, default)

        def read_optional_jsonl_name(name: str) -> list[dict[str, Any]]:
            return _read_optional_jsonl(data_dir / name)

    capture_manifest = read_json_name("manifest.json")
    events = read_jsonl_name("domain-events.jsonl")
    events.sort(key=lambda item: (int(item["timestamp_ns"]), int(item.get("source_sequence", 0))))
    source_records = build_demo_source_records(events)
    resources = read_jsonl_name("resources.jsonl")
    for record in resources:
        record.setdefault("resource_id", resource_id(record))
        record.setdefault("label", _label_from_id(record["resource_id"]))
    event_times = [int(item["timestamp_ns"]) for item in events]
    kinds = sorted({str(item.get("kind", "UNKNOWN")) for item in resources})
    descriptors = read_optional_json_name("kind-descriptors.json", [])
    if not descriptors:
        descriptors = [_kind_descriptor(kind) for kind in kinds]
    dashboard_descriptors = read_optional_json_name(
        "dashboard-descriptors.json", []
    )
    resource_table_views = read_optional_json_name(
        "resource-table-view-descriptors.json", []
    )

    lifecycle = read_optional_jsonl_name("lifecycle-intervals.jsonl")
    if not lifecycle:
        lifecycle = [
            {
                "resource": item["resource_id"],
                "valid_from_ns": None,
                "valid_to_ns": None,
                "start_event_uid": None,
                "end_event_uid": None,
                "quality": "best_effort",
            }
            for item in resources
        ]
    state_intervals = read_jsonl_name("state-intervals.jsonl")
    relationship_intervals = read_jsonl_name("relationship-intervals.jsonl")
    relationships = read_jsonl_name("relationships.jsonl")
    causal_links = read_jsonl_name("causal-links.jsonl")
    relationship_descriptors = read_optional_json_name(
        "relationship-descriptors.json", []
    )
    if not relationship_descriptors:
        relationship_descriptors = [
            _relationship_descriptor(relation_type)
            for relation_type in sorted(
                {
                    str(item.get("relation_type", item.get("type", "related_to")))
                    for item in relationship_intervals + relationships
                }
            )
        ]
    causal_link_descriptors = read_optional_json_name(
        "causal-link-descriptors.json", []
    )
    if not causal_link_descriptors:
        causal_link_descriptors = [
            _causal_link_descriptor(link_type)
            for link_type in sorted({str(item["link_type"]) for item in causal_links})
        ]

    demo_metadata: dict[str, Any] = {
        "name": "Router State Lab",
        "revision_id": REVISION_ID,
        "node": str(capture_manifest.get("node", "node-a")),
        "fixture": "synthetic",
        "mode": "illustrative",
        "scenario": "MPLS, SRv6, EVPN and IS-IS temporal forwarding",
        "disclosure": "Illustrative precomputed fixture; not an end-to-end analyzer.",
        "event_count": len(events),
        "source_record_count": len(source_records),
        "unmatched_source_record_count": sum(
            not item.get("matched_event_uid") for item in source_records
        ),
        "resource_count": len(resources),
        "timeline_start_ns": str(min(event_times)),
        "timeline_end_ns": str(max(event_times)),
        "capture_ns": str(capture_manifest["capture_time_ns"]),
    }
    if pack_manifest is not None:
        packed_scale = pack_manifest["scale"]
        demo_metadata.update(
            {
                "fixture": "synthetic-packed-tgz",
                "mode": "packed-fixture",
                "scenario": (
                    "100K+-event EVPN single-home to multi-home failover pack "
                    "(browser-sized temporal review projection)"
                ),
                "disclosure": (
                    f"Loaded directly from {archive.name}. The outer TGZ contains "
                    f"{packed_scale['events']:,} events, "
                    f"{packed_scale['resources']:,} resources, and "
                    f"{len(pack_manifest['containers'])} nested container packs; "
                    "the browser renders its embedded review projection."
                ),
                "packed_event_count": int(packed_scale["events"]),
                "packed_resource_count": int(packed_scale["resources"]),
                "packed_container_count": len(pack_manifest["containers"]),
                "packed_scenario_id": pack_manifest["scenario_id"],
            }
        )

    dataset: dict[str, Any] = {
        "demo": demo_metadata,
        "summary": read_json_name("dashboard-summary.json"),
        "coverage": read_json_name("reconstruction-coverage.json"),
        "events": events,
        "source_records": source_records,
        "resources": resources,
        "kind_descriptors": descriptors,
        "dashboard_descriptors": dashboard_descriptors,
        "resource_table_view_descriptors": resource_table_views,
        "source_record_group_descriptors": SOURCE_RECORD_GROUP_DESCRIPTORS,
        "source_record_descriptors": SOURCE_RECORD_DESCRIPTORS,
        "record_lane_presets": RECORD_LANE_PRESETS,
        "relationship_descriptors": relationship_descriptors,
        "causal_link_descriptors": causal_link_descriptors,
        "schema": {
            "resource_kinds": descriptors,
            "dashboards": dashboard_descriptors,
            "resource_table_views": resource_table_views,
            "source_record_groups": SOURCE_RECORD_GROUP_DESCRIPTORS,
            "source_record_types": SOURCE_RECORD_DESCRIPTORS,
            "record_lane_presets": RECORD_LANE_PRESETS,
            "relationship_types": relationship_descriptors,
            "causal_link_types": causal_link_descriptors,
            "semantic_owner": "plugin",
            "core_semantics": (
                "generic typed resources, temporal typed relationships, and "
                "timestamped source records with stable normalization links"
            ),
            "core_interprets_domain_types": False,
        },
        "relationships": relationships,
        "relationship_intervals": relationship_intervals,
        "relationship_mutations": read_jsonl_name(
            "relationship-mutations.jsonl"
        ),
        "lifecycle_intervals": lifecycle,
        "state_intervals": state_intervals,
        "findings": read_jsonl_name("consistency-findings.jsonl"),
        "causal_links": causal_links,
        "route_scenarios": read_jsonl_name("route-scenarios.jsonl"),
        "routes": {
            "reconstructed_time": read_json_name("route-resolution.json"),
            "observed_capture_vector": read_json_name(
                "route-resolution-observed.json"
            ),
        },
        "topology": read_optional_json_name("topology.json", {}),
        "manifest": capture_manifest,
        "pack_manifest": pack_manifest,
        "inventory": _archive_inventory(archive),
        "gaps": DEMO_GAPS,
        "review_prompts": REVIEW_PROMPTS,
    }
    return dataset


def scale_runtime(dataset: dict[str, Any] | None = None) -> ScaleRuntime | None:
    """Return the server-only full-scale indexes when scale mode is active."""

    candidate = (dataset or load_demo_dataset()).get("_scale_runtime")
    return candidate if isinstance(candidate, ScaleRuntime) else None


def is_scale_dataset(dataset: dict[str, Any] | None = None) -> bool:
    return scale_runtime(dataset) is not None


def client_demo_dataset() -> dict[str, Any]:
    """Remove server-only indexes from the browser bootstrap payload."""

    dataset = load_demo_dataset()
    if not is_scale_dataset(dataset):
        descriptor_by_kind = {
            str(item.get("kind")): item
            for item in dataset.get("kind_descriptors", [])
            if isinstance(item, dict) and item.get("kind")
        }
        client = dict(dataset)
        client["resources"] = []
        for record in dataset.get("resources", []):
            projected = _redact_resource_view(
                {
                    "state": dict(record.get("state", {})),
                    "key": dict(record.get("key", {})),
                    "resource": record,
                },
                descriptor_by_kind.get(str(record.get("kind", "UNKNOWN"))),
            )
            safe_record = dict(projected.get("resource") or record)
            safe_record["state"] = projected.get("state", {})
            safe_record["key"] = projected.get("key", {})
            client["resources"].append(safe_record)
        client["events"] = [
            redact_event_for_client(item, dataset)
            for item in dataset.get("events", [])
        ]
        return client
    client = {key: value for key, value in dataset.items() if not key.startswith("_")}
    # The browser needs every resource identity for its catalog, but history is
    # queried in bounded windows.  Keeping the two large history streams out of
    # the scale bootstrap prevents the browser from parsing and indexing more
    # than 100K events before it can render the first useful view.
    client["resources"] = [
        {
            "resource_id": item["resource_id"],
            "kind": item["kind"],
            "layer": item["layer"],
            "label": item["label"],
            **(
                {"presentation_tags": item["presentation_tags"]}
                if item.get("presentation_tags")
                else {}
            ),
        }
        for item in dataset["resources"]
    ]
    client["events"] = []
    client["source_records"] = []
    revision_id = str(client.get("demo", {}).get("revision_id") or REVISION_ID)
    client["history_transport"] = {
        "mode": "server-windowed",
        "events": {
            "server_windowed": True,
            "total_count": len(dataset.get("events", [])),
            "query_endpoint": f"/v1/revisions/{revision_id}/event-log/query",
            "detail_endpoint_template": (
                f"/v1/revisions/{revision_id}/events/{{event_uid}}"
            ),
        },
        "source_records": {
            "server_windowed": True,
            "total_count": len(dataset.get("source_records", [])),
            "query_endpoint": f"/v1/revisions/{revision_id}/event-log/query",
        },
        "density": {
            "server_windowed": True,
            "query_endpoint": (
                f"/v1/revisions/{revision_id}/events/density/query"
            ),
        },
    }
    return client


def _active_resource_ids(
    dataset: dict[str, Any], timestamp_ns: int
) -> set[str]:
    """Return catalog identities whose lifecycle contains ``timestamp_ns``."""

    catalog_ids = {item["resource_id"] for item in dataset["resources"]}
    return {
        item["resource"]
        for item in dataset["lifecycle_intervals"]
        if item["resource"] in catalog_ids
        and _contains(
            timestamp_ns,
            item.get("valid_from_ns"),
            item.get("valid_to_ns"),
        )
    }


def relationships_at(timestamp_ns: int) -> list[dict[str, Any]]:
    dataset = load_demo_dataset()
    runtime = scale_runtime(dataset)
    if runtime is not None:
        return [
            {
                **item,
                "type": item.get("type", item.get("relation_type", "related_to")),
                "temporal_note": "selected from full-scale validity interval",
            }
            for item in runtime.relationships
            if _contains(
                timestamp_ns,
                item.get("valid_from_ns"),
                item.get("valid_to_ns"),
            )
            and _active_interval(
                runtime.lifecycle_by_resource.get(item["source"], []),
                timestamp_ns,
            )
            and _active_interval(
                runtime.lifecycle_by_resource.get(item["target"], []),
                timestamp_ns,
            )
        ]
    intervals = dataset["relationship_intervals"]
    active_resource_ids = _active_resource_ids(dataset, timestamp_ns)
    interval_keys = {
        (item["source"], item["target"], item.get("relation_type", item.get("type")))
        for item in intervals
    }
    result: list[dict[str, Any]] = []
    for item in dataset["relationships"]:
        if not {
            item["source"],
            item["target"],
        } <= active_resource_ids:
            continue
        key = (item["source"], item["target"], item.get("type", item.get("relation_type")))
        if key in interval_keys:
            continue
        carried = dict(item)
        carried["temporal_note"] = "capture observation without reconstructed interval"
        result.append(carried)
    for interval in intervals:
        if not _contains(timestamp_ns, interval.get("valid_from_ns"), interval.get("valid_to_ns")):
            continue
        if not {
            interval["source"],
            interval["target"],
        } <= active_resource_ids:
            continue
        active = dict(interval)
        active["type"] = active.pop("relation_type", active.get("type", "related_to"))
        active["temporal_note"] = "selected from validity interval"
        result.append(active)
    return result


def _active_interval(
    records: Iterable[dict[str, Any]], timestamp_ns: int
) -> dict[str, Any] | None:
    candidates = [
        item
        for item in records
        if _contains(timestamp_ns, item.get("valid_from_ns"), item.get("valid_to_ns"))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: int(item.get("valid_from_ns") or -1))


def resource_state_at(resource_identifier: str, timestamp_ns: int) -> dict[str, Any]:
    dataset = load_demo_dataset()
    runtime = scale_runtime(dataset)
    if runtime is not None:
        record = runtime.resource_by_id.get(resource_identifier)
        lifecycle_records = runtime.lifecycle_by_resource.get(resource_identifier, [])
        state_records = runtime.state_by_resource.get(resource_identifier, [])
    else:
        record = next(
            (
                item
                for item in dataset["resources"]
                if item["resource_id"] == resource_identifier
            ),
            None,
        )
        lifecycle_records = [
            item
            for item in dataset["lifecycle_intervals"]
            if item["resource"] == resource_identifier
        ]
        state_records = [
            item
            for item in dataset["state_intervals"]
            if item["resource"] == resource_identifier
        ]
    lifecycle = _active_interval(lifecycle_records, timestamp_ns)
    exists = lifecycle is not None
    state_interval = _active_interval(state_records, timestamp_ns)
    state = dict(state_interval.get("properties", {})) if state_interval else {}
    if not state and record and exists:
        state = dict(record.get("state", {}))
    kind = record.get("kind", "UNKNOWN") if record else "UNKNOWN"
    descriptor = next(
        (
            item
            for item in dataset.get("kind_descriptors", [])
            if str(item.get("kind")) == str(kind)
        ),
        None,
    )
    condition_field = descriptor.get("condition_field") if descriptor else None
    if not exists:
        status = "absent"
        status_class = "absent"
    else:
        status = (
            (state_interval or {}).get("status")
            or (state.get(condition_field) if condition_field else None)
            or "unknown"
        )
        status_class = (
            (state_interval or {}).get("status_class")
            or state.get("status_class")
            or "unknown"
        )
    view = {
        "resource_id": resource_identifier,
        "kind": kind,
        "layer": record.get("layer", resource_identifier.split("/", 1)[0]) if record else resource_identifier.split("/", 1)[0],
        "label": record.get("label", _label_from_id(resource_identifier)) if record else _label_from_id(resource_identifier),
        "exists": exists,
        "status": status,
        "status_class": status_class,
        "state": state,
        "valid_from_ns": state_interval.get("valid_from_ns") if state_interval else None,
        "valid_to_ns": state_interval.get("valid_to_ns") if state_interval else None,
        "source_event_uid": state_interval.get("start_event_uid") if state_interval else None,
        "quality": state_interval.get("quality", "unknown") if state_interval else "unknown",
        "resource": record,
    }
    return _redact_resource_view(view, descriptor)


def _descriptor_property_rules(
    descriptor: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if not descriptor:
        return {}
    return {
        str(item["name"]): item
        for item in descriptor.get("properties", [])
        if isinstance(item, dict) and item.get("name")
    }


def _without_sensitive_fields(
    value: Any,
    sensitive_fields: set[str],
) -> Any:
    """Redact explicitly sensitive plug-in fields without guessing semantics."""

    if not isinstance(value, dict) or not sensitive_fields:
        return value
    return {
        key: nested
        for key, nested in value.items()
        if str(key) not in sensitive_fields
    }


type EventRedactionPolicy = tuple[
    dict[str, frozenset[str]],
    dict[str, str],
    frozenset[str],
]


def _event_redaction_policy(
    dataset: dict[str, Any],
) -> EventRedactionPolicy:
    """Compile plug-in sensitivity declarations for repeated event projection.

    Event queries can walk more than 100K normalized records.  Compiling the
    descriptor and resource-identity indexes once keeps the core security
    boundary independent from page size without rebuilding those indexes for
    every candidate event.
    """

    runtime = scale_runtime(dataset)
    if runtime is not None and runtime.event_redaction_policy is not None:
        return runtime.event_redaction_policy

    sensitive_by_kind: dict[str, frozenset[str]] = {}
    all_sensitive: set[str] = set()
    for descriptor in dataset.get("kind_descriptors", []):
        if not isinstance(descriptor, dict) or not descriptor.get("kind"):
            continue
        sensitive = frozenset(
            name
            for name, rule in _descriptor_property_rules(descriptor).items()
            if bool(rule.get("sensitive", False))
        )
        sensitive_by_kind[str(descriptor["kind"])] = sensitive
        all_sensitive.update(sensitive)

    if not all_sensitive:
        compiled = (sensitive_by_kind, {}, frozenset())
        if runtime is not None:
            runtime.event_redaction_policy = compiled
        return compiled

    records = (
        runtime.resource_by_id.values()
        if runtime is not None
        else dataset.get("resources", [])
    )
    kind_by_resource_id = {
        resource_id(record): str(record.get("kind", "UNKNOWN"))
        for record in records
        if isinstance(record, dict)
    }
    compiled = (
        sensitive_by_kind,
        kind_by_resource_id,
        frozenset(all_sensitive),
    )
    if runtime is not None:
        runtime.event_redaction_policy = compiled
    return compiled


def _event_resource_kinds(
    event: dict[str, Any],
    kind_by_resource_id: dict[str, str],
) -> set[str]:
    """Resolve the resource kinds explicitly referenced by a normalized event."""

    kinds: set[str] = set()
    identifiers: set[str] = set()

    def collect(value: Any) -> None:
        if not isinstance(value, dict):
            return
        for field in ("resource_kind", "kind"):
            if value.get(field):
                kinds.add(str(value[field]))
        for field in ("resource_id", "resource"):
            if value.get(field):
                identifiers.add(str(value[field]))

    collect(event)
    collect(event.get("subject"))
    for subject in event.get("subjects", []):
        collect(subject)
    for effect in event.get("effects", []):
        collect(effect)
    kinds.update(
        kind_by_resource_id[identifier]
        for identifier in identifiers
        if identifier in kind_by_resource_id
    )
    return kinds


def _redact_sensitive_tree(value: Any, sensitive_fields: set[str]) -> Any:
    """Remove declared sensitive property names at any plug-in payload depth."""

    if isinstance(value, dict):
        return {
            key: _redact_sensitive_tree(nested, sensitive_fields)
            for key, nested in value.items()
            if str(key) not in sensitive_fields
        }
    if isinstance(value, list):
        return [
            _redact_sensitive_tree(nested, sensitive_fields)
            for nested in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_sensitive_tree(nested, sensitive_fields)
            for nested in value
        )
    return value


def _redact_resource_view(
    view: dict[str, Any],
    descriptor: dict[str, Any] | None,
) -> dict[str, Any]:
    rules = _descriptor_property_rules(descriptor)
    sensitive_fields = {
        name for name, rule in rules.items() if bool(rule.get("sensitive", False))
    }
    if not sensitive_fields:
        return view
    projected = dict(view)
    projected["state"] = _without_sensitive_fields(
        projected.get("state", {}), sensitive_fields
    )
    projected["key"] = _without_sensitive_fields(
        projected.get("key", {}), sensitive_fields
    )
    record = projected.get("resource")
    if isinstance(record, dict):
        safe_record = {
            key: nested
            for key, nested in record.items()
            if str(key) not in sensitive_fields
        }
        safe_record["state"] = _without_sensitive_fields(
            record.get("state", {}), sensitive_fields
        )
        safe_record["key"] = _without_sensitive_fields(
            record.get("key", {}), sensitive_fields
        )
        projected["resource"] = safe_record
    return projected


def redact_event_for_client(
    event: dict[str, Any],
    dataset: dict[str, Any] | None = None,
    *,
    policy: EventRedactionPolicy | None = None,
) -> dict[str, Any]:
    """Apply resource-property sensitivity rules to one event projection."""

    active_dataset = dataset or load_demo_dataset()
    sensitive_by_kind, kind_by_resource_id, all_sensitive = (
        policy or _event_redaction_policy(active_dataset)
    )
    if not all_sensitive:
        return event
    sensitive: set[str] = set()
    kinds = _event_resource_kinds(event, kind_by_resource_id)
    for kind in kinds:
        sensitive.update(sensitive_by_kind.get(kind, ()))
    # A plug-in event that does not identify a resource kind, or names a kind
    # outside the resource descriptor catalog, cannot safely be scoped to one
    # policy. Fail closed rather than exposing an unclassifiable payload.
    if not kinds or any(kind not in sensitive_by_kind for kind in kinds):
        sensitive.update(all_sensitive)
    if not sensitive:
        return event
    return _redact_sensitive_tree(event, sensitive)


def redact_state_interval_for_client(
    resource_identifier: str,
    interval: dict[str, Any],
    dataset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Redact one generic temporal state interval using its kind descriptor."""

    active_dataset = dataset or load_demo_dataset()
    runtime = scale_runtime(active_dataset)
    record = (
        runtime.resource_by_id.get(resource_identifier)
        if runtime is not None
        else next(
            (
                item
                for item in active_dataset.get("resources", [])
                if resource_id(item) == resource_identifier
            ),
            None,
        )
    )
    kind = str(record.get("kind", "UNKNOWN")) if record else "UNKNOWN"
    descriptor = next(
        (
            item
            for item in active_dataset.get("kind_descriptors", [])
            if str(item.get("kind")) == kind
        ),
        None,
    )
    projected = dict(interval)
    projected["properties"] = _redact_resource_view(
        {"state": dict(interval.get("properties", {}))}, descriptor
    ).get("state", {})
    return projected


def _resource_search_text(
    record: dict[str, Any],
    view: dict[str, Any],
    descriptor: dict[str, Any] | None,
) -> str:
    """Build generic point-in-time search text from plug-in declarations."""

    rules = _descriptor_property_rules(descriptor)
    sensitive_fields = {
        name for name, rule in rules.items() if bool(rule.get("sensitive", False))
    }
    values: list[Any] = [
        view.get("resource_id", record.get("resource_id", "")),
        view.get("label", record.get("label", "")),
        view.get("kind", record.get("kind", "")),
        view.get("layer", record.get("layer", "")),
        view.get("status", ""),
        view.get("status_class", ""),
        view.get("exists", ""),
    ]
    key = view.get("key") or record.get("key") or {}
    if isinstance(key, dict):
        values.extend(
            nested
            for name, nested in key.items()
            if str(name) not in sensitive_fields
        )
    state = view.get("state") or {}
    if rules:
        for name, rule in rules.items():
            if rule.get("sensitive", False) or not rule.get("searchable", False):
                continue
            if isinstance(state, dict) and name in state:
                values.append(state[name])
            elif name in record:
                values.append(record[name])
        for name in descriptor.get("display_name_fields", ()) if descriptor else ():
            if name in sensitive_fields:
                continue
            if isinstance(state, dict) and name in state:
                values.append(state[name])
            elif isinstance(key, dict) and name in key:
                values.append(key[name])
    else:
        # Backward compatibility for legacy illustrative descriptors that did
        # not yet declare PropertyDescriptor metadata. Explicit sensitive
        # declarations always take precedence over this fallback.
        values.append(state)
    return " ".join(
        json.dumps(value, sort_keys=True, ensure_ascii=False)
        if isinstance(value, (dict, list, tuple))
        else str(value)
        for value in values
        if value is not None
    ).casefold()


def _resource_table_view_at(
    dataset: dict[str, Any],
    timestamp_ns: int,
    view_id: str,
    *,
    search: str | None,
    limit: int | None,
    offset: int,
) -> dict[str, Any]:
    """Project a bounded, plug-in-declared relationship tree at one moment.

    The descriptor supplies every domain choice: root kinds, relationship hops,
    direction, target kinds, columns, and bounds. This core helper only applies
    temporal validity and performs generic graph traversal.
    """

    descriptors = dataset.get("resource_table_view_descriptors") or dataset.get(
        "schema", {}
    ).get("resource_table_views", [])
    descriptor = next(
        (item for item in descriptors if item.get("view_id") == view_id), None
    )
    if descriptor is None:
        raise ValueError(f"unknown resource table view: {view_id}")

    runtime = scale_runtime(dataset)
    if runtime is not None:
        resource_by_id = runtime.resource_by_id
        root_records = [
            record
            for kind in descriptor.get("root_kinds", [])
            for record in runtime.resources_by_kind.get(kind, [])
        ]
        counts_by_kind = dict(sorted(runtime.resource_counts.items()))

        def endpoint_relationships(identifier: str) -> Iterable[dict[str, Any]]:
            return runtime.relationships_by_endpoint.get(identifier, ())

    else:
        resource_by_id = {
            resource_id(record): record for record in dataset.get("resources", [])
        }
        root_kinds = set(descriptor.get("root_kinds", []))
        root_records = [
            record
            for record in dataset.get("resources", [])
            if record.get("kind") in root_kinds
        ]
        counts_by_kind = dict(
            sorted(
                Counter(
                    record.get("kind", "UNKNOWN")
                    for record in resource_by_id.values()
                ).items()
            )
        )
        relationships_by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for relationship in relationships_at(timestamp_ns):
            relationships_by_endpoint[relationship["source"]].append(relationship)
            if relationship["target"] != relationship["source"]:
                relationships_by_endpoint[relationship["target"]].append(relationship)

        def endpoint_relationships(identifier: str) -> Iterable[dict[str, Any]]:
            return relationships_by_endpoint.get(identifier, ())

    descriptor_by_kind = {
        item.get("kind"): item
        for item in dataset.get("kind_descriptors", [])
        if item.get("kind")
    }
    include_absent = bool(descriptor.get("include_absent", False))
    levels = list(descriptor.get("levels", []))
    max_children = max(
        1, min(int(descriptor.get("max_children_per_node", 16)), 100)
    )
    traversal_node_limit = max(
        1,
        min(
            int(
                descriptor.get(
                    "max_nodes",
                    MAX_RESOURCE_TABLE_TRAVERSAL_NODES,
                )
            ),
            MAX_RESOURCE_TABLE_TRAVERSAL_NODES,
        ),
    )
    descriptor_limit = max(1, min(int(descriptor.get("max_roots", 100)), 500))
    safe_limit = max(1, min(int(limit or descriptor_limit), descriptor_limit))
    safe_offset = max(0, int(offset))
    needle = search.casefold() if search else None
    state_cache: dict[str, dict[str, Any]] = {}
    existence_cache: dict[str, bool] = {}
    neighbor_cache: dict[
        tuple[str, int], list[tuple[dict[str, Any], dict[str, Any]]]
    ] = {}

    def temporal_state(identifier: str) -> dict[str, Any]:
        if identifier not in state_cache:
            raw_view = resource_state_at(identifier, timestamp_ns)
            state_cache[identifier] = _redact_resource_view(
                raw_view,
                descriptor_by_kind.get(raw_view.get("kind")),
            )
        return state_cache[identifier]

    def resource_exists(identifier: str) -> bool:
        if identifier in existence_cache:
            return existence_cache[identifier]
        if runtime is not None:
            exists = (
                _active_interval(
                    runtime.lifecycle_by_resource.get(identifier, []),
                    timestamp_ns,
                )
                is not None
            )
        else:
            exists = temporal_state(identifier)["exists"]
        existence_cache[identifier] = exists
        return exists

    def neighbors(
        identifier: str, depth: int
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        cache_key = (identifier, depth)
        cached = neighbor_cache.get(cache_key)
        if cached is not None:
            return cached
        if depth >= len(levels):
            return []
        level = levels[depth]
        relation_types = set(level.get("relation_types", []))
        target_kinds = set(level.get("target_kinds", []))
        direction = level.get("direction", "outgoing")
        found: list[tuple[dict[str, Any], dict[str, Any]]] = []
        seen: set[tuple[Any, ...]] = set()
        for relationship in endpoint_relationships(identifier):
            relation_type = relationship.get(
                "relation_type", relationship.get("type", "related_to")
            )
            if relation_type not in relation_types:
                continue
            if runtime is not None and not _contains(
                timestamp_ns,
                relationship.get("valid_from_ns"),
                relationship.get("valid_to_ns"),
            ):
                continue
            candidates: list[str] = []
            if (
                direction in {"outgoing", "both"}
                and relationship.get("source") == identifier
            ):
                candidates.append(str(relationship.get("target")))
            if (
                direction in {"incoming", "both"}
                and relationship.get("target") == identifier
            ):
                candidates.append(str(relationship.get("source")))
            for target_id in candidates:
                target = resource_by_id.get(target_id)
                if target is None or (
                    target_kinds and target.get("kind") not in target_kinds
                ):
                    continue
                if not include_absent and not resource_exists(target_id):
                    continue
                relationship_id = relationship.get("relationship_id")
                identity = (
                    ("id", str(relationship_id), target_id)
                    if relationship_id is not None
                    else (
                        "structural",
                        str(relation_type),
                        str(relationship.get("source")),
                        str(relationship.get("target")),
                        relationship.get("valid_from_ns"),
                        relationship.get("valid_to_ns"),
                        target_id,
                    )
                )
                if identity in seen:
                    continue
                seen.add(identity)
                found.append((relationship, target))
        found.sort(
            key=lambda pair: (
                pair[1].get("kind", "UNKNOWN"),
                pair[1].get("label", _label_from_id(resource_id(pair[1]))),
                resource_id(pair[1]),
                str(pair[0].get("relationship_id", "")),
            )
        )
        neighbor_cache[cache_key] = found
        return found

    match_cache: dict[tuple[str, int], bool] = {}
    search_traversal_count = 0
    search_traversal_truncated = False

    def branch_matches(record: dict[str, Any], depth: int) -> bool:
        nonlocal search_traversal_count, search_traversal_truncated
        identifier = resource_id(record)
        cache_key = (identifier, depth)
        cached = match_cache.get(cache_key)
        if cached is not None:
            return cached
        if needle is not None:
            if search_traversal_count >= traversal_node_limit:
                search_traversal_truncated = True
                match_cache[cache_key] = False
                return False
            search_traversal_count += 1
        if not include_absent and not resource_exists(identifier):
            match_cache[cache_key] = False
            return False
        matched = needle is None or needle in _resource_search_text(
            record,
            temporal_state(identifier),
            descriptor_by_kind.get(record.get("kind")),
        )
        if not matched and depth < len(levels):
            matched = any(
                branch_matches(target, depth + 1)
                for _, target in neighbors(identifier, depth)[:max_children]
            )
        match_cache[cache_key] = matched
        return matched

    node_occurrence_count = 0
    traversal_truncated = False

    def build_node(
        record: dict[str, Any],
        depth: int,
        relationship: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        nonlocal node_occurrence_count, traversal_truncated
        # Check the global budget before materializing or recursively visiting
        # this occurrence. A relationship tree may intentionally duplicate a
        # resource under different parents, so the budget applies to rendered
        # occurrences rather than unique resource identities.
        if node_occurrence_count >= traversal_node_limit:
            traversal_truncated = True
            return None
        identifier = resource_id(record)
        view = temporal_state(identifier)
        if not include_absent and not view["exists"]:
            return None
        node_occurrence_count += 1
        node: dict[str, Any] = {
            "resource": view,
            "depth": depth,
            "children": [],
            "child_count": 0,
            "truncated_child_count": 0,
        }
        if relationship is not None:
            relation_type = relationship.get(
                "relation_type", relationship.get("type", "related_to")
            )
            node["relationship"] = {
                "relationship_id": relationship.get("relationship_id"),
                "type": relation_type,
                "source": relationship.get("source"),
                "target": relationship.get("target"),
                "quality": relationship.get("quality", "unknown"),
                "valid_from_ns": relationship.get("valid_from_ns"),
                "valid_to_ns": relationship.get("valid_to_ns"),
            }
            node["relation_label"] = levels[depth - 1].get(
                "label", relation_type
            )
        if depth < len(levels):
            children: list[dict[str, Any]] = []
            child_candidates = neighbors(identifier, depth)
            for child_relationship, child_record in child_candidates[:max_children]:
                if node_occurrence_count >= traversal_node_limit:
                    traversal_truncated = True
                    break
                child = build_node(child_record, depth + 1, child_relationship)
                if child is not None:
                    children.append(child)
            node["child_count"] = len(child_candidates)
            node["children"] = children
            node["truncated_child_count"] = max(
                0,
                len(child_candidates) - len(children),
            )
            if node["truncated_child_count"]:
                traversal_truncated = True
        return node

    root_records.sort(
        key=lambda record: (
            record.get("kind", "UNKNOWN"),
            record.get("label", _label_from_id(resource_id(record))),
            resource_id(record),
        )
    )
    matched_roots: list[dict[str, Any]] = []
    matched_count = 0
    for record in root_records:
        if not include_absent and not resource_exists(resource_id(record)):
            continue
        if not branch_matches(record, 0):
            continue
        if safe_offset <= matched_count < safe_offset + safe_limit:
            matched_roots.append(record)
        matched_count += 1

    bundles: list[dict[str, Any]] = []
    for record in matched_roots:
        if node_occurrence_count >= traversal_node_limit:
            traversal_truncated = True
            break
        node = build_node(record, 0)
        if node is not None:
            bundles.append(node)
    unique_items: dict[str, dict[str, Any]] = {}

    def collect(node: dict[str, Any]) -> None:
        view = node["resource"]
        unique_items[view["resource_id"]] = view
        for child in node["children"]:
            collect(child)

    for bundle in bundles:
        collect(bundle)
    return {
        "revision_id": REVISION_ID,
        "time_ns": str(timestamp_ns),
        "view_id": view_id,
        "view": descriptor,
        "bundles": bundles,
        "items": list(unique_items.values()),
        "count": matched_count,
        "matched_count": matched_count,
        "returned_count": len(bundles),
        "returned_node_count": node_occurrence_count,
        "traversal_node_limit": traversal_node_limit,
        "traversal_truncated": traversal_truncated,
        "search_traversal_count": search_traversal_count,
        "search_traversal_truncated": search_traversal_truncated,
        "matched_count_exact": not search_traversal_truncated,
        "total_count": len(root_records),
        "counts_by_kind": counts_by_kind,
        "limit": safe_limit,
        "offset": safe_offset,
        "next_offset": (
            safe_offset + len(bundles)
            if safe_offset + len(bundles) < matched_count
            else None
        ),
        "tables": [],
        "windowed": runtime is not None or matched_count > len(bundles),
    }


def resources_at(
    timestamp_ns: int,
    *,
    kinds: set[str] | None = None,
    layers: set[str] | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    view_id: str | None = None,
) -> dict[str, Any]:
    dataset = load_demo_dataset()
    if view_id:
        return _resource_table_view_at(
            dataset,
            timestamp_ns,
            view_id,
            search=search,
            limit=limit,
            offset=offset,
        )
    needle = search.casefold() if search else None
    runtime = scale_runtime(dataset)
    if runtime is not None:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit or 500), 1000))
        descriptor_index = {
            item["kind"]: item for item in dataset["kind_descriptors"]
        }
        counts_by_kind: Counter[str] = Counter()
        matched_count = 0
        page_records: list[dict[str, Any]] = []
        temporal_page_views: dict[str, dict[str, Any]] = {}
        for record in runtime.resources:
            if layers and record["layer"] not in layers:
                continue
            if needle:
                point_view = _redact_resource_view(
                    resource_state_at(record["resource_id"], timestamp_ns),
                    descriptor_index.get(record["kind"]),
                )
                if needle not in _resource_search_text(
                    record,
                    point_view,
                    descriptor_index.get(record["kind"]),
                ):
                    continue
                temporal_page_views[record["resource_id"]] = point_view
            counts_by_kind[record["kind"]] += 1
            if kinds and record["kind"] not in kinds:
                continue
            if safe_offset <= matched_count < safe_offset + safe_limit:
                page_records.append(record)
            matched_count += 1
        rows = [
            temporal_page_views.get(record["resource_id"])
            or _redact_resource_view(
                resource_state_at(record["resource_id"], timestamp_ns),
                descriptor_index.get(record["kind"]),
            )
            for record in page_records
        ]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[row["kind"]].append(row)
        return {
            "revision_id": REVISION_ID,
            "time_ns": str(timestamp_ns),
            "items": rows,
            "count": matched_count,
            "matched_count": matched_count,
            "returned_count": len(rows),
            "total_count": len(runtime.resources),
            "counts_by_kind": dict(sorted(counts_by_kind.items())),
            "limit": safe_limit,
            "offset": safe_offset,
            "next_offset": (
                safe_offset + len(rows)
                if safe_offset + len(rows) < matched_count
                else None
            ),
            "tables": [
                {
                    "kind": kind,
                    "descriptor": descriptor_index.get(
                        kind,
                        _kind_descriptor(kind),
                    ),
                    "count": counts_by_kind[kind],
                    "items": items,
                }
                for kind, items in sorted(grouped.items())
            ],
            "windowed": True,
        }
    descriptor_index = {item["kind"]: item for item in dataset["kind_descriptors"]}
    rows = []
    for record in dataset["resources"]:
        if kinds and record["kind"] not in kinds:
            continue
        if layers and record["layer"] not in layers:
            continue
        view = _redact_resource_view(
            resource_state_at(record["resource_id"], timestamp_ns),
            descriptor_index.get(record["kind"]),
        )
        if needle and needle not in _resource_search_text(
            record,
            view,
            descriptor_index.get(record["kind"]),
        ):
            continue
        rows.append(view)
    rows.sort(key=lambda item: (item["kind"], item["label"], item["resource_id"]))
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["kind"]].append(row)
    tables = [
        {
            "kind": kind,
            "descriptor": descriptor_index.get(kind, _kind_descriptor(kind)),
            "count": len(items),
            "items": items,
        }
        for kind, items in sorted(grouped.items())
    ]
    return {
        "revision_id": REVISION_ID,
        "time_ns": str(timestamp_ns),
        "items": rows,
        "count": len(rows),
        "tables": tables,
    }


def events_in_range(start_ns: int, end_ns: int) -> list[dict[str, Any]]:
    dataset = load_demo_dataset()
    runtime = scale_runtime(dataset)
    if runtime is not None:
        left = bisect_left(runtime.event_times, start_ns)
        right = bisect_right(runtime.event_times, end_ns)
        return runtime.events[left:right]
    return [
        event
        for event in dataset["events"]
        if start_ns <= int(event["timestamp_ns"]) <= end_ns
    ]


def dashboard_query(
    timestamp_ns: int,
    *,
    dashboard_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Evaluate plug-in dashboard declarations over one temporal population."""

    dataset = load_demo_dataset()
    descriptors = [
        item
        for item in (
            dataset.get("dashboard_descriptors")
            or dataset.get("schema", {}).get("dashboards", [])
        )
        if isinstance(item, dict) and item.get("dashboard_id")
    ]
    selected_ids = (
        {str(item) for item in dashboard_ids if str(item)}
        if dashboard_ids is not None
        else None
    )
    selected_descriptors = [
        item
        for item in descriptors
        if selected_ids is None or str(item["dashboard_id"]) in selected_ids
    ]
    relevant_kinds: set[str] = set()
    requires_unfiltered_population = False
    for descriptor in selected_descriptors:
        for widget in [
            *descriptor.get("statistics", []),
            *descriptor.get("tables", []),
        ]:
            if not isinstance(widget, dict) or str(
                widget.get("aggregation", "count")
            ) == "precomputed":
                continue
            kinds = {str(item) for item in widget.get("resource_kinds", [])}
            if kinds:
                relevant_kinds.update(kinds)
            else:
                requires_unfiltered_population = True

    runtime = scale_runtime(dataset)
    records = runtime.resources if runtime is not None else dataset.get("resources", [])
    descriptor_by_kind = {
        str(item.get("kind")): item
        for item in dataset.get("kind_descriptors", [])
        if isinstance(item, dict) and item.get("kind")
    }
    rows: list[dict[str, Any]] = []
    if selected_descriptors and (relevant_kinds or requires_unfiltered_population):
        for record in records:
            kind = str(record.get("kind", "UNKNOWN"))
            if not requires_unfiltered_population and kind not in relevant_kinds:
                continue
            rows.append(
                _redact_resource_view(
                    resource_state_at(resource_id(record), timestamp_ns),
                    descriptor_by_kind.get(kind),
                )
            )
    return {
        "revision_id": REVISION_ID,
        "time_ns": str(timestamp_ns),
        "population_count": len(rows),
        "dashboards": evaluate_dashboards(
            selected_descriptors,
            rows,
            dashboard_ids=selected_ids,
        ),
    }


def range_summary(start_ns: int, end_ns: int) -> dict[str, Any]:
    dataset = load_demo_dataset()
    selected = events_in_range(start_ns, end_ns)
    runtime = scale_runtime(dataset)
    if runtime is not None:
        affected_ids = {
            identifier
            for event in selected
            for identifier in event.get("affected_resources", [])
            if identifier
        }
        mutation_left = bisect_left(runtime.mutation_times, start_ns)
        mutation_right = bisect_right(runtime.mutation_times, end_ns)
        mutations = runtime.mutations[mutation_left:mutation_right]
        for mutation in mutations:
            affected_ids.update((mutation["source"], mutation["target"]))
        descriptors = {
            item["relation_type"]: item
            for item in dataset["relationship_descriptors"]
        }
        affected = sorted(affected_ids)
        endpoint_diff: list[dict[str, Any]] = []
        for identifier in affected[:500]:
            before = resource_state_at(identifier, start_ns)
            after = resource_state_at(identifier, end_ns)
            if (before["exists"], before["status"], before["state"]) != (
                after["exists"],
                after["status"],
                after["state"],
            ):
                endpoint_diff.append(
                    {"resource_id": identifier, "before": before, "after": after}
                )

        # Endpoint comparison and in-range status collection have independent
        # budgets. A resource with many state intervals must not prevent later
        # affected resources from being compared at the two range boundaries.
        status_segments: list[dict[str, Any]] = []
        status_segments_truncated = False
        for identifier in affected:
            for interval in runtime.state_by_resource.get(identifier, []):
                if _overlaps_range(
                    interval.get("valid_from_ns"),
                    interval.get("valid_to_ns"),
                    start_ns,
                    end_ns,
                ):
                    if len(status_segments) >= 500:
                        status_segments_truncated = True
                        break
                    status_segments.append(interval)
            if status_segments_truncated:
                break
        return {
            "revision_id": REVISION_ID,
            "start_ns": str(start_ns),
            "end_ns": str(end_ns),
            "event_count": len(selected),
            "failure_count": sum(
                item.get("outcome") == "failure" for item in selected
            ),
            "events": [
                redact_event_for_client(item, dataset)
                for item in selected[:500]
            ],
            "counts": {
                "by_outcome": dict(
                    Counter(item.get("outcome", "unknown") for item in selected)
                ),
                "by_action": dict(
                    Counter(item.get("action", "unknown") for item in selected)
                ),
            },
            "affected_resource_count": len(affected),
            "affected_resources": affected[:500],
            "status_segments": [
                redact_state_interval_for_client(
                    str(item.get("resource", "")), item, dataset
                )
                for item in status_segments[:500]
            ],
            "endpoint_diff": endpoint_diff[:500],
            "endpoint_diff_evaluated_count": min(len(affected), 500),
            "relationship_change_count": len(mutations),
            "relationship_changes": [
                {
                    **item,
                    "event_uid": item.get("cause_event_uid"),
                    "descriptor": descriptors.get(item["relation_type"]),
                }
                for item in mutations[:500]
            ],
            "truncated": {
                "events": len(selected) > 500,
                "affected_resources": len(affected) > 500,
                "status_segments": status_segments_truncated,
                "endpoint_diff": len(affected) > 500,
                "relationship_changes": len(mutations) > 500,
            },
                "selection_behavior": (
                    "highlight events and status spans; exact counts use the full "
                    "100K+-event stream while detail arrays are bounded"
            ),
        }
    affected_ids = (
        {
            effect["resource_id"]
            for event in selected
            for effect in event.get("effects", [])
            if effect.get("resource_id")
        }
        | {
            subject["resource_id"]
            for event in selected
            for subject in event.get("subjects", [])
            if subject.get("resource_id")
        }
    )
    descriptor_by_type = {
        item["relation_type"]: item
        for item in dataset["relationship_descriptors"]
    }
    relationship_changes: list[dict[str, Any]] = []
    for mutation in dataset["relationship_mutations"]:
        if not start_ns <= int(mutation["effective_time_ns"]) <= end_ns:
            continue
        boundary_field = (
            "valid_from_ns" if mutation["operation"] == "add" else "valid_to_ns"
        )
        interval = next(
            (
                item
                for item in dataset["relationship_intervals"]
                if item["source"] == mutation["source"]
                and item["target"] == mutation["target"]
                and item["relation_type"] == mutation["relation_type"]
                and item.get(boundary_field) == mutation["effective_time_ns"]
            ),
            None,
        )
        relationship_changes.append(
            {
                **mutation,
                "relationship_id": (
                    interval.get("relationship_id") if interval else None
                ),
                "event_uid": mutation.get("cause_event_uid"),
                "descriptor": descriptor_by_type.get(mutation["relation_type"]),
            }
        )
        affected_ids.update((mutation["source"], mutation["target"]))
    affected = sorted(affected_ids)
    endpoint_diff = []
    for identifier in affected:
        before = resource_state_at(identifier, start_ns)
        after = resource_state_at(identifier, end_ns)
        if (before["exists"], before["status"], before["state"]) != (
            after["exists"],
            after["status"],
            after["state"],
        ):
            endpoint_diff.append(
                {"resource_id": identifier, "before": before, "after": after}
            )
    status_segments = [
        item
        for item in dataset["state_intervals"]
        if item["resource"] in affected
        and (item.get("valid_to_ns") is None or int(item["valid_to_ns"]) > start_ns)
        and (item.get("valid_from_ns") is None or int(item["valid_from_ns"]) < end_ns)
    ]
    return {
        "revision_id": REVISION_ID,
        "start_ns": str(start_ns),
        "end_ns": str(end_ns),
        "event_count": len(selected),
        "events": [redact_event_for_client(item, dataset) for item in selected],
        "counts": {
            "by_outcome": dict(Counter(item.get("outcome", "unknown") for item in selected)),
            "by_action": dict(Counter(item.get("action", "unknown") for item in selected)),
        },
        "affected_resources": affected,
        "status_segments": [
            redact_state_interval_for_client(
                str(item.get("resource", "")), item, dataset
            )
            for item in status_segments
        ],
        "endpoint_diff": endpoint_diff,
        "relationship_changes": relationship_changes,
        "selection_behavior": "highlight events and status spans; endpoint diff is supplemental",
    }


def _overlaps_range(
    start: Any,
    end: Any,
    query_start_ns: int,
    query_end_ns: int,
) -> bool:
    return (end is None or int(end) > query_start_ns) and (
        start is None or int(start) < query_end_ns
    )
