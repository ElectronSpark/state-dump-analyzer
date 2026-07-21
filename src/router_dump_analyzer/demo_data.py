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
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .demo_source_plugin import (
    RECORD_LANE_PRESETS,
    SOURCE_RECORD_DESCRIPTORS,
    build_demo_source_records,
)
from .scale_data import ScaleRuntime, load_scale_dataset


REVISION_ID = "illustrative-revision-node-a"
PACK_ROOT = "router-state-lab-100k"
PACK_ARCHIVE_ENV = "ROUTER_DUMP_DEMO_ARCHIVE"
_demo_archive_override: Path | None = None
_full_scale_enabled = False


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
        "title": "100K-item browser performance proof",
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

    explicit = record.get("resource_id")
    if explicit:
        return str(explicit)
    key = record.get("key", {})
    kind = str(record.get("kind", "UNKNOWN"))
    if kind == "ETG":
        suffix = f"{key.get('vrf', 'default')}/{key.get('id', 'unknown')}"
    elif kind == "ETE":
        suffix = f"{key.get('etg', 'unknown')}/{key.get('id', 'unknown')}"
    else:
        suffix = "/".join(str(value) for value in key.values()) or "unknown"
    return f"{record.get('layer', 'unknown')}/{kind}/{suffix}"


def _label_from_id(identifier: str) -> str:
    parts = identifier.split("/")
    if len(parts) <= 2:
        return identifier
    return "/".join(parts[-2:] if parts[1] in {"ETG", "ETE", "EVPN_ROUTE"} else parts[-1:])


def _kind_descriptor(kind: str) -> dict[str, Any]:
    tags = ["connector", "compact"] if kind == "GLUE" else []
    return {
        "kind": kind,
        "display_name": kind.replace("_", " ").title(),
        "display_name_fields": ["name", "id"],
        "default_table_fields": ["status", "oper_state", "program_state"],
        "condition_field": "status",
        "presentation_tags": tags,
        "plugin_defined": True,
    }


def _relationship_descriptor(relation_type: str) -> dict[str, Any]:
    return {
        "relation_type": relation_type,
        "label": relation_type.replace("_", " ").title(),
        "directed": True,
        "structural": False,
        "plugin_defined": True,
    }


def _causal_link_descriptor(link_type: str) -> dict[str, Any]:
    return {
        "link_type": link_type,
        "label": link_type.replace("_", " ").title(),
        "directed": True,
        "plugin_defined": True,
    }


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
                    "100K+ EVPN single-home to multi-home failover pack "
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
        "source_record_descriptors": SOURCE_RECORD_DESCRIPTORS,
        "record_lane_presets": RECORD_LANE_PRESETS,
        "relationship_descriptors": relationship_descriptors,
        "causal_link_descriptors": causal_link_descriptors,
        "schema": {
            "resource_kinds": descriptors,
            "dashboards": dashboard_descriptors,
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
        return dataset
    client = {key: value for key, value in dataset.items() if not key.startswith("_")}
    # The browser needs every identity and event timestamp for catalog search,
    # density, and exact range grouping, but it does not need the server's full
    # state/effect records for all 100K objects. Timeline/resource queries return
    # those details on demand for the bounded visible working set.
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
    client["events"] = [
        {
            "event_uid": item["event_uid"],
            "timestamp_ns": item["timestamp_ns"],
            "event_type": item["event_type"],
            "display_name": item.get("display_name"),
            "action": item.get("action", "observe"),
            "outcome": item.get("outcome", "unknown"),
            "state_changed": item.get("state_changed", False),
            "layer": item.get("layer", "unknown"),
            "phase": item.get("phase"),
            "resource_id": item.get("resource_id"),
            "resource_kind": item.get("resource_kind", "UNKNOWN"),
            "subject": item.get("subject", {}),
            **(
                {"result": item["result"]}
                if item.get("outcome") == "failure" and item.get("result")
                else {}
            ),
        }
        for item in dataset["events"]
    ]
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
    if not exists:
        status = "absent"
        status_class = "absent"
    else:
        status = (
            (state_interval or {}).get("status")
            or state.get("status")
            or state.get("oper_state")
            or state.get("program_state")
            or "unknown"
        )
        status_class = (state_interval or {}).get("status_class")
        if not status_class:
            normalized = str(status).casefold()
            status_class = (
                "error"
                if normalized in {"down", "error", "failed", "ineligible"}
                else "healthy"
                if normalized in {"up", "active", "ready", "programmed", "selected"}
                else "unknown"
            )
    return {
        "resource_id": resource_identifier,
        "kind": record.get("kind", "UNKNOWN") if record else "UNKNOWN",
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


def resources_at(
    timestamp_ns: int,
    *,
    kinds: set[str] | None = None,
    layers: set[str] | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    dataset = load_demo_dataset()
    needle = search.casefold() if search else None
    runtime = scale_runtime(dataset)
    if runtime is not None:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(int(limit or 500), 1000))
        counts_by_kind: Counter[str] = Counter()
        matched_count = 0
        page_records: list[dict[str, Any]] = []
        for record in runtime.resources:
            if layers and record["layer"] not in layers:
                continue
            if needle:
                searchable = " ".join(
                    (
                        record["resource_id"],
                        record.get("label", ""),
                        record.get("kind", ""),
                        json.dumps(record.get("key", {}), sort_keys=True),
                        json.dumps(record.get("state", {}), sort_keys=True),
                    )
                ).casefold()
                if needle not in searchable:
                    continue
            counts_by_kind[record["kind"]] += 1
            if kinds and record["kind"] not in kinds:
                continue
            if safe_offset <= matched_count < safe_offset + safe_limit:
                page_records.append(record)
            matched_count += 1
        rows = [
            resource_state_at(record["resource_id"], timestamp_ns)
            for record in page_records
        ]
        descriptor_index = {
            item["kind"]: item for item in dataset["kind_descriptors"]
        }
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
    rows = []
    for record in dataset["resources"]:
        if kinds and record["kind"] not in kinds:
            continue
        if layers and record["layer"] not in layers:
            continue
        if needle and needle not in json.dumps(record, sort_keys=True).casefold():
            continue
        rows.append(resource_state_at(record["resource_id"], timestamp_ns))
    rows.sort(key=lambda item: (item["kind"], item["label"], item["resource_id"]))
    descriptor_index = {item["kind"]: item for item in dataset["kind_descriptors"]}
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
        status_segments: list[dict[str, Any]] = []
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
            for interval in runtime.state_by_resource.get(identifier, []):
                if _overlaps_range(
                    interval.get("valid_from_ns"),
                    interval.get("valid_to_ns"),
                    start_ns,
                    end_ns,
                ):
                    status_segments.append(interval)
                    if len(status_segments) >= 500:
                        break
            if len(status_segments) >= 500:
                break
        return {
            "revision_id": REVISION_ID,
            "start_ns": str(start_ns),
            "end_ns": str(end_ns),
            "event_count": len(selected),
            "failure_count": sum(
                item.get("outcome") == "failure" for item in selected
            ),
            "events": selected[:500],
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
            "status_segments": status_segments[:500],
            "endpoint_diff": endpoint_diff[:500],
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
                "status_segments": len(status_segments) >= 500,
                "endpoint_diff": len(affected) > 500,
                "relationship_changes": len(mutations) > 500,
            },
            "selection_behavior": (
                "highlight events and status spans; exact counts use the full "
                "100K stream while detail arrays are bounded"
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
        and (item.get("valid_from_ns") is None or int(item["valid_from_ns"]) <= end_ns)
    ]
    return {
        "revision_id": REVISION_ID,
        "start_ns": str(start_ns),
        "end_ns": str(end_ns),
        "event_count": len(selected),
        "events": selected,
        "counts": {
            "by_outcome": dict(Counter(item.get("outcome", "unknown") for item in selected)),
            "by_action": dict(Counter(item.get("action", "unknown") for item in selected)),
        },
        "affected_resources": affected,
        "status_segments": status_segments,
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
        start is None or int(start) <= query_end_ns
    )
