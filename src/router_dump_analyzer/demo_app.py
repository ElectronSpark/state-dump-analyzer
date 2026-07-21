"""Local FastAPI review demo for the router dump analyzer design pack."""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from .demo_data import (
    REVISION_ID,
    client_demo_dataset,
    configure_demo_archive,
    configure_demo_scale,
    events_in_range,
    is_scale_dataset,
    load_demo_dataset,
    range_summary,
    relationships_at,
    resource_id,
    resource_state_at,
    resources_at,
    scale_runtime,
)
from .source_record_core import query_source_records, record_lanes_for_window


STATIC_DIR = Path(__file__).with_name("demo_static")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_demo_dataset()
    yield


app = FastAPI(
    title="Router State Lab demo API",
    version="0.1.0",
    description=(
        "Read-only API over a trusted local synthetic fixture or its packed "
        "review projection. It does not ingest caller-provided dumps."
    ),
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)


@app.middleware("http")
async def disable_demo_asset_cache(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="demo-assets")


def _require_revision(revision_id: str) -> None:
    if revision_id != REVISION_ID:
        raise HTTPException(status_code=404, detail="unknown illustrative revision")


def _resource_id(record: dict[str, Any]) -> str:
    return resource_id(record)


def _layer_of(resource_id: str) -> str:
    return resource_id.split("/", 1)[0]


def _kind_of(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[1] if len(parts) > 1 else "unknown"


def _label_of(resource_id: str) -> str:
    parts = resource_id.split("/")
    if len(parts) <= 2:
        return resource_id
    tail = parts[-2:] if parts[1] in {"ETG", "ETE", "ROUTE", "NBR"} else parts[-1:]
    return "/".join(tail)


def _contains_time(timestamp_ns: int, start: Any, end: Any) -> bool:
    return (start is None or timestamp_ns >= int(start)) and (
        end is None or timestamp_ns < int(end)
    )


def _scale_resource_exists(runtime: Any, identifier: str, timestamp_ns: int) -> bool:
    return any(
        _contains_time(
            timestamp_ns,
            interval.get("valid_from_ns"),
            interval.get("valid_to_ns"),
        )
        for interval in runtime.lifecycle_by_resource.get(identifier, [])
    )


def _graph_payload(timestamp_ns: int) -> dict[str, Any]:
    dataset = load_demo_dataset()
    complete = {_resource_id(item): item for item in dataset["resources"]}
    descriptor_index = {item["kind"]: item for item in dataset["kind_descriptors"]}
    active_views = {
        identifier: view
        for identifier in complete
        if (view := resource_state_at(identifier, timestamp_ns))["exists"]
    }
    relationships = [
        item
        for item in relationships_at(timestamp_ns)
        if item["source"] in active_views and item["target"] in active_views
    ]

    nodes: list[dict[str, Any]] = []
    for identifier in sorted(active_views):
        record = complete.get(identifier)
        view = active_views[identifier]
        nodes.append(
            {
                "id": identifier,
                "label": view["label"],
                "layer": view["layer"],
                "kind": view["kind"],
                "status": view["status_class"],
                "status_value": view["status"],
                "state": view["state"],
                "quality": view["quality"],
                "state_basis": "selected from temporal resource intervals",
                "complete_record": record is not None,
                "presentation_tags": record.get("presentation_tags", []) if record else [],
                "icon": descriptor_index.get(view["kind"], {}).get("icon"),
            }
        )

    edges = [
        {
            "id": item.get("relationship_id", f"edge-{index}"),
            "source": item["source"],
            "target": item["target"],
            "type": item["type"],
            "quality": item.get("quality", "unknown"),
            "provenance": item.get("provenance", "unknown"),
            "temporal_note": item.get("temporal_note"),
            "valid_from_ns": item.get("valid_from_ns"),
            "valid_to_ns": item.get("valid_to_ns"),
            "start_event_uid": item.get("start_event_uid"),
            "end_event_uid": item.get("end_event_uid"),
        }
        for index, item in enumerate(relationships)
    ]
    return {
        "revision_id": REVISION_ID,
        "time_ns": str(timestamp_ns),
        "nodes": nodes,
        "edges": edges,
        "incomplete_node_count": sum(not node["complete_record"] for node in nodes),
        "demo_note": (
            "Nodes require an active resource lifecycle; edges additionally require "
            "an active relationship interval and two active endpoints."
        ),
    }


def _correlation_payload(body: dict[str, Any]) -> dict[str, Any]:
    dataset = load_demo_dataset()
    if is_scale_dataset(dataset):
        return _scale_correlation_payload(dataset, body)
    timestamp_ns = int(body.get("time_ns", dataset["demo"]["capture_ns"]))
    payload = _graph_payload(timestamp_ns)
    relation_types = set(body.get("relation_types") or [])
    edges = [
        edge
        for edge in payload["edges"]
        if not relation_types or edge["type"] in relation_types
    ]
    roots = set(body.get("resource_ids") or [])
    if not roots:
        payload["edges"] = edges
        payload["query"] = {"resource_ids": [], "depth": None, "direction": "both"}
        return payload

    direction = str(body.get("direction", "both"))
    if direction not in {"incoming", "outgoing", "both"}:
        raise HTTPException(status_code=422, detail="direction must be incoming, outgoing or both")
    depth = int(body.get("depth", 3))
    if depth < 0 or depth > 20:
        raise HTTPException(status_code=422, detail="depth must be between 0 and 20")
    reached = set(roots)
    frontier = set(roots)
    for _ in range(depth):
        following: set[str] = set()
        for edge in edges:
            if direction in {"outgoing", "both"} and edge["source"] in frontier:
                following.add(edge["target"])
            if direction in {"incoming", "both"} and edge["target"] in frontier:
                following.add(edge["source"])
        following -= reached
        if not following:
            break
        reached.update(following)
        frontier = following
    payload["nodes"] = [node for node in payload["nodes"] if node["id"] in reached]
    payload["edges"] = [
        edge
        for edge in edges
        if edge["source"] in reached and edge["target"] in reached
    ]
    payload["query"] = {
        "resource_ids": sorted(roots),
        "depth": depth,
        "direction": direction,
        "relation_types": sorted(relation_types),
    }
    return payload


def _scale_correlation_payload(
    dataset: dict[str, Any],
    body: dict[str, Any],
) -> dict[str, Any]:
    """Return a bounded, time-valid neighborhood from the 100K indexes."""

    runtime = scale_runtime(dataset)
    if runtime is None:  # pragma: no cover - guarded by the caller
        raise HTTPException(status_code=500, detail="scale indexes are unavailable")
    timestamp_ns = int(body.get("time_ns", dataset["demo"]["capture_ns"]))
    direction = str(body.get("direction", "both"))
    if direction not in {"incoming", "outgoing", "both"}:
        raise HTTPException(
            status_code=422,
            detail="direction must be incoming, outgoing or both",
        )
    depth = int(body.get("depth", 3))
    if depth < 0 or depth > 20:
        raise HTTPException(status_code=422, detail="depth must be between 0 and 20")
    relation_types = set(body.get("relation_types") or [])
    requested_roots = [str(item) for item in body.get("resource_ids") or []]
    defaulted = not requested_roots
    if defaulted:
        requested_roots = runtime.initial_resource_ids[:4]
    roots = [
        identifier
        for identifier in dict.fromkeys(requested_roots)
        if identifier in runtime.resource_by_id
        and _scale_resource_exists(runtime, identifier, timestamp_ns)
    ]
    max_nodes = max(1, min(int(body.get("max_nodes", 500)), 500))
    reached = set(roots)
    frontier = set(roots)
    truncated = False
    for _ in range(depth):
        following: set[str] = set()
        for identifier in frontier:
            for relationship in runtime.relationships_by_endpoint.get(identifier, []):
                relation_type = relationship.get(
                    "relation_type",
                    relationship.get("type", "related_to"),
                )
                if relation_types and relation_type not in relation_types:
                    continue
                if not _contains_time(
                    timestamp_ns,
                    relationship.get("valid_from_ns"),
                    relationship.get("valid_to_ns"),
                ):
                    continue
                source = relationship["source"]
                target = relationship["target"]
                other: str | None = None
                if direction in {"outgoing", "both"} and source == identifier:
                    other = target
                elif direction in {"incoming", "both"} and target == identifier:
                    other = source
                if (
                    other
                    and other not in reached
                    and _scale_resource_exists(runtime, other, timestamp_ns)
                ):
                    following.add(other)
        following -= reached
        remaining = max_nodes - len(reached)
        if len(following) > remaining:
            following = set(sorted(following)[: max(0, remaining)])
            truncated = True
        if not following:
            break
        reached.update(following)
        frontier = following
        if len(reached) >= max_nodes:
            truncated = True
            break

    edge_records: dict[str, dict[str, Any]] = {}
    for identifier in reached:
        for relationship in runtime.relationships_by_endpoint.get(identifier, []):
            source = relationship["source"]
            target = relationship["target"]
            relation_type = relationship.get(
                "relation_type",
                relationship.get("type", "related_to"),
            )
            if source not in reached or target not in reached:
                continue
            if relation_types and relation_type not in relation_types:
                continue
            if not _contains_time(
                timestamp_ns,
                relationship.get("valid_from_ns"),
                relationship.get("valid_to_ns"),
            ):
                continue
            key = str(
                relationship.get(
                    "relationship_id",
                    f"{source}|{relation_type}|{target}|{relationship.get('valid_from_ns')}",
                )
            )
            edge_records[key] = relationship

    descriptor_index = {
        item["kind"]: item for item in dataset["kind_descriptors"]
    }
    nodes: list[dict[str, Any]] = []
    for identifier in sorted(reached):
        view = resource_state_at(identifier, timestamp_ns)
        if not view["exists"]:
            continue
        record = runtime.resource_by_id[identifier]
        nodes.append(
            {
                "id": identifier,
                "label": view["label"],
                "layer": view["layer"],
                "kind": view["kind"],
                "status": view["status_class"],
                "status_value": view["status"],
                "state": view["state"],
                "quality": view["quality"],
                "state_basis": "selected from full-scale temporal indexes",
                "complete_record": True,
                "presentation_tags": record.get("presentation_tags", []),
                "icon": descriptor_index.get(view["kind"], {}).get("icon"),
            }
        )
    node_ids = {node["id"] for node in nodes}
    edges = [
        {
            "id": key,
            "source": item["source"],
            "target": item["target"],
            "type": item.get("relation_type", item.get("type", "related_to")),
            "quality": item.get("quality", "unknown"),
            "provenance": item.get("provenance", "unknown"),
            "temporal_note": "selected from full-scale validity interval",
            "valid_from_ns": item.get("valid_from_ns"),
            "valid_to_ns": item.get("valid_to_ns"),
            "start_event_uid": item.get("start_event_uid"),
            "end_event_uid": item.get("end_event_uid"),
        }
        for key, item in sorted(edge_records.items())
        if item["source"] in node_ids and item["target"] in node_ids
    ]
    return {
        "revision_id": REVISION_ID,
        "time_ns": str(timestamp_ns),
        "nodes": nodes,
        "edges": edges,
        "incomplete_node_count": 0,
        "truncated": truncated,
        "max_nodes": max_nodes,
        "query": {
            "resource_ids": roots,
            "depth": depth,
            "direction": direction,
            "relation_types": sorted(relation_types),
            "defaulted_to_representative_roots": defaulted,
        },
        "demo_note": (
            "Time-valid full-scale neighborhood; the response is capped at "
            f"{max_nodes} nodes for browser layout safety."
        ),
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, Any]:
    dataset = load_demo_dataset()
    return {
        "status": "ok",
        "revision_id": REVISION_ID,
        "mode": str(dataset["demo"].get("mode", "illustrative")),
        "event_count": int(dataset["demo"].get("event_count", 0)),
        "matched_event_count": int(
            dataset["demo"].get(
                "matched_event_count",
                dataset["demo"].get("event_count", 0),
            )
        ),
        "resource_count": int(dataset["demo"].get("resource_count", 0)),
        "source_record_count": int(
            dataset["demo"].get(
                "source_record_count",
                len(dataset.get("source_records", [])),
            )
        ),
    }


@lru_cache(maxsize=1)
def _client_demo_json() -> bytes:
    return json.dumps(
        client_demo_dataset(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


@app.get("/api/demo")
def demo_dataset() -> Response:
    """Return the browser bootstrap fixture without server-only indexes."""

    return Response(content=_client_demo_json(), media_type="application/json")


@app.get("/v1/revisions/{revision_id}/capabilities")
def capabilities(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    return {
        "revision_id": revision_id,
        "implemented": [
            "canonical_resource_lanes",
            "lifecycle_and_status_intervals",
            "failed_event_without_implicit_mutation",
            "generic_retained_source_records",
            "paged_source_record_queries",
            "validated_regex_source_lanes",
            "stable_source_to_normalized_navigation",
            "time_varying_relationship_view",
            "point_in_time_resource_tables",
            "plugin_defined_dashboard_descriptors",
            "selected_range_summary_and_endpoint_diff",
            "consistency_finding_view",
            "precomputed_route_explanation",
            "archive_inventory",
            "review_notes_local_to_browser",
        ],
        "limitations": dataset["gaps"],
        "disclosure": dataset["demo"]["disclosure"],
    }


@app.get("/v1/revisions/{revision_id}/resources")
def resources(
    revision_id: str,
    kind: str | None = None,
    layer: str | None = None,
) -> dict[str, Any]:
    _require_revision(revision_id)
    items = load_demo_dataset()["resources"]
    if kind:
        items = [item for item in items if item.get("kind") == kind]
    if layer:
        items = [item for item in items if item.get("layer") == layer]
    return {"items": items, "count": len(items), "next_cursor": None}


@app.get("/v1/revisions/{revision_id}/resources/at")
def resource_tables_at(
    revision_id: str,
    time_ns: int | None = None,
    kind: list[str] = Query(default=[]),
    layer: list[str] = Query(default=[]),
    search: str | None = None,
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    timestamp_ns = int(time_ns or dataset["demo"]["capture_ns"])
    return resources_at(
        timestamp_ns,
        kinds=set(kind) or None,
        layers=set(layer) or None,
        search=search,
        limit=limit if is_scale_dataset(dataset) else None,
        offset=offset,
    )


@app.post("/v1/revisions/{revision_id}/resources/query")
def resource_tables_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    return resources_at(
        int(body.get("time_ns", dataset["demo"]["capture_ns"])),
        kinds=set(body.get("kinds") or []) or None,
        layers=set(body.get("layers") or []) or None,
        search=body.get("search"),
        limit=body.get("limit") if is_scale_dataset(dataset) else None,
        offset=int(body.get("offset", 0)),
    )


@app.get("/v1/revisions/{revision_id}/events")
def events(
    revision_id: str,
    layer: str | None = None,
    outcome: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    _require_revision(revision_id)
    items = load_demo_dataset()["events"]
    if layer:
        items = [item for item in items if item.get("subjects", [{}])[0].get("layer") == layer]
    if outcome:
        items = [item for item in items if item.get("outcome") == outcome]
    if search:
        needle = search.casefold()
        items = [item for item in items if needle in str(item).casefold()]
    return {"items": items[:limit], "count": len(items), "next_cursor": None}


@app.get("/v1/revisions/{revision_id}/events/{event_uid}")
def event_detail(revision_id: str, event_uid: str) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    runtime = scale_runtime(dataset)
    if runtime is not None:
        item = runtime.event_by_uid.get(event_uid)
        if item is not None:
            return item
        raise HTTPException(status_code=404, detail="event not found")
    for item in dataset["events"]:
        if item["event_uid"] == event_uid:
            return item
    raise HTTPException(status_code=404, detail="event not found")


@app.post("/v1/revisions/{revision_id}/source-records/query")
def source_records_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Page retained CTF and non-CTF input records without domain assumptions."""

    _require_revision(revision_id)
    dataset = load_demo_dataset()
    known_source_types = {
        str(item["source_type"])
        for item in dataset.get("source_record_descriptors", [])
        if item.get("source_type")
    }
    try:
        result = query_source_records(
            dataset.get("source_records", []),
            body,
            known_source_types=known_source_types,
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "revision_id": revision_id,
        **result,
        "source_record_types": dataset.get("source_record_descriptors", []),
    }


def _event_resource_ids(event: dict[str, Any]) -> list[str]:
    identifiers = [
        str(identifier)
        for identifier in event.get("affected_resources", [])
        if identifier
    ]
    identifiers.extend(
        effect["resource_id"]
        for effect in event.get("effects", [])
        if effect.get("resource_id")
    )
    identifiers.extend(
        subject["resource_id"]
        for subject in event.get("subjects", [])
        if subject.get("resource_id")
    )
    return list(dict.fromkeys(identifiers))


def _interval_duration(start: Any, end: Any) -> str | None:
    if start is None or end is None:
        return None
    return str(int(end) - int(start))


def _overlaps_window(
    start: Any,
    end: Any,
    query_start_ns: int,
    query_end_ns: int,
) -> bool:
    """Return whether a half-open interval intersects an inclusive query window."""

    return (end is None or int(end) > query_start_ns) and (
        start is None or int(start) <= query_end_ns
    )


def _effective_relationship_intervals(
    dataset: dict[str, Any],
    lane_ids: set[str],
    query_start_ns: int,
    query_end_ns: int,
) -> list[dict[str, Any]]:
    """Project relationships onto the overlapping lifecycles of both endpoints."""

    runtime = scale_runtime(dataset)
    if runtime is not None:
        lifecycle_by_resource = runtime.lifecycle_by_resource
        candidate_map: dict[str, dict[str, Any]] = {}
        for identifier in lane_ids:
            for relationship in runtime.relationships_by_endpoint.get(identifier, []):
                if (
                    relationship["source"] not in lane_ids
                    or relationship["target"] not in lane_ids
                ):
                    continue
                key = str(
                    relationship.get(
                        "relationship_id",
                        f"{relationship['source']}|{relationship['relation_type']}|"
                        f"{relationship['target']}|{relationship.get('valid_from_ns')}",
                    )
                )
                candidate_map[key] = relationship
        relationship_candidates = list(candidate_map.values())
    else:
        lifecycle_by_resource: dict[str, list[dict[str, Any]]] = {}
        for lifecycle in dataset["lifecycle_intervals"]:
            lifecycle_by_resource.setdefault(lifecycle["resource"], []).append(
                lifecycle
            )
        relationship_candidates = dataset["relationship_intervals"]
    descriptors = {
        item["relation_type"]: item
        for item in dataset["relationship_descriptors"]
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for relationship in relationship_candidates:
        source = relationship["source"]
        target = relationship["target"]
        if source not in lane_ids or target not in lane_ids:
            continue
        source_lifecycles = lifecycle_by_resource.get(source, [])
        target_lifecycles = lifecycle_by_resource.get(target, [])
        for source_lifecycle in source_lifecycles:
            for target_lifecycle in target_lifecycles:
                start_candidates = [
                    (
                        relationship.get("valid_from_ns"),
                        relationship.get("start_event_uid"),
                        "relationship",
                    ),
                    (
                        source_lifecycle.get("valid_from_ns"),
                        source_lifecycle.get("start_event_uid"),
                        "source_lifecycle",
                    ),
                    (
                        target_lifecycle.get("valid_from_ns"),
                        target_lifecycle.get("start_event_uid"),
                        "target_lifecycle",
                    ),
                ]
                finite_starts = [item for item in start_candidates if item[0] is not None]
                effective_start = (
                    max(finite_starts, key=lambda item: int(item[0]))
                    if finite_starts
                    else (None, None, "open")
                )
                end_candidates = [
                    (
                        relationship.get("valid_to_ns"),
                        relationship.get("end_event_uid"),
                        "relationship",
                    ),
                    (
                        source_lifecycle.get("valid_to_ns"),
                        source_lifecycle.get("end_event_uid"),
                        "source_lifecycle",
                    ),
                    (
                        target_lifecycle.get("valid_to_ns"),
                        target_lifecycle.get("end_event_uid"),
                        "target_lifecycle",
                    ),
                ]
                finite_ends = [item for item in end_candidates if item[0] is not None]
                effective_end = (
                    min(finite_ends, key=lambda item: int(item[0]))
                    if finite_ends
                    else (None, None, "open")
                )
                start_ns = effective_start[0]
                end_ns = effective_end[0]
                if (
                    start_ns is not None
                    and end_ns is not None
                    and int(start_ns) >= int(end_ns)
                ):
                    continue
                if not _overlaps_window(
                    start_ns,
                    end_ns,
                    query_start_ns,
                    query_end_ns,
                ):
                    continue
                segment_key = (
                    str(relationship.get("relationship_id", "")),
                    str(start_ns) if start_ns is not None else None,
                    str(end_ns) if end_ns is not None else None,
                )
                if segment_key in seen:
                    continue
                seen.add(segment_key)
                relation_type = relationship["relation_type"]
                result.append(
                    {
                        **relationship,
                        "relationship_valid_from_ns": relationship.get(
                            "valid_from_ns"
                        ),
                        "relationship_valid_to_ns": relationship.get(
                            "valid_to_ns"
                        ),
                        "relationship_start_event_uid": relationship.get(
                            "start_event_uid"
                        ),
                        "relationship_end_event_uid": relationship.get(
                            "end_event_uid"
                        ),
                        "valid_from_ns": start_ns,
                        "valid_to_ns": end_ns,
                        "start_ns": start_ns,
                        "end_ns": end_ns,
                        "start_event_uid": effective_start[1],
                        "end_event_uid": effective_end[1],
                        "effective_start_source": effective_start[2],
                        "effective_end_source": effective_end[2],
                        "duration_ns": _interval_duration(start_ns, end_ns),
                        "descriptor": descriptors.get(relation_type),
                    }
                )
    result.sort(
        key=lambda item: (
            item["relation_type"],
            item["source"],
            item["target"],
            int(item.get("valid_from_ns") or -1),
        )
    )
    return result


def _relationship_mutations_in_window(
    dataset: dict[str, Any],
    lane_ids: set[str],
    query_start_ns: int,
    query_end_ns: int,
) -> list[dict[str, Any]]:
    descriptors = {
        item["relation_type"]: item
        for item in dataset["relationship_descriptors"]
    }
    runtime = scale_runtime(dataset)
    if runtime is not None:
        candidate_map: dict[str, dict[str, Any]] = {}
        for identifier in lane_ids:
            for mutation in runtime.mutations_by_endpoint.get(identifier, []):
                key = str(
                    mutation.get(
                        "mutation_id",
                        f"{mutation['source']}|{mutation['relation_type']}|"
                        f"{mutation['target']}|{mutation['effective_time_ns']}|"
                        f"{mutation['operation']}",
                    )
                )
                candidate_map[key] = mutation
        mutation_candidates = candidate_map.values()
    else:
        mutation_candidates = dataset["relationship_mutations"]
    result = [
        {
            **item,
            "descriptor": descriptors.get(item["relation_type"]),
            "event_uid": item.get("cause_event_uid"),
        }
        for item in mutation_candidates
        if item["source"] in lane_ids
        and item["target"] in lane_ids
        and query_start_ns <= int(item["effective_time_ns"]) <= query_end_ns
    ]
    result.sort(
        key=lambda item: (
            int(item["effective_time_ns"]),
            item["relation_type"],
            item["source"],
            item["target"],
            item["operation"],
        )
    )
    return result


def _timeline_mark(
    event: dict[str, Any], resource_identifier: str, next_change_ns: int | None
) -> dict[str, Any]:
    effect = next(
        (
            item
            for item in event.get("effects", [])
            if item.get("resource_id") == resource_identifier
        ),
        {},
    )
    failed = event.get("outcome") == "failure"
    result = event.get("attributes", {}).get("result", {})
    return {
        "event_uid": event["event_uid"],
        "time_ns": str(event["timestamp_ns"]),
        "timestamp_ns": str(event["timestamp_ns"]),
        "event_type": event.get("event_type"),
        "action": event.get("action", "unknown"),
        "operation": effect.get("effect_type", event.get("action", "unknown")),
        "outcome": event.get("outcome", "unknown"),
        "label": event.get("display_name", event.get("event_type", "event")),
        "failure": {"failed": failed, "status": result} if failed else None,
        "state_changed": bool(effect.get("state_changed", event.get("state_changed", not failed))),
        "effect_type": effect.get("effect_type", "none" if failed else event.get("action")),
        "duration_to_next_change_ns": (
            str(next_change_ns - int(event["timestamp_ns"]))
            if next_change_ns is not None and next_change_ns >= int(event["timestamp_ns"])
            else None
        ),
        "resource_id": resource_identifier,
        "event": event,
    }


@app.post("/v1/revisions/{revision_id}/timeline/query")
def timeline_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    start_ns = int(body.get("start_ns", dataset["demo"]["timeline_start_ns"]))
    end_ns = int(body.get("end_ns", dataset["demo"]["timeline_end_ns"]))
    if end_ns < start_ns:
        raise HTTPException(status_code=422, detail="end_ns must be >= start_ns")
    layers = set(body.get("layers") or [])
    kinds = set(body.get("kinds") or [])
    requested_id_values = [str(item) for item in body.get("resource_ids") or []]
    runtime = scale_runtime(dataset)
    if (
        runtime is not None
        and not requested_id_values
        and not body.get("allow_empty")
    ):
        requested_id_values = runtime.initial_resource_ids
    if runtime is not None and len(requested_id_values) > 100:
        raise HTTPException(
            status_code=422,
            detail="full-scale timeline queries are limited to 100 resource lanes",
        )
    requested_ids = set(requested_id_values)
    search = str(body.get("search") or "").casefold()
    if runtime is not None:
        filtered: list[dict[str, Any]] = []
        lifecycle_by_resource = runtime.lifecycle_by_resource
        state_by_resource = runtime.state_by_resource
        resource_candidates = [
            runtime.resource_by_id[identifier]
            for identifier in requested_id_values
            if identifier in runtime.resource_by_id
        ]
    else:
        filtered = events_in_range(start_ns, end_ns)
        lifecycle_by_resource: dict[str, list[dict[str, Any]]] = {}
        state_by_resource: dict[str, list[dict[str, Any]]] = {}
        for item in dataset["lifecycle_intervals"]:
            lifecycle_by_resource.setdefault(item["resource"], []).append(item)
        for item in dataset["state_intervals"]:
            state_by_resource.setdefault(item["resource"], []).append(item)
        resource_candidates = dataset["resources"]

    lanes: list[dict[str, Any]] = []
    all_marks: list[dict[str, Any]] = []
    for order, resource in enumerate(resource_candidates):
        identifier = resource["resource_id"]
        if layers and resource.get("layer") not in layers:
            continue
        if kinds and resource.get("kind") not in kinds:
            continue
        if requested_ids and identifier not in requested_ids:
            continue
        if search and search not in str(resource).casefold():
            continue
        lifecycles = [
            item
            for item in lifecycle_by_resource.get(identifier, [])
            if (item.get("valid_to_ns") is None or int(item["valid_to_ns"]) >= start_ns)
            and (item.get("valid_from_ns") is None or int(item["valid_from_ns"]) <= end_ns)
        ]
        statuses = [
            item
            for item in state_by_resource.get(identifier, [])
            if (item.get("valid_to_ns") is None or int(item["valid_to_ns"]) >= start_ns)
            and (item.get("valid_from_ns") is None or int(item["valid_from_ns"]) <= end_ns)
        ]
        if runtime is not None:
            resource_events = [
                item
                for item in runtime.events_by_resource.get(identifier, [])
                if start_ns <= int(item["timestamp_ns"]) <= end_ns
            ]
        else:
            resource_events = [
                item
                for item in filtered
                if identifier in _event_resource_ids(item)
            ]
        if body.get("only_with_activity") and not (lifecycles or statuses or resource_events):
            continue
        change_times = sorted(
            int(item["valid_from_ns"])
            for item in state_by_resource.get(identifier, [])
            if item.get("valid_from_ns") is not None
        )
        marks = []
        for event in resource_events:
            next_change = next(
                (time for time in change_times if time > int(event["timestamp_ns"])),
                None,
            )
            mark = _timeline_mark(event, identifier, next_change)
            marks.append(mark)
            all_marks.append(mark)
        lifecycle_payload = [
            {
                **item,
                "start_ns": item.get("valid_from_ns"),
                "end_ns": item.get("valid_to_ns"),
                "duration_ns": _interval_duration(item.get("valid_from_ns"), item.get("valid_to_ns")),
                "open_start": item.get("valid_from_ns") is None,
                "open_end": item.get("valid_to_ns") is None,
            }
            for item in lifecycles
        ]
        status_payload = [
            {
                **item,
                "start_ns": item.get("valid_from_ns"),
                "end_ns": item.get("valid_to_ns"),
                "duration_ns": _interval_duration(item.get("valid_from_ns"), item.get("valid_to_ns")),
                "start_event_uid": item.get("start_event_uid", item.get("cause_event_uid")),
            }
            for item in statuses
        ]
        lanes.append(
            {
                "lane_id": identifier,
                "resource_id": identifier,
                "order": order,
                "layer": resource.get("layer", "unknown"),
                "kind": resource.get("kind", "UNKNOWN"),
                "label": resource.get("label", _label_of(identifier)),
                "resource": resource,
                "lifecycle_intervals": lifecycle_payload,
                "status_intervals": status_payload,
                "event_marks": marks,
                "events": resource_events,
            }
        )

    cluster_window_ns = int(body.get("cluster_window_ns", 20_000_000))
    clusters: list[dict[str, Any]] = []
    for lane in lanes:
        marks = sorted(lane["event_marks"], key=lambda item: int(item["time_ns"]))
        groups: list[list[dict[str, Any]]] = []
        for mark in marks:
            if groups and int(mark["time_ns"]) - int(groups[-1][-1]["time_ns"]) <= cluster_window_ns:
                groups[-1].append(mark)
            else:
                groups.append([mark])
        for index, group in enumerate(groups):
            if len(group) < 2:
                continue
            clusters.append(
                {
                    "cluster_id": f"{lane['lane_id']}::{index}",
                    "lane_id": lane["lane_id"],
                    "start_ns": group[0]["time_ns"],
                    "end_ns": group[-1]["time_ns"],
                    "count": len(group),
                    "failure_count": sum(item["outcome"] == "failure" for item in group),
                    "event_uids": [item["event_uid"] for item in group],
                    "items": group,
                    "scrollable": True,
                }
            )
    lane_ids = {lane["resource_id"] for lane in lanes}
    relationship_intervals = _effective_relationship_intervals(
        dataset,
        lane_ids,
        start_ns,
        end_ns,
    )
    relationship_mutations = _relationship_mutations_in_window(
        dataset,
        lane_ids,
        start_ns,
        end_ns,
    )
    cursor_time_ns = body.get("cursor_time_ns")
    if cursor_time_ns is not None:
        cursor_time_ns = str(cursor_time_ns)
    selected_range = body.get("range")
    if isinstance(selected_range, dict):
        selected_range = {
            key: str(value) if key.endswith("_ns") and value is not None else value
            for key, value in selected_range.items()
        }
    known_source_types = {
        str(item["source_type"])
        for item in dataset.get("source_record_descriptors", [])
        if item.get("source_type")
    }
    try:
        record_lanes = record_lanes_for_window(
            dataset.get("source_records", []),
            body.get("record_lane_rules") or [],
            start_ns=start_ns,
            end_ns=end_ns,
            known_source_types=known_source_types,
            max_marks=int(body.get("max_record_marks", 5_000)),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "revision_id": revision_id,
        "start_ns": str(start_ns),
        "end_ns": str(end_ns),
        "lanes": lanes,
        "clusters": clusters,
        "record_lanes": record_lanes,
        "record_lane_count": len(record_lanes),
        "relationship_intervals": relationship_intervals,
        "relationship_interval_count": len(relationship_intervals),
        "relationship_mutations": relationship_mutations,
        "relationship_mutation_count": len(relationship_mutations),
        "relationship_type_descriptors": dataset["relationship_descriptors"],
        "relationship_descriptors": dataset["relationship_descriptors"],
        "event_count": len({item["event_uid"] for item in all_marks}),
        "mark_count": len(all_marks),
        "aggregation": "resource-lanes-with-time-window-clusters",
        "selection": {
            "cursor_time_ns": cursor_time_ns,
            "selected_event_uid": body.get("selected_event_uid"),
            "range": selected_range,
            "independent_controls": True,
        },
    }


@app.post("/v1/revisions/{revision_id}/range/summary")
def selected_range_summary(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    start_ns = int(body.get("start_ns", dataset["demo"]["timeline_start_ns"]))
    end_ns = int(body.get("end_ns", dataset["demo"]["timeline_end_ns"]))
    if end_ns < start_ns:
        raise HTTPException(status_code=422, detail="end_ns must be >= start_ns")
    return range_summary(start_ns, end_ns)


@app.post("/v1/revisions/{revision_id}/graph/query")
def graph_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    return _correlation_payload(body)


@app.post("/v1/revisions/{revision_id}/correlations/query")
def correlation_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Return the typed relationship subgraph at one selected moment."""

    _require_revision(revision_id)
    return _correlation_payload(body)


@app.get("/v1/revisions/{revision_id}/consistency-findings")
def consistency_findings(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    items = load_demo_dataset()["findings"]
    return {"items": items, "count": len(items), "next_cursor": None}


@app.post("/v1/revisions/{revision_id}/routes/resolve")
def resolve_route(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_demo_dataset()
    basis = body.get("basis_kind", "observed_capture_vector")
    destination = body.get("destination", "203.0.113.42")
    if destination != "203.0.113.42" or basis not in dataset["routes"]:
        raise HTTPException(
            status_code=422,
            detail=(
                "This review demo only has precomputed responses for "
                "203.0.113.42 in observed and reconstructed modes."
            ),
        )
    response = dict(dataset["routes"][basis])
    response["demo_precomputed"] = True
    return response


@app.get("/v1/revisions/{revision_id}/inventory")
def inventory(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    return load_demo_dataset()["inventory"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Router State Lab demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument(
        "--fixture-archive",
        type=Path,
        help=(
            "Trusted local outer TGZ containing the embedded review projection "
            "and nested container dumps"
        ),
    )
    parser.add_argument(
        "--full-scale",
        action="store_true",
        help=(
            "Load all normalized events, resources, relationships, and mutations "
            "from the packed 100K fixture instead of its review projection"
        ),
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the demo in the default browser after the server starts",
    )
    args = parser.parse_args()
    if args.fixture_archive is not None:
        configure_demo_archive(args.fixture_archive)
    configure_demo_scale(args.full_scale)
    _client_demo_json.cache_clear()
    url = f"http://{args.host}:{args.port}"
    if args.open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
