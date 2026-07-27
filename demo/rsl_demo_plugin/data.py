"""Example plug-in data-source and presentation facade.

The core owns normalized resource/event queries.  This module is intentionally
limited to opening the generated fixture through its runtime-owned store,
extracting example metadata, declaring workspace presentation, and formatting
example route/source evidence.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Mapping

from .assembly_store import DemoAssemblyStore
from .scale_data import ScaleRuntime


REVISION_ID = "demo/node-a/revision-0001"
_active_revision_id: ContextVar[str | None] = ContextVar(
    "router_dump_demo_revision_id",
    default=None,
)
_active_revision_store: ContextVar[DemoAssemblyStore | None] = ContextVar(
    "router_dump_plugin_runtime_revision_store",
    default=None,
)


def current_revision_store() -> DemoAssemblyStore:
    """Return the fixture store bound by the active plug-in runtime."""

    store = _active_revision_store.get()
    if store is None:
        raise RuntimeError(
            "No plug-in runtime input is active. Start the core with "
            "`router-dump-analyzer --plugin demo_router "
            "--input <archive>`; the core opens input through plugin.runtime."
        )
    return store


@contextmanager
def revision_store_scope(store: DemoAssemblyStore):
    """Bind one runtime-owned fixture store to the current request/task."""

    token = _active_revision_store.set(store)
    try:
        yield
    finally:
        _active_revision_store.reset(token)


@contextmanager
def demo_revision_scope(revision_id: str):
    """Select one revision for helpers called inside a request/task context."""

    token = _active_revision_id.set(revision_id)
    try:
        yield
    finally:
        _active_revision_id.reset(token)


DEMO_GAPS = [
    {
        "id": "ingestion",
        "area": "Ingestion",
        "title": "Upload and safe nested-archive extraction",
        "status": "missing",
        "detail": (
            "The server loads only the trusted assembly emitted by the demo "
            "generator. Arbitrary upload and admission of untrusted archives "
            "are not implemented."
        ),
    },
    {
        "id": "ctf",
        "area": "Decoding",
        "title": "Production Babeltrace/CTF decoding worker",
        "status": "fixture-only",
        "detail": (
            "The demo serves generated normalized records; production CTF "
            "decoding remains isolated work."
        ),
    },
    {
        "id": "plugins",
        "area": "Extensibility",
        "title": "Third-party plugin discovery and sandboxing",
        "status": "demo-only",
        "detail": (
            "The comprehensive corpus is synthesized offline by the installed "
            "example plug-in's fixture policy. Runtime validates and loads its "
            "immutable precomputed projections without replaying the tiny "
            "conformance parser; production discovery and sandboxing remain "
            "unimplemented."
        ),
    },
    {
        "id": "reconstruction",
        "area": "Temporal model",
        "title": "Runtime reconstruction from arbitrary dumps",
        "status": "fixture-only",
        "detail": (
            "Intervals are deterministic generated expectations, not "
            "reconstructed during the request."
        ),
    },
    {
        "id": "routing",
        "area": "Forwarding",
        "title": "Production forwarding coordination",
        "status": "demo-only",
        "detail": (
            "The demo scenario evaluator executes its advertised IP, MPLS, SR, "
            "VPN, recursion, and policy cases. Coordinating arbitrary "
            "plugin-resolved production tables remains future work."
        ),
    },
    {
        "id": "source-context",
        "area": "Evidence",
        "title": "Jump to decoded source context",
        "status": "missing",
        "detail": (
            "Evidence locators are returned, but raw bytes cannot yet be "
            "opened in context."
        ),
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
        "title": "100K+-event generated assembly",
        "status": "implemented",
        "detail": (
            "The single demo generator emits at least 100K events and "
            "5K-10K resources per node for the same browser and API paths."
        ),
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
    "Do these directional Forwarding Group, ETG, ETE and DTE correlations "
    "match the product model?",
    "Which plugin-defined status fields should drive lane color for each kind?",
    "Should Glue use a compact connector rendering everywhere or only in "
    "correlation views?",
    "Which raw evidence must be reachable from an event, interval, or "
    "relationship?",
    "Which endpoint-diff and event aggregates are most useful for a selected "
    "range?",
]


def load_demo_dataset(
    revision_id: str | None = None,
    *,
    node_id: str | None = None,
) -> dict[str, Any]:
    """Load one exact node revision from the runtime-owned fixture store."""

    if revision_id is not None and node_id is not None:
        raise ValueError("choose revision_id or node_id, not both")
    store = current_revision_store()
    selected_revision = revision_id or _active_revision_id.get()
    if node_id is not None:
        return store.dataset_for_node(node_id)
    if selected_revision is not None:
        return store.dataset_for_revision(selected_revision)
    return store.dataset_for_revision(store.default_revision_id)


def scale_runtime(dataset: Mapping[str, Any] | None = None) -> ScaleRuntime | None:
    """Return the example fixture's optional generic indexed-history object."""

    candidate = (dataset or load_demo_dataset()).get("_scale_runtime")
    return candidate if isinstance(candidate, ScaleRuntime) else None


def dataset_revision_id(dataset: Mapping[str, Any] | None = None) -> str:
    """Extract the revision identity declared by this fixture format."""

    active = dataset or load_demo_dataset()
    metadata = active.get("demo")
    if not isinstance(metadata, Mapping) or not metadata.get("revision_id"):
        raise RuntimeError("normalized example dataset lacks a revision identity")
    return str(metadata["revision_id"])


def analysis_metadata(dataset: Mapping[str, Any]) -> dict[str, Any]:
    """Return opaque example analysis metadata for plug-in-owned views."""

    metadata = dataset.get("demo")
    if not isinstance(metadata, Mapping):
        raise RuntimeError("normalized example dataset lacks analysis metadata")
    return dict(metadata)


def is_scale_dataset(dataset: Mapping[str, Any] | None = None) -> bool:
    return scale_runtime(dataset) is not None


def workspace_metadata(
    dataset: Mapping[str, Any],
    *,
    revision_id: str,
    history_mode: str,
) -> dict[str, Any]:
    """Project the example fixture's node workspace for the core bootstrap."""

    metadata = analysis_metadata(dataset)
    node_id = str(metadata.get("node") or "unknown-node")
    event_count = int(
        metadata.get("event_count", len(dataset.get("events", [])))
    )
    resource_count = int(
        metadata.get("resource_count", len(dataset.get("resources", [])))
    )
    source_count = int(
        metadata.get(
            "source_record_count",
            len(dataset.get("source_records", [])),
        )
    )
    workspace = {
        "workspace_id": f"node-workspace:{revision_id}",
        "revision_id": revision_id,
        "scope": "node",
        "workspace_kind": "node",
        "history_mode": history_mode,
        "capabilities": {
            "historical_state": True,
            "server_windowed_history": history_mode == "server-windowed",
        },
        "node_id": node_id,
        "node_label": str(
            metadata.get("node_label")
            or metadata.get("label")
            or node_id
        ),
        "label": str(metadata.get("name") or node_id),
        "event_count": event_count,
        "matched_event_count": int(
            metadata.get("matched_event_count", event_count)
        ),
        "resource_count": resource_count,
        "source_record_count": source_count,
        "timeline_start_ns": str(metadata.get("timeline_start_ns")),
        "timeline_end_ns": str(metadata.get("timeline_end_ns")),
        "capture_ns": str(metadata.get("capture_ns")),
        "time_bounds": {
            "start_ns": str(metadata.get("timeline_start_ns")),
            "end_ns": str(metadata.get("timeline_end_ns")),
            "capture_ns": str(metadata.get("capture_ns")),
        },
        "scale_mode": bool(metadata.get("scale_mode", False)),
        "large_dataset": is_scale_dataset(dataset),
        "initial_resource_ids": list(
            metadata.get("initial_resource_ids") or []
        ),
        "initial_focus_resource_id": metadata.get(
            "initial_focus_resource_id"
        ),
        "disclosure": str(metadata.get("disclosure") or ""),
    }
    if metadata.get("assembly_id"):
        workspace["assembly_id"] = str(metadata["assembly_id"])
    return workspace


def route_resolution_capability(
    dataset: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Expose the exact plug-in-declared routes for one node revision."""

    active = dataset or load_demo_dataset()
    metadata = active.get("demo")
    if not isinstance(metadata, Mapping):
        return {"available": False, "routes": []}
    node_id = str(metadata.get("node") or "")
    revision_id = str(metadata.get("revision_id") or "")
    if not node_id or not revision_id:
        return {"available": False, "routes": []}
    store = current_revision_store()
    try:
        descriptor = store.revision_for_node(node_id)
        projection = store.projection_for_node(node_id)
    except KeyError:
        return {"available": False, "routes": []}
    if descriptor.revision_id != revision_id:
        return {"available": False, "routes": []}
    coverage_labels = {
        str(item.get("case_id")): str(
            item.get("title") or item.get("case_id")
        )
        for item in store.coverage.get("cases", [])
        if isinstance(item, Mapping) and item.get("case_id")
    }
    routes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in projection.get("routes", []):
        if not isinstance(row, Mapping):
            continue
        route_id = str(row.get("route_id") or "")
        destination = str(row.get("destination") or "")
        if (
            not route_id
            or not destination
            or route_id in seen
            or str(row.get("node_id") or "") != node_id
            or str(row.get("revision_id") or "") != revision_id
        ):
            continue
        seen.add(route_id)
        scenario_id = (
            str(row["scenario_id"]) if row.get("scenario_id") else None
        )
        routes.append(
            {
                "route_id": route_id,
                "label": coverage_labels.get(scenario_id or "")
                or destination,
                "destination": destination,
                "scenario_id": scenario_id,
                "route_type": row.get("route_type"),
                "route_family": row.get("route_family"),
                "address_family": row.get("address_family"),
                "vrf": row.get("vrf"),
                "decision": row.get("decision"),
                "observed_at_ns": row.get("observed_at_ns"),
            }
        )
    routes.sort(
        key=lambda item: (
            item["scenario_id"] is None,
            str(item["label"]),
            str(item["route_id"]),
        )
    )
    manifest = projection.get("manifest")
    provider = (
        {
            "plugin_id": manifest.get("plugin_id"),
            "plugin_version": manifest.get("plugin_version"),
        }
        if isinstance(manifest, Mapping)
        else {}
    )
    return {
        "available": bool(routes),
        "plugin_defined": True,
        "scope": "node",
        "node_id": node_id,
        "revision_id": revision_id,
        "provider": provider,
        "routes": routes,
        "basis_kinds": [
            {
                "basis_kind": "observed_capture_vector",
                "label": "Observed plug-in projection",
            }
        ],
        "default_route_id": routes[0]["route_id"] if routes else None,
        "default_basis_kind": (
            "observed_capture_vector" if routes else None
        ),
    }


def generated_route_row(
    route_id: str,
    dataset: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return one exact generated node-local route projection row."""

    capability = route_resolution_capability(dataset)
    declared_ids = {
        str(item["route_id"]) for item in capability.get("routes", [])
    }
    if route_id not in declared_ids:
        raise KeyError(route_id)
    projection = current_revision_store().projection_for_node(
        str(capability["node_id"])
    )
    matches = [
        dict(item)
        for item in projection.get("routes", [])
        if isinstance(item, Mapping)
        and str(item.get("route_id") or "") == route_id
    ]
    if len(matches) != 1:
        raise KeyError(route_id)
    return matches[0]
