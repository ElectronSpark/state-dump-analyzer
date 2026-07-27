"""Configure one reusable generated assembly for app-dependent tests."""

from __future__ import annotations

import atexit
import copy
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Iterator

from fastapi.testclient import TestClient

from router_dump_analyzer.runtime import (
    CoreRuntimeSession,
    RuntimeApplicationRequest,
    create_runtime_application,
)
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.web.runtime_context import activate_runtime_session
from rsl_demo_generator import (
    DEMO_NODES,
    AssemblyConfig,
    build_demo_fixture,
)
from rsl_demo_plugin import plugin as demo_plugin


_LOCK = Lock()
_TEMPORARY: tempfile.TemporaryDirectory[str] | None = None
_ARCHIVE: Path | None = None


def configure_generated_demo_for_tests() -> Path:
    """Generate once and select the sole 10-node demo assembly."""

    global _TEMPORARY, _ARCHIVE
    with _LOCK:
        if _ARCHIVE is None:
            _TEMPORARY = tempfile.TemporaryDirectory()
            root = Path(_TEMPORARY.name)
            os.environ.setdefault(
                "ROUTER_DUMP_SEARCH_CACHE_DIR",
                str(root / "search-cache"),
            )
            _ARCHIVE = build_demo_fixture(
                root / "router-state-lab-test-demo.tgz",
                config=AssemblyConfig(
                    nodes=DEMO_NODES,
                    events_per_node=120,
                    resources_per_node=120,
                    seed=20_260_725,
                    allow_small=True,
                    assembly_id="demo.fabric.multi-node",
                ),
            )
        archive = _ARCHIVE

    return archive


def generated_demo_application(
    input_path: Path | None = None,
) -> Any:
    """Create the core application over the example plug-in and one archive."""

    archive = (
        configure_generated_demo_for_tests()
        if input_path is None
        else Path(input_path)
    )
    return create_runtime_application(
        RuntimeApplicationRequest(
            runtime=demo_plugin.runtime,
            input_path=archive,
        )
    )


def generated_demo_client(
    input_path: Path | None = None,
) -> TestClient:
    """Return a client context for the core-owned generated-demo application."""

    return TestClient(generated_demo_application(input_path))


@contextmanager
def generated_demo_runtime_session(
    input_path: Path | None = None,
) -> Iterator[Any]:
    """Open and bind a generated-demo session for direct core service tests."""

    archive = (
        configure_generated_demo_for_tests()
        if input_path is None
        else Path(input_path)
    )
    with demo_plugin.runtime.open(archive) as plugin_session:
        session = CoreRuntimeSession(
            plugin_session=plugin_session,
            data_service=NormalizedDataService(
                plugin_session.data_source,
                plugin_session.data_policy,
            ),
        )
        with activate_runtime_session(session):
            yield session


def query_all_route_table_rows(
    client: Any,
    query: dict[str, Any] | None = None,
    *,
    page_limit: int = 500,
) -> dict[str, Any]:
    """Follow the public cursor contract and return one combined test view."""

    request = copy.deepcopy(query or {})
    request.pop("page", None)
    items: list[dict[str, Any]] = []
    first_payload: dict[str, Any] | None = None
    cursor: str | None = None

    while True:
        page_request = copy.deepcopy(request)
        page_request["page"] = {"limit": page_limit}
        if cursor is not None:
            page_request["page"]["cursor"] = cursor
        response = client.post(
            "/v1/topologies/routes/tables/query",
            json=page_request,
        )
        response.raise_for_status()
        payload = response.json()
        if first_payload is None:
            first_payload = payload
        items.extend(payload["items"])
        if not payload["page"]["truncated"]:
            break
        cursor = payload["page"]["next_cursor"]

    assert first_payload is not None
    return {
        **first_payload,
        "items": items,
        "counts": {
            **first_payload["counts"],
            "returned": len(items),
        },
        "page": {
            **payload["page"],
            "truncated": False,
            "next_cursor": None,
        },
    }


def _cleanup() -> None:
    global _TEMPORARY, _ARCHIVE
    if _TEMPORARY is not None:
        _TEMPORARY.cleanup()
    _TEMPORARY = None
    _ARCHIVE = None


atexit.register(_cleanup)
