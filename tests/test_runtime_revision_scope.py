from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Mapping

from fastapi.testclient import TestClient

from router_dump_analyzer.revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
)
from router_dump_analyzer.runtime import (
    PLUGIN_RUNTIME_CAPABILITY_ID,
    RuntimeApplicationRequest,
    create_runtime_application,
)
from tests.support.normalized_data import StaticDataPolicy


class _RevisionStore:
    def __init__(self) -> None:
        self._descriptors = {
            revision_id: RevisionDescriptor(
                node_id=node_id,
                revision_id=revision_id,
                label=revision_id,
                event_count=0,
                resource_count=0,
            )
            for node_id, revision_id in (
                ("node-a", "a"),
                ("node-nested", "a/inventory"),
            )
        }
        self.assembly = AssemblyDescriptor(
            assembly_id="revision-scope-test",
            revisions=tuple(self._descriptors.values()),
        )
        self.default_revision_id = "a"

    def revision(self, revision_id: str) -> RevisionDescriptor:
        try:
            return self._descriptors[revision_id]
        except KeyError:
            raise KeyError(revision_id) from None

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        for descriptor in self._descriptors.values():
            if descriptor.node_id == node_id:
                return descriptor
        raise KeyError(node_id)

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        self.revision(revision_id)
        return _dataset(revision_id)

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        return self.dataset_for_revision(
            self.revision_for_node(node_id).revision_id
        )

    def loaded_revision_ids(self) -> tuple[str, ...]:
        return tuple(self._descriptors)


def _dataset(revision_id: str) -> dict[str, Any]:
    return {
        "workspace": {"revision_id": revision_id},
        "inventory": {"selected_revision_id": revision_id},
        "events": [],
        "resources": [],
        "relationships": [],
        "state_intervals": {},
        "lifecycle_intervals": {},
    }


class _RevisionSource:
    def __init__(self, store: _RevisionStore) -> None:
        self.store = store
        self.active_revision: ContextVar[str | None] = ContextVar(
            f"revision_scope_test_{id(self)}",
            default=None,
        )
        self.entered: list[str] = []

    @contextmanager
    def revision_scope(self, revision_id: str) -> Iterator[None]:
        self.store.revision(revision_id)
        token = self.active_revision.set(revision_id)
        self.entered.append(revision_id)
        try:
            yield
        finally:
            self.active_revision.reset(token)

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        del selection
        selected = (
            revision_id
            or self.active_revision.get()
            or self.store.default_revision_id
        )
        return dict(self.store.dataset_for_revision(selected))

    def revision_id(self, dataset: Mapping[str, Any]) -> str:
        return str(dataset["workspace"]["revision_id"])

    def indexed_history(self, dataset: Mapping[str, Any]) -> None:
        del dataset
        return None


class _Runtime:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    def __init__(self) -> None:
        self.store = _RevisionStore()
        self.source = _RevisionSource(self.store)

    @contextmanager
    def open(self, input_path: Path) -> Iterator[Any]:
        del input_path
        yield SimpleNamespace(
            revision_store=self.store,
            data_source=self.source,
            data_policy=StaticDataPolicy(),
            temporal_provider=None,
            topology_provider=None,
            route_provider=None,
        )


class RuntimeRevisionScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = _Runtime()
        self.application = create_runtime_application(
            RuntimeApplicationRequest(
                runtime=self.runtime,
                input_path=Path("unused"),
                serve_frontend=False,
            )
        )

    def test_router_parsed_revision_disambiguates_overlapping_slash_ids(
        self,
    ) -> None:
        with TestClient(self.application) as client:
            short = client.get("/v1/revisions/a/inventory")
            nested = client.get(
                "/v1/revisions/a/inventory/inventory"
            )

        self.assertEqual(short.status_code, 200)
        self.assertEqual(short.json()["selected_revision_id"], "a")
        self.assertEqual(nested.status_code, 200)
        self.assertEqual(
            nested.json()["selected_revision_id"],
            "a/inventory",
        )
        self.assertIsNone(self.runtime.source.active_revision.get())

    def test_revision_scope_uses_path_params_with_an_asgi_root_path(self) -> None:
        with TestClient(
            self.application,
            root_path="/router-lab",
        ) as client:
            response = client.get(
                "/v1/revisions/a/inventory/inventory"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["selected_revision_id"],
            "a/inventory",
        )

    def test_unknown_router_parsed_revision_still_returns_not_found(self) -> None:
        with TestClient(self.application) as client:
            response = client.get("/v1/revisions/missing/inventory")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "unknown node revision")

    def test_concurrent_requests_keep_revision_context_isolated(self) -> None:
        paths = [
            "/v1/revisions/a/inventory",
            "/v1/revisions/a/inventory/inventory",
        ] * 12
        with TestClient(self.application) as client:
            with ThreadPoolExecutor(max_workers=8) as executor:
                responses = list(executor.map(client.get, paths))

        selected = [
            response.json()["selected_revision_id"]
            for response in responses
        ]
        self.assertEqual(selected, ["a", "a/inventory"] * 12)
        self.assertTrue(
            all(response.status_code == 200 for response in responses)
        )
        self.assertIsNone(self.runtime.source.active_revision.get())


if __name__ == "__main__":
    unittest.main()
