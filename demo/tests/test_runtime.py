from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(DEMO_ROOT))

from router_dump_analyzer.runtime import (  # noqa: E402
    PLUGIN_RUNTIME_CAPABILITY_ID,
    PluginRuntimeSession,
    require_plugin_runtime,
    validate_runtime_session,
)
from router_dump_analyzer.normalized_data import (  # noqa: E402
    NormalizedDataService,
)
from rsl_demo_plugin import data  # noqa: E402
from rsl_demo_plugin import session as runtime_module  # noqa: E402
from rsl_demo_plugin import plugin  # noqa: E402
from rsl_demo_plugin.session import (  # noqa: E402
    DemoDataPolicy,
    DemoDatasetSource,
)


class _FakeStore:
    default_revision_id = "revision-a"
    assembly = SimpleNamespace(revisions=())

    def __init__(self) -> None:
        self.close_count = 0
        self.revision_requests: list[str] = []

    def revision(self, revision_id: str) -> SimpleNamespace:
        self.revision_requests.append(revision_id)
        if revision_id != "revision-a":
            raise KeyError(revision_id)
        return SimpleNamespace(revision_id=revision_id)

    def revision_for_node(self, node_id: str) -> SimpleNamespace:
        if node_id != "node-a":
            raise KeyError(node_id)
        return SimpleNamespace(
            node_id=node_id,
            revision_id=self.default_revision_id,
        )

    def dataset_for_revision(self, revision_id: str) -> dict[str, object]:
        self.revision(revision_id)
        return {"demo": {"revision_id": revision_id}}

    def dataset_for_node(self, node_id: str) -> dict[str, object]:
        descriptor = self.revision_for_node(node_id)
        return self.dataset_for_revision(descriptor.revision_id)

    def loaded_revision_ids(self) -> tuple[str, ...]:
        return ()

    def close(self) -> None:
        self.close_count += 1


class DemoRuntimeTests(unittest.TestCase):
    def test_installed_plugin_exposes_non_web_runtime_contract(self) -> None:
        capability = require_plugin_runtime(plugin)

        self.assertEqual(
            capability.capability_id,
            PLUGIN_RUNTIME_CAPABILITY_ID,
        )
        source = Path(runtime_module.__file__).read_text(encoding="utf-8")
        for forbidden in ("FastAPI", "APIRouter", "uvicorn", "create_web_app"):
            self.assertNotIn(forbidden, source)

    def test_runtime_context_owns_and_closes_fixture_once(self) -> None:
        store = _FakeStore()
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            with patch.object(
                runtime_module,
                "DemoAssemblyStore",
                return_value=store,
            ) as constructor:
                with require_plugin_runtime(plugin).open(fixture) as session:
                    self.assertIsInstance(session, PluginRuntimeSession)
                    self.assertIs(validate_runtime_session(session), session)
                    self.assertIs(session.revision_store, store)
                    self.assertIs(
                        session.data_source.revision_store,
                        store,
                    )
                    self.assertEqual(
                        session.topology_provider.topology_id,
                        "demo.fabric.multi-node",
                    )
                    self.assertEqual(store.close_count, 0)

                self.assertEqual(store.close_count, 1)
                session.close()
                self.assertEqual(store.close_count, 1)

        constructor.assert_called_once_with(
            fixture,
            cache_size=2,
            dataset_loader=runtime_module._load_generated_revision,
        )

    def test_dataset_source_binds_store_and_revision_by_context(self) -> None:
        store = _FakeStore()
        source = DemoDatasetSource(store)
        observed: list[tuple[object, str | None]] = []

        def load(
            revision_id: str | None = None,
            *,
            node_id: str | None = None,
        ) -> dict[str, object]:
            observed.append(
                (
                    data.current_revision_store(),
                    revision_id
                    or node_id
                    or data._active_revision_id.get(),
                )
            )
            return {
                "demo": {
                    "revision_id": revision_id
                    or node_id
                    or data._active_revision_id.get()
                    or store.default_revision_id,
                    "capture_ns": 1,
                }
            }

        with patch.object(data, "load_demo_dataset", side_effect=load):
            self.assertEqual(
                source.load_dataset("revision-a")["demo"]["revision_id"],
                "revision-a",
            )
            self.assertEqual(
                source.load_dataset(node_id="node-a")["demo"]["revision_id"],
                "node-a",
            )
            with source.revision_scope("revision-a"):
                self.assertEqual(
                    source.load_dataset()["demo"]["revision_id"],
                    "revision-a",
                )

        self.assertEqual(
            observed,
            [
                (store, "revision-a"),
                (store, "node-a"),
                (store, "revision-a"),
            ],
        )
        self.assertIsNone(data._active_revision_id.get())
        self.assertIsNone(data._active_revision_store.get())
        self.assertEqual(store.revision_requests, ["revision-a"])

    def test_core_service_owns_generic_queries(self) -> None:
        source = DemoDatasetSource(_FakeStore())
        policy = DemoDataPolicy(source)
        service = NormalizedDataService(source, policy)
        dataset = {
            "demo": {
                "revision_id": "revision-a",
                "capture_ns": 17,
                "timeline_start_ns": 1,
                "timeline_end_ns": 20,
            }
        }
        self.assertEqual(policy.analysis_metadata(dataset)["capture_ns"], 17)
        for forbidden in (
            "client_dataset",
            "resource_state_at",
            "relationships_at",
            "resources_at",
            "events_in_range",
            "dashboard_query",
            "range_summary",
            "redact_event_for_client",
        ):
            self.assertFalse(
                hasattr(source, forbidden),
                f"plug-in source must not own core query {forbidden}",
            )
        for method_name in (
            "load_dataset",
            "client_dataset",
            "revision_scope",
            "current_revision_id",
            "history_runtime",
            "has_indexed_history",
            "route_resolution_capability",
            "route_row",
            "resource_state_at",
            "relationships_at",
            "resources_at",
            "events_in_range",
            "dashboard_query",
            "range_summary",
            "redact_event_for_client",
            "event_redaction_policy",
            "redact_resource_for_client",
            "redact_resource_view",
            "source_record_for_event",
        ):
            self.assertTrue(callable(getattr(service, method_name)))


if __name__ == "__main__":
    unittest.main()
