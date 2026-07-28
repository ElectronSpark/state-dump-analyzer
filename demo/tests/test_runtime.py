from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import patch

DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(DEMO_ROOT))

from rsl_demo_plugin import (  # noqa: E402
    data,
    plugin,
)
from rsl_demo_plugin import session as runtime_module  # noqa: E402
from rsl_demo_plugin.session import (  # noqa: E402
    DemoDataPolicy,
    DemoDatasetSource,
    DemoTemporalProvider,
)

from router_dump_analyzer.normalized_data import (  # noqa: E402
    NormalizedDataService,
)
from router_dump_analyzer.runtime import (  # noqa: E402
    PLUGIN_RUNTIME_CAPABILITY_ID,
    PluginRuntimeSession,
    require_plugin_runtime,
    validate_runtime_session,
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

    def test_dataset_source_does_not_serialize_independent_calls(self) -> None:
        source = DemoDatasetSource(_FakeStore())
        first_started = Event()
        allow_first = Event()
        second_finished = Event()
        results: dict[str, dict[str, object]] = {}
        errors: list[BaseException] = []

        def load(
            revision_id: str | None = None,
            *,
            node_id: str | None = None,
        ) -> dict[str, object]:
            selected = revision_id or node_id or ""
            if selected == "revision-a":
                first_started.set()
                if not allow_first.wait(10):
                    raise TimeoutError("test did not release first call")
            else:
                second_finished.set()
            return {"demo": {"revision_id": selected}}

        def request(name: str, revision_id: str) -> None:
            try:
                results[name] = source.load_dataset(revision_id)
            except Exception as error:
                errors.append(error)

        with patch.object(data, "load_demo_dataset", side_effect=load):
            first = Thread(target=request, args=("first", "revision-a"))
            second = Thread(target=request, args=("second", "revision-b"))
            first.start()
            self.assertTrue(first_started.wait(10))
            second.start()
            try:
                self.assertTrue(
                    second_finished.wait(10),
                    "independent source call was serialized",
                )
            finally:
                allow_first.set()
                first.join(10)
                second.join(10)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(
            results["first"]["demo"]["revision_id"],
            "revision-a",
        )
        self.assertEqual(
            results["second"]["demo"]["revision_id"],
            "revision-b",
        )

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

    def test_temporal_services_do_not_pin_revisions_in_a_second_cache(
        self,
    ) -> None:
        source = DemoDatasetSource(_FakeStore())
        provider = DemoTemporalProvider(source)
        data_service = NormalizedDataService(source, DemoDataPolicy(source))
        dataset = {
            "resources": [],
            "events": [],
            "relationship_mutations": [],
            "demo": {"revision_id": "revision-a"},
        }
        metadata = {
            "revision_id": "revision-a",
            "timeline_start_ns": 0,
            "timeline_end_ns": 1,
            "capture_ns": 1,
            "default_node": "node-a",
        }

        with (
            patch.object(source, "load_dataset", return_value=dataset) as load,
            patch(
                "rsl_demo_plugin.temporal_contract.build_demo_plugin_contract",
                return_value={},
            ),
            patch(
                "rsl_demo_plugin.temporal_contract.build_temporal_metadata",
                return_value=metadata,
            ),
        ):
            first = provider.for_revision("revision-a", data_service)
            second = provider.for_revision("revision-a", data_service)

        self.assertIsNot(first, second)
        self.assertEqual(load.call_count, 2)
        self.assertFalse(hasattr(provider, "_services"))


if __name__ == "__main__":
    unittest.main()
