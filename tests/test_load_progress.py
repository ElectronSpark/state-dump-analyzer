from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.history_search_core import HistorySearchCapacityError
from router_dump_analyzer.load_progress import (
    AnalysisLoadOperation,
    AnalysisLoadStage,
    AnalysisLoadState,
    AnalysisLoadTracker,
    report_analysis_load,
)
from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.multi_node_topology import MultiNodeTopologyService
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS
from router_dump_analyzer.revision_queries import RevisionQueryService
from router_dump_analyzer.runtime import CoreRuntimeSession
from router_dump_analyzer.web.runtime_api import (
    _active_topology_assembly_id,
    _multi_node_route,
    _multi_node_topology,
    _require_revision,
    _RuntimeHTTPResponse,
    analysis_health_projection,
    node_workspace_dataset,
    start_runtime_warmup,
)
from router_dump_analyzer.web.runtime_context import activate_runtime_session
from router_dump_analyzer.web.service_api import service_router
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource


class _FailingSource(StaticDatasetSource):
    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        del revision_id, selection
        raise RuntimeError(r"failed at C:\private\router-state.tgz")


class _ProcessControlSource(StaticDatasetSource):
    def __init__(self, interruption: BaseException) -> None:
        super().__init__({})
        self.interruption = interruption

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        del revision_id, selection
        raise self.interruption


class _ReportingTopologyProvider:
    topology_id = "test-topology"

    def get(self) -> MultiNodeTopologyService:
        report_analysis_load(
            AnalysisLoadStage.PARSING,
            completed=2,
            total=3,
            records_processed=2,
        )
        return object.__new__(MultiNodeTopologyService)


class _ReportingRouteProvider:
    def get(self) -> MultiNodeRouteService:
        report_analysis_load(
            AnalysisLoadStage.PARSING,
            completed=3,
            total=3,
            records_processed=3,
        )
        return object.__new__(MultiNodeRouteService)


class _HealthTrackingSource(StaticDatasetSource):
    def __init__(
        self,
        dataset: dict[str, Any],
        tracker: AnalysisLoadTracker,
        loaded: dict[str, bool],
    ) -> None:
        super().__init__(dataset)
        self._tracker = tracker
        self._loaded = loaded
        self.observed = None

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        self.observed = self._tracker.snapshot()
        self._loaded["value"] = True
        return super().load_dataset(revision_id, **selection)


class _HealthRevisionStore:
    def __init__(
        self,
        loaded: dict[str, bool],
        tracker: AnalysisLoadTracker,
    ) -> None:
        self._loaded = loaded
        self._tracker = tracker
        self.observations: list[Any] = []

    def _observe(self) -> None:
        self.observations.append(self._tracker.snapshot())
        self._loaded["value"] = True

    @staticmethod
    def _revision() -> Any:
        return SimpleNamespace(
            node_id="node-a",
            revision_id="health/revision",
            label="Node A",
            event_count=3,
            resource_count=2,
        )

    @property
    def default_revision_id(self) -> str:
        raise AssertionError("health consulted the lazy store before loading")

    @property
    def assembly(self) -> Any:
        self._observe()
        return SimpleNamespace(
            assembly_id="health-assembly",
            revisions=(self._revision(),),
            coverage_case_ids=(),
        )

    def revision(self, revision_id: str) -> Any:
        self._observe()
        if revision_id != "health/revision":
            raise KeyError(revision_id)
        return self._revision()

    def revision_for_node(self, node_id: str) -> Any:
        self._observe()
        if node_id != "node-a":
            raise KeyError(node_id)
        return self._revision()

    def loaded_revision_ids(self) -> tuple[str, ...]:
        self._observe()
        return ("health/revision",)


class _TrackingEventSearch:
    def __init__(
        self,
        tracker: AnalysisLoadTracker,
        *,
        capacity_error: bool = False,
    ) -> None:
        self._tracker = tracker
        self._capacity_error = capacity_error
        self.observed = None

    def query(self, search: str, documents: Any) -> tuple[int, ...]:
        del search, documents
        self.observed = self._tracker.snapshot()
        if self._capacity_error:
            raise HistorySearchCapacityError("bounded corpus exceeded")
        return ()


class AnalysisLoadProgressTests(unittest.TestCase):
    def test_tracker_exposes_immutable_json_safe_progress(self) -> None:
        tracker = AnalysisLoadTracker()
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.WAITING)

        operation = tracker.begin(
            AnalysisLoadStage.PARSING,
            completed=2,
            total=10,
            records_processed=1_024,
        )
        running = tracker.snapshot()
        self.assertEqual(running.state, AnalysisLoadState.RUNNING)
        self.assertEqual(running.completed, 2)
        self.assertEqual(running.total, 10)
        self.assertEqual(running.records_processed, 1_024)
        self.assertIsInstance(running.as_dict()["updated_at_ns"], str)

        operation.complete()
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.READY)

        with self.assertRaisesRegex(ValueError, "total is required"):
            tracker.begin(AnalysisLoadStage.PARSING, completed=1)

    def test_optional_reporter_fails_open_while_direct_updates_stay_strict(
        self,
    ) -> None:
        tracker = AnalysisLoadTracker()
        operation = tracker.begin(AnalysisLoadStage.PARSING)
        with operation.bind():
            report_analysis_load(  # type: ignore[arg-type]
                "plug-in-owned-stage",
                completed=2,
                total=1,
            )
        self.assertEqual(tracker.snapshot().stage, AnalysisLoadStage.PARSING)
        with self.assertRaises(TypeError):
            operation.update(cast(Any, "plug-in-owned-stage"))

    def test_optional_reporter_rethrows_native_process_control(self) -> None:
        tracker = AnalysisLoadTracker()
        operation = tracker.begin(AnalysisLoadStage.PARSING)
        for control_type in PROCESS_CONTROL_EXCEPTIONS:
            interruption = control_type("stop")
            with (
                self.subTest(control=control_type.__name__),
                operation.bind(),
                patch.object(
                    AnalysisLoadOperation,
                    "update",
                    side_effect=interruption,
                ),
                self.assertRaises(control_type) as raised,
            ):
                report_analysis_load(AnalysisLoadStage.PARSING)
            self.assertIs(raised.exception, interruption)

    def test_overlapping_failure_survives_until_the_batch_finishes(self) -> None:
        tracker = AnalysisLoadTracker()
        failed = tracker.begin(
            AnalysisLoadStage.PARSING,
            records_processed=12,
        )
        remaining = tracker.begin(AnalysisLoadStage.INDEXING)

        failed.fail("parser_failed")
        active = tracker.snapshot()
        self.assertEqual(active.state, AnalysisLoadState.RUNNING)
        self.assertEqual(active.active_operations, 1)
        self.assertEqual(active.operation_id, remaining.operation_id)
        self.assertIsNone(active.error_code)

        remaining.complete()
        completed = tracker.snapshot()
        self.assertEqual(completed.state, AnalysisLoadState.FAILED)
        self.assertEqual(completed.active_operations, 0)
        self.assertEqual(completed.operation_id, failed.operation_id)
        self.assertEqual(completed.stage, AnalysisLoadStage.PARSING)
        self.assertEqual(completed.records_processed, 12)
        self.assertEqual(completed.error_code, "parser_failed")

    def test_new_non_overlapping_batch_clears_the_prior_batch_failure(self) -> None:
        tracker = AnalysisLoadTracker()
        failed = tracker.begin(AnalysisLoadStage.PARSING)
        overlapping = tracker.begin(AnalysisLoadStage.INDEXING)
        failed.fail("parser_failed")
        overlapping.complete()
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.FAILED)

        retry = tracker.begin(AnalysisLoadStage.LOADING_REVISION)
        retry_running = tracker.snapshot()
        self.assertEqual(retry_running.state, AnalysisLoadState.RUNNING)
        self.assertIsNone(retry_running.error_code)
        retry.complete()
        retry_complete = tracker.snapshot()
        self.assertEqual(retry_complete.state, AnalysisLoadState.READY)
        self.assertIsNone(retry_complete.error_code)

    def test_invalid_failure_code_does_not_close_or_orphan_operation(self) -> None:
        tracker = AnalysisLoadTracker()
        operation = tracker.begin(AnalysisLoadStage.PARSING)

        with self.assertRaisesRegex(ValueError, "error_code is invalid"):
            operation.fail("INVALID-CODE")
        still_active = tracker.snapshot()
        self.assertEqual(still_active.state, AnalysisLoadState.RUNNING)
        self.assertEqual(still_active.active_operations, 1)
        self.assertEqual(still_active.operation_id, operation.operation_id)

        operation.update(
            AnalysisLoadStage.PARSING,
            records_processed=1,
        )
        operation.fail("parser_failed")
        finished = tracker.snapshot()
        self.assertEqual(finished.state, AnalysisLoadState.FAILED)
        self.assertEqual(finished.active_operations, 0)
        self.assertEqual(finished.records_processed, 1)
        self.assertEqual(finished.error_code, "parser_failed")

    def test_service_endpoint_is_non_cacheable_and_total(self) -> None:
        application = FastAPI()
        application.include_router(service_router)
        application.state.analysis_load_tracker = AnalysisLoadTracker()
        with TestClient(application) as client:
            response = client.get("/v1/analysis-load")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.json()["state"], "waiting")

            application.state.analysis_load_tracker = object()
            failed = client.get("/v1/analysis-load")
            self.assertEqual(failed.status_code, 200)
            self.assertEqual(failed.json()["state"], "failed")
            self.assertEqual(
                failed.json()["error_code"],
                "progress_observation_failed",
            )

    def test_multi_node_provider_materialization_is_tracked(self) -> None:
        tracker = AnalysisLoadTracker()
        service = NormalizedDataService(
            StaticDatasetSource({}),
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        plugin_session = SimpleNamespace(
            topology_provider=_ReportingTopologyProvider(),
            route_provider=_ReportingRouteProvider(),
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, plugin_session),
            data_service=service,
        )

        with activate_runtime_session(session):
            self.assertIsInstance(_multi_node_topology(), MultiNodeTopologyService)
        topology = tracker.snapshot()
        self.assertEqual(topology.state, AnalysisLoadState.READY)
        self.assertEqual(topology.stage, AnalysisLoadStage.PARSING)
        self.assertEqual(topology.records_processed, 2)

        with activate_runtime_session(session):
            self.assertIsInstance(_multi_node_route(), MultiNodeRouteService)
        route = tracker.snapshot()
        self.assertEqual(route.state, AnalysisLoadState.READY)
        self.assertEqual(route.stage, AnalysisLoadStage.PARSING)
        self.assertEqual(route.records_processed, 3)

    def test_health_loads_lazy_revision_inside_progress_operation(self) -> None:
        tracker = AnalysisLoadTracker()
        loaded = {"value": False}
        source = _HealthTrackingSource(
            {
                "workspace": {"revision_id": "health/revision"},
                "demo": {
                    "event_count": 3,
                    "resource_count": 2,
                    "source_record_count": 0,
                },
            },
            tracker,
            loaded,
        )
        service = NormalizedDataService(
            source,
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        store = _HealthRevisionStore(loaded, tracker)
        plugin_session = SimpleNamespace(
            revision_store=store,
            temporal_provider=None,
            topology_provider=None,
            route_provider=None,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, plugin_session),
            data_service=service,
        )

        with activate_runtime_session(session):
            projection = analysis_health_projection()

        self.assertTrue(projection["analysis_ready"])
        self.assertIsNotNone(source.observed)
        self.assertEqual(source.observed.state, AnalysisLoadState.RUNNING)
        self.assertEqual(
            source.observed.stage,
            AnalysisLoadStage.LOADING_REVISION,
        )
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.READY)
        self.assertTrue(store.observations)
        self.assertTrue(
            all(item.state is AnalysisLoadState.RUNNING for item in store.observations)
        )

    def test_node_workspace_cold_load_is_tracked_before_store_lookup(self) -> None:
        tracker = AnalysisLoadTracker()
        loaded = {"value": False}
        source = _HealthTrackingSource(
            {
                "workspace": {"revision_id": "health/revision"},
                "demo": {"event_count": 3, "resource_count": 2},
            },
            tracker,
            loaded,
        )
        store = _HealthRevisionStore(loaded, tracker)
        service = NormalizedDataService(
            source,
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        plugin_session = SimpleNamespace(
            revision_store=store,
            temporal_provider=None,
            topology_provider=None,
            route_provider=None,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, plugin_session),
            data_service=service,
        )

        with activate_runtime_session(session):
            workspace = node_workspace_dataset(
                "node-a",
                time_ns=None,
                basis_offset_ns=None,
            )

        self.assertEqual(workspace["workspace"]["node_id"], "node-a")
        self.assertIsNotNone(source.observed)
        self.assertEqual(source.observed.state, AnalysisLoadState.RUNNING)
        self.assertTrue(store.observations)
        self.assertTrue(
            all(item.state is AnalysisLoadState.RUNNING for item in store.observations)
        )
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.READY)

    def test_revision_and_topology_store_guards_are_tracked(self) -> None:
        tracker = AnalysisLoadTracker()
        loaded = {"value": False}
        store = _HealthRevisionStore(loaded, tracker)
        service = NormalizedDataService(
            StaticDatasetSource({}),
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        plugin_session = SimpleNamespace(
            revision_store=store,
            temporal_provider=None,
            topology_provider=None,
            route_provider=None,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, plugin_session),
            data_service=service,
        )

        with activate_runtime_session(session):
            revision = _require_revision("health/revision")
            assembly_id = _active_topology_assembly_id()

        self.assertEqual(revision.revision_id, "health/revision")
        self.assertEqual(assembly_id, "health-assembly")
        self.assertGreaterEqual(len(store.observations), 2)
        self.assertTrue(
            all(item.state is AnalysisLoadState.RUNNING for item in store.observations)
        )
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.READY)

    def test_unknown_revision_and_node_do_not_poison_load_progress(self) -> None:
        tracker = AnalysisLoadTracker()
        loaded = {"value": False}
        source = _HealthTrackingSource({}, tracker, loaded)
        store = _HealthRevisionStore(loaded, tracker)
        service = NormalizedDataService(
            source,
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        plugin_session = SimpleNamespace(
            revision_store=store,
            temporal_provider=None,
            topology_provider=None,
            route_provider=None,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, plugin_session),
            data_service=service,
        )

        with activate_runtime_session(session):
            with self.assertRaises(_RuntimeHTTPResponse) as revision_error:
                _require_revision("missing/revision")
            self.assertEqual(revision_error.exception.status_code, 404)
            revision_snapshot = tracker.snapshot()
            self.assertEqual(revision_snapshot.state, AnalysisLoadState.READY)
            self.assertIsNone(revision_snapshot.error_code)

            with self.assertRaises(_RuntimeHTTPResponse) as node_error:
                node_workspace_dataset(
                    "missing-node",
                    time_ns=None,
                    basis_offset_ns=None,
                )
            self.assertEqual(node_error.exception.status_code, 404)

        terminal = tracker.snapshot()
        self.assertEqual(terminal.state, AnalysisLoadState.READY)
        self.assertIsNone(terminal.error_code)
        self.assertIsNone(source.observed)

    def test_first_event_search_build_is_tracked_as_indexing(self) -> None:
        tracker = AnalysisLoadTracker()
        service = NormalizedDataService(
            StaticDatasetSource({}),
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        event_search = _TrackingEventSearch(tracker)
        queries = RevisionQueryService(
            service, revision_id="test/revision", dataset={},
            indexed_history=SimpleNamespace(event_search=event_search, resource_by_id={}),
        )
        matches = queries.search_events("needle")

        self.assertEqual(matches, ())
        self.assertIsNotNone(event_search.observed)
        self.assertEqual(event_search.observed.state, AnalysisLoadState.RUNNING)
        self.assertEqual(event_search.observed.stage, AnalysisLoadStage.INDEXING)
        terminal = tracker.snapshot()
        self.assertEqual(terminal.state, AnalysisLoadState.READY)
        self.assertEqual(terminal.stage, AnalysisLoadStage.INDEXING)

    def test_event_search_capacity_fallback_does_not_mark_loading_failed(
        self,
    ) -> None:
        tracker = AnalysisLoadTracker()
        service = NormalizedDataService(
            StaticDatasetSource({}),
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        event_search = _TrackingEventSearch(tracker, capacity_error=True)
        queries = RevisionQueryService(
            service, revision_id="test/revision", dataset={},
            indexed_history=SimpleNamespace(event_search=event_search, resource_by_id={}),
        )
        with self.assertRaises(HistorySearchCapacityError):
            queries.search_events("needle")

        terminal = tracker.snapshot()
        self.assertEqual(terminal.state, AnalysisLoadState.READY)
        self.assertEqual(terminal.stage, AnalysisLoadStage.INDEXING)
        self.assertIsNone(terminal.error_code)

    def test_headless_warmup_provider_failure_is_tracked_and_fail_fast(self) -> None:
        tracker = AnalysisLoadTracker()
        source = _FailingSource({})
        service = NormalizedDataService(
            source,
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, object()),
            data_service=service,
        )
        stderr = io.StringIO()
        with (
            activate_runtime_session(session),
            redirect_stderr(stderr),
            self.assertRaises(RuntimeError),
        ):
            start_runtime_warmup()

        self.assertEqual(stderr.getvalue(), "")
        snapshot = tracker.snapshot()
        self.assertEqual(snapshot.state, AnalysisLoadState.FAILED)
        self.assertEqual(snapshot.error_code, "dataset_load_failed")

    def test_headless_warmup_rethrows_native_process_control(self) -> None:
        interruption = KeyboardInterrupt("stop")
        tracker = AnalysisLoadTracker()
        service = NormalizedDataService(
            _ProcessControlSource(interruption),
            StaticDataPolicy(),
            load_tracker=tracker,
        )
        session = CoreRuntimeSession(
            plugin_session=cast(Any, object()),
            data_service=service,
        )
        stderr = io.StringIO()
        with (
            activate_runtime_session(session),
            redirect_stderr(stderr),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            start_runtime_warmup()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIs(raised.exception, interruption)
        self.assertEqual(tracker.snapshot().state, AnalysisLoadState.FAILED)


if __name__ == "__main__":
    unittest.main()
