"""Real ASGI disconnects stop core read scans without cancelling other readers."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from threading import Event, Lock, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import APIRouter, FastAPI

from router_dump_analyzer.cancellation import (
    _QUERY_CANCELLED,
    current_query_cancellation_probe,
)
from router_dump_analyzer.dashboard_core import evaluate_dashboards
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.revision_queries import RevisionQueryCancellationError
from router_dump_analyzer.revision_store import RevisionDescriptor
from router_dump_analyzer.runtime import CoreRuntimeSession
from router_dump_analyzer.web.runtime_api import api_router
from router_dump_analyzer.web.runtime_context import activate_runtime_session
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource
from tests.test_revision_queries import REVISION, query_fixture


class _TrackedSource(StaticDatasetSource):
    def __init__(self, dataset, index):
        super().__init__(dataset)
        self.index = index
        self.active = 0
        self.entries = 0
        self.lock = Lock()

    def indexed_history(self, dataset):
        return self.index

    @contextmanager
    def revision_scope(self, revision_id):
        if revision_id != REVISION:
            raise KeyError(revision_id)
        with self.lock:
            self.active += 1
            self.entries += 1
        try:
            yield
        finally:
            with self.lock:
                self.active -= 1


class _HeldRows(list):
    """Hold the actual scan at a batch boundary; do not replace its handler."""
    def __init__(self, rows, loop):
        super().__init__(rows)
        self.loop = loop
        self.started = asyncio.Event()
        self.release = Event()
        self.probe = None
        self.visited = 0

    def __iter__(self):
        for index, row in enumerate(super().__iter__()):
            self.visited += 1
            if index == 256 and not self.release.is_set():
                self.probe = current_query_cancellation_probe()
                self.loop.call_soon_threadsafe(self.started.set)
                if not self.release.wait(5):
                    raise AssertionError("scan was not released")
            yield row


def _scope(path, method="POST"):
    return {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 80), "client": ("test", 123),
    }


class ReadQueryCancellationTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        dataset, _, queries = query_fixture(indexed=True)
        index = queries.indexed_history
        source = _TrackedSource(dataset, index)
        service = NormalizedDataService(source, StaticDataPolicy())
        descriptor = RevisionDescriptor("node", REVISION, "Node", 3, 3)
        store = SimpleNamespace(revision=lambda revision: {REVISION: descriptor}[revision])
        session = CoreRuntimeSession(SimpleNamespace(revision_store=store), service)
        app = FastAPI()
        app.include_router(api_router)
        return dataset, index, source, service, session, app

    async def begin(self, app, path, body=None, method="POST"):
        incoming = asyncio.Queue()
        await incoming.put({"type": "http.request", "body": json.dumps(body or {}).encode(), "more_body": False})
        sent = []

        async def send(message):
            sent.append(message)

        task = asyncio.create_task(app(_scope(path, method), incoming.get, send))
        return task, incoming, sent

    async def disconnect(self, incoming, rows):
        self.assertIsNotNone(rows.probe, "route did not bind request cancellation")
        await incoming.put({"type": "http.disconnect"})

        async def observed():
            while not rows.probe():
                await asyncio.sleep(0)

        await asyncio.wait_for(observed(), 3)
        rows.release.set()

    def status(self, sent):
        return [m["status"] for m in sent if m["type"] == "http.response.start"]

    async def test_graph_resources_dashboards_and_source_scans_abort_and_recover(self):
        for route in ("graph/query", "resources/query", "resources/at", "dashboards/query", "source-records/query"):
            with self.subTest(route=route):
                dataset, index, source, _, session, app = self.fixture()
                if route == "graph/query":
                    original = index.relationships_by_endpoint["root"]
                elif route == "source-records/query":
                    original = dataset["source_records"]
                else:
                    original = dataset["resources"]
                rows = _HeldRows(original * 600, asyncio.get_running_loop())
                if route == "graph/query":
                    index.relationships_by_endpoint["root"] = rows
                elif route == "source-records/query":
                    dataset["source_records"] = rows
                else:
                    index.resources = rows
                dataset["dashboard_descriptors"] = [{
                    "dashboard_id": "all", "statistics": [{"statistic_id": "count", "aggregation": "count"}],
                }]
                path = f"/v1/revisions/{REVISION}/{route}"
                method = "GET" if route == "resources/at" else "POST"
                with activate_runtime_session(session):
                    task, incoming, sent = await self.begin(app, path, {"time_ns": "25"}, method)
                    try:
                        await asyncio.wait_for(rows.started.wait(), 3)
                        self.assertGreater(source.active, 0)
                        await self.disconnect(incoming, rows)
                        await asyncio.wait_for(task, 3)
                    finally:
                        rows.release.set()
                        if not task.done():
                            task.cancel()
                    self.assertEqual(self.status(sent), [499])
                    self.assertEqual(source.active, 0)
                    self.assertEqual(rows.visited, 257, "cancelled scan continued beyond its checkpoint")
                    self.assertIsNone(current_query_cancellation_probe())
                    # Use the same service and collection again, proving cleanup
                    # and that cancellation was not installed on the shared owner.
                    recovery, _, recovered = await self.begin(app, path, {"time_ns": "25"}, method)
                    await asyncio.wait_for(recovery, 3)
                    self.assertEqual(self.status(recovered), [200])
                    self.assertEqual(source.active, 0)

    async def test_disconnected_reader_releases_only_its_own_revision_lease(self):
        dataset, index, source, _, session, app = self.fixture()
        original = dataset["resources"]
        first = _HeldRows(index.relationships_by_endpoint["root"] * 600, asyncio.get_running_loop())
        second = _HeldRows(original * 200, asyncio.get_running_loop())
        index.relationships_by_endpoint["root"] = first
        index.resources = second
        with activate_runtime_session(session):
            a, a_input, a_sent = await self.begin(app, f"/v1/revisions/{REVISION}/graph/query")
            b, _, b_sent = await self.begin(app, f"/v1/revisions/{REVISION}/resources/query")
            try:
                await asyncio.wait_for(asyncio.gather(first.started.wait(), second.started.wait()), 3)
                self.assertFalse(first.probe())
                self.assertFalse(second.probe())
                await self.disconnect(a_input, first)
                await asyncio.wait_for(a, 3)
                self.assertEqual(self.status(a_sent), [499])
                self.assertFalse(second.probe(), "one reader cancelled another")
                self.assertEqual(source.active, 1)
                second.release.set()
                await asyncio.wait_for(b, 3)
                self.assertEqual(self.status(b_sent), [200])
                self.assertEqual(source.active, 0)
                self.assertTrue(second.probe(), "successful scope left its watcher active")
            finally:
                first.release.set()
                second.release.set()
                for task in (a, b):
                    if not task.done():
                        task.cancel()

    async def test_all_read_routes_observe_disconnect_before_provider_acquisition(self):
        app = FastAPI()
        app.include_router(api_router)
        paths = (
            "/v1/revisions/unloaded/graph/query",
            "/v1/revisions/unloaded/resources/query",
            "/v1/revisions/unloaded/dashboards/query",
            "/v1/revisions/unloaded/topology/query",
            "/v1/revisions/unloaded/topology/changes/query",
            "/v1/revisions/unloaded/routes/resolve",
            "/v1/revisions/unloaded/range/summary",
            "/v1/revisions/unloaded/event-log/query",
            "/v1/revisions/unloaded/source-records/query",
            "/v1/topologies/query", "/v1/topologies/routes/trace",
            "/v1/topologies/routes/tables/query",
        )
        for path in paths:
            with self.subTest(path=path):
                incoming = asyncio.Queue()
                await incoming.put({"type": "http.request", "body": b'{"incomplete":', "more_body": True})
                await incoming.put({"type": "http.disconnect"})
                sent = []

                async def send(message):
                    sent.append(message)

                await asyncio.wait_for(app(_scope(path), incoming.get, send), 3)
                self.assertEqual(self.status(sent), [499])
                self.assertIsNone(current_query_cancellation_probe())

    async def test_included_mutation_router_does_not_inherit_read_cancellation(self):
        # FastAPI preserves the included router's route class. This is the same
        # composition used by service routes; durable actions must finish under
        # their own lifecycle even after their response consumer disconnects.
        action_router = APIRouter()
        observed = []

        @action_router.post("/durable-action")
        def action():
            observed.append(current_query_cancellation_probe())
            return {"committed": True}

        read_router = APIRouter(route_class=api_router.route_class)
        read_router.include_router(action_router)
        app = FastAPI()
        app.include_router(read_router)
        task, incoming, sent = await self.begin(app, "/durable-action")
        await incoming.put({"type": "http.disconnect"})
        await asyncio.wait_for(task, 3)
        self.assertEqual(self.status(sent), [200])
        self.assertEqual(observed, [None])


class QueryLoopCancellationTests(unittest.TestCase):
    def test_cancelled_search_builder_does_not_poison_waiting_reader(self):
        from router_dump_analyzer.history_search_core import HistorySearchCorpus

        corpus = HistorySearchCorpus()
        cancelled, started, release, waiting = Event(), Event(), Event(), Event()
        errors, results = [], []
        wait = corpus._condition.wait

        def observe_wait(*args, **kwargs):
            waiting.set()
            return wait(*args, **kwargs)

        def interrupted_documents():
            for ordinal in range(1000):
                if ordinal == 256:
                    started.set()
                    if not release.wait(3):
                        raise AssertionError("builder release missing")
                yield f"safe-{ordinal}"

        def first():
            token = _QUERY_CANCELLED.set(cancelled)
            try:
                corpus.query("safe-999", interrupted_documents)
            except BaseException as error:
                errors.append(error)
            finally:
                _QUERY_CANCELLED.reset(token)

        def second():
            try:
                results.append(list(corpus.query("safe-999", lambda: (f"safe-{i}" for i in range(1000)))))
            except BaseException as error:
                errors.append(error)

        a, b = Thread(target=first), Thread(target=second)
        with patch.object(corpus._condition, "wait", side_effect=observe_wait):
            a.start()
            self.assertTrue(started.wait(3))
            b.start()
            self.assertTrue(waiting.wait(3))
            cancelled.set()
            release.set()
            a.join(3)
            b.join(3)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RevisionQueryCancellationError)
        self.assertEqual(results, [[999]])
        self.assertTrue(corpus.ready)
        self.assertIsNone(corpus._error)
        corpus.close()

    def test_cancelled_search_waiter_leaves_shared_builder_running(self):
        from router_dump_analyzer.history_search_core import HistorySearchCorpus

        corpus = HistorySearchCorpus()
        cancelled, started, release, waiting = Event(), Event(), Event(), Event()
        errors, results = [], []
        wait = corpus._condition.wait

        def observe_wait(*args, **kwargs):
            waiting.set()
            return wait(*args, **kwargs)

        def documents():
            started.set()
            if not release.wait(3):
                raise AssertionError("builder release missing")
            return ["shared-safe"]

        def first():
            try:
                results.append(list(corpus.query("shared", documents)))
            except BaseException as error:
                errors.append(error)

        def second():
            token = _QUERY_CANCELLED.set(cancelled)
            try:
                corpus.query("safe", lambda: self.fail("waiter became builder"))
            except BaseException as error:
                errors.append(error)
            finally:
                _QUERY_CANCELLED.reset(token)

        a, b = Thread(target=first), Thread(target=second)
        with patch.object(corpus._condition, "wait", side_effect=observe_wait):
            a.start()
            self.assertTrue(started.wait(3))
            b.start()
            self.assertTrue(waiting.wait(3))
            cancelled.set()
            b.join(2)
            try:
                self.assertFalse(b.is_alive(), "cancelled waiter did not retire promptly")
                self.assertTrue(a.is_alive(), "waiter cancelled the independent builder")
                self.assertTrue(corpus._building)
            finally:
                release.set()
                a.join(3)
        self.assertEqual(results, [[0]])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RevisionQueryCancellationError)
        self.assertEqual(list(corpus.query("safe", lambda: self.fail("unexpected rebuild"))), [0])
        corpus.close()

    def test_cancelled_query_retires_progress_without_failed_dataset_state(self):
        from router_dump_analyzer.load_progress import AnalysisLoadStage, AnalysisLoadTracker

        dataset, _, _ = query_fixture()
        tracker = AnalysisLoadTracker()
        service = NormalizedDataService(StaticDatasetSource(dataset), StaticDataPolicy(), load_tracker=tracker)
        with self.assertRaises(RevisionQueryCancellationError):
            with service._loading_operation(AnalysisLoadStage.INDEXING):
                raise RevisionQueryCancellationError("revision query was cancelled")
        snapshot = tracker.snapshot()
        self.assertEqual(snapshot.active_operations, 0)
        self.assertIsNone(snapshot.error_code)
        self.assertNotEqual(snapshot.state.value, "failed")

    def test_dashboard_aggregation_stops_inside_population_scan(self):
        cancelled = Event()

        class Rows(list):
            visited = 0

            def __iter__(self):
                for row in super().__iter__():
                    self.visited += 1
                    if self.visited == 257:
                        cancelled.set()
                    yield row

        rows = Rows([{"kind": "K", "exists": True, "value": 2}] * 1000)
        descriptors = [{"dashboard_id": "d", "statistics": [{"statistic_id": "s", "aggregation": "sum", "field": "value"}]}]
        token = _QUERY_CANCELLED.set(cancelled)
        try:
            with self.assertRaises(RevisionQueryCancellationError):
                evaluate_dashboards(descriptors, rows)
            self.assertEqual(rows.visited, 257)
        finally:
            _QUERY_CANCELLED.reset(token)
        self.assertEqual(evaluate_dashboards(descriptors, rows)[0]["statistics"][0]["value"], 2000)

    def test_temporal_relationship_scan_cancels_without_publishing_partial_result(self):
        from tests.test_temporal_index import ExplicitIndexSource, construct, snapshot_body, temporal_fixture

        dataset, index, template, identifier = temporal_fixture()
        service = NormalizedDataService(ExplicitIndexSource(dataset, index), StaticDataPolicy())
        temporal = construct(dataset, service, template, indexed_history=index)
        original = index.relationships_by_endpoint[identifier]
        cancelled = Event()

        class Relationships(list):
            visited = 0

            def __iter__(self):
                for item in super().__iter__():
                    self.visited += 1
                    if self.visited == 257:
                        cancelled.set()
                    yield item

        rows = Relationships(original * 600)
        index.relationships_by_endpoint[identifier] = rows
        token = _QUERY_CANCELLED.set(cancelled)
        try:
            with self.assertRaises(RevisionQueryCancellationError):
                temporal.query(snapshot_body(identifier))
            self.assertEqual(rows.visited, 257)
        finally:
            _QUERY_CANCELLED.reset(token)
        index.relationships_by_endpoint[identifier] = original
        self.assertEqual(temporal.query(snapshot_body(identifier))["relationships"][0]["relationship_id"], "link")
