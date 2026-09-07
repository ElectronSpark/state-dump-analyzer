"""Headless execution and HTTP parity for bounded revision query services."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from router_dump_analyzer.history_search_core import HistorySearchCorpus
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.revision_queries import (
    CorrelationQuery,
    EventDensityQuery,
    EventLogQuery,
    RevisionQueryCancellationError,
    RevisionQueryRequestError,
    RevisionQueryService,
    TimelineQuery,
)
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource

REVISION = "headless/revision"


def query_fixture(*, indexed: bool = False, cancellation_probe=None):
    resources = [
        {
            "resource_id": name,
            "kind": "opaque-kind",
            "layer": "opaque-layer",
            "label": name,
            "state": {"mode": "ready", "secret": "private-sentinel"},
        }
        for name in ("root", "child", "absent")
    ]
    lifecycle = [
        {
            "resource": name,
            "valid_from_ns": "0",
            "valid_to_ns": "5" if name == "absent" else None,
        }
        for name in ("root", "child", "absent")
    ]
    states = [
        {
            **life,
            "status": "ready",
            "status_class": "up",
            "properties": {"mode": "ready", "secret": "private-sentinel"},
        }
        for life in lifecycle
    ]
    relationships = [
        {
            "relationship_id": "link",
            "source": "root",
            "target": "child",
            "relation_type": "opaque-link",
            "present": None,
            "quality": "ambiguous",
            "valid_from_ns": "0",
            "valid_to_ns": None,
        }
    ]
    events = [
        {
            "event_uid": f"event-{index}",
            "timestamp_ns": str(timestamp),
            "source_sequence": index,
            "event_type": "opaque-event",
            "layer": "opaque-layer",
            "outcome": "failure" if index == 1 else "success",
            "affected_resources": ["root"],
            "effects": [
                {
                    "resource_id": "root",
                    "effect_type": "modified",
                    "state_changed": True,
                }
            ],
            "attributes": {"visible": "needle", "secret": "private-sentinel"},
        }
        for index, timestamp in enumerate((10, 25, 30))
    ]
    dataset = {
        "workspace": {"revision_id": REVISION},
        "demo": {
            "capture_ns": "50",
            "timeline_start_ns": "0",
            "timeline_end_ns": "100",
        },
        "resources": resources,
        "events": events,
        "lifecycle_intervals": lifecycle,
        "state_intervals": states,
        "relationship_intervals": relationships,
        "relationship_mutations": [],
        "kind_descriptors": [
            {
                "kind": "opaque-kind",
                "label": "Literal kind",
                "condition_field": "mode",
                "properties": [{"name": "mode"}, {"name": "secret", "sensitive": True}],
            }
        ],
        "relationship_descriptors": [
            {"relation_type": "opaque-link", "label": "Literal link", "directed": True}
        ],
        "source_record_descriptors": [{"source_type": "trace"}],
        "source_records": [
            {
                "source_record_uid": "source-1",
                "source_type": "trace",
                "timestamp_ns": "15",
                "message": "retained record",
            }
        ],
    }
    index = None
    if indexed:
        index = SimpleNamespace(
            resources=resources,
            resource_by_id={r["resource_id"]: r for r in resources},
            resources_by_kind={"opaque-kind": resources},
            resource_counts={"opaque-kind": 3},
            events=events,
            event_by_uid={e["event_uid"]: e for e in events},
            event_index_by_uid={e["event_uid"]: i for i, e in enumerate(events)},
            event_times=[int(e["timestamp_ns"]) for e in events],
            events_by_resource={
                r["resource_id"]: events if r["resource_id"] == "root" else []
                for r in resources
            },
            lifecycle_by_resource={
                r["resource_id"]: [
                    x for x in lifecycle if x["resource"] == r["resource_id"]
                ]
                for r in resources
            },
            state_by_resource={
                r["resource_id"]: [
                    x for x in states if x["resource"] == r["resource_id"]
                ]
                for r in resources
            },
            relationships=relationships,
            relationships_by_endpoint={
                r["resource_id"]: relationships if r["resource_id"] != "absent" else []
                for r in resources
            },
            mutations=[],
            mutations_by_endpoint={},
            initial_resource_ids=["root"],
            event_search=HistorySearchCorpus(),
        )

    class ExplicitIndexSource(StaticDatasetSource):
        def indexed_history(self, dataset):
            return index

    service = NormalizedDataService(ExplicitIndexSource(dataset), StaticDataPolicy())
    queries = RevisionQueryService(
        service,
        revision_id=REVISION,
        dataset=dataset,
        indexed_history=index,
        cancellation_probe=cancellation_probe,
    )
    return dataset, service, queries


class RevisionQueryTests(unittest.TestCase):
    def test_all_query_families_execute_with_web_imports_blocked(self) -> None:
        root = Path(__file__).resolve().parents[1]
        program = f"""
import importlib.abc
import json
import sys
sys.path[:0] = [{str(root / "src")!r}, {str(root)!r}]
class NoWeb(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {{"fastapi", "starlette", "uvicorn"}} or fullname.startswith("router_dump_analyzer.web"):
            raise ImportError("web dependency blocked: " + fullname)
sys.meta_path.insert(0, NoWeb())
from tests.test_revision_queries import query_fixture
from router_dump_analyzer.revision_queries import CorrelationQuery, EventDensityQuery, EventLogQuery, TimelineQuery
for indexed in (False, True):
    dataset, service, queries = query_fixture(indexed=indexed)
    graph = queries.correlation(CorrelationQuery(50, resource_ids=("root",), depth=1))
    density = queries.event_density(EventDensityQuery(0, 100, 10, 10, 0, 10))
    log = queries.event_log(EventLogQuery(source_types=(), search="needle", limit=2))
    timeline = queries.timeline(TimelineQuery(0, 100, resource_ids=("root", "child")))
    assert {{node["id"] for node in graph["nodes"]}} == {{"root", "child"}}
    assert graph["edges"][0]["present"] is None
    assert density["total_count"] == 3
    assert sum(item["failure_count"] for item in density["bins"]) == 1
    assert log["total_count"] == 3 and log["returned_count"] == 2
    assert timeline["event_count"] == 3 and len(timeline["lanes"]) == 2
    assert "private-sentinel" not in json.dumps([graph, log, timeline])
assert not any(name.startswith("router_dump_analyzer.web") for name in sys.modules)
print("headless scan and indexed queries passed")
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", program],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("headless scan and indexed queries passed", result.stdout)

    def test_http_parsing_matches_explicit_core_queries(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from router_dump_analyzer.revision_store import RevisionDescriptor
        from router_dump_analyzer.runtime import CoreRuntimeSession
        from router_dump_analyzer.web.runtime_api import api_router
        from router_dump_analyzer.web.runtime_context import activate_runtime_session

        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                dataset, service, queries = query_fixture(indexed=indexed)
                descriptor = RevisionDescriptor("node", REVISION, "Node", 3, 3)
                store = SimpleNamespace(
                    revision=lambda revision_id: {REVISION: descriptor}[revision_id]
                )
                session = CoreRuntimeSession(
                    SimpleNamespace(revision_store=store), service
                )
                app = FastAPI()
                app.include_router(api_router)

                @app.middleware("http")
                async def bind(request, call_next):
                    with activate_runtime_session(session):
                        return await call_next(request)

                cases = [
                    (
                        "correlations/query",
                        {"time_ns": "50", "resource_ids": ["root"], "depth": 1},
                        queries.correlation(
                            CorrelationQuery(50, resource_ids=("root",), depth=1)
                        ),
                    ),
                    (
                        "events/density/query",
                        {
                            "start_ns": "0",
                            "end_ns": "100",
                            "bin_count": 10,
                            "bin_start_index": 1,
                            "bin_end_index": 4,
                        },
                        queries.event_density(EventDensityQuery(0, 100, 10, 10, 1, 4)),
                    ),
                    (
                        "event-log/query",
                        {
                            "source_types": [],
                            "search": "needle",
                            "start_ns": "20",
                            "end_ns": "30",
                            "limit": 2,
                        },
                        queries.event_log(
                            EventLogQuery(
                                source_types=(),
                                search="needle",
                                selected_range=(20, 30),
                                limit=2,
                            )
                        ),
                    ),
                    (
                        "timeline/query",
                        {
                            "start_ns": "0",
                            "end_ns": "100",
                            "resource_ids": ["root", "child"],
                            "max_glyphs": 1,
                            "cursor_time_ns": "25",
                        },
                        queries.timeline(
                            TimelineQuery(
                                0,
                                100,
                                resource_ids=("root", "child"),
                                max_glyphs=1,
                                cursor_time_ns=25,
                            )
                        ),
                    ),
                    (
                        "event-log/query",
                        {"source_types": [], "search": "ß" * 256},
                        queries.event_log(
                            EventLogQuery(source_types=(), search="ß" * 256)
                        ),
                    ),
                ]
                with TestClient(app) as client:
                    for suffix, body, expected in cases:
                        with self.subTest(endpoint=suffix):
                            response = client.post(
                                f"/v1/revisions/{REVISION}/{suffix}", json=body
                            )
                            self.assertEqual(response.status_code, 200, response.text)
                            self.assertEqual(response.json(), expected)
                    invalid = client.post(
                        f"/v1/revisions/{REVISION}/event-log/query",
                        json={"source_types": ["not-declared"]},
                    )
                    self.assertEqual(invalid.status_code, 422, invalid.text)
                    self.assertIn("unknown source types", invalid.json()["detail"])
                    nested = None
                    for _ in range(64):
                        nested = [nested]
                    invalid_range = client.post(
                        f"/v1/revisions/{REVISION}/timeline/query",
                        json={"range": {"nested": nested}},
                    )
                    self.assertEqual(invalid_range.status_code, 422, invalid_range.text)
                    self.assertIn("64 nested containers", invalid_range.json()["detail"])

    def test_core_values_enforce_bounds_without_http_validation(self) -> None:
        for build in (
            lambda: CorrelationQuery(0, max_nodes=501),
            lambda: CorrelationQuery(0, depth=-1),
            lambda: EventDensityQuery(10, 0, 10, 10, 0, 10),
            lambda: EventDensityQuery(0, 10_000, 10_000, 10_000, 0, 4_097),
            lambda: EventLogQuery(limit=501),
            lambda: EventLogQuery(selected_range=(20, 10)),
            lambda: TimelineQuery(0, 100, max_glyphs=0),
        ):
            with (
                self.subTest(build=build),
                self.assertRaises(RevisionQueryRequestError),
            ):
                build()

    def test_explicit_no_index_does_not_read_a_private_dataset_accelerator(
        self,
    ) -> None:
        dataset, _, queries = query_fixture()
        dataset["_scale_runtime"] = object()
        density = queries.event_density(EventDensityQuery(0, 100, 10, 10, 0, 10))
        self.assertFalse(density["indexed"])
        self.assertEqual(density["total_count"], 3)

    def test_timeline_snapshots_nested_selectors_and_returns_independent_json(
        self,
    ) -> None:
        _, _, queries = query_fixture()
        selected_range = {
            "start_ns": "10",
            "end_ns": "30",
            "selection": {"ids": ["root"]},
        }
        rule = {"lane_id": "retained", "pattern": "retained", "source_types": ["trace"]}
        query = TimelineQuery(
            0,
            100,
            resource_ids=("root",),
            selected_range=selected_range,
            record_lane_rules=(rule,),
        )
        selected_range["selection"]["ids"].append("changed")
        rule["source_types"][0] = "not-declared"
        with self.assertRaises(TypeError):
            query.selected_range["selection"]["ids"][0] = "changed"
        with self.assertRaises(TypeError):
            query.record_lane_rules[0]["source_types"][0] = "changed"
        first = queries.timeline(query)
        self.assertEqual(first["selection"]["range"]["selection"]["ids"], ["root"])
        self.assertEqual(first["record_lanes"][0]["record_count"], 1)
        first["selection"]["range"]["selection"]["ids"].clear()
        second = queries.timeline(query)
        self.assertEqual(second["selection"]["range"]["selection"]["ids"], ["root"])
        self.assertEqual(second["record_lanes"][0]["record_count"], 1)

    def test_every_query_family_honors_cancellation_before_work(self) -> None:
        _, _, queries = query_fixture(cancellation_probe=lambda: True)
        for operation in (
            lambda: queries.correlation(CorrelationQuery(50)),
            lambda: queries.event_density(EventDensityQuery(0, 100, 10, 10, 0, 10)),
            lambda: queries.event_log(EventLogQuery()),
            lambda: queries.timeline(TimelineQuery(0, 100)),
        ):
            with (
                self.subTest(operation=operation),
                self.assertRaises(RevisionQueryCancellationError),
            ):
                operation()

    def test_long_scan_checks_cancellation_and_does_not_return_partial_counts(
        self,
    ) -> None:
        checks = 0

        def cancel_during_scan():
            nonlocal checks
            checks += 1
            return checks >= 3

        dataset, _, queries = query_fixture(cancellation_probe=cancel_during_scan)
        dataset["events"] = [
            dict(dataset["events"][0], event_uid=f"many-{i}") for i in range(1_000)
        ]
        with self.assertRaises(RevisionQueryCancellationError):
            queries.event_density(EventDensityQuery(0, 100, 10, 10, 0, 10))
        self.assertEqual(checks, 3)

    def test_invalid_cancellation_probes_fail_closed(self) -> None:
        for probe in (lambda: None, lambda: 1):
            _, _, queries = query_fixture(cancellation_probe=probe)
            with self.assertRaises(RevisionQueryCancellationError):
                queries.event_log(EventLogQuery())

    def test_cancellation_during_redaction_does_not_publish_a_search_corpus(
        self,
    ) -> None:
        checks = 0

        def cancel_during_redaction():
            nonlocal checks
            checks += 1
            return checks >= 3

        _, _, queries = query_fixture(
            indexed=True, cancellation_probe=cancel_during_redaction
        )
        with self.assertRaises(RevisionQueryCancellationError):
            queries.search_events("needle")
        self.assertFalse(
            queries.indexed_history.event_search.status_snapshot()["ready"]
        )


if __name__ == "__main__":
    unittest.main()
