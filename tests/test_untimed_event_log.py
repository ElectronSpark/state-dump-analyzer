"""Untimed retained records remain selectable without acquiring a timestamp."""

from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from rsl_demo_plugin import parser_plugin

from router_dump_analyzer.revision_queries import EventLogQuery, RevisionQueryService
from router_dump_analyzer.revision_store import RevisionDescriptor
from router_dump_analyzer.runtime import (
    CoreRuntimeSession,
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)
from router_dump_analyzer.web.runtime_api import api_router
from router_dump_analyzer.web.runtime_context import activate_runtime_session
from tests.support.normalized_data import static_data_service

REVISION = "untimed/revision"


def mixed_log_fixture():
    event_values = [
        ("negative-event", "-5", 2),
        ("zero-event", "0", 2),
        ("\ue000", "0", 3),
        ("\U00010000", "0", 3),
        ("large-seq-high", "0", 9007199254740993),
        ("untimed-event", None, 4),
    ]
    source_values = [
        ("negative-source", "-5", 1),
        ("zero-source", "0", 1),
        ("positive-source", "5", 1),
        ("large-seq-low", "0", 9007199254740992),
        ("unknown-a", None, 3),
        ("unknown-b", None, 3),
        ("unknown-seq", None, 1),
    ]
    return {
        "workspace": {"revision_id": REVISION},
        "demo": {
            "revision_id": REVISION,
            "timeline_start_ns": "-5",
            "timeline_end_ns": "5",
            "capture_ns": "5",
        },
        "resources": [],
        "kind_descriptors": [],
        "state_intervals": [],
        "lifecycle_intervals": [],
        "events": [
            {
                "event_uid": uid,
                "timestamp_ns": stamp,
                "source_sequence": sequence,
                "event_type": "observation",
                "layer": "opaque",
                "subjects": [],
                "outcome": "success",
            }
            for uid, stamp, sequence in reversed(event_values)
        ],
        "source_records": [
            {
                "source_record_uid": uid,
                "timestamp_ns": stamp,
                "source_sequence": sequence,
                "source_type": "trace",
                "record_name": uid,
                "message": uid,
                "copy_text": f"copy:{uid}",
                "matched_event_uids": [],
            }
            for uid, stamp, sequence in reversed(source_values)
        ],
        "source_record_descriptors": [{"source_type": "trace"}],
    }


def queries_for(dataset):
    service = static_data_service(dataset)
    return RevisionQueryService(service, revision_id=REVISION, dataset=dataset)


@contextmanager
def bound_client(dataset):
    service = static_data_service(dataset)
    descriptor = RevisionDescriptor("node", REVISION, "Node", len(dataset["events"]), 0)
    store = SimpleNamespace(revision=lambda revision: {REVISION: descriptor}[revision])
    session = CoreRuntimeSession(SimpleNamespace(revision_store=store), service)
    application = FastAPI()
    application.include_router(api_router)

    @application.middleware("http")
    async def bind(request, call_next):
        with activate_runtime_session(session):
            return await call_next(request)

    with TestClient(application) as client:
        yield client


def identities(payload):
    return [f"{item['stream_kind']}:{item['uid']}" for item in payload["items"]]


ORDERED = [
    "source:negative-source",
    "event:negative-event",
    "source:zero-source",
    "event:zero-event",
    "event:\ue000",
    "event:\U00010000",
    "source:large-seq-low",
    "event:large-seq-high",
    "source:positive-source",
    "source:unknown-seq",
    "source:unknown-a",
    "source:unknown-b",
    "event:untimed-event",
]
RANGED = ORDERED[2:8] + ORDERED[:2] + ORDERED[8:]


class UntimedEventLogTests(unittest.TestCase):
    def test_missing_sequence_defaults_to_zero_before_explicit_sequences(self):
        dataset = mixed_log_fixture()
        event = {"event_uid": "missing", "timestamp_ns": "0", "subjects": []}
        source = {
            "source_record_uid": "missing",
            "timestamp_ns": "0",
            "source_type": "trace",
        }
        dataset["events"] = [
            dict(event, event_uid="explicit", source_sequence=1),
            event,
        ]
        dataset["source_records"] = [
            dict(source, source_record_uid="explicit", source_sequence=1),
            source,
        ]
        payload = queries_for(dataset).event_log(EventLogQuery())
        self.assertEqual(
            identities(payload),
            ["event:missing", "source:missing", "event:explicit", "source:explicit"],
        )
        self.assertEqual(payload["items"][1]["entry"]["source_sequence"], 0)

    def test_shared_browser_order_fixture_matches_live_core_projection(self):
        expected = json.loads(
            (Path(__file__).parent / "fixtures/event-log-time-parity.json").read_text(
                encoding="utf-8"
            )
        )
        dataset = mixed_log_fixture()
        self.assertEqual(
            static_data_service(dataset).client_dataset(), expected["dataset"]
        )
        queries = queries_for(dataset)
        for case in expected["cases"]:
            selected_range = case["selected_range"]
            actual = queries.event_log(
                EventLogQuery(
                    selected_range=None
                    if selected_range is None
                    else tuple(selected_range)
                )
            )
            self.assertEqual(actual, case["response"])

    def test_mixed_order_pagination_locate_and_nullable_projection(self):
        dataset = mixed_log_fixture()
        query = queries_for(dataset)
        payload = query.event_log(EventLogQuery())
        self.assertEqual(identities(payload), ORDERED)
        self.assertEqual(
            [row["display_index"] for row in payload["items"]], list(range(13))
        )
        for row in payload["items"][9:]:
            self.assertIsNone(row["timestamp_ns"])
            self.assertIsNone(row["entry"]["timestamp_ns"])
        self.assertEqual(payload["items"][2]["entry"]["source_sequence"], 1)
        self.assertEqual(
            payload["items"][6]["entry"]["source_sequence"], "9007199254740992"
        )
        self.assertEqual(
            payload["items"][7]["entry"]["source_sequence"], "9007199254740993"
        )
        page = query.event_log(
            EventLogQuery(offset=9, limit=2, locate=("source", "unknown-b"))
        )
        self.assertEqual(identities(page), ORDERED[9:11])
        self.assertEqual(page["located_display_index"], 11)

    def test_range_uses_only_known_inclusive_instants_and_retains_other_rows(self):
        payload = queries_for(mixed_log_fixture()).event_log(
            EventLogQuery(selected_range=(0, 0))
        )
        self.assertEqual(identities(payload), RANGED)
        self.assertEqual(payload["inside_count"], 6)
        self.assertEqual(payload["outside_count"], 7)
        for row in payload["items"][9:]:
            self.assertIsNone(row["timestamp_ns"])
            self.assertEqual(row["membership"], "outside")
            self.assertFalse(row["in_selected_range"])

    def test_http_selection_matches_query_uid_and_retains_unknown_timestamp(self):
        with bound_client(mixed_log_fixture()) as client:
            endpoint = f"/v1/revisions/{REVISION}/event-log"
            for bounds, expected in (
                ({}, ORDERED),
                ({"start_ns": "0", "end_ns": "0"}, RANGED),
            ):
                response = client.post(endpoint + "/query", json=bounds)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(identities(response.json()), expected)
                for index in (1, 6, 7, 9, 11, 12):
                    selected = client.post(
                        endpoint + "/selection",
                        json={
                            **bounds,
                            "selection_ranges": [{"start": index, "end": index}],
                        },
                    )
                    self.assertEqual(selected.status_code, 200, selected.text)
                    row = selected.json()["items"][0]
                    self.assertEqual(row["entry_id"], expected[index])
                    self.assertEqual(
                        row["timestamp_ns"],
                        response.json()["items"][index]["timestamp_ns"],
                    )
                    if row["stream_kind"] == "source":
                        self.assertEqual(
                            selected.json()["copy"]["items"][0]["text"],
                            "copy:" + row["uid"],
                        )

    def test_http_time_bounds_remain_exact_and_signed(self):
        with bound_client(mixed_log_fixture()) as client:
            for suffix in ("query", "selection"):
                base = (
                    {"selection_ranges": [{"start": 0, "end": 0}]}
                    if suffix == "selection"
                    else {}
                )
                endpoint = f"/v1/revisions/{REVISION}/event-log/{suffix}"
                for bounds in (
                    {
                        "start_ns": "-9223372036854775808",
                        "end_ns": "9223372036854775807",
                    },
                    {"start_ns": "-5", "end_ns": "-5"},
                ):
                    response = client.post(endpoint, json={**base, **bounds})
                    self.assertEqual(response.status_code, 200, response.text)
                for bounds in (
                    {"start_ns": "0"},
                    {"start_ns": None, "end_ns": "0"},
                    {"start_ns": True, "end_ns": "0"},
                    {"start_ns": 0.0, "end_ns": "0"},
                    {"start_ns": "-01", "end_ns": "0"},
                    {"start_ns": "0", "end_ns": "-1"},
                    {"start_ns": "-9223372036854775809", "end_ns": "0"},
                    {"start_ns": "0", "end_ns": "9223372036854775808"},
                ):
                    with self.subTest(suffix=suffix, bounds=bounds):
                        response = client.post(endpoint, json={**base, **bounds})
                        self.assertEqual(response.status_code, 422, response.text)

    def test_real_status_parser_unknown_row_does_not_break_timed_selection(self):
        fixture = (
            Path(__file__).resolve().parents[1] / "demo/fixtures/minimal-status.jsonl"
        )
        application = create_runtime_application(
            RuntimeApplicationRequest(
                runtime=require_plugin_runtime(parser_plugin),
                input_path=fixture,
                serve_frontend=False,
            )
        )
        with TestClient(application) as client:
            workspace = client.get("/v1/workspace").json()
            endpoint = (
                f"/v1/revisions/{workspace['workspace']['revision_id']}/event-log"
            )
            body = {
                "include_normalized": True,
                "source_types": ["status-json"],
                "layers": [],
                "search": "",
            }
            response = client.post(endpoint + "/query", json=body)
            self.assertEqual(response.status_code, 200, response.text)
            rows = response.json()["items"]
            self.assertEqual(len(rows), 4)
            self.assertIsNone(rows[-1]["timestamp_ns"])
            for index in (1, 3):
                selection = client.post(
                    endpoint + "/selection",
                    json={**body, "selection_ranges": [{"start": index, "end": index}]},
                )
                self.assertEqual(selection.status_code, 200, selection.text)
                selected = selection.json()
                self.assertEqual(selected["items"][0]["uid"], rows[index]["uid"])
                self.assertEqual(
                    selected["items"][0]["timestamp_ns"], rows[index]["timestamp_ns"]
                )
                self.assertEqual(selected["copy"]["item_count"], 1)


if __name__ == "__main__":
    unittest.main()
