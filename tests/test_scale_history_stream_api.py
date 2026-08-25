from __future__ import annotations

import json
import unittest
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient
from rsl_demo_plugin.data import REVISION_ID
from rsl_demo_plugin.scale_data import ScaleRuntime

from router_dump_analyzer.history_search_core import HistorySearchCorpus
from router_dump_analyzer.normalized_data import IndexedHistory
from router_dump_analyzer.web import runtime_api as demo_app
from tests.support.generated_demo import generated_demo_application
from tests.support.normalized_data import static_data_service


class DemoLifespanCleanupTests(unittest.TestCase):
    def test_core_lifespan_closes_the_plugin_runtime_session(self) -> None:
        application = generated_demo_application()

        with TestClient(application):
            session = application.state.runtime_session
            self.assertFalse(session.plugin_session._closed)

        self.assertTrue(session.plugin_session._closed)
        self.assertIsNone(application.state.runtime_session)


def _runtime(
    resources: list[dict],
    events: list[dict],
) -> ScaleRuntime:
    ordered = sorted(events, key=lambda item: int(item["timestamp_ns"]))
    failure_event_times: list[int] = []
    event_times_by_type: dict[str, list[int]] = defaultdict(list)
    for event in ordered:
        timestamp_ns = int(event["timestamp_ns"])
        if event.get("outcome") == "failure":
            failure_event_times.append(timestamp_ns)
        event_times_by_type[
            str(event.get("event_type") or event.get("event_name") or "unknown")
        ].append(timestamp_ns)
    resources_by_kind: dict[str, list[dict]] = defaultdict(list)
    for resource in resources:
        resources_by_kind[resource["kind"]].append(resource)
    return ScaleRuntime(
        resources=resources,
        resource_by_id={item["resource_id"]: item for item in resources},
        resources_by_kind=dict(resources_by_kind),
        resource_counts={
            kind: len(items) for kind, items in resources_by_kind.items()
        },
        events=ordered,
        event_by_uid={item["event_uid"]: item for item in ordered},
        event_times=[int(item["timestamp_ns"]) for item in ordered],
        failure_event_times=failure_event_times,
        event_times_by_type=dict(event_times_by_type),
        events_by_resource={},
        lifecycle_by_resource={},
        state_by_resource={},
        relationships=[],
        relationships_by_endpoint={},
        mutations=[],
        mutation_times=[],
        mutations_by_endpoint={},
        initial_resource_ids=[],
    )


def _dataset(*, scale: bool = False) -> dict:
    resources = [
        {
            "resource_id": "test/RESOURCE/one",
            "kind": "TEST",
            "layer": "layer-a",
            "label": "Resource one",
            "key": {"id": 1, "secret": "key-secret"},
            "state": {"status": "up", "secret": "state-secret"},
        }
    ]
    events = [
        {
            "event_uid": "event-a",
            "timestamp_ns": "100",
            "event_type": "plugin.alpha",
            "outcome": "success",
            "layer": "layer-a",
            "resource_id": "test/RESOURCE/one",
            "resource_kind": "TEST",
            "display_name": "Visible alpha",
            "result": {"message": "peer-a accepted", "secret": "event-secret"},
        },
        {
            "event_uid": "event-c",
            "timestamp_ns": "200",
            "event_type": "plugin.alpha",
            "outcome": "failure",
            "subjects": [{"layer": "layer-a"}],
            "resource_id": "test/RESOURCE/one",
            "resource_kind": "TEST",
            "display_name": "Visible failure",
        },
        {
            "event_uid": "event-b",
            "timestamp_ns": "300",
            "event_type": "plugin.beta",
            "outcome": "failure",
            "layer": "layer-b",
            "resource_id": "test/RESOURCE/one",
            "resource_kind": "TEST",
            "display_name": "Visible beta",
        },
    ]
    source_records = [
        {
            "source_record_uid": "source-a",
            "timestamp_ns": "150",
            "source_type": "ctf",
            "source_name": "trace.ctf2",
            "layer": "layer-a",
            "record_name": "trace-a",
            "message": "retained ctf record",
            "copy_text": "[150] trace-a { peer = \"peer-a\" }",
            "matched_event_uid": "event-a",
            "matched_event_uids": ["event-a"],
        },
        {
            "source_record_uid": "source-b",
            "timestamp_ns": "250",
            "source_type": "syslog",
            "source_name": "daemon",
            "layer": "layer-b",
            "record_name": "log-b",
            "message": "retained syslog record",
        },
    ]
    dataset = {
        "demo": {
            "revision_id": REVISION_ID,
            "event_count": len(events),
            "source_record_count": len(source_records),
        },
        "summary": {"parse": {"artifacts": 1}},
        "presentation": {"layers": [{"id": "layer-a"}]},
        "schema": {"semantic_owner": "plugin"},
        "resources": resources,
        "events": events,
        "source_records": source_records,
        "source_record_descriptors": [
            {"source_type": "ctf", "label": "CTF"},
            {"source_type": "syslog", "label": "Syslog"},
        ],
        "source_record_group_descriptors": [
            {
                "group_id": "ctf",
                "label": "CTF records",
                "copy_action_label": "Copy fixture text",
            }
        ],
        "kind_descriptors": [
            {
                "kind": "TEST",
                "label": "Test",
                "properties": [
                    {"name": "id", "searchable": True},
                    {"name": "secret", "searchable": True, "sensitive": True},
                ],
            }
        ],
    }
    if scale:
        dataset["_scale_runtime"] = _runtime(resources, events)
    return dataset


class ScaleHistoryBootstrapTests(unittest.TestCase):
    def test_scale_bootstrap_keeps_catalog_and_metadata_but_streams_history(self) -> None:
        dataset = _dataset(scale=True)
        client = static_data_service(dataset).client_dataset()

        self.assertEqual(client["events"], [])
        self.assertEqual(client["source_records"], [])
        self.assertNotIn("_scale_runtime", client)
        self.assertEqual(client["summary"], dataset["summary"])
        self.assertEqual(client["schema"], dataset["schema"])
        self.assertEqual(client["presentation"], dataset["presentation"])
        self.assertEqual(
            client["resources"],
            [
                {
                    "resource_id": "test/RESOURCE/one",
                    "kind": "TEST",
                    "layer": "layer-a",
                    "label": "Resource one",
                }
            ],
        )
        transport = client["history_transport"]
        self.assertEqual(transport["mode"], "server-windowed")
        self.assertEqual(transport["events"]["total_count"], 3)
        self.assertEqual(transport["source_records"]["total_count"], 2)
        self.assertTrue(transport["density"]["server_windowed"])

    def test_non_scale_bootstrap_retains_compatible_eager_streams(self) -> None:
        dataset = _dataset(scale=False)
        client = static_data_service(dataset).client_dataset()

        self.assertEqual(len(client["events"]), 3)
        self.assertEqual(len(client["source_records"]), 2)
        self.assertNotIn("copy_text", client["source_records"][0])
        self.assertNotIn("attributes", client["source_records"][0])
        self.assertNotIn("history_transport", client)
        serialized = json.dumps(client)
        self.assertNotIn("event-secret", serialized)
        self.assertNotIn("state-secret", serialized)
        self.assertNotIn("[150] trace-a", serialized)


class ScaleHistoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def _post(self, path: str, body: dict, *, scale: bool = False):
        dataset = _dataset(scale=scale)
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            return self.client.post(
                f"/v1/revisions/{REVISION_ID}/{path}",
                json=body,
            )

    def test_health_reports_scale_search_warmup_readiness(self) -> None:
        dataset = _dataset(scale=True)
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            before = self.client.get("/health")
            searched = self.client.post(
                f"/v1/revisions/{REVISION_ID}/event-log/query",
                json={"search": "visible", "source_types": []},
            )
            after = self.client.get("/health")

        self.assertEqual(before.status_code, 200)
        self.assertFalse(before.json()["history_search_ready"])
        self.assertEqual(before.json()["history_search_document_count"], 0)
        self.assertEqual(before.json()["history_search_backend"], "pending")
        self.assertEqual(searched.status_code, 200)
        self.assertTrue(after.json()["history_search_ready"])
        self.assertEqual(after.json()["history_search_document_count"], 3)
        self.assertEqual(after.json()["history_search_storage"], "memory")
        self.assertEqual(after.json()["history_search_backend"], "memory-scan")

    def test_density_returns_exact_sparse_aggregates(self) -> None:
        response = self._post(
            "events/density/query",
            {"start_ns": "100", "end_ns": "399", "bin_count": 3},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_count"], 3)
        self.assertEqual(payload["bin_count"], 3)
        self.assertEqual(
            [(item["start_ns"], item["end_ns"]) for item in payload["bins"]],
            [("100", "199"), ("200", "299"), ("300", "399")],
        )
        self.assertEqual(
            [item["failure_count"] for item in payload["bins"]],
            [0, 1, 1],
        )
        self.assertEqual(
            payload["bins"][0]["top_types"],
            [{"event_type": "plugin.alpha", "count": 1}],
        )

    def test_density_uses_scale_index_and_caps_resolution(self) -> None:
        response = self._post(
            "events/density/query",
            {"start_ns": 0, "end_ns": 10_000, "bin_count": 1_000_000},
            scale=True,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_count"], 3)
        self.assertEqual(payload["requested_bin_count"], 1_000_000)
        self.assertEqual(payload["bin_count"], demo_app.MAX_DENSITY_BINS)
        self.assertTrue(payload["indexed"])
        self.assertLessEqual(len(payload["bins"]), 3)

    def test_density_pages_keep_one_global_partition_for_nondivisible_spans(self) -> None:
        events = [
            {
                "event_uid": f"event-{timestamp_ns}",
                "timestamp_ns": str(timestamp_ns),
                "event_type": "plugin.even" if timestamp_ns % 2 == 0 else "plugin.odd",
                "outcome": "failure" if timestamp_ns == 5 else "success",
                "resource_id": "test/RESOURCE/one",
            }
            for timestamp_ns in range(10)
        ]
        expected_boundaries = {
            1: ("1", "2"),
            2: ("3", "4"),
            3: ("5", "5"),
            4: ("6", "7"),
        }
        observed_partitions: list[list[dict]] = []
        for scale in (False, True):
            with self.subTest(scale=scale):
                dataset = _dataset(scale=False)
                dataset["events"] = events
                if scale:
                    dataset["_scale_runtime"] = _runtime(dataset["resources"], events)
                with patch.object(demo_app, "load_dataset", return_value=dataset):
                    middle = self.client.post(
                        f"/v1/revisions/{REVISION_ID}/events/density/query",
                        json={
                            "start_ns": "0",
                            "end_ns": "9",
                            "bin_count": 6,
                            "bin_start_index": 1,
                            "bin_end_index": 5,
                        },
                    )
                    left = self.client.post(
                        f"/v1/revisions/{REVISION_ID}/events/density/query",
                        json={
                            "start_ns": "0",
                            "end_ns": "9",
                            "bin_count": 6,
                            "bin_start_index": 0,
                            "bin_end_index": 3,
                        },
                    )
                    right = self.client.post(
                        f"/v1/revisions/{REVISION_ID}/events/density/query",
                        json={
                            "start_ns": "0",
                            "end_ns": "9",
                            "bin_count": 6,
                            "bin_start_index": 2,
                            "bin_end_index": 6,
                        },
                    )

                self.assertEqual(middle.status_code, 200, middle.text)
                payload = middle.json()
                self.assertEqual(payload["indexed"], scale)
                self.assertEqual(payload["total_count"], 10)
                self.assertEqual(payload["bin_count"], 6)
                self.assertEqual(payload["bin_start_index"], 1)
                self.assertEqual(payload["bin_end_index"], 5)
                observed_partitions.append(payload["bins"])
                self.assertEqual(
                    {
                        item["index"]: (item["start_ns"], item["end_ns"])
                        for item in payload["bins"]
                    },
                    expected_boundaries,
                )
                timestamp_three_bin = next(
                    item for item in payload["bins"] if item["index"] == 2
                )
                self.assertEqual(
                    (
                        timestamp_three_bin["start_ns"],
                        timestamp_three_bin["end_ns"],
                        timestamp_three_bin["count"],
                    ),
                    ("3", "4", 2),
                )
                self.assertEqual(
                    timestamp_three_bin["top_types"],
                    [
                        {"event_type": "plugin.even", "count": 1},
                        {"event_type": "plugin.odd", "count": 1},
                    ],
                )
                left_bin = next(item for item in left.json()["bins"] if item["index"] == 2)
                right_bin = next(item for item in right.json()["bins"] if item["index"] == 2)
                self.assertEqual(left_bin, right_bin)
                self.assertEqual(
                    (right.json()["bins"][-1]["start_ns"], right.json()["bins"][-1]["end_ns"]),
                    ("8", "9"),
                )
        self.assertEqual(observed_partitions[0], observed_partitions[1])

    def test_density_index_does_not_scan_scale_event_payloads(self) -> None:
        class NoIterationEvents(list):
            def __iter__(self):
                raise AssertionError("indexed density must not scan event payloads")

        dataset = _dataset(scale=True)
        runtime = dataset["_scale_runtime"]
        runtime.events = NoIterationEvents(runtime.events)
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            response = self.client.post(
                f"/v1/revisions/{REVISION_ID}/events/density/query",
                json={"start_ns": "100", "end_ns": "399", "bin_count": 3},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["indexed"])
        self.assertEqual(payload["total_count"], 3)
        self.assertEqual(
            [item["failure_count"] for item in payload["bins"]],
            [0, 1, 1],
        )

    def test_density_accepts_public_indexed_history_without_demo_indexes(self) -> None:
        class LegacyIndexedHistory:
            __slots__ = tuple(IndexedHistory.__annotations__)

            def __init__(self, source: ScaleRuntime) -> None:
                for name in self.__slots__:
                    setattr(self, name, getattr(source, name))

        dataset = _dataset(scale=True)
        runtime = LegacyIndexedHistory(dataset["_scale_runtime"])
        self.assertIsInstance(runtime, IndexedHistory)
        self.assertFalse(hasattr(runtime, "failure_event_times"))
        self.assertFalse(hasattr(runtime, "event_times_by_type"))
        dataset["_scale_runtime"] = runtime

        with (
            patch.object(demo_app, "load_dataset", return_value=dataset),
            patch.object(demo_app, "history_runtime", return_value=runtime),
        ):
            response = self.client.post(
                f"/v1/revisions/{REVISION_ID}/events/density/query",
                json={"start_ns": "100", "end_ns": "399", "bin_count": 3},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["indexed"])
        self.assertEqual(payload["total_count"], 3)
        self.assertEqual(
            [item["failure_count"] for item in payload["bins"]],
            [0, 1, 1],
        )
        self.assertEqual(
            [item["top_types"] for item in payload["bins"]],
            [
                [{"event_type": "plugin.alpha", "count": 1}],
                [{"event_type": "plugin.alpha", "count": 1}],
                [{"event_type": "plugin.beta", "count": 1}],
            ],
        )

    def test_density_sweeps_high_cardinality_type_index_once(self) -> None:
        class CountingTypeIndex(dict[str, list[int]]):
            items_calls = 0

            def items(self):
                self.items_calls += 1
                return super().items()

        event_count = 2_048
        bin_count = 128
        events = [
            {
                "event_uid": f"event-{index:04d}",
                "timestamp_ns": str(index % bin_count),
                "event_type": f"plugin.type-{index:04d}",
                "outcome": "failure" if index % 257 == 0 else "success",
                "resource_id": "test/RESOURCE/one",
            }
            for index in range(event_count)
        ]
        dataset = _dataset(scale=False)
        dataset["events"] = events
        runtime = _runtime(dataset["resources"], events)
        type_index = CountingTypeIndex(runtime.event_times_by_type)
        runtime.event_times_by_type = type_index
        dataset["_scale_runtime"] = runtime

        with patch.object(demo_app, "load_dataset", return_value=dataset):
            response = self.client.post(
                f"/v1/revisions/{REVISION_ID}/events/density/query",
                json={
                    "start_ns": "0",
                    "end_ns": str(bin_count - 1),
                    "bin_count": bin_count,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["total_count"], event_count)
        self.assertEqual(len(payload["bins"]), bin_count)
        self.assertTrue(all(item["count"] == 16 for item in payload["bins"]))
        self.assertEqual(
            payload["bins"][0]["top_types"],
            [
                {"event_type": "plugin.type-0000", "count": 1},
                {"event_type": "plugin.type-0128", "count": 1},
                {"event_type": "plugin.type-0256", "count": 1},
                {"event_type": "plugin.type-0384", "count": 1},
            ],
        )
        self.assertEqual(
            type_index.items_calls,
            1,
            "type index must be swept once, not once per populated bin",
        )

    def test_density_rejects_missing_or_reversed_bounds(self) -> None:
        for body in (
            {"start_ns": 0},
            {"start_ns": 2, "end_ns": 1},
            {"start_ns": 0, "end_ns": 1, "bin_count": 0},
            {
                "start_ns": 0,
                "end_ns": 9,
                "bin_count": 6,
                "bin_start_index": 1,
            },
            {
                "start_ns": 0,
                "end_ns": 10_000,
                "bin_count": 10_001,
                "bin_start_index": 0,
                "bin_end_index": demo_app.MAX_DENSITY_BINS + 1,
            },
        ):
            with self.subTest(body=body):
                self.assertEqual(
                    self._post("events/density/query", body).status_code,
                    422,
                )

    def test_event_log_groups_range_then_stably_pages_and_locates(self) -> None:
        response = self._post(
            "event-log/query",
            {
                "start_ns": "180",
                "end_ns": "260",
                "offset": 1,
                "limit": 3,
                "locate": {"kind": "event", "uid": "event-b"},
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_count"], 5)
        self.assertEqual(payload["inside_count"], 2)
        self.assertEqual(payload["outside_count"], 3)
        self.assertEqual(payload["returned_count"], 3)
        self.assertEqual(payload["next_offset"], 4)
        self.assertEqual(payload["located_display_index"], 4)
        self.assertEqual(
            [(item["stream_kind"], item["uid"]) for item in payload["items"]],
            [
                ("source", "source-b"),
                ("event", "event-a"),
                ("source", "source-a"),
            ],
        )
        self.assertEqual(
            [item["membership"] for item in payload["items"]],
            ["inside", "outside", "outside"],
        )

    def test_event_log_same_timestamp_order_uses_source_sequence(self) -> None:
        dataset = _dataset(scale=False)
        template = dataset["events"][0]
        dataset["events"] = [
            {
                **template,
                "event_uid": "later",
                "timestamp_ns": "100",
                "source_sequence": 20,
            },
            {
                **template,
                "event_uid": "earlier",
                "timestamp_ns": "100",
                "source_sequence": 10,
            },
        ]
        dataset["source_records"] = []
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            response = self.client.post(
                f"/v1/revisions/{REVISION_ID}/event-log/query",
                json={"source_types": []},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            ["earlier", "later"],
            [item["uid"] for item in response.json()["items"]],
        )

    def test_event_log_filters_each_generic_stream_independently(self) -> None:
        only_ctf = self._post(
            "event-log/query",
            {
                "include_normalized": False,
                "source_types": ["ctf"],
                "layers": ["layer-a"],
            },
        )
        self.assertEqual(only_ctf.status_code, 200)
        self.assertEqual(only_ctf.json()["total_count"], 1)
        self.assertEqual(only_ctf.json()["items"][0]["uid"], "source-a")

        no_streams = self._post(
            "event-log/query",
            {"include_normalized": False, "source_types": []},
        )
        self.assertEqual(no_streams.status_code, 200)
        self.assertEqual(no_streams.json()["total_count"], 0)

    def test_event_log_selection_resolves_ranges_and_safe_plugin_copy_text(self) -> None:
        endpoint = f"/v1/revisions/{REVISION_ID}/event-log/selection"
        dataset = _dataset()
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            response = self.client.post(
                endpoint,
                json={
                    "include_normalized": True,
                    "source_types": ["ctf", "syslog"],
                    "selection_ranges": [{"start": 0, "end": 2}],
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["selection_count"], 3)
        self.assertEqual(
            [item["entry_id"] for item in payload["items"]],
            ["event:event-a", "source:source-a", "event:event-c"],
        )
        self.assertEqual(payload["copy_action_label"], "Copy fixture text")
        self.assertEqual(
            [item["source_record_uid"] for item in payload["copy"]["items"]],
            ["source-a", "copy-ctf-event-c"],
        )
        serialized_items = json.dumps(payload["items"])
        self.assertNotIn("copy_text", serialized_items)
        self.assertNotIn("key-secret", serialized_items)
        self.assertNotIn("state-secret", serialized_items)

    def test_event_log_selection_rejects_unbounded_ranges(self) -> None:
        endpoint = f"/v1/revisions/{REVISION_ID}/event-log/selection"
        with patch.object(demo_app, "load_dataset", return_value=_dataset()):
            response = self.client.post(
                endpoint,
                json={
                    "selection_ranges": [
                        {
                            "start": 0,
                            "end": demo_app.MAX_EVENT_LOG_SELECTION_ITEMS,
                        }
                    ]
                },
            )

        self.assertEqual(response.status_code, 422)

    def test_scale_event_only_pages_use_timestamp_index_without_full_merge(self) -> None:
        response = self._post(
            "event-log/query",
            {
                "source_types": [],
                "start_ns": "150",
                "end_ns": "250",
                "offset": 1,
                "limit": 2,
                "locate": {"kind": "event", "uid": "event-b"},
            },
            scale=True,
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["indexed_fast_path"])
        self.assertEqual(payload["inside_count"], 1)
        self.assertEqual(payload["outside_count"], 2)
        self.assertEqual(payload["located_display_index"], 2)
        self.assertEqual(
            [item["uid"] for item in payload["items"]],
            ["event-a", "event-b"],
        )

    def test_scale_event_search_preserves_filters_range_order_and_locate(self) -> None:
        response = self._post(
            "event-log/query",
            {
                "search": "VISIBLE",
                "source_types": [],
                "layers": ["layer-a"],
                "start_ns": "150",
                "end_ns": "250",
                "limit": 10,
                "locate": {"kind": "event", "uid": "event-a"},
            },
            scale=True,
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_count"], 2)
        self.assertEqual(payload["inside_count"], 1)
        self.assertEqual(payload["outside_count"], 1)
        self.assertEqual(payload["located_display_index"], 1)
        self.assertEqual(
            [item["uid"] for item in payload["items"]],
            ["event-c", "event-a"],
        )
        self.assertEqual(
            [item["membership"] for item in payload["items"]],
            ["inside", "outside"],
        )

    def test_scale_event_search_reuses_index_without_raw_stream_scan(self) -> None:
        class NoIterationEvents(list):
            def __iter__(self):
                raise AssertionError(
                    "indexed scale search must not rescan the raw event stream"
                )

        dataset = _dataset(scale=True)
        runtime = dataset["_scale_runtime"]
        endpoint = f"/v1/revisions/{REVISION_ID}/event-log/query"
        with patch.object(demo_app, "load_dataset", return_value=dataset):
            # The first query may initialize a reusable search corpus for a
            # synthetic runtime. Packed scale fixtures can build it while
            # loading; either way, later queries must not walk all raw events.
            warm = self.client.post(
                endpoint,
                json={"search": "visible", "source_types": []},
            )
            self.assertEqual(warm.status_code, 200)
            self.assertEqual(warm.json()["total_count"], 3)

            guarded_events = NoIterationEvents(runtime.events)
            runtime.events = guarded_events
            dataset["events"] = guarded_events

            visible = self.client.post(
                endpoint,
                json={"search": "PEER-A", "source_types": []},
            )
            sensitive = self.client.post(
                endpoint,
                json={"search": "event-secret", "source_types": []},
            )

        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["total_count"], 1)
        self.assertEqual(visible.json()["items"][0]["uid"], "event-a")
        self.assertEqual(sensitive.status_code, 200)
        self.assertEqual(sensitive.json()["total_count"], 0)

    def test_persistent_search_sidecar_never_stores_sensitive_event_values(self) -> None:
        dataset = _dataset(scale=True)
        runtime = dataset["_scale_runtime"]
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "safe-history.sqlite3"
            runtime.event_search = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="redacted-test-revision",
                expected_documents=len(runtime.events),
            )
            with patch.object(demo_app, "load_dataset", return_value=dataset):
                visible = self.client.post(
                    f"/v1/revisions/{REVISION_ID}/event-log/query",
                    json={"search": "peer-a", "source_types": []},
                )
                sensitive = self.client.post(
                    f"/v1/revisions/{REVISION_ID}/event-log/query",
                    json={"search": "event-secret", "source_types": []},
                )

            sidecar_bytes = sidecar.read_bytes()
            runtime.event_search.close()

        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["total_count"], 1)
        self.assertEqual(sensitive.status_code, 200)
        self.assertEqual(sensitive.json()["total_count"], 0)
        self.assertIn(b"peer-a", sidecar_bytes)
        self.assertNotIn(b"event-secret", sidecar_bytes)

    def test_event_redaction_precedes_search_and_return(self) -> None:
        secret = self._post("event-log/query", {"search": "event-secret"})
        self.assertEqual(secret.status_code, 200)
        self.assertEqual(secret.json()["total_count"], 0)

        visible = self._post(
            "event-log/query",
            {"search": "peer-a", "source_types": []},
        )
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["total_count"], 1)
        serialized = json.dumps(visible.json())
        self.assertNotIn("secret", serialized)
        self.assertNotIn("event-secret", serialized)

    def test_event_log_rejects_unbounded_or_unknown_inputs(self) -> None:
        invalid_bodies = (
            {"source_types": ["unknown"]},
            {"search": "x" * (demo_app.MAX_EVENT_LOG_SEARCH_LENGTH + 1)},
            {"start_ns": 1},
            {"start_ns": 2, "end_ns": 1},
            {"limit": demo_app.MAX_EVENT_LOG_LIMIT + 1},
            {"locate": {"kind": "other", "uid": "x"}},
        )
        for body in invalid_bodies:
            with self.subTest(body=body):
                self.assertEqual(
                    self._post("event-log/query", body).status_code,
                    422,
                )


if __name__ == "__main__":
    unittest.main()
