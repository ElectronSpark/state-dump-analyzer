"""Bounded timeline projection, temporal indexes and exact coarse summaries."""

import unittest
from unittest.mock import patch

from router_dump_analyzer.revision_queries import (
    TimelineQuery,
    MAX_TIMELINE_CLUSTER_DETAIL,
    MAX_TIMELINE_INTERVAL_DETAILS,
    _timeline_intervals,
)
from tests.test_revision_queries import query_fixture


def populated_fixture(count=12000):
    dataset, service, queries = query_fixture(indexed=True)
    events = [
        {
            **dataset["events"][0],
            "event_uid": f"zoom-{i}",
            "timestamp_ns": str(i),
            "source_sequence": i,
            "outcome": "failure" if i % 17 == 0 else "success",
        }
        for i in range(count)
    ]
    dataset["events"] = events
    queries.indexed_history.events_by_resource["root"] = events
    return dataset, service, queries


class ZoomTimelineTests(unittest.TestCase):
    def test_coarse_projection_is_bounded_and_counts_and_selection_are_exact(self):
        dataset, service, queries = populated_fixture()
        with patch.object(
            queries, "_redact_event_for_client", wraps=queries._redact_event_for_client
        ) as project:
            result = queries.timeline(
                TimelineQuery(
                    0,
                    11999,
                    resource_ids=("root",),
                    max_glyphs=2,
                    selected_event_uid="zoom-9000",
                )
            )
        assert project.call_count <= 2 * MAX_TIMELINE_CLUSTER_DETAIL
        assert result["event_count"] == result["mark_count"] == 12000
        assert sum(cluster["count"] for cluster in result["clusters"]) == 12000
        assert sum(cluster["failure_count"] for cluster in result["clusters"]) == len(
            range(0, 12000, 17)
        )
        assert "zoom-9000" in {
            mark["event_uid"]
            for cluster in result["clusters"]
            for mark in cluster["items"]
        }
        assert "private-sentinel" not in str(result)

    def test_warm_zoom_does_not_iterate_resource_history(self):
        dataset, service, queries = populated_fixture()

        class NoIteration(list):
            blocked = False

            def __iter__(self):
                if self.blocked:
                    raise AssertionError("warm query traversed resource history")
                return super().__iter__()

        source = NoIteration(dataset["events"])
        queries.indexed_history.events_by_resource["root"] = source
        queries.timeline(TimelineQuery(0, 11999, resource_ids=("root",), max_glyphs=2))
        source.blocked = True
        result = queries.timeline(
            TimelineQuery(6000, 6004, resource_ids=("root",), cluster_window_ns=0)
        )
        assert result["event_count"] == 5
        assert [mark["time_ns"] for mark in result["lanes"][0]["event_marks"]] == [
            str(i) for i in range(6000, 6005)
        ]

    def test_interval_index_preserves_open_and_nested_overlaps(self):
        from types import SimpleNamespace

        owner = SimpleNamespace()
        intervals = [
            {"valid_from_ns": None, "valid_to_ns": "100"},
            {"valid_from_ns": "10", "valid_to_ns": "20"},
            {"valid_from_ns": "15", "valid_to_ns": None},
            {"valid_from_ns": "25", "valid_to_ns": "30"},
        ]
        assert _timeline_intervals(
            owner, "rev", "r", intervals, 20, 25, lambda: None
        ) == [
            intervals[0],
            intervals[2],
        ]
        assert _timeline_intervals(
            owner, "rev", "r", intervals, 100, 101, lambda: None
        ) == [intervals[2]]

    def test_state_details_are_bounded_with_explicit_summary(self):
        dataset, service, queries = populated_fixture(3)
        states = [
            {
                "resource": "root",
                "valid_from_ns": str(i),
                "valid_to_ns": str(i + 1),
                "properties": {"mode": "ready"},
                "status_class": "error" if i == 2999 else "healthy",
                "status": "brief failure" if i == 2999 else "ready",
            }
            for i in range(3000)
        ]
        queries.indexed_history.state_by_resource["root"] = states
        result = queries.timeline(TimelineQuery(0, 3000, resource_ids=("root",)))
        lane = result["lanes"][0]
        assert len(lane["status_intervals"]) == MAX_TIMELINE_INTERVAL_DETAILS
        assert lane["status_interval_count"] == 3000
        assert lane["status_intervals_truncated"]
        assert lane["status_interval_mode"] == "summary-with-bounded-details"
        assert lane["status_interval_summary"]["properties_omitted"]
        assert lane["status_interval_summary"]["status_class_counts"]["error"] == 1
        assert lane["status_interval_summary"]["status_counts"]["brief failure"] == 1
        assert lane["event_marks"][0]["duration_to_next_change_ns"] == "1"

    def test_runtime_replacement_with_same_revision_does_not_reuse_event_index(self):
        from copy import copy

        dataset, service, queries = populated_fixture(3)
        queries.timeline(TimelineQuery(0, 10, resource_ids=("root",)))
        replacement = copy(queries.indexed_history)
        replacement.events_by_resource = {
            "root": [
                {
                    **dataset["events"][0],
                    "event_uid": "replacement",
                    "timestamp_ns": "7",
                }
            ]
        }
        queries.indexed_history = replacement
        result = queries.timeline(TimelineQuery(0, 10, resource_ids=("root",)))
        assert result["event_count"] == 1
        assert result["lanes"][0]["event_marks"][0]["event_uid"] == "replacement"

    def test_oversized_index_is_not_retained(self):
        dataset, service, queries = populated_fixture(30)
        with patch(
            "router_dump_analyzer.revision_queries.MAX_TIMELINE_INDEX_UNITS", 40
        ):
            result = queries.timeline(
                TimelineQuery(0, 29, resource_ids=("root",), max_glyphs=1)
            )
        assert result["event_count"] == 30
        assert not service._timeline_query_indexes

    def test_selected_event_gets_a_glyph_when_lane_budget_is_smaller_than_lane_count(
        self,
    ):
        dataset, service, queries = populated_fixture(100)
        queries.indexed_history.events_by_resource["child"] = [
            {
                **dataset["events"][0],
                "event_uid": "selected-child",
                "timestamp_ns": "50",
                "affected_resources": ["child"],
                "effects": [],
            }
        ]
        result = queries.timeline(
            TimelineQuery(
                0,
                99,
                resource_ids=("root", "child"),
                max_glyphs=1,
                selected_event_uid="selected-child",
            )
        )
        assert result["glyphs"]["glyph_count"] == 1
        assert result["lanes"][1]["event_marks"][0]["event_uid"] == "selected-child"

    def test_nonindexed_sequential_zoom_keeps_complete_history(self):
        dataset, service, queries = query_fixture(indexed=False)
        first = queries.timeline(TimelineQuery(0, 15, resource_ids=("root",)))
        second = queries.timeline(TimelineQuery(20, 30, resource_ids=("root",)))
        wider = queries.timeline(TimelineQuery(0, 100, resource_ids=("root",)))
        assert (first["event_count"], second["event_count"], wider["event_count"]) == (
            1,
            2,
            3,
        )

    def test_cancelled_build_does_not_publish_partial_indexes(self):
        from types import SimpleNamespace
        from router_dump_analyzer.revision_queries import _timeline_index

        owner = SimpleNamespace()
        events = [
            {"event_uid": str(i), "timestamp_ns": str(i)} for i in range(5000, 0, -1)
        ]
        probes = 0

        def checkpoint():
            nonlocal probes
            probes += 1
            if probes == 6:
                raise RuntimeError("cancelled")

        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            _timeline_index(owner, "rev", "r", events, (), checkpoint)
        assert not owner._timeline_query_indexes
        result = _timeline_index(owner, "rev", "r", events, (), lambda: None)
        assert result[1] == list(range(1, 5001))

    def test_overlapping_builds_publish_complete_thread_safe_indexes(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from types import SimpleNamespace
        from router_dump_analyzer.revision_queries import _timeline_index

        owner = SimpleNamespace()
        barrier = Barrier(2)
        events = [
            {"event_uid": str(i), "timestamp_ns": str(i)} for i in range(10000, 0, -1)
        ]

        def build():
            entered = False

            def checkpoint():
                nonlocal entered
                if not entered:
                    entered = True
                    barrier.wait(timeout=5)

            return _timeline_index(owner, "rev", "r", events, (), checkpoint)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: build(), range(2)))
        assert results[0][1] == results[1][1] == list(range(1, 10001))
        assert len(owner._timeline_query_indexes) == 1

    def test_many_lane_warm_event_union_is_not_rebuilt(self):
        dataset, service, queries = populated_fixture(1000)
        queries.indexed_history.events_by_resource["child"] = dataset["events"][::2]
        query = TimelineQuery(0, 999, resource_ids=("root", "child"), max_glyphs=2)
        assert queries.timeline(query)["event_count"] == 1000
        with patch(
            "router_dump_analyzer.revision_queries._cooperative_sorted",
            side_effect=AssertionError("warm union rebuilt"),
        ):
            result = queries.timeline(query)
        assert result["event_count"] == 1000
        assert result["mark_count"] == 1500

    def test_sensitive_condition_is_redacted_from_summary_and_details(self):
        dataset, service, queries = populated_fixture(3)
        dataset["kind_descriptors"][0]["condition_field"] = "secret"
        queries.indexed_history.state_by_resource["root"] = [
            {
                "resource": "root",
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "status": "private-sentinel",
                "status_class": "error",
                "properties": {"secret": "private-sentinel"},
            }
        ]
        result = queries.timeline(TimelineQuery(0, 100, resource_ids=("root",)))
        lane = result["lanes"][0]
        assert lane["status_interval_summary"]["status_counts"] == {"unknown": 1}
        assert lane["status_interval_summary"]["status_class_counts"] == {"error": 1}
        assert lane["status_intervals"][0]["status"] == "unknown"
        assert "private-sentinel" not in str(result)

    def test_unindexed_narrow_window_checks_only_window_events_per_lane(self):
        from router_dump_analyzer.revision_queries import event_resource_ids

        dataset, service, queries = query_fixture(indexed=False)
        dataset["resources"] += [
            {**dataset["resources"][0], "resource_id": f"lane-{i}"} for i in range(30)
        ]
        template = dataset["events"][0]
        dataset["events"] = [
            {**template, "event_uid": f"event-{i}", "timestamp_ns": str(i)}
            for i in range(10000)
        ]
        with (
            patch.object(
                service, "events_in_range", wraps=service.events_in_range
            ) as window,
            patch(
                "router_dump_analyzer.revision_queries.event_resource_ids",
                wraps=event_resource_ids,
            ) as membership,
        ):
            result = queries.timeline(TimelineQuery(5000, 5001, max_glyphs=2))
        self.assertEqual(window.call_count, 1)
        self.assertEqual(membership.call_count, len(dataset["resources"]) * 2)
        self.assertEqual(result["event_count"], 2)
        self.assertFalse(getattr(service, "_timeline_query_indexes", {}))
        self.assertFalse(getattr(service, "_timeline_union_indexes", {}))
