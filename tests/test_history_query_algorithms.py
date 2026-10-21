"""Exact queries avoid retaining retired histories and repeating broad work."""
import gc
import unittest
import weakref
from collections.abc import Sequence
from copy import copy
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer._query_generation import generation_queries
from router_dump_analyzer.revision_queries import (
    EventLogQuery,
    RevisionQueryService,
    TimelineQuery,
    _density_index,
    _timeline_index,
    _timeline_unique_count,
)
from tests.test_revision_queries import query_fixture
from tests.test_zoom_timeline import populated_fixture


class WeakRuntime(SimpleNamespace):
    pass


class HistoryQueryAlgorithms(unittest.TestCase):
    def test_density_cache_does_not_pin_retired_generation(self):
        service = SimpleNamespace()
        runtime = WeakRuntime(events=[], event_times=[], failure_event_times=[], event_times_by_type={})
        reference = weakref.ref(runtime)
        density = _density_index(service, "same", runtime, lambda: None)
        del runtime
        gc.collect()
        self.assertIsNone(reference())
        self.assertFalse(hasattr(service, "_density_query_indexes"))
        self.assertEqual(density.page(start_ns=0, integer_span=1, bin_count=1,
                                     bin_start_index=0, bin_end_index=1), {})

    def test_timeline_cache_lives_with_generation_and_active_reader(self):
        runtime = WeakRuntime()
        scope = generation_queries(runtime)
        index = _timeline_index(scope, "r", "a", [
            {"event_uid": "a", "timestamp_ns": "4"}], (), lambda: None)
        scope_ref = weakref.ref(scope)
        del scope, runtime
        gc.collect()
        self.assertIsNone(scope_ref())
        # A request already using its index can finish after retirement.
        self.assertEqual(index[0][0]["event_uid"], "a")

    def test_shallow_runtime_replacement_gets_a_new_scope(self):
        first = WeakRuntime()
        old = generation_queries(first)
        second = copy(first)
        self.assertIsNot(generation_queries(second), old)
        self.assertIs(generation_queries(first), old)

    def test_immutable_adapter_uses_request_local_cache(self):
        class Immutable:
            __slots__ = ()
        runtime = Immutable()
        self.assertIsNot(generation_queries(runtime), generation_queries(runtime))

    def test_cold_ordered_closeup_does_not_walk_whole_lane(self):
        dataset, service, queries = populated_fixture(30000)
        class OrderedOnly(list):
            reads = 0
            def __iter__(self):
                raise AssertionError("walked complete lane")
            def __getitem__(self, key):
                self.reads += 1
                return super().__getitem__(key)
        source = OrderedOnly(dataset["events"])
        runtime = queries.indexed_history
        runtime.events_by_resource["root"] = source
        runtime.ordered_events_by_resource = runtime.events_by_resource
        result = queries.timeline(TimelineQuery(12000, 12004, resource_ids=("root",)))
        self.assertEqual(result["event_count"], 5)
        self.assertLess(source.reads, 40)
        self.assertEqual([m["time_ns"] for m in result["lanes"][0]["event_marks"]],
                         [str(i) for i in range(12000, 12005)])

    def test_cold_union_counts_only_windows_and_deduplicates(self):
        class Source(list):
            def __iter__(self):
                raise AssertionError("whole union scanned")
        a = Source({"event_uid": str(i), "timestamp_ns": str(i)} for i in range(10000))
        b = Source(a[:])
        self.assertEqual(_timeline_unique_count(
            SimpleNamespace(), "r", [a,b], 700, 704, lambda: None,
            windows=[(a,700,705),(b,700,705)]), 5)

    def test_layer_filter_is_reused_across_pages(self):
        dataset, service, queries = query_fixture(indexed=True)
        query = dict(source_types=(), search="needle", layers=("opaque-layer",), limit=1)
        first = queries.event_log(EventLogQuery(**query))
        with patch("router_dump_analyzer.revision_queries.event_layer_values",
                   side_effect=AssertionError("repeated layer projection")):
            second = queries.event_log(EventLogQuery(**query, offset=1))
        self.assertEqual(first["total_count"], 3)
        self.assertEqual(second["items"][0]["uid"], "event-1")
        self.assertNotIn("private-sentinel", str(first))
        self.assertNotIn("private-sentinel", str(second))

    def test_indexed_merge_matches_exact_sort_for_pages_ranges_and_locates(self):
        dataset, service, queries = query_fixture(indexed=True)
        template = dataset["events"][0]
        events = [
            dict(template, event_uid=uid, timestamp_ns=str(stamp), source_sequence=seq)
            for uid, stamp, seq in [
                ("duplicate", -10, 0), ("before", -1, 0),
                ("duplicate", 0, 1), ("\ue000", 0, 2), ("\U00010000", 0, 2),
                ("later", 1, 0), ("last", 10, 0), ("", 50, 0),
            ]
        ]
        runtime = queries.indexed_history
        dataset["events"] = runtime.events = events
        runtime.event_times = [int(event["timestamp_ns"]) for event in events]
        runtime.event_index_by_uid = {
            event["event_uid"]: i for i, event in enumerate(events) if event["event_uid"]
        }
        runtime.event_by_uid = {event["event_uid"]: event for event in events}
        dataset["source_records"] = [
            {"source_record_uid": uid, "timestamp_ns": stamp,
             "source_sequence": sequence, "source_type": kind, "layer": "opaque-layer"}
            for uid, stamp, sequence, kind in [
                ("unknown", None, 0, "trace"), ("duplicate", "0", 1, "trace"),
                ("early", "-20", 0, "trace"), ("tie", "0", 2, "trace"),
                ("late", "20", 0, "second"), ("middle", "1", 1, "second"),
                ("duplicate", "-10", 0, "trace"),
            ]
        ]
        exact = RevisionQueryService(service, revision_id=queries.revision_id, dataset=dataset)
        for selected_range in (None, (0, 0), (-10, -1), (2, 9), (-100, 100)):
            for source_types in (None, ("trace",), ("second",)):
                for offset in (0, 1, 4, 8, 12, 30):
                    for locate in (None, ("event", "duplicate"), ("event", "last"),
                                   ("source", "duplicate"), ("source", "unknown"),
                                   ("event", "missing"), ("event", "event-7")):
                        query = EventLogQuery(
                            selected_range=selected_range, source_types=source_types,
                            offset=offset, limit=3, locate=locate,
                        )
                        with self.subTest(query=query):
                            self.assertEqual(queries.event_log(query), exact.event_log(query))
        for query in (
            EventLogQuery(layers=("opaque-layer",)),
            EventLogQuery(search="needle"),
            EventLogQuery(search="private-sentinel"),
            EventLogQuery(include_normalized=False, source_types=("trace",)),
        ):
            with self.subTest(query=query):
                self.assertEqual(queries.event_log(query), exact.event_log(query))

    def test_million_event_merge_reads_only_ties_and_page_at_deep_offset(self):
        dataset, _, queries = query_fixture(indexed=True)
        template = dataset["events"][0]

        class Events(Sequence):
            reads = 0
            def __len__(self):
                return 1_000_000
            def __getitem__(self, index):
                if not isinstance(index, int) or not 0 <= index < len(self):
                    raise AssertionError("unbounded event traversal")
                self.reads += 1
                if self.reads > 100:
                    raise AssertionError("merge visited the complete event stream")
                return dict(template, event_uid=f"event-{index}", timestamp_ns=str(index))

        class Ordinals:
            def __len__(self):
                return 1_000_000
            def get(self, uid):
                return 900_000 if uid == "event-900000" else None

        runtime = queries.indexed_history
        runtime.events = Events()
        runtime.event_times = range(1_000_000)
        runtime.event_index_by_uid = Ordinals()
        dataset["source_records"] = [
            {"source_record_uid": uid, "timestamp_ns": stamp, "source_type": "trace"}
            for uid, stamp in (("early", "99"), ("middle", "500000"), ("untimed", None))
        ]
        result = queries.event_log(EventLogQuery(
            source_types=("trace",), offset=900_000, limit=7,
            locate=("event", "event-900000"),
        ))
        self.assertEqual(result["total_count"], 1_000_003)
        self.assertEqual(result["located_display_index"], 900_002)
        self.assertEqual([item["uid"] for item in result["items"]],
                         [f"event-{i}" for i in range(899_998, 900_005)])
        self.assertLess(runtime.events.reads, 15)
        result = queries.event_log(EventLogQuery(
            source_types=("trace",), selected_range=(500_000, 500_002),
            offset=999_999, limit=7, locate=("source", "untimed"),
        ))
        self.assertEqual(result["inside_count"], 4)
        self.assertEqual(result["located_display_index"], 1_000_002)
        self.assertEqual([item["uid"] for item in result["items"]],
                         ["event-999997", "event-999998", "event-999999", "untimed"])
        self.assertLess(runtime.events.reads, 25)
