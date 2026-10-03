"""Exact queries avoid retaining retired histories and repeating broad work."""
import gc
import unittest
import weakref
from copy import copy
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer._query_generation import generation_queries
from router_dump_analyzer.revision_queries import (
    EventLogQuery, TimelineQuery, _density_index, _timeline_index,
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
