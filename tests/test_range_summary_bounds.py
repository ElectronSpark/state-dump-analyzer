"""Exact range facts without unbounded display projection or request copies."""

from __future__ import annotations

import json
import unittest
from collections import Counter, UserDict
from unittest.mock import patch

from router_dump_analyzer.normalized_data import MAX_RANGE_DETAILS
from router_dump_analyzer.revision_queries import TimelineQuery
from tests.test_revision_queries import query_fixture


class DetailBoundedSequence(list):
    def __getitem__(self, key):
        if isinstance(key, slice) and len(range(*key.indices(len(self)))) > MAX_RANGE_DETAILS:
            raise AssertionError("range query copied more than its detail budget")
        return super().__getitem__(key)


class RangeSummaryBoundsTests(unittest.TestCase):
    def test_indexed_summary_counts_the_full_window_but_projects_only_detail_budget(self):
        dataset, service, queries = query_fixture(indexed=True)
        runtime = queries.indexed_history
        events = DetailBoundedSequence([
            {**dataset["events"][0], "event_uid": f"event-{index}",
             "timestamp_ns": str(index), "action": "modify" if index < 600 else "remove",
             "outcome": "failure" if index >= 500 else "success",
             "affected_resources": ["root"] if index < 600 else ["child"]}
            for index in range(1_002)
        ])
        runtime.events = events
        runtime.event_times = list(range(len(events)))
        runtime.mutations = DetailBoundedSequence([
            {"source": "root", "target": "absent", "operation": "add",
             "effective_time_ns": str(index), "relation_type": "opaque-link",
             "attributes": {"secret": "private-sentinel", "public": index}}
            for index in range(1_002)
        ])
        runtime.mutation_times = list(range(len(runtime.mutations)))
        with patch.object(service, "redact_event_for_client", wraps=service.redact_event_for_client) as projection:
            summary = service.range_summary(1, 1_000)
        self.assertEqual(projection.call_count, MAX_RANGE_DETAILS)
        self.assertEqual(summary["event_count"], 1_000)
        self.assertEqual(summary["failure_count"], 501)
        self.assertEqual(summary["counts"], {
            "by_outcome": {"success": 499, "failure": 501},
            "by_action": {"modify": 599, "remove": 401},
        })
        self.assertEqual(summary["affected_resources"], ["absent", "child", "root"])
        self.assertEqual(summary["affected_resource_count"], 3)
        self.assertEqual(summary["endpoint_diff_evaluated_count"], 3)
        self.assertEqual(summary["relationship_change_count"], 1_000)
        self.assertEqual(len(summary["relationship_changes"]), MAX_RANGE_DETAILS)
        self.assertEqual([item["event_uid"] for item in summary["events"]],
                         [f"event-{index}" for index in range(1, 501)])
        self.assertTrue(summary["truncated"]["events"])
        self.assertTrue(summary["truncated"]["relationship_changes"])
        self.assertNotIn("private-sentinel", json.dumps(summary))
        reversed_range = service.range_summary(1_000, 1)
        self.assertEqual(reversed_range["event_count"], 0)
        self.assertEqual(reversed_range["relationship_change_count"], 0)
        self.assertEqual(reversed_range["events"], [])

    def test_indexed_aggregate_facts_match_safe_projection_for_generic_values(self):
        dataset, service, queries = query_fixture(indexed=True)
        runtime = queries.indexed_history
        base = dataset["events"][0]
        events = [
            UserDict({**base, "timestamp_ns": str(index), **fields})
            for index, fields in enumerate((
                {"outcome": {"secret": "private-sentinel"}, "action": ["private-sentinel"]},
                {"outcome": None, "action": False},
                {"outcome": "failure", "affected_resources": [
                    UserDict({"resource_id": "child", "properties": {"secret": "private-sentinel", "mode": "ready"}}),
                    "root", None, 0, ["private-sentinel"],
                ]},
                {"affected_resources": {"secret": "private-sentinel"}},
            ))
        ]
        events.append(UserDict({"event_uid": "missing-fields", "timestamp_ns": "4"}))
        runtime.events = events
        runtime.event_times = list(range(len(events)))
        runtime.mutation_times = []
        projected = [service.redact_event_for_client(event, dataset) for event in events]
        summary = service.range_summary(0, 4)
        self.assertEqual(summary["events"], projected)
        self.assertEqual(summary["counts"], {
            "by_outcome": dict(Counter(event.get("outcome", "unknown") for event in projected)),
            "by_action": dict(Counter(event.get("action", "unknown") for event in projected)),
        })
        self.assertEqual(summary["affected_resources"], sorted({
            str(identifier) for event in projected
            for identifier in event.get("affected_resources", []) if identifier
        }))
        self.assertNotIn("private-sentinel", json.dumps(summary))
        empty = service.range_summary(5, 6)
        self.assertEqual(empty["event_count"], 0)
        self.assertEqual(empty["failure_count"], 0)
        self.assertEqual(empty["counts"], {"by_outcome": {}, "by_action": {}})
        reversed_range = service.range_summary(4, 0)
        self.assertEqual(reversed_range["event_count"], 0)
        self.assertEqual(reversed_range["relationship_change_count"], 0)
        self.assertEqual(reversed_range["events"], [])

    def test_full_explicit_lane_budget_does_not_drop_late_roots_for_dependencies(self):
        dataset, _, queries = query_fixture(indexed=True)
        runtime = queries.indexed_history
        requested = [f"requested-{index:03d}" for index in range(100)]
        for identifier in requested:
            runtime.resource_by_id[identifier] = {
                **dataset["resources"][0], "resource_id": identifier,
            }
            runtime.relationships_by_endpoint[identifier] = [{
                "source": identifier, "target": "child", "relation_type": "opaque-link",
                "valid_from_ns": "0", "valid_to_ns": None,
            }]
        payload = queries.timeline(TimelineQuery(
            0, 100, resource_ids=tuple(requested),
            relationship_history_roots=tuple(requested),
        ))
        expansion = payload["relationship_history_expansion"]
        self.assertEqual(expansion["accepted_base_ids"], requested)
        self.assertEqual(expansion["dropped_base_ids"], [])
        self.assertEqual(expansion["dropped_root_ids"], [])
        self.assertEqual(expansion["accepted_resource_ids"], [])
        self.assertEqual(expansion["dropped_resource_ids"], ["child"])
        self.assertEqual({item["resource_id"] for item in payload["lanes"]}, set(requested))


if __name__ == "__main__":
    unittest.main()
