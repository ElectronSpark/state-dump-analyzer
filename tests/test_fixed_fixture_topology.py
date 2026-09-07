from __future__ import annotations

import copy
import unittest
from unittest.mock import Mock

from router_dump_analyzer.route_topology import MultiNodeTopologyRequestError
from router_dump_analyzer.value_core import snapshot_json_value
from tests.support.fixed_fixture_topology import FixedFixtureTopologyMemoizer


class _RetainedTopology:
    def __init__(self):
        self.contexts = {}
        self.query_count = 0
        self.failure = None
        self.retain = True

    def query(self, body):
        self.query_count += 1
        if self.failure is not None:
            raise self.failure
        response = {
            "context_id": f"tctx1-{self.query_count}",
            "request": copy.deepcopy(body),
            "nodes": [{"labels": ["original"]}],
        }
        if self.retain:
            self.contexts[response["context_id"]] = snapshot_json_value(response)
        return response

    def context_snapshot(self, context_id):
        return self.contexts.get(context_id)


class FixedFixtureTopologyMemoizerTests(unittest.TestCase):
    def setUp(self):
        self.delegate = _RetainedTopology()
        self.memoizer = FixedFixtureTopologyMemoizer(self.delegate)
        self.body = {
            "basis": {"kind": "relative_to_watermark", "offset_ns": "0"},
            "clock_policy": "best_effort",
            "resource_limit": 500,
            "inter_node_link_limit": 1000,
            "network_segment_limit": 500,
            "segment_attachment_limit": 4000,
            "node_queries": [
                {
                    "node_id": "a",
                    "plugin_set_id": "set",
                    "projections": [
                        {
                            "projection_id": "p",
                            "status_perspective_id": "seen",
                        }
                    ],
                }
            ],
        }

    def test_complete_request_key_keeps_every_selector_and_limit(self):
        variants = []
        for field, value in (
            ("clock_policy", "strict"),
            ("resource_limit", 499),
            ("inter_node_link_limit", 999),
            ("network_segment_limit", 499),
            ("segment_attachment_limit", 3999),
            ("future_selector", "new-selection"),
        ):
            changed = copy.deepcopy(self.body)
            changed[field] = value
            variants.append((field, changed))
        for field, value in (
            ("node_id", "b"),
            ("plugin_set_id", "other"),
            ("basis", {"kind": "absolute", "timestamp_ns": "3"}),
        ):
            changed = copy.deepcopy(self.body)
            changed["node_queries"][0][field] = value
            variants.append((f"node.{field}", changed))
        for field, value in (
            ("projection_id", "q"),
            ("status_perspective_id", "reported"),
        ):
            changed = copy.deepcopy(self.body)
            changed["node_queries"][0]["projections"][0][field] = value
            variants.append((f"projection.{field}", changed))
        changed = copy.deepcopy(self.body)
        changed["basis"]["offset_ns"] = "-1"
        variants.append(("global basis", changed))

        for label, changed in variants:
            with self.subTest(selector=label):
                delegate = _RetainedTopology()
                memoizer = FixedFixtureTopologyMemoizer(delegate)
                first = memoizer.query(self.body)
                second = memoizer.query(changed)
                self.assertNotEqual(first["context_id"], second["context_id"])
                self.assertEqual(memoizer.query(self.body), first)
                self.assertEqual(delegate.query_count, 2)

    def test_mapping_order_reuses_but_array_order_and_scalar_types_do_not(self):
        first = self.memoizer.query(self.body)
        reordered = {key: self.body[key] for key in reversed(self.body)}
        self.assertEqual(self.memoizer.query(reordered), first)
        self.assertEqual(self.delegate.query_count, 1)
        bodies = (
            {"node_ids": ["a", "b"]},
            {"node_ids": ["b", "a"]},
            {"node_queries": [{"node_id": "a"}, {"node_id": "b"}]},
            {"node_queries": [{"node_id": "b"}, {"node_id": "a"}]},
            {"selector": True},
            {"selector": 1},
            {"selector": "1"},
        )
        for body in bodies:
            before = self.delegate.query_count
            self.memoizer.query(body)
            self.assertEqual(self.delegate.query_count, before + 1)

    def test_wire_copies_and_input_aliases_cannot_change_retained_results(self):
        original_body = copy.deepcopy(self.body)
        first = self.memoizer.query(self.body)
        first["nodes"][0]["labels"][0] = "changed"
        self.body["node_queries"][0]["node_id"] = "caller-change"
        second = self.memoizer.query(original_body)
        self.assertEqual(second["nodes"][0]["labels"], ["original"])
        self.assertEqual(second["request"], original_body)
        second["request"]["node_queries"].clear()
        self.assertEqual(self.memoizer.query(original_body)["request"], original_body)
        self.assertEqual(self.delegate.query_count, 1)

    def test_replaced_or_evicted_context_is_recomputed(self):
        first = self.memoizer.query(self.body)
        self.delegate.contexts[first["context_id"]] = snapshot_json_value(first)
        second = self.memoizer.query(self.body)
        self.assertNotEqual(second["context_id"], first["context_id"])
        del self.delegate.contexts[second["context_id"]]
        third = self.memoizer.query(self.body)
        self.assertNotEqual(third["context_id"], second["context_id"])
        self.assertEqual(self.delegate.query_count, 3)

    def test_query_count_and_key_size_are_bounded(self):
        self.memoizer.query({"selection": 0})
        for selection in range(1, self.memoizer.MAX_QUERIES + 1):
            self.memoizer.query({"selection": selection})
        before = self.delegate.query_count
        self.memoizer.query({"selection": 0})
        self.assertEqual(self.delegate.query_count, before + 1)
        before = self.delegate.query_count
        with self.assertRaisesRegex(AssertionError, "key budget"):
            self.memoizer.query({"selection": "x" * self.memoizer.MAX_KEY_BYTES})
        self.assertEqual(self.delegate.query_count, before)

    def test_query_failures_and_unretained_results_are_never_cached(self):
        self.delegate.failure = MultiNodeTopologyRequestError("invalid selection")
        with self.assertRaisesRegex(MultiNodeTopologyRequestError, "invalid selection"):
            self.memoizer.query(self.body)
        self.delegate.failure = None
        self.delegate.retain = False
        with self.assertRaisesRegex(AssertionError, "exact wire result"):
            self.memoizer.query(self.body)
        self.delegate.retain = True
        self.memoizer.query(self.body)
        self.assertEqual(self.delegate.query_count, 3)
        self.assertEqual(self.memoizer.query_misses, 1)
        self.assertEqual(self.memoizer.query_hits, 0)

    def test_other_protocol_operations_remain_with_the_same_context_owner(self):
        owner = Mock(assembly_id="assembly", topology_id="topology", start_ns=3)
        memoizer = FixedFixtureTopologyMemoizer(owner)
        self.assertEqual(
            (memoizer.assembly_id, memoizer.topology_id, memoizer.start_ns),
            ("assembly", "topology", 3),
        )
        calls = (
            ("context_snapshot", ("context",)),
            ("route_catalog", ()),
            ("node_contract", ("a",)),
            ("normalize_node_queries", (self.body,)),
            ("normalize_projection_selection", ("a", self.body)),
            ("normalize_basis", (self.body["basis"], "node basis")),
            ("capabilities", ()),
        )
        for name, args in calls:
            with self.subTest(operation=name):
                expected = getattr(owner, name).return_value
                self.assertIs(getattr(memoizer, name)(*args), expected)
                getattr(owner, name).assert_called_once_with(*args)


if __name__ == "__main__":
    unittest.main()
