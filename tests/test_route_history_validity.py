from __future__ import annotations

import unittest
from types import SimpleNamespace

from rsl_demo_plugin.typed_topology import (
    _claim_state,
    _DemoTopologyProjectionStateProvider,
)

from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.plugin_api import Quality


class RouteHistoryValidityTests(unittest.TestCase):
    def test_native_validity_is_half_open_and_covers_clock_uncertainty(self) -> None:
        row = {"observed_at_ns": "100", "valid_to_ns": "200"}
        valid = MultiNodeRouteService._route_evidence_valid_at
        for timestamp, expected in ((99, False), (100, True), (199, True), (200, False)):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(valid(row, {
                    "local_time_ns": str(timestamp), "query_time_ns": "999",
                    "uncertainty_ns": "0",
                }), expected)
        self.assertFalse(valid(row, {"local_time_ns": "100", "uncertainty_ns": "1"}))
        self.assertTrue(valid(row, {"local_time_ns": "101", "uncertainty_ns": "1"}))
        self.assertFalse(valid(row, {"local_time_ns": "199", "uncertainty_ns": "1"}))
        self.assertFalse(valid(row, {}))
        self.assertTrue(valid({**row, "valid_from_ns": "50"}, {"local_time_ns": "75"}))
        self.assertFalse(valid(row, {
            "local_time_ns": "198", "query_time_ns": "998",
            "absolute_min_ns": "997", "absolute_max_ns": "1000",
        }))

    def test_typed_claim_replays_carrier_lifecycle_and_failed_changes(self) -> None:
        claim = _claim_state("node-a", {
            "interface_resource_id": "node-a/interface/1", "claim_id": "c1",
            "segment_key": "s1", "subnet": {"render_hint": "direct_line"},
            "status": "usable", "confidence": "exact", "valid_from_ns": "10",
        })
        provider = _DemoTopologyProjectionStateProvider(
            {"instance": {claim.resource: claim}},
            {"instance": {"node-a/interface/1": {
                "initial_status": "up", "valid_from_ns": "10",
                "changes": [
                    {"time_ns": "20", "status": "down"},
                    {"time_ns": "30", "status": "up", "state_changed": False},
                    {"time_ns": "40", "status": "up"},
                    {"time_ns": "50", "operation": "delete"},
                    {"time_ns": "60", "operation": "restore", "exists": True},
                ],
            }}},
        )
        pin = SimpleNamespace(pin=SimpleNamespace(instance_id="instance"))
        for timestamp, exists, status in (
            (9, False, "absent"), (10, True, "up"), (19, True, "up"),
            (20, True, "down"), (30, True, "down"), (40, True, "up"),
            (50, False, "absent"), (60, True, "up"), (20, True, "down"),
        ):
            with self.subTest(timestamp=timestamp):
                result = provider(pin, "observed", {"query_time_ns": str(timestamp)})
                self.assertEqual(result[claim.resource].exists, exists)
                self.assertEqual(result[claim.resource].properties["status"], status)
        ambiguous = provider(pin, "observed", {
            "query_time_ns": "20", "absolute_min_ns": "19", "absolute_max_ns": "21",
        })[claim.resource]
        self.assertIsNone(ambiguous.exists)
        self.assertEqual(ambiguous.properties["status"], "ambiguous")
        self.assertEqual(ambiguous.quality, Quality.AMBIGUOUS)
        zero = provider(pin, "observed", {
            "query_time_ns": 0, "local_time_ns": "20",
            "absolute_min_ns": 0, "absolute_max_ns": 0,
        })[claim.resource]
        self.assertFalse(zero.exists)
        self.assertEqual(claim.properties["status"], "usable")


if __name__ == "__main__":
    unittest.main()
