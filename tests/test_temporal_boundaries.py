from __future__ import annotations

import unittest

from router_dump_analyzer.normalized_data import overlaps_range
from router_dump_analyzer.temporal_topology import TemporalTopologyService
from router_dump_analyzer.web.runtime_api import _overlaps_window


class TemporalBoundaryTests(unittest.TestCase):
    def test_state_intervals_use_half_open_intersection(self) -> None:
        self.assertFalse(overlaps_range(0, 10, 10, 20))
        self.assertFalse(overlaps_range(20, 30, 10, 20))
        self.assertTrue(overlaps_range(0, 11, 10, 20))
        self.assertTrue(overlaps_range(19, 30, 10, 20))
        self.assertTrue(overlaps_range(None, None, 10, 20))
        self.assertFalse(_overlaps_window(0, 10, 10, 20))
        self.assertFalse(_overlaps_window(20, 30, 10, 20))


class TemporalReplayOrderingTests(unittest.TestCase):
    @staticmethod
    def _service(
        events: list[dict],
        *,
        state_reader=None,
    ) -> TemporalTopologyService:
        return TemporalTopologyService(
            {
                "resources": [
                    {
                        "resource_id": "node-a/layer/THING/1",
                        "layer": "layer",
                        "kind": "THING",
                        "label": "thing",
                        # A current snapshot is not historical evidence when
                        # no state reader is installed.
                        "state": {"status": "snapshot-only"},
                    }
                ],
                "events": events,
                "relationship_mutations": [],
            },
            state_reader,
            lambda _timestamp: [],
            contract={
                "nodes": [
                    {
                        "node_id": "node-a",
                        "clocks": {
                            "observed": {
                                "clock_domain": "test",
                                "local_minus_absolute_ns": 0,
                                "uncertainty_ns": 0,
                            }
                        },
                    }
                ]
            },
            temporal_metadata={
                "revision_id": "revision:test",
                "timeline_start_ns": 0,
                "timeline_end_ns": 1_000,
                "capture_ns": 1_000,
                "default_node": "node-a",
            },
        )

    @staticmethod
    def _event(
        uid: str,
        timestamp: int,
        sequence: int,
        operation: str,
        after: dict,
    ) -> dict:
        resource_id = "node-a/layer/THING/1"
        return {
            "event_uid": uid,
            "timestamp_ns": timestamp,
            "source_sequence": sequence,
            "layer": "layer",
            "resource_id": resource_id,
            "affected_resources": [resource_id],
            "state_changed": True,
            "effects": [
                {
                    "resource_id": resource_id,
                    "effect_type": operation,
                    "after": after,
                    "state_changed": True,
                }
            ],
        }

    @staticmethod
    def _perspective() -> dict:
        return {
            "perspective_id": "observed",
            "layer": "layer",
            "usable_statuses": ["up"],
            "unusable_statuses": ["down"],
        }

    def test_modify_after_delete_retains_latent_state_without_recreating(self) -> None:
        service = self._service(
            [
                self._event("create", 100, 1, "create", {"status": "up"}),
                self._event("delete", 200, 2, "delete", {"reason": "gone"}),
                self._event("modify", 300, 3, "modify", {"generation": 2}),
                self._event("recreate", 400, 4, "add", {"status": "up"}),
            ]
        )
        record = service.resource_by_id["node-a/layer/THING/1"]
        perspective = self._perspective()
        entries = service._perspective_status_events(
            record["resource_id"], perspective
        )

        deleted = service._perspective_state_at(
            record, perspective, 350, entries
        )
        self.assertFalse(deleted["exists"])
        self.assertEqual(deleted["status"], "absent")
        self.assertEqual(deleted["state"]["generation"], 2)

        recreated = service._perspective_state_at(
            record, perspective, 450, entries
        )
        self.assertTrue(recreated["exists"])
        self.assertEqual(recreated["state"], {"status": "up"})

    def test_same_timestamp_events_follow_source_sequence(self) -> None:
        service = self._service(
            [
                self._event("second", 100, 20, "modify", {"status": "down"}),
                self._event("first", 100, 10, "create", {"status": "up"}),
            ]
        )
        record = service.resource_by_id["node-a/layer/THING/1"]
        perspective = self._perspective()
        entries = service._perspective_status_events(
            record["resource_id"], perspective
        )
        self.assertEqual(
            [item["event_uid"] for item in entries],
            ["first", "second"],
        )
        after_first = service._perspective_state_at(
            record,
            perspective,
            100,
            entries,
            through_order=(100, 10, "first", 2**31 - 1),
        )
        after_second = service._perspective_state_at(
            record,
            perspective,
            100,
            entries,
            through_order=(100, 20, "second", 2**31 - 1),
        )
        self.assertEqual(after_first["status"], "up")
        self.assertEqual(after_second["status"], "down")

    def test_change_stream_reports_same_timestamp_steps_sequentially(self) -> None:
        service = self._service(
            [
                self._event("second", 100, 20, "modify", {"status": "down"}),
                self._event("first", 100, 10, "create", {"status": "up"}),
            ]
        )

        changes, metadata = service._changes(
            {"relationship_types": []},
            self._perspective(),
            100,
            100,
            {"node-a/layer/THING/1"},
            10,
            after=None,
            position=0,
        )

        self.assertFalse(metadata["truncated"])
        self.assertEqual(
            [item["event_uid"] for item in changes],
            ["first", "second"],
        )
        self.assertEqual(changes[0]["after"]["status"], "up")
        self.assertEqual(changes[1]["before"]["status"], "up")
        self.assertEqual(changes[1]["after"]["status"], "down")

    def test_missing_reader_and_future_event_do_not_claim_native_evidence(self) -> None:
        service = self._service(
            [
                self._event(
                    "future",
                    500,
                    1,
                    "modify",
                    {"status": "up"},
                )
            ]
        )
        record = service.resource_by_id["node-a/layer/THING/1"]
        perspective = self._perspective()
        state = service._perspective_state_at(
            record,
            perspective,
            100,
            service._perspective_status_events(
                record["resource_id"], perspective
            ),
        )
        self.assertIsNone(state["exists"])
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["quality"], "unknown")


if __name__ == "__main__":
    unittest.main()
