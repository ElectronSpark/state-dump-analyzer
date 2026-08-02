from __future__ import annotations

import unittest

from router_dump_analyzer.normalized_data import overlaps_range
from router_dump_analyzer.temporal_core import (
    MAX_TEMPORAL_NS,
    MIN_TEMPORAL_NS,
    checked_temporal_add,
    checked_temporal_subtract,
    temporal_integer,
)
from router_dump_analyzer.temporal_topology import (
    TemporalTopologyRequestError,
    TemporalTopologyService,
    _ns,
)
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

    def test_shared_temporal_integer_and_arithmetic_are_signed_64(self) -> None:
        self.assertEqual(temporal_integer(str(MIN_TEMPORAL_NS), "time"), MIN_TEMPORAL_NS)
        self.assertEqual(temporal_integer(str(MAX_TEMPORAL_NS), "time"), MAX_TEMPORAL_NS)
        self.assertEqual(checked_temporal_add(MAX_TEMPORAL_NS, 0, "time"), MAX_TEMPORAL_NS)
        self.assertEqual(
            checked_temporal_subtract(MIN_TEMPORAL_NS, 0, "time"),
            MIN_TEMPORAL_NS,
        )
        for operation in (
            lambda: temporal_integer(str(MAX_TEMPORAL_NS + 1), "time"),
            lambda: temporal_integer(str(MIN_TEMPORAL_NS - 1), "time"),
            lambda: checked_temporal_add(MAX_TEMPORAL_NS, 1, "time"),
            lambda: checked_temporal_subtract(MIN_TEMPORAL_NS, 1, "time"),
        ):
            with self.assertRaises(ValueError):
                operation()


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

    def test_insert_is_a_lifecycle_creation_operation(self) -> None:
        service = self._service(
            [
                self._event(
                    "insert",
                    100,
                    1,
                    "insert",
                    {"status": "up"},
                )
            ]
        )
        record = service.resource_by_id["node-a/layer/THING/1"]
        perspective = self._perspective()
        entries = service._perspective_status_events(
            record["resource_id"], perspective
        )

        self.assertFalse(
            service._perspective_state_at(
                record, perspective, 99, entries
            )["exists"]
        )
        self.assertTrue(
            service._perspective_state_at(
                record, perspective, 100, entries
            )["exists"]
        )

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
            101,
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

    def test_adjacent_change_windows_do_not_duplicate_boundary_events(
        self,
    ) -> None:
        service = self._service(
            [
                self._event(
                    "boundary",
                    100,
                    10,
                    "create",
                    {"status": "up"},
                )
            ]
        )

        before, _ = service._changes(
            {"relationship_types": []},
            self._perspective(),
            0,
            100,
            {"node-a/layer/THING/1"},
            10,
            after=None,
            position=0,
        )
        after, _ = service._changes(
            {"relationship_types": []},
            self._perspective(),
            100,
            101,
            {"node-a/layer/THING/1"},
            10,
            after=None,
            position=0,
        )

        self.assertEqual(before, [])
        self.assertEqual(
            [item["event_uid"] for item in after],
            ["boundary"],
        )

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

    def test_validity_only_transition_is_ambiguous_in_clock_window(self) -> None:
        service = self._service(
            [
                self._event(
                    "same-state",
                    200,
                    1,
                    "modify",
                    {"status": "up", "generation": 1},
                )
            ],
            state_reader=lambda _resource_id, _timestamp_ns: {
                "exists": True,
                "status": "up",
                "state": {"status": "up", "generation": 1},
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "quality": "exact",
            },
        )
        record = service.resource_by_id["node-a/layer/THING/1"]

        result = service._state_with_uncertainty(
            record,
            "node-a",
            {
                "query_time_ns": "200",
                "resolved_at_min_ns": "190",
                "resolved_at_max_ns": "210",
                "uncertainty_ns": "20",
            },
            self._perspective(),
        )

        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(
            {
                (item["valid_from_ns"], item["valid_to_ns"])
                for item in result["possible_states"]
            },
            {("0", "200"), ("200", None)},
        )

    def test_uncomparable_state_fails_closed(self) -> None:
        cyclic_state: dict[str, object] = {"status": "up"}
        cyclic_state["cycle"] = cyclic_state
        service = self._service(
            [],
            state_reader=lambda _resource_id, _timestamp_ns: {
                "exists": True,
                "status": "up",
                "state": cyclic_state,
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "quality": "exact",
            },
        )
        record = service.resource_by_id["node-a/layer/THING/1"]

        result = service._state_with_uncertainty(
            record,
            "node-a",
            {
                "query_time_ns": "200",
                "resolved_at_min_ns": "200",
                "resolved_at_max_ns": "200",
                "uncertainty_ns": "0",
            },
            self._perspective(),
        )

        self.assertIsNone(result["exists"])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["temporal_resolution"], "unknown")
        self.assertEqual(
            result["unknown_fields"][0]["reason_code"],
            "state_comparison_unavailable",
        )

    def test_float_nanoseconds_are_rejected_with_existing_error_contract(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            TemporalTopologyRequestError,
            "^basis.time_ns must be an integer nanosecond value$",
        ):
            _ns(1.5, "basis.time_ns")

    def test_ordering_cursor_version_rejects_stale_handles(self) -> None:
        service = self._service([])
        token = service._encode_cursor(
            "resource",
            "query-fingerprint",
            position=1,
        )
        self.assertTrue(token.startswith("tt2."))
        stale = token.replace("tt2.", "tt1.", 1)

        with self.assertRaisesRegex(
            TemporalTopologyRequestError,
            "^invalid resource_cursor$",
        ):
            service._decode_cursor(
                stale,
                "resource",
                "query-fingerprint",
            )


if __name__ == "__main__":
    unittest.main()
