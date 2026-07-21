"""Regression tests for the full-scale loader's lazy temporal indexes."""

from __future__ import annotations

import unittest

from router_dump_analyzer.scale_data import (
    _LazyIntervalMap,
    _ScaleTemporalIndex,
    _compact_event,
)


RESOURCE_ID = "data-bridge-layer/DTE/blue/dte-000001"
SNAPSHOT_ID = "control-plane/EVPN_ES/es-00001"


def event(
    uid: str,
    timestamp_ns: int,
    *,
    outcome: str,
    effect_type: str,
    after: dict[str, str],
) -> dict[str, object]:
    return _compact_event(
        {
            "event_uid": uid,
            "timestamp_ns": str(timestamp_ns),
            "source_sequence": timestamp_ns,
            "event_name": "resource_update",
            "action": effect_type,
            "outcome": outcome,
            "state_changed": True,
            "layer": "data-bridge-layer",
            "resource_id": RESOURCE_ID,
            "resource_kind": "DTE",
            "resource": RESOURCE_ID,
            "effects": [
                {
                    "resource_id": RESOURCE_ID,
                    "kind": "DTE",
                    "effect_type": effect_type,
                    "state_changed": True,
                    "after": after,
                }
            ],
            "properties": {},
            "result": {"updateStatus": "Ok" if outcome == "success" else "Error"},
        }
    )


class LazyScaleTemporalIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.create = event(
            "event-create",
            10,
            outcome="success",
            effect_type="create",
            after={"status": "active", "next_hop": "etg-a"},
        )
        self.failure = event(
            "event-failure",
            20,
            outcome="failure",
            effect_type="update",
            after={"status": "down", "next_hop": "etg-b"},
        )
        self.update = event(
            "event-update",
            30,
            outcome="success",
            effect_type="update",
            after={"next_hop": "etg-c"},
        )
        resources = {
            RESOURCE_ID: {
                "resource_id": RESOURCE_ID,
                "state": {"status": "programmed", "next_hop": "snapshot-etg"},
            },
            SNAPSHOT_ID: {
                "resource_id": SNAPSHOT_ID,
                "state": {"status": "up", "esi": "00:01"},
            },
        }
        events_by_resource = {
            RESOURCE_ID: [self.create, self.failure, self.update],
        }
        self.index = _ScaleTemporalIndex(resources, events_by_resource)
        self.lifecycle = _LazyIntervalMap(
            resources,
            self.index.lifecycle_intervals,
        )
        self.states = _LazyIntervalMap(resources, self.index.state_intervals)

    def test_state_intervals_are_built_lazily_and_failures_do_not_mutate(self) -> None:
        intervals = self.states[RESOURCE_ID]

        self.assertIs(intervals, self.states[RESOURCE_ID])
        self.assertEqual(len(intervals), 2)
        self.assertEqual(intervals[0]["valid_from_ns"], "10")
        self.assertEqual(intervals[0]["valid_to_ns"], "30")
        self.assertEqual(intervals[0]["properties"]["next_hop"], "etg-a")
        self.assertEqual(intervals[1]["valid_from_ns"], "30")
        self.assertIsNone(intervals[1]["valid_to_ns"])
        self.assertEqual(intervals[1]["properties"]["next_hop"], "etg-c")
        self.assertEqual(intervals[1]["status"], "active")

    def test_lifecycle_and_snapshot_fallback_match_eager_contract(self) -> None:
        lifecycle = self.lifecycle[RESOURCE_ID]
        snapshot = self.states[SNAPSHOT_ID]

        self.assertEqual(lifecycle[0]["valid_from_ns"], "10")
        self.assertEqual(lifecycle[0]["start_event_uid"], "event-create")
        self.assertEqual(lifecycle[0]["quality"], "exact")
        self.assertEqual(snapshot[0]["quality"], "observed_snapshot")
        self.assertEqual(snapshot[0]["properties"]["esi"], "00:01")
        sentinel = object()
        self.assertIs(self.states.get("missing", sentinel), sentinel)

    def test_compactor_retains_only_successful_state_payloads(self) -> None:
        self.assertEqual(
            self.create["effects"][0]["after"]["next_hop"],
            "etg-a",
        )
        self.assertNotIn("after", self.failure["effects"][0])


if __name__ == "__main__":
    unittest.main()
