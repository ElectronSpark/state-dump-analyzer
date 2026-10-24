from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from rsl_demo_generator import _scale


class ScaleGeneratorOptimizationTests(unittest.TestCase):
    def test_multihome_intervals_match_each_attachment_event(self) -> None:
        for resource_count in (75, 120, 7_500):
            layout = _scale._layout(resource_count)
            phase = "multihome_add"
            start = _scale._phase_start_ns(phase)
            rows = [
                json.loads(line)
                for line in _scale._relationship_lines(12_500, layout)
            ]
            by_identity = {
                (row["source"], row["target"], row["relation_type"]): row
                for row in rows if row["phase"] == phase
            }
            for index in range(layout.multi_home_service_count):
                timestamp = start + index * _scale.EVENT_STEP_NS
                event = _scale._event_for_phase(phase, index, index, timestamp, layout)
                for effect in event["relationship_effects"]:
                    identity = (effect["source"], effect["target"], effect["type"])
                    with self.subTest(resource_count=resource_count, index=index, identity=identity):
                        row = by_identity[identity]
                        self.assertEqual(int(row["valid_from_ns"]), int(event["timestamp_ns"]))
                # Persisted backup routing/egress observations share its actual birth.
                backup = _scale._backup_ete_id(index)
                for row in rows:
                    if row["source"] == backup and row["phase"] == phase:
                        self.assertEqual(int(row["valid_from_ns"]), timestamp)

            # A later service reuses an already-existing ES and primary ETE.
            # Its membership must be absent before its own event, even though
            # endpoint lifecycle filtering can no longer conceal a wrong start.
            index = layout.es_count
            target = _scale._es_id(0)
            attachment = start + index * _scale.EVENT_STEP_NS
            members = [row for row in rows if row["target"] == target and row["relation_type"] == "member_of_es"]
            for timestamp, expected in ((attachment - 1, False), (attachment, True), (attachment + 1, True), (attachment - 1, False)):
                visible = {row["source"] for row in members if int(row["valid_from_ns"]) <= timestamp and (row["valid_to_ns"] is None or timestamp < int(row["valid_to_ns"]))}
                self.assertEqual(_scale._etg_id(index) in visible, expected)

    def test_es_event_counts_match_actual_shared_service_membership(self) -> None:
        for resource_count in (40, 75, 120, 7_500):
            layout = _scale._layout(resource_count)
            counts = {index: 0 for index in range(layout.es_count)}
            for index in range(layout.multi_home_service_count):
                counts[_scale._es_index(layout, index)] += 1
            for phase in ("mass_es_withdraw", "mass_es_restore"):
                for index, expected in counts.items():
                    with self.subTest(resource_count=resource_count, phase=phase, es=index):
                        event = _scale._event_for_phase(phase, index, index, _scale._phase_start_ns(phase) + index * _scale.EVENT_STEP_NS, layout)
                        self.assertEqual(event["properties"]["affected_services"], expected)

    def test_effect_declares_closed_condition_classes_without_core_inference(
        self,
    ) -> None:
        expected_classes = {
            "active": "healthy",
            "degraded": "degraded",
            "down": "error",
            "absent": "absent",
            "vendor-specific": "unknown",
        }

        for condition, expected_class in expected_classes.items():
            with self.subTest(condition=condition):
                effect = _scale._effect(
                    "node-a/data-bridge-layer/ETG/blue/etg-000000",
                    "ETG",
                    "state-change",
                    {"status": condition},
                )
                self.assertEqual(effect["condition"], condition)
                self.assertEqual(effect["status_class"], expected_class)

    def test_buffered_line_writer_preserves_bytes_count_and_digest(self) -> None:
        lines = [
            '{"ascii":1}',
            '{"unicode":"邻居"}',
            "",
            "x" * (_scale.WRITE_BUFFER_BYTES + 17),
            '{"tail":true}',
        ]
        expected = "".join(f"{line}\n" for line in lines).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "records.jsonl"
            count, digest = _scale._write_lines(path, iter(lines))
            actual = path.read_bytes()

        self.assertEqual(count, len(lines))
        self.assertEqual(actual, expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())

    def test_analytic_churn_counts_and_targets_match_reference_scan(self) -> None:
        for event_count, resource_count in (
            (0, 0),
            (1, 8),
            (7, 40),
            (120, 120),
            (25_000, 2_500),
            (125_000, 7_500),
            (1_250_000, 7_500),
        ):
            with self.subTest(
                event_count=event_count,
                resource_count=resource_count,
            ):
                layout = _scale._layout(resource_count)
                churn_count = _scale._phase_event_counts(event_count)[
                    "next_hop_churn"
                ]
                reference_success_count = sum(
                    not _scale._churn_transition(layout, local_index)[4]
                    for local_index in range(churn_count)
                ) if layout.multi_home_service_count else 0
                self.assertEqual(
                    _scale._churn_success_count(event_count, layout),
                    reference_success_count,
                )

                service_indexes = range(layout.multi_home_service_count)
                if layout.multi_home_service_count > 64:
                    service_indexes = (
                        *range(32),
                        *range(
                            layout.multi_home_service_count - 32,
                            layout.multi_home_service_count,
                        ),
                    )
                for service_index in service_indexes:
                    target = _scale._etg_id(service_index)
                    successful = []
                    for local_index in range(
                        service_index,
                        churn_count,
                        layout.multi_home_service_count,
                    ):
                        (
                            _index,
                            _occurrence,
                            before,
                            after,
                            failed,
                            _generation,
                        ) = _scale._churn_transition(layout, local_index)
                        if not failed:
                            successful.append((local_index, before, after))
                            target = after
                    self.assertEqual(
                        _scale._final_churn_target(
                            event_count,
                            layout,
                            service_index,
                        ),
                        target,
                    )
                    self.assertEqual(
                        _scale._successful_churn_transitions(
                            event_count,
                            layout,
                            service_index,
                        ),
                        tuple(successful),
                    )

    def test_million_scale_phases_remain_globally_time_ordered(self) -> None:
        event_count = 1_250_000
        phase_counts = _scale._phase_event_counts(event_count)
        for phase, count in phase_counts.items():
            with self.subTest(phase=phase):
                self.assertLess(
                    max(0, count - 1) * _scale.EVENT_STEP_NS,
                    _scale.PHASE_GAP_NS,
                )
        metadata = _scale._scenario_metadata(
            event_count,
            _scale._layout(7_500),
        )
        self.assertGreaterEqual(
            metadata["expected_changes"]["state_change_events"],
            1_000_000,
        )


if __name__ == "__main__":
    unittest.main()
