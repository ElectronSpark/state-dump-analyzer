from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from rsl_demo_generator import _scale


class ScaleGeneratorOptimizationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
