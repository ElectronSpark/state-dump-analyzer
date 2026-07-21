from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from router_dump_analyzer.source_record_core import (
    compile_record_pattern,
    query_source_records,
    record_lanes_for_window,
)


RECORDS = [
    {
        "source_record_uid": "record-1",
        "timestamp_ns": "100",
        "source_type": "ctf",
        "source_name": "trace.ctf2",
        "record_name": "evpn_es_withdraw",
        "message": "mass withdraw for ESI 00:11",
        "matched_event_uid": None,
    },
    {
        "source_record_uid": "record-2",
        "timestamp_ns": "200",
        "source_type": "syslog",
        "source_name": "evpnd",
        "record_name": "restore",
        "message": "Ethernet segment restored",
        "matched_event_uid": "event-2",
    },
]


class SourceRecordCoreTests(unittest.TestCase):
    def test_query_filters_and_pages_generic_records(self) -> None:
        result = query_source_records(
            RECORDS,
            {"source_types": ["ctf"], "matched": False, "limit": 1},
            known_source_types={"ctf", "syslog"},
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["source_record_uid"], "record-1")

    def test_regex_lanes_keep_stable_source_ids_and_match_state(self) -> None:
        lanes = record_lanes_for_window(
            RECORDS,
            [
                {
                    "lane_id": "unmatched-es",
                    "label": "Unmatched ES",
                    "pattern": "ESI|ethernet segment",
                    "source_types": ["ctf", "syslog"],
                    "unmatched_only": True,
                }
            ],
            start_ns=0,
            end_ns=300,
            known_source_types={"ctf", "syslog"},
        )
        self.assertEqual(lanes[0]["record_count"], 1)
        self.assertEqual(lanes[0]["marks"][0]["source_record_uid"], "record-1")

    def test_regex_validation_rejects_unbounded_features(self) -> None:
        for pattern in ("(?=ESI)", r"(a+)++", r"(a+) +", r"(a+)\\1"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                compile_record_pattern(pattern)

    def test_lane_rejects_unknown_source_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown source types"):
            record_lanes_for_window(
                RECORDS,
                [
                    {
                        "lane_id": "bad-source",
                        "label": "Bad source",
                        "pattern": ".+",
                        "source_types": ["missing"],
                    }
                ],
                start_ns=0,
                end_ns=300,
                known_source_types={"ctf", "syslog"},
            )


if __name__ == "__main__":
    unittest.main()
