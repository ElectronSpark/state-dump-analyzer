from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "demo"))

from router_dump_analyzer.source_record_core import (
    compile_record_pattern,
    project_source_record_text_selection,
    query_source_records,
    record_lanes_for_window,
    source_record_event_uids,
)
from plugin.source_records import (
    SOURCE_RECORD_DESCRIPTORS,
    SOURCE_RECORD_GROUP_DESCRIPTORS,
)


RECORDS = [
    {
        "source_record_uid": "record-1",
        "timestamp_ns": "100",
        "source_type": "ctf",
        "source_name": "trace.ctf2",
        "record_name": "evpn_es_withdraw",
        "message": "mass withdraw for ESI 00:11",
        "copy_text": "[100] evpn_es_withdraw { esi = 00:11 }",
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
        "matched_event_uids": ["event-2", "event-2-companion"],
    },
]

UNTIMED_RECORD = {
    "source_record_uid": "record-untimed",
    "timestamp_ns": None,
    "source_type": "ctf",
    "source_name": "capture-without-clock",
    "layer": "data-plane",
    "record_name": "untimed_withdraw",
    "message": "withdraw observed without a usable clock",
    "matched_event_uid": None,
}


class SourceRecordCoreTests(unittest.TestCase):
    def test_demo_plugin_explicitly_groups_ctf_and_external_streams(self) -> None:
        descriptors = {
            descriptor["group_id"]: descriptor
            for descriptor in SOURCE_RECORD_GROUP_DESCRIPTORS
        }
        groups = {
            descriptor["source_type"]: descriptor["stream_group"]
            for descriptor in SOURCE_RECORD_DESCRIPTORS
        }
        self.assertEqual(descriptors["ctf"]["label"], "CTF records")
        self.assertEqual(descriptors["external"]["label"], "Non-CTF records")
        self.assertFalse(descriptors["ctf"]["default_included"])
        self.assertEqual(descriptors["ctf"]["copy_action_label"], "Copy CTF text")
        self.assertEqual(groups["ctf"], "ctf")
        self.assertEqual(groups["syslog"], "external")
        self.assertEqual(groups["agent-event"], "external")
        self.assertEqual(groups["status-text"], "external")

    def test_query_filters_and_pages_generic_records(self) -> None:
        result = query_source_records(
            RECORDS,
            {"source_types": ["ctf"], "matched": False, "limit": 1},
            known_source_types={"ctf", "syslog"},
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["source_record_uid"], "record-1")
        self.assertEqual(result["unplaced_count"], 0)

    def test_query_accepts_decimal_integer_strings(self) -> None:
        result = query_source_records(
            RECORDS,
            {
                "start_ns": "100",
                "end_ns": "200",
                "offset": "0",
                "limit": "1",
            },
        )

        self.assertEqual(result["count"], 2)
        self.assertEqual(result["offset"], 0)
        self.assertEqual(result["limit"], 1)

    def test_query_rejects_coerced_request_shapes(self) -> None:
        invalid_queries = [
            {"start_ns": 100.5},
            {"end_ns": True},
            {"offset": " 0"},
            {"limit": False},
            {"source_types": "ctf"},
            {"source_types": [1]},
            {"matched": "false"},
            {"case_sensitive": "false"},
            {"pattern": 123},
            {"search": {"text": "withdraw"}},
        ]
        for query in invalid_queries:
            with self.subTest(query=query), self.assertRaises(ValueError):
                query_source_records(RECORDS, query)

    def test_query_preserves_untimed_records_but_excludes_them_from_ranges(self) -> None:
        records = [*RECORDS, UNTIMED_RECORD]

        unbounded = query_source_records(records, {})
        bounded = query_source_records(
            records,
            {"start_ns": 0, "end_ns": 300},
        )

        self.assertEqual(unbounded["count"], 3)
        self.assertEqual(unbounded["unplaced_count"], 1)
        self.assertIn(
            "record-untimed",
            [record["source_record_uid"] for record in unbounded["items"]],
        )
        self.assertEqual(bounded["count"], 2)
        self.assertEqual(bounded["unplaced_count"], 1)
        self.assertNotIn(
            "record-untimed",
            [record["source_record_uid"] for record in bounded["items"]],
        )

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

    def test_regex_lanes_report_untimed_matches_without_placing_them_at_zero(self) -> None:
        lanes = record_lanes_for_window(
            [*RECORDS, UNTIMED_RECORD],
            [
                {
                    "lane_id": "withdraws",
                    "label": "Withdraws",
                    "pattern": "withdraw",
                    "source_types": ["ctf"],
                }
            ],
            start_ns=0,
            end_ns=300,
            known_source_types={"ctf", "syslog"},
        )

        self.assertEqual(lanes[0]["record_count"], 1)
        self.assertEqual(lanes[0]["unplaced_count"], 1)
        self.assertEqual(
            [mark["source_record_uid"] for mark in lanes[0]["marks"]],
            ["record-1"],
        )

    def test_lane_marks_expose_only_the_bounded_generic_record_projection(self) -> None:
        private_record = {
            **RECORDS[0],
            "layer": "control-plane",
            "message": "x" * 2_000,
            "attributes": {"password": "do-not-return"},
            "raw_payload": b"private bytes",
            "plugin_private": {"vendor": "secret"},
        }

        mark = record_lanes_for_window(
            [private_record],
            [{"lane_id": "all", "label": "All", "pattern": ".+"}],
            start_ns=0,
            end_ns=300,
        )[0]["marks"][0]

        projected_keys = {
            "source_record_uid",
            "timestamp_ns",
            "source_type",
            "source_name",
            "layer",
            "record_name",
            "message",
            "matched_event_uid",
            "matched_event_uids",
            "matched",
        }
        self.assertEqual(set(mark["record"]), projected_keys)
        self.assertNotIn("attributes", mark)
        self.assertNotIn("raw_payload", mark)
        self.assertNotIn("plugin_private", mark)
        self.assertEqual(len(mark["message"]), 1_024)
        self.assertEqual(mark["record"]["layer"], "control-plane")

    def test_copy_projection_is_plugin_owned_ordered_deduplicated_and_bounded(self) -> None:
        records = [
            RECORDS[0],
            {
                **RECORDS[1],
                "copy_text": "[200] restore { esi = 00:11 }",
            },
        ]
        result = project_source_record_text_selection(
            records,
            [
                {"kind": "event", "uid": "event-2"},
                {"kind": "source", "uid": "record-2"},
                {"kind": "source", "uid": "record-1"},
            ],
        )

        self.assertEqual(
            [item["source_record_uid"] for item in result["items"]],
            ["record-2", "record-1"],
        )
        self.assertEqual(result["item_count"], 2)
        self.assertFalse(result["truncated"])
        self.assertNotIn("message", result["items"][0])
        self.assertEqual(
            source_record_event_uids(RECORDS[1]),
            ("event-2", "event-2-companion"),
        )

    def test_copy_projection_rejects_private_or_oversized_text_without_leaking(self) -> None:
        result = project_source_record_text_selection(
            [
                {**RECORDS[0], "copy_text": "safe\x00private"},
                {
                    **RECORDS[1],
                    "copy_text": "x" * 70_000,
                },
            ],
            [
                {"kind": "source", "uid": "record-1"},
                {"kind": "source", "uid": "record-2"},
            ],
        )

        self.assertEqual(result["items"], [])
        self.assertEqual(result["omitted_count"], 2)
        self.assertEqual(
            [item["reason"] for item in result["omitted"]],
            ["invalid_copy_text", "copy_text_too_large"],
        )

    def test_regex_validation_rejects_unbounded_features(self) -> None:
        for pattern in ("(?=ESI)", r"(a+)++", r"(a+) +", r"(a+)\\1"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                compile_record_pattern(pattern)

    def test_lane_rules_reject_coerced_request_shapes(self) -> None:
        base = {
            "lane_id": "strict-lane",
            "label": "Strict lane",
            "description": "Strict request shape",
            "pattern": ".+",
            "source_types": ["ctf"],
            "unmatched_only": False,
            "case_sensitive": False,
            "plugin_defined": False,
        }
        invalid_fields = {
            "lane_id": 1,
            "label": True,
            "description": {"text": "description"},
            "pattern": 123,
            "source_types": "ctf",
            "unmatched_only": "false",
            "case_sensitive": 0,
            "plugin_defined": "true",
        }
        for field, value in invalid_fields.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                record_lanes_for_window(
                    RECORDS,
                    [{**base, field: value}],
                    start_ns=0,
                    end_ns=300,
                )

    def test_source_record_timestamp_rejects_fractional_numbers(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid timestamp_ns"):
            query_source_records(
                [{**RECORDS[0], "timestamp_ns": 100.5}],
                {},
            )

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
