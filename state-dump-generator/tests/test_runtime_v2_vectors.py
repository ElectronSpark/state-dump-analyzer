from __future__ import annotations

import json
import unittest
from pathlib import Path
from uuid import UUID

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "runtime-v2-ingestion-temporal-conformance.json"
)


class RuntimeV2IngestionTemporalVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = {case["case_id"]: case for case in cls.vector["cases"]}

    def test_vector_is_versioned_and_case_ids_are_unique(self) -> None:
        self.assertEqual(
            self.vector["schema_id"],
            "router-dump-ingestion-temporal-conformance",
        )
        self.assertEqual(self.vector["schema_version"], 1)
        self.assertEqual(len(self.cases), len(self.vector["cases"]))

    def test_integer_timestamps_keep_source_order_at_equal_time(self) -> None:
        case = self.cases["status.exact-integer-and-source-order"]
        records = case["records"]
        for record in records:
            self.assertIs(type(record["timestamp_ns"]), int)
            self.assertIs(type(record["source_sequence"]), int)
        self.assertEqual(
            {record["timestamp_ns"] for record in records},
            {1_759_680_000_000_000_000},
        )
        self.assertEqual(
            [record["source_sequence"] for record in records],
            case["expected_order"],
        )
        self.assertEqual(
            [record["lifecycle"] for record in records],
            ["create", "modify"],
        )

    def test_create_lifecycle_and_window_only_uncertainty_are_explicit(
        self,
    ) -> None:
        lifecycle = self.cases["status.create-modify-lifecycle"]
        self.assertEqual(lifecycle["first_lifecycle"], "create")
        self.assertEqual(lifecycle["following_lifecycle"], "modify")
        self.assertEqual(
            lifecycle["resource_key"]["parts"],
            [{"name": "ifindex", "type": "integer", "value": 7}],
        )

        window = self.cases["status.validity-window-only-uncertainty"]
        self.assertIsNone(window["timestamp_ns"])
        self.assertIs(type(window["observed_at_min_ns"]), int)
        self.assertIs(type(window["observed_at_max_ns"]), int)
        self.assertLess(
            window["observed_at_min_ns"],
            window["observed_at_max_ns"],
        )
        self.assertEqual(window["quality"], "best_effort")

        inserted = self.cases["temporal.insert-is-creation"]
        self.assertEqual(inserted["operation"], "insert")
        self.assertEqual(inserted["operation_class"], "creation")
        self.assertTrue(inserted["expected_exists_after"])

    def test_native_numeric_uuid_bytes_and_compound_keys_are_preserved(
        self,
    ) -> None:
        keys = self.cases["identity.native-key-types"]["keys"]
        numeric = keys["numeric"]["parts"][0]
        self.assertEqual(numeric["type"], "integer")
        self.assertIs(type(numeric["value"]), int)

        uuid_part = keys["uuid"]["parts"][0]
        self.assertEqual(str(UUID(uuid_part["value"])), uuid_part["value"])

        bytes_part = keys["bytes16"]["parts"][0]
        self.assertEqual(bytes_part["encoding"], "hex")
        self.assertEqual(len(bytes.fromhex(bytes_part["value"])), 16)

        compound = keys["compound"]["parts"]
        self.assertEqual(
            [(part["name"], part["type"]) for part in compound],
            [("group_uuid", "uuid"), ("path_id", "integer")],
        )
        self.assertEqual(str(UUID(compound[0]["value"])), compound[0]["value"])
        self.assertIs(type(compound[1]["value"]), int)

    def test_exact_and_rule_resolved_relationships_are_distinct(self) -> None:
        exact = self.cases["relationship.exact-compound-key"]
        self.assertEqual(exact["relation_type"], "member_of")
        self.assertEqual(len(exact["source_key"]["parts"]), 2)
        self.assertEqual(len(exact["target_key"]["parts"]), 1)
        self.assertNotIn("match", exact)

        resolved = self.cases["relationship.rule-resolved-target"]
        self.assertEqual(resolved["relation_type"], "resolves_via")
        self.assertEqual(
            resolved["match"]["matcher_id"],
            "demo.ip-prefix-lpm.v1",
        )
        self.assertEqual(
            resolved["match"]["arguments"]["address"]["type"],
            "ipv6",
        )
        self.assertEqual(resolved["missing_match_is"], "unresolved")

    def test_status_log_ctf_and_artifact_diagnostics_are_enumerated(
        self,
    ) -> None:
        records = self.cases["records.status-log-ctf"]["records"]
        self.assertEqual(
            [record["source_type"] for record in records],
            ["status-json", "syslog", "ctf"],
        )
        self.assertEqual(records[-1]["expected_event_count"], 2)

        artifacts = self.cases["artifact.malformed-and-unsupported"]["artifacts"]
        self.assertEqual(
            [artifact["expected"] for artifact in artifacts],
            [
                "recoverable_parser_diagnostic",
                "decoder_diagnostic",
                "unselected_unsupported_artifact",
            ],
        )


if __name__ == "__main__":
    unittest.main()
