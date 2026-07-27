from __future__ import annotations

import copy
import unittest

from router_dump_analyzer.topology_core import (
    resolve_connectivity_domain_reference,
)


class ConnectivityDomainReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference = {
            "reference_kind": "connectivity_domain",
            "match": {
                "matcher_id": "vendor.exact-domain.v1",
                "matcher_contract_version": "1.0",
                "arguments": {
                    "segment_key": {
                        "type": "compound",
                        "value": ["blue", 310],
                    }
                },
            },
        }
        self.snapshot = {
            "network_segments": [
                {
                    "segment_id": "network-segment:west",
                    "match": {
                        "matcher_id": "vendor.exact-domain.v1",
                        "matcher_contract_version": "1.0",
                        "segment_key": {
                            "value": ["blue", 310],
                            "type": "compound",
                        },
                    },
                    "connectivity_enabled": True,
                    "exists": True,
                    "semantic_conflict": False,
                    "operational_status": "usable",
                    # A third participant proves this is not treated as a
                    # fabricated point-to-point link.
                    "node_ids": ["a", "p1", "p2"],
                }
            ],
            "segment_attachments": [
                self._attachment("a", "a/if/1", "attachment:a"),
                self._attachment("p1", "p1/if/1", "attachment:p1"),
                self._attachment("p2", "p2/if/9", "attachment:p2"),
            ],
            "completeness": {
                "network_segments_truncated": False,
                "segment_attachments_truncated": False,
            },
        }

    @staticmethod
    def _attachment(
        node_id: str,
        resource_id: str,
        attachment_id: str,
    ) -> dict[str, object]:
        return {
            "attachment_id": attachment_id,
            "segment_id": "network-segment:west",
            "member_id": f"member:{node_id}",
            "node_id": node_id,
            "resource_id": resource_id,
            "exists": True,
            "claim_valid_at_basis": True,
            "endpoint_exists_at_basis": True,
            "operational_status": "usable",
        }

    def resolve(self, snapshot: dict[str, object] | None = None):
        return resolve_connectivity_domain_reference(
            snapshot or self.snapshot,
            self.reference,
            source_node_id="a",
            target_node_id="p1",
            source_resource_id="a/if/1",
            target_resource_id="p1/if/1",
        )

    def test_exact_reference_resolves_across_multi_access_domain(self) -> None:
        result = self.resolve()
        self.assertTrue(result.resolved)
        self.assertEqual(result.domain["segment_id"], "network-segment:west")
        self.assertEqual(
            result.as_dict()["source_attachment_id"],
            "attachment:a",
        )
        self.assertEqual(
            result.as_dict()["target_attachment_id"],
            "attachment:p1",
        )

    def test_ambiguous_domain_never_selects_the_first_candidate(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        duplicate = copy.deepcopy(snapshot["network_segments"][0])
        duplicate["segment_id"] = "network-segment:duplicate"
        snapshot["network_segments"].append(duplicate)
        result = self.resolve(snapshot)
        self.assertFalse(result.resolved)
        self.assertEqual(result.state, "ambiguous")
        self.assertEqual(
            result.reason_code,
            "connectivity_domain_ambiguous",
        )

    def test_missing_or_unusable_attachment_fails_closed(self) -> None:
        for mutation, reason in (
            (
                lambda snapshot: snapshot["segment_attachments"].pop(1),
                "target_attachment_not_found",
            ),
            (
                lambda snapshot: snapshot["segment_attachments"][1].update(
                    {"operational_status": "unusable"}
                ),
                "target_attachment_not_usable",
            ),
        ):
            with self.subTest(reason=reason):
                snapshot = copy.deepcopy(self.snapshot)
                mutation(snapshot)
                result = self.resolve(snapshot)
                self.assertFalse(result.resolved)
                self.assertEqual(result.reason_code, reason)

    def test_truncated_evidence_fails_closed(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["completeness"]["segment_attachments_truncated"] = True
        result = self.resolve(snapshot)
        self.assertFalse(result.resolved)
        self.assertEqual(result.reason_code, "topology_evidence_truncated")

    def test_reference_kind_is_explicit_and_not_inferred(self) -> None:
        reference = copy.deepcopy(self.reference)
        reference["reference_kind"] = "resource"
        with self.assertRaisesRegex(ValueError, "connectivity_domain"):
            resolve_connectivity_domain_reference(
                self.snapshot,
                reference,
                source_node_id="a",
                target_node_id="p1",
                source_resource_id="a/if/1",
                target_resource_id="p1/if/1",
            )

    def test_shared_canonical_serializer_preserves_topology_error_contract(
        self,
    ) -> None:
        reference = copy.deepcopy(self.reference)
        reference["match"]["arguments"]["segment_key"] = {"not-json"}
        with self.assertRaisesRegex(
            ValueError,
            "topology match arguments must be JSON-serializable",
        ):
            resolve_connectivity_domain_reference(
                self.snapshot,
                reference,
                source_node_id="a",
                target_node_id="p1",
                source_resource_id="a/if/1",
                target_resource_id="p1/if/1",
            )

    def test_unicode_keys_still_match_exactly(self) -> None:
        reference = copy.deepcopy(self.reference)
        snapshot = copy.deepcopy(self.snapshot)
        key = {"site": "Montréal", "vrf": "蓝"}
        reference["match"]["arguments"]["segment_key"] = key
        snapshot["network_segments"][0]["match"]["segment_key"] = copy.deepcopy(
            key
        )
        result = resolve_connectivity_domain_reference(
            snapshot,
            reference,
            source_node_id="a",
            target_node_id="p1",
            source_resource_id="a/if/1",
            target_resource_id="p1/if/1",
        )
        self.assertTrue(result.resolved)


if __name__ == "__main__":
    unittest.main()
