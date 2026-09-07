from __future__ import annotations

import json
import unittest
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from router_dump_analyzer import annotation_store as review
from router_dump_analyzer import control_plane as coordinator
from router_dump_analyzer import session_store as catalog


class RetentionCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = review.ReviewScope("tenant-a", "project-a", "workspace-a")
        self.review_policy = review.ReviewRetentionPolicy(maximum_candidates=2)
        self.catalog_policy = catalog.CatalogRetentionPolicy(maximum_candidates=2)

    def _payload(self, family: str) -> dict[str, Any]:
        candidate = {
            "category": "fixture" if family == "catalog" else "annotation_tombstone",
            "identifier": "candidate-a",
            "retention_value": 10,
            "blockers": [],
        }
        if family == "catalog":
            candidate["qualifier"] = None
        blocked = {**candidate, "identifier": "candidate-b", "blockers": ["protected"]}
        result = {
            "inventory": {
                "total_candidate_count": 2,
                "candidates": [candidate, blocked],
                "truncated": False,
            },
            "purged": [deepcopy(candidate)],
        }
        if family == "catalog":
            result["artifact_releases"] = [
                {
                    "artifact_kind": "fixture_view",
                    "artifact_ref": "sha256:fixture-a",
                    "owner_operation_id": "import-a",
                    "catalog_category": "fixture",
                    "catalog_identifier": "candidate-a",
                }
            ]
        return result

    def _phase(self, family: str, payload: dict[str, Any], kind: str) -> dict[str, Any]:
        return {
            "schema": "router_dump_analyzer.retention_phase.v1",
            "kind": kind,
            "policy": (
                self.catalog_policy.as_dict()
                if family == "catalog"
                else review._review_retention_policy_document(self.review_policy)
            ),
            **deepcopy(payload),
        }

    def _store_decode(self, family: str, payload: dict[str, Any]) -> Any:
        if family == "catalog":
            return catalog._catalog_result_from_document(
                payload,
                tenant_id=self.scope.tenant_id,
                workspace_id=self.scope.workspace_id,
                policy=self.catalog_policy,
            )
        return review._review_retention_result_from_json(
            json.dumps(
                {
                    "schema_version": "router_dump_analyzer.review_retention_result.v1",
                    **payload,
                }
            ),
            scope=self.scope,
            policy=self.review_policy,
        )

    def _phase_decode(self, family: str, value: dict[str, Any]) -> Any:
        decode = (
            coordinator._catalog_phase_from_document
            if family == "catalog"
            else coordinator._review_phase_from_document
        )
        return decode(self.scope, value)

    def test_existing_store_and_phase_wire_forms_round_trip_exactly(self) -> None:
        for family in ("review", "catalog"):
            for truncated in (False, True):
                with self.subTest(family=family, truncated=truncated):
                    payload = self._payload(family)
                    if truncated:
                        payload["inventory"].update(
                            total_candidate_count=3, truncated=True
                        )
                    expected = self._phase(family, payload, "result")
                    result = self._store_decode(family, payload)
                    self.assertEqual(self._phase_decode(family, expected), result)
                    encode_result = (
                        catalog._catalog_result_document
                        if family == "catalog"
                        else review._review_retention_result_document
                    )
                    encode_phase = (
                        coordinator._catalog_phase_document
                        if family == "catalog"
                        else coordinator._review_phase_document
                    )
                    self.assertEqual(encode_result(result), payload)
                    self.assertEqual(encode_phase(result), expected)
                    expected.update(kind="inventory", purged=[])
                    if family == "catalog":
                        expected["artifact_releases"] = []
                    self.assertEqual(encode_phase(result.inventory), expected)
                    self.assertEqual(
                        self._phase_decode(family, expected), result.inventory
                    )

    def test_inventory_validation_is_identical_in_store_and_both_phase_kinds(
        self,
    ) -> None:
        mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            ("negative count", lambda value: value.update(total_candidate_count=-1)),
            ("bool count", lambda value: value.update(total_candidate_count=True)),
            (
                "oversize count",
                lambda value: value.update(total_candidate_count=1 << 63),
            ),
            ("count below rows", lambda value: value.update(total_candidate_count=1)),
            ("false truncation", lambda value: value.update(total_candidate_count=3)),
            ("true truncation", lambda value: value.update(truncated=True)),
            ("nonboolean truncation", lambda value: value.update(truncated=0)),
            ("unknown field", lambda value: value.update(unexpected=1)),
            ("nonlist candidates", lambda value: value.update(candidates={})),
            (
                "over policy limit",
                lambda value: value.update(
                    candidates=[
                        *value["candidates"],
                        {**value["candidates"][0], "identifier": "candidate-c"},
                    ],
                    total_candidate_count=3,
                ),
            ),
            (
                "duplicate candidate",
                lambda value: value.update(
                    candidates=[value["candidates"][0], value["candidates"][0]]
                ),
            ),
            (
                "duplicate identity changed fields",
                lambda value: value.update(
                    candidates=[
                        value["candidates"][0],
                        {**value["candidates"][0], "retention_value": 11},
                    ]
                ),
            ),
            (
                "empty identifier",
                lambda value: value["candidates"][0].update(identifier=""),
            ),
            (
                "oversize identifier",
                lambda value: value["candidates"][0].update(identifier="x" * 1025),
            ),
            (
                "boolean timestamp",
                lambda value: value["candidates"][0].update(retention_value=True),
            ),
            (
                "oversize timestamp",
                lambda value: value["candidates"][0].update(retention_value=1 << 63),
            ),
            (
                "empty blocker",
                lambda value: value["candidates"][1].update(blockers=[""]),
            ),
            (
                "duplicate blocker",
                lambda value: value["candidates"][1].update(
                    blockers=["protected", "protected"]
                ),
            ),
            (
                "over blocker limit",
                lambda value: value["candidates"][1].update(
                    blockers=[f"blocker-{index}" for index in range(5001)]
                ),
            ),
        )
        for family in ("review", "catalog"):
            error = (
                catalog.SessionStoreError
                if family == "catalog"
                else review.ReviewOverlayError
            )
            for label, mutate in mutations:
                with self.subTest(family=family, invalid=label):
                    payload = self._payload(family)
                    mutate(payload["inventory"])
                    with self.assertRaises(error):
                        self._store_decode(family, payload)
                    with self.assertRaises(coordinator.ControlPlaneError):
                        self._phase_decode(
                            family, self._phase(family, payload, "result")
                        )
                    payload["purged"] = []
                    if family == "catalog":
                        payload["artifact_releases"] = []
                    with self.assertRaises(coordinator.ControlPlaneError):
                        self._phase_decode(
                            family, self._phase(family, payload, "inventory")
                        )

    def test_purge_validation_is_identical_in_store_and_saga_recovery(self) -> None:
        for family in ("review", "catalog"):
            error = (
                catalog.SessionStoreError
                if family == "catalog"
                else review.ReviewOverlayError
            )
            original = self._payload(family)
            candidate, blocked = original["inventory"]["candidates"]
            for label, purged in (
                ("duplicate", [candidate, candidate]),
                ("blocked", [blocked]),
                ("not in inventory", [{**candidate, "identifier": "missing"}]),
                ("over policy limit", [candidate] * 3),
                ("nonlist", {}),
            ):
                with self.subTest(family=family, invalid=label):
                    payload = {**original, "purged": purged}
                    with self.assertRaises(error):
                        self._store_decode(family, payload)
                    with self.assertRaises(coordinator.ControlPlaneError):
                        self._phase_decode(
                            family, self._phase(family, payload, "result")
                        )

    def test_catalog_release_validation_is_shared_and_qualifiers_distinguish_receipts(
        self,
    ) -> None:
        payload = self._payload("catalog")
        release = payload["artifact_releases"][0]
        for invalid in (
            [release, release],
            [release] * 3,
            [{**release, "artifact_ref": ""}],
            {},
        ):
            with self.subTest(releases=invalid):
                malformed = {**payload, "artifact_releases": invalid}
                with self.assertRaises(catalog.SessionStoreError):
                    self._store_decode("catalog", malformed)
                with self.assertRaises(coordinator.ControlPlaneError):
                    self._phase_decode(
                        "catalog", self._phase("catalog", malformed, "result")
                    )
        receipt = {
            **payload["inventory"]["candidates"][0],
            "category": "catalog_idempotency",
            "qualifier": "operation-a",
        }
        payload["inventory"]["candidates"] = [
            receipt,
            {**receipt, "qualifier": "operation-b"},
        ]
        payload["purged"] = payload["inventory"]["candidates"]
        payload["artifact_releases"] = []
        self.assertEqual(
            self._store_decode("catalog", payload),
            self._phase_decode("catalog", self._phase("catalog", payload, "result")),
        )

    def test_inventory_phase_cannot_include_purge_side_effects(self) -> None:
        for family in ("review", "catalog"):
            with self.subTest(family=family):
                phase = self._phase(family, self._payload(family), "inventory")
                with self.assertRaises(coordinator.ControlPlaneError):
                    self._phase_decode(family, phase)
                phase["purged"] = {}
                with self.assertRaises(coordinator.ControlPlaneError):
                    self._phase_decode(family, phase)

    def test_catalog_release_reconciliation_uses_the_result_codec(self) -> None:
        release = self._payload("catalog")["artifact_releases"][0]
        self.assertEqual(
            coordinator.ControlPlane._catalog_release(release),
            catalog._catalog_artifact_release_from_document(release),
        )
        for invalid in (
            {**release, "unexpected": True},
            {**release, "artifact_ref": ""},
            {**release, "owner_operation_id": 1},
        ):
            with self.subTest(release=invalid):
                with self.assertRaises(catalog.SessionStoreError):
                    catalog._catalog_artifact_release_from_document(invalid)
                with self.assertRaises(coordinator.ControlPlaneError):
                    coordinator.ControlPlane._catalog_release(invalid)


if __name__ == "__main__":
    unittest.main()
