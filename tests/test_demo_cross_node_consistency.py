from __future__ import annotations

import json
import unittest
from copy import deepcopy
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from rsl_demo_generator import DEMO_NODES, AssemblyConfig, build_coverage
from rsl_demo_generator.assembly import _projection_rows, _source_resource_id
from rsl_demo_generator.catalog import DEFAULT_SCENARIO_SOURCE
from rsl_demo_plugin.cross_node_consistency import (
    evaluate_boundary_findings,
    revalidate_boundary_coverage,
)
from rsl_demo_plugin.scenario_registry import SCENARIO_BY_ID

CASE_IDS = (
    "cross-node-mpls-label-mismatch",
    "cross-node-vxlan-vni-mismatch",
)


class BoundaryFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario_id = "unit-boundary"
        self.rule = {
            "contract_id": "demo.test.exact-handoff.v1",
            "finding_type": "boundary_value_mismatch",
            "field_label": "boundary value",
            "sender_field": "outgoing_value",
            "receiver_field": "expected_value",
            "resource_type": "BOUNDARY",
            "resource_layer": "hardware-driver-plane",
            "participants": {
                "forward": {
                    "sender": {
                        "node_id": "node-a",
                        "source_resource_id": "boundary:sender",
                    },
                    "receiver": {
                        "node_id": "node-b",
                        "source_resource_id": "boundary:receiver",
                    },
                },
                "reverse": {
                    "sender": {
                        "node_id": "node-b",
                        "source_resource_id": "boundary:sender",
                    },
                    "receiver": {
                        "node_id": "node-a",
                        "source_resource_id": "boundary:receiver",
                    },
                },
            },
        }
        self.revisions = {"node-a": "revision-a", "node-b": "revision-b"}
        self.paths = [
            {
                "candidate_id": "candidate:forward",
                "path_id": "path:forward",
                "direction": "forward",
                "node_sequence": ["node-a", "node-b"],
            }
        ]
        self.observations = [
            {
                "scenario_id": self.scenario_id,
                "direction": "forward",
                "boundary_id": "boundary:a-b",
                "contract_id": self.rule["contract_id"],
                "role": role,
                "field": self.rule[f"{role}_field"],
                "value": value,
                "complete": True,
                "node_id": node_id,
                "peer_node_id": peer_node_id,
                "revision_id": self.revisions[node_id],
                "resource_type": "BOUNDARY",
                "resource_id": (
                    f"{node_id}/hardware-driver-plane/BOUNDARY/boundary:{role}"
                ),
                "source_resource_id": f"boundary:{role}",
                "observed_at_ns": "1700000000000000000",
            }
            for role, value, node_id, peer_node_id in (
                ("sender", 24001, "node-a", "node-b"),
                ("receiver", 24002, "node-b", "node-a"),
            )
        ]

    def evaluate(self) -> list[dict[str, Any]]:
        return evaluate_boundary_findings(
            self.scenario_id,
            self.rule,
            self.paths,
            self.observations,
            self.revisions,
        )

    def assert_unknown(self) -> None:
        findings = self.evaluate()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["result"], "unknown")
        self.assertIs(findings[0]["affects_consistency"], False)
        self.assertEqual(findings[0]["candidate_ids"], ["candidate:forward"])
        self.assertEqual(findings[0]["path_ids"], ["path:forward"])

    def test_complete_unequal_pair_exposes_values_and_both_provenances(self) -> None:
        findings = self.evaluate()
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["result"], "mismatch")
        self.assertIs(finding["affects_consistency"], True)
        self.assertEqual(finding["semantic_owner"], "plugin")
        self.assertEqual(finding["observations"], self.observations)
        self.assertEqual(finding["candidate_ids"], ["candidate:forward"])
        self.assertEqual(finding["path_ids"], ["path:forward"])
        for observation in self.observations:
            for field in (
                "field",
                "value",
                "node_id",
                "revision_id",
                "resource_id",
                "source_resource_id",
                "observed_at_ns",
            ):
                with self.subTest(role=observation["role"], field=field):
                    self.assertIn(str(observation[field]), finding["detail"])

    def test_equal_complete_values_have_no_finding(self) -> None:
        self.observations[1]["value"] = self.observations[0]["value"]
        self.assertEqual(self.evaluate(), [])

    def test_missing_each_role_is_unknown(self) -> None:
        original = deepcopy(self.observations)
        for role in ("sender", "receiver"):
            with self.subTest(missing_role=role):
                self.observations = [item for item in original if item["role"] != role]
                self.assert_unknown()

    def test_incomplete_pair_is_unknown_even_when_values_are_equal(self) -> None:
        for value in (24001, 24002):
            with self.subTest(receiver_value=value):
                self.observations[1].update(value=value, complete=False)
                self.assert_unknown()

    def test_absent_observations_are_unknown_for_each_candidate_direction(self) -> None:
        self.paths.append(
            {
                "candidate_id": "candidate:reverse",
                "path_id": "path:reverse",
                "direction": "reverse",
                "node_sequence": ["node-b", "node-a"],
            }
        )
        self.observations = []
        findings = self.evaluate()
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {tuple(item["candidate_ids"]) for item in findings},
            {("candidate:forward",), ("candidate:reverse",)},
        )
        self.assertTrue(all(item["result"] == "unknown" for item in findings))
        self.assertTrue(all(item["affects_consistency"] is False for item in findings))

    def test_invalid_identity_or_contract_never_establishes_mismatch(self) -> None:
        original = deepcopy(self.observations)
        mutations = {
            "scenario_id": "other-scenario",
            "contract_id": "other-contract",
            "boundary_id": "other-boundary",
            "node_id": "unknown-node",
            "peer_node_id": "unknown-peer",
            "revision_id": "stale-revision",
            "resource_id": "node-a/data-plane/BOUNDARY/receiver",
            "source_resource_id": "boundary:unrelated-resource",
            "observed_at_ns": "",
            "field": "other-field",
            "resource_type": "OTHER_BINDING",
            "identity_valid": False,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.observations = deepcopy(original)
                self.observations[1][field] = value
                self.assert_unknown()

    def test_invalid_values_do_not_become_numeric_mismatches(self) -> None:
        for value in (None, True, False, -1, "24002", 24002.0):
            with self.subTest(value=value):
                self.observations[1]["value"] = value
                self.assert_unknown()

    def test_invalid_observation_times_do_not_establish_mismatch(self) -> None:
        for timestamp in (
            None,
            "",
            0,
            "0",
            -1,
            "-1",
            True,
            False,
            12.5,
            "12.5",
            "not-a-time",
        ):
            with self.subTest(timestamp=timestamp):
                self.observations[1]["observed_at_ns"] = timestamp
                self.assert_unknown()

    def test_observation_times_accept_positive_integer_and_integer_string(self) -> None:
        for timestamp in (1700000000000000000, "1700000000000000000"):
            with self.subTest(timestamp=timestamp):
                self.observations[1]["observed_at_ns"] = timestamp
                findings = self.evaluate()
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["result"], "mismatch")

    def test_ambiguous_duplicate_receiver_is_unknown(self) -> None:
        duplicate = deepcopy(self.observations[1])
        duplicate["value"] = 24003
        self.observations.append(duplicate)
        self.assert_unknown()

    def test_both_boundary_participants_must_be_on_the_candidate_path(self) -> None:
        self.paths[0]["node_sequence"] = ["node-a", "unrelated-node"]
        self.assert_unknown()

    def test_same_node_cannot_supply_both_sides_of_boundary(self) -> None:
        self.observations[0]["peer_node_id"] = "node-a"
        self.observations[1].update(
            node_id="node-a",
            peer_node_id="node-a",
            revision_id="revision-a",
            resource_id="node-a/hardware-driver-plane/BOUNDARY/boundary:receiver",
        )
        self.assert_unknown()


class PersistedBoundaryCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        cls.generated_coverage = build_coverage(cls.config)
        cls.generated_projections = {}
        for node in cls.config.nodes:
            routes, forwarding = _projection_rows(node, config=cls.config)
            cls.generated_projections[node.node_id] = {
                "routes": [row for row in routes if row.get("scenario_id") in CASE_IDS],
                "forwarding": [
                    row for row in forwarding if row.get("scenario_id") in CASE_IDS
                ],
            }
        cls.revisions = {node.node_id: node.revision_id for node in cls.config.nodes}

    def setUp(self) -> None:
        self.coverage = deepcopy(self.generated_coverage)
        self.projections = deepcopy(self.generated_projections)

    def revalidate(self) -> dict[str, Any]:
        return revalidate_boundary_coverage(
            self.coverage, self.projections, self.revisions, SCENARIO_BY_ID
        )

    def case(self, coverage: dict[str, Any], case_id: str) -> dict[str, Any]:
        return next(item for item in coverage["cases"] if item["case_id"] == case_id)

    def findings(
        self, coverage: dict[str, Any], case_id: str, direction: str
    ) -> list[dict[str, Any]]:
        case = self.case(coverage, case_id)
        candidates = {
            item["candidate_id"]
            for item in case["candidate_paths"]
            if item["direction"] == direction
        }
        self.assertTrue(candidates)
        return [
            item
            for item in case["consistency_findings"]
            if candidates.intersection(item["candidate_ids"])
        ]

    def observations(
        self, case_id: str, direction: str
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        return [
            (row, observation)
            for projection in self.projections.values()
            for row in projection["forwarding"]
            if row.get("scenario_id") == case_id
            for decision in row["directional_decisions"].get(direction, [])
            for observation in decision.get("boundary_observations", [])
        ]

    def observation(
        self, case_id: str, direction: str, role: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        matches = [
            pair
            for pair in self.observations(case_id, direction)
            if pair[1]["role"] == role
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def assert_result(
        self, coverage: dict[str, Any], case_id: str, direction: str, result: str
    ) -> dict[str, Any]:
        findings = self.findings(coverage, case_id, direction)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["result"], result)
        self.assertIs(findings[0]["affects_consistency"], result == "mismatch")
        return findings[0]

    def test_both_generated_cases_have_forward_mismatch_and_agreeing_reverse(
        self,
    ) -> None:
        revalidated = self.revalidate()
        for case_id in CASE_IDS:
            with self.subTest(case_id=case_id):
                rule = SCENARIO_BY_ID[case_id]["cross_node_rule"]
                for direction in ("forward", "reverse"):
                    _, sender = self.observation(case_id, direction, "sender")
                    _, receiver = self.observation(case_id, direction, "receiver")
                    self.assertEqual(sender["contract_id"], rule["contract_id"])
                    self.assertEqual(receiver["contract_id"], rule["contract_id"])
                    self.assertEqual(sender["field"], rule["sender_field"])
                    self.assertEqual(receiver["field"], rule["receiver_field"])
                    self.assertNotEqual(sender["node_id"], receiver["node_id"])
                    self.assertIs(sender["complete"], True)
                    self.assertIs(receiver["complete"], True)
                    if direction == "forward":
                        self.assertNotEqual(sender["value"], receiver["value"])
                    else:
                        self.assertEqual(sender["value"], receiver["value"])
                for coverage in (self.coverage, revalidated):
                    finding = self.assert_result(
                        coverage, case_id, "forward", "mismatch"
                    )
                    self.assertEqual(self.findings(coverage, case_id, "reverse"), [])
                    self.assertEqual(len(finding["observations"]), 2)
                    for observation in finding["observations"]:
                        self.assertIn(str(observation["value"]), finding["detail"])
                        self.assertIn(observation["resource_id"], finding["detail"])
                        self.assertIn(observation["revision_id"], finding["detail"])

    def test_persisted_observations_preserve_authored_resources_and_provenance(
        self,
    ) -> None:
        authored = {
            (node.node_id, resource.resource_id): (node, resource)
            for node in self.config.nodes
            for resource in DEFAULT_SCENARIO_SOURCE.resources_at(node.node_id)
            if resource.properties.get("scenario_id") in CASE_IDS
        }
        self.assertEqual(len(authored), 8)
        seen = set()
        for case_id in CASE_IDS:
            for direction in ("forward", "reverse"):
                for row, observation in self.observations(case_id, direction):
                    identity = (
                        observation["node_id"],
                        observation["source_resource_id"],
                    )
                    with self.subTest(case_id=case_id, identity=identity):
                        self.assertIn(identity, authored)
                        self.assertNotIn(identity, seen)
                        seen.add(identity)
                        node, resource = authored[identity]
                        for field, value in resource.properties.items():
                            self.assertEqual(observation[field], value)
                        self.assertEqual(observation["revision_id"], node.revision_id)
                        self.assertEqual(
                            observation["resource_id"],
                            _source_resource_id(
                                node.node_id,
                                resource.resource_type,
                                resource.resource_id,
                            ),
                        )
                        self.assertEqual(
                            int(observation["observed_at_ns"]),
                            resource.updated_at_ns + node.clock_offset_ns,
                        )
                        self.assertIn(
                            observation["resource_id"], row["evidence_resource_ids"]
                        )
        self.assertEqual(seen, set(authored))

    def test_reverse_values_are_independently_authored_not_swapped_forward_values(
        self,
    ) -> None:
        values_by_case = {
            CASE_IDS[0]: {"forward": (16011, 16012), "reverse": (16021, 16021)},
            CASE_IDS[1]: {"forward": (50100, 50200), "reverse": (50300, 50300)},
        }
        for case_id, values_by_direction in values_by_case.items():
            for direction, expected in values_by_direction.items():
                with self.subTest(case_id=case_id, direction=direction):
                    actual = tuple(
                        self.observation(case_id, direction, role)[1]["value"]
                        for role in ("sender", "receiver")
                    )
                    self.assertEqual(actual, expected)

    def test_diagnostic_bindings_do_not_invent_packet_actions_or_numeric_labels(
        self,
    ) -> None:
        label_fields = ("label_stack", "outgoing_label_stack", "vni", "outgoing_vni")
        for case_id in CASE_IDS:
            for candidate in self.case(self.coverage, case_id)["candidate_paths"]:
                with self.subTest(case_id=case_id, path_id=candidate["path_id"]):
                    for field in label_fields:
                        self.assertNotIn(field, candidate["encapsulation"])
            for projection in self.projections.values():
                for route in projection["routes"]:
                    if route["scenario_id"] != case_id:
                        continue
                    with self.subTest(case_id=case_id, route_id=route["route_id"]):
                        self.assertEqual(route["forwarding_actions"], [])
                        for field in (*label_fields, "encapsulation"):
                            self.assertNotIn(field, route)
                for row in projection["forwarding"]:
                    if row["scenario_id"] != case_id:
                        continue
                    self.assertEqual(row["forwarding_actions"], [])
                    for decisions in row["directional_decisions"].values():
                        for decision in decisions:
                            self.assertEqual(decision["forwarding_actions"], [])
                            for field in label_fields:
                                self.assertNotIn(field, decision["encapsulation"])

    def test_local_resolution_text_uses_authored_values_and_resource_provenance(
        self,
    ) -> None:
        for case_id in CASE_IDS:
            for projection in self.projections.values():
                for row in projection["forwarding"]:
                    if row["scenario_id"] != case_id:
                        continue
                    for direction, decisions in row["directional_decisions"].items():
                        for decision in decisions:
                            for observation in decision["boundary_observations"]:
                                with self.subTest(
                                    case_id=case_id,
                                    direction=direction,
                                    node_id=row["node_id"],
                                ):
                                    text = decision["resolution_text"]
                                    self.assertIn(
                                        f"{observation['field']}={observation['value']}",
                                        text,
                                    )
                                    self.assertIn(observation["resource_id"], text)
                                    self.assertIn(
                                        str(observation["observed_at_ns"]), text
                                    )
                for route in projection["routes"]:
                    if route["scenario_id"] != case_id:
                        continue
                    for observation in route["boundary_observations"]:
                        self.assertIn(
                            f"{observation['field']}={observation['value']}",
                            route["resolution_text"],
                        )
                        self.assertIn(
                            observation["resource_id"], route["resolution_text"]
                        )

    def test_persisted_equal_receiver_clears_stale_generated_mismatch(self) -> None:
        for case_id in CASE_IDS:
            _, sender = self.observation(case_id, "forward", "sender")
            _, receiver = self.observation(case_id, "forward", "receiver")
            receiver["value"] = sender["value"]
        revalidated = self.revalidate()
        for case_id in CASE_IDS:
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    self.case(revalidated, case_id)["consistency_findings"], []
                )
                self.assert_result(self.coverage, case_id, "forward", "mismatch")

    def test_deleted_receiver_replaces_stale_mismatch_with_unknown(self) -> None:
        for case_id in CASE_IDS:
            row, receiver = self.observation(case_id, "forward", "receiver")
            for decision in row["directional_decisions"]["forward"]:
                decision["boundary_observations"] = [
                    item
                    for item in decision.get("boundary_observations", [])
                    if item is not receiver
                ]
        revalidated = self.revalidate()
        for case_id in CASE_IDS:
            with self.subTest(case_id=case_id):
                self.assert_result(revalidated, case_id, "forward", "unknown")
                self.assertEqual(self.findings(revalidated, case_id, "reverse"), [])

    def test_incomplete_receiver_replaces_stale_mismatch_with_unknown(self) -> None:
        for case_id in CASE_IDS:
            _, receiver = self.observation(case_id, "forward", "receiver")
            receiver["complete"] = False
        revalidated = self.revalidate()
        for case_id in CASE_IDS:
            with self.subTest(case_id=case_id):
                self.assert_result(revalidated, case_id, "forward", "unknown")

    def test_no_persisted_observations_is_unknown_in_both_directions(self) -> None:
        for projection in self.projections.values():
            for row in projection["forwarding"]:
                if row.get("scenario_id") not in CASE_IDS:
                    continue
                for decisions in row["directional_decisions"].values():
                    for decision in decisions:
                        decision.pop("boundary_observations", None)
        revalidated = self.revalidate()
        for case_id in CASE_IDS:
            for direction in ("forward", "reverse"):
                with self.subTest(case_id=case_id, direction=direction):
                    self.assert_result(revalidated, case_id, direction, "unknown")

    def test_malformed_persisted_observation_containers_are_unknown(self) -> None:
        for malformed in (None, [None]):
            for case_id in CASE_IDS:
                with self.subTest(case_id=case_id, malformed=malformed):
                    self.projections = deepcopy(self.generated_projections)
                    row, receiver = self.observation(case_id, "forward", "receiver")
                    for decision in row["directional_decisions"]["forward"]:
                        if any(
                            item is receiver
                            for item in decision.get("boundary_observations", [])
                        ):
                            decision["boundary_observations"] = malformed
                    self.assert_result(self.revalidate(), case_id, "forward", "unknown")

    def test_missing_authored_field_or_value_projects_as_unknown_without_crashing(
        self,
    ) -> None:
        original_resources_at = DEFAULT_SCENARIO_SOURCE.resources_at
        for missing_field in ("field", "value"):
            for case_id in CASE_IDS:
                with self.subTest(case_id=case_id, missing_field=missing_field):
                    self.projections = deepcopy(self.generated_projections)
                    _, receiver = self.observation(case_id, "forward", "receiver")
                    receiver_node_id = receiver["node_id"]
                    receiver_source_id = receiver["source_resource_id"]

                    def resources_at(
                        source: Any,
                        node_id: str,
                        *,
                        timestamp_ns: int | None = None,
                        target_node_id: str = receiver_node_id,
                        target_resource_id: str = receiver_source_id,
                        omitted_field: str = missing_field,
                    ) -> tuple[Any, ...]:
                        resources = original_resources_at(
                            node_id, timestamp_ns=timestamp_ns
                        )
                        if node_id != target_node_id:
                            return resources
                        result = []
                        for resource in resources:
                            if resource.resource_id == target_resource_id:
                                properties = resource.properties
                                properties.pop(omitted_field)
                                resource = replace(
                                    resource, properties_json=json.dumps(properties)
                                )
                            result.append(resource)
                        return tuple(result)

                    node = next(
                        item
                        for item in self.config.nodes
                        if item.node_id == receiver_node_id
                    )
                    with patch.object(
                        type(DEFAULT_SCENARIO_SOURCE),
                        "resources_at",
                        autospec=True,
                        side_effect=resources_at,
                    ):
                        routes, forwarding = _projection_rows(node, config=self.config)
                        generated = build_coverage(self.config)
                    self.projections[receiver_node_id] = {
                        "routes": [
                            row for row in routes if row.get("scenario_id") in CASE_IDS
                        ],
                        "forwarding": [
                            row
                            for row in forwarding
                            if row.get("scenario_id") in CASE_IDS
                        ],
                    }
                    _, observation = self.observation(case_id, "forward", "receiver")
                    self.assertNotIn(missing_field, observation)
                    self.assert_result(generated, case_id, "forward", "unknown")
                    self.assert_result(self.revalidate(), case_id, "forward", "unknown")

    def test_spoofed_observation_identity_cannot_reuse_stale_mismatch(self) -> None:
        for field, value in (
            ("revision_id", "stale-revision"),
            ("node_id", "unrelated-node"),
            ("peer_node_id", "unrelated-peer"),
            ("resource_id", "unbound-resource"),
        ):
            for case_id in CASE_IDS:
                with self.subTest(case_id=case_id, field=field):
                    self.projections = deepcopy(self.generated_projections)
                    _, receiver = self.observation(case_id, "forward", "receiver")
                    receiver[field] = value
                    self.assert_result(self.revalidate(), case_id, "forward", "unknown")

    def test_enclosing_forwarding_row_identity_and_evidence_are_required(self) -> None:
        for field, value in (
            ("revision_id", "stale-revision"),
            ("node_id", "unrelated-node"),
            ("evidence_resource_ids", []),
        ):
            for case_id in CASE_IDS:
                with self.subTest(case_id=case_id, field=field):
                    self.projections = deepcopy(self.generated_projections)
                    row, _ = self.observation(case_id, "forward", "receiver")
                    row[field] = value
                    self.assert_result(self.revalidate(), case_id, "forward", "unknown")

    def test_persisted_provenance_must_match_the_declared_source_binding(self) -> None:
        for mutation in ("source_id", "resource_type", "unrelated_complete_binding"):
            for case_id in CASE_IDS:
                with self.subTest(case_id=case_id, mutation=mutation):
                    self.projections = deepcopy(self.generated_projections)
                    row, receiver = self.observation(case_id, "forward", "receiver")
                    if mutation == "source_id":
                        receiver["source_resource_id"] = "consistency:unrelated"
                    else:
                        if mutation == "resource_type":
                            parts = receiver["resource_id"].split("/", 3)
                            parts[2] = "OTHER_BINDING"
                            receiver["resource_id"] = "/".join(parts)
                        else:
                            receiver["source_resource_id"] = "consistency:unrelated"
                            receiver["resource_id"] = (
                                receiver["resource_id"].rsplit("/", 1)[0]
                                + "/consistency:unrelated"
                            )
                        row["evidence_resource_ids"].append(receiver["resource_id"])
                    self.assert_result(self.revalidate(), case_id, "forward", "unknown")

    def test_revalidation_is_detached_and_preserves_unrelated_cases(self) -> None:
        coverage_before = deepcopy(self.coverage)
        projections_before = deepcopy(self.projections)
        revalidated = self.revalidate()
        self.assertEqual(self.coverage, coverage_before)
        self.assertEqual(self.projections, projections_before)
        for case in self.coverage["cases"]:
            if case["case_id"] not in CASE_IDS:
                with self.subTest(case_id=case["case_id"]):
                    self.assertEqual(self.case(revalidated, case["case_id"]), case)
        returned = self.case(revalidated, CASE_IDS[0])
        returned["consistency_findings"][0]["observations"][0]["value"] = -1
        returned["candidate_paths"].clear()
        self.assertEqual(self.coverage, coverage_before)
        self.assertEqual(self.projections, projections_before)


if __name__ == "__main__":
    unittest.main()
