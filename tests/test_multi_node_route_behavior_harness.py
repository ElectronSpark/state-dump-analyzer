"""Behavior-first safety net for the cross-node route coordinator.

These tests intentionally exercise the public HTTP contract instead of
private route-building helpers.  They preserve the externally observable
semantics needed to safely extract pieces from ``multi_node_route.py`` later
without freezing incidental response metadata or byte-identical payloads.
"""

from __future__ import annotations

import unittest
from typing import Any

from fastapi.testclient import TestClient

from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
)


def _path_behavior(path: dict[str, Any]) -> tuple[Any, ...]:
    """Return the stable routing decisions exposed for one candidate."""

    return (
        path["path_id"],
        path["perspective"],
        path["role"],
        path["result"],
        path["eligibility"],
        path["terminal_reason"],
        path["active"],
        path["primary"],
        path["alternative_state"],
        tuple(path["node_sequence"]),
        tuple(
            (
                segment["ordinal"],
                segment["segment_kind"],
                segment["phase"],
                segment["state"]["operational"],
                segment["completeness"]["state"],
            )
            for segment in path["segments"]
        ),
        tuple(
            (
                layer["presentation_id"],
                layer["role"],
                layer["style"],
                layer["geometry_role"],
            )
            for layer in path.get("presentations", [])
        ),
    )


def _packet_behavior(path: dict[str, Any]) -> tuple[Any, ...]:
    """Return ordered packet actions and layer-stack changes for one path."""

    return tuple(
        (
            transition["node_id"],
            transition["transition"]["action_label"],
            transition["transition"]["disposition"],
            tuple(
                layer["layer_id"]
                for layer in transition["transition"]["after"]["layers"]
            ),
            tuple(transition["diff"]["added_layer_ids"]),
            tuple(transition["diff"]["changed_layer_ids"]),
            tuple(transition["diff"]["removed_layer_ids"]),
        )
        for transition in path["packet_trace"]["transitions"]
    )


class MultiNodeRouteBehaviorHarnessTests(unittest.TestCase):
    """Small semantic matrix that must survive route-service extraction."""

    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def _trace(
        self,
        scenario_id: str,
        **request: Any,
    ) -> dict[str, Any]:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": scenario_id, **request},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def assert_ordered_route_contract(
        self,
        payload: dict[str, Any],
    ) -> None:
        """Check ordering relationships consumed by the route UI."""

        for path in payload["paths"]:
            segments = path["segments"]
            self.assertEqual(
                [segment["ordinal"] for segment in segments],
                list(range(1, len(segments) + 1)),
            )
            sequence = path["route_resolution_sequence"]
            self.assertEqual(
                [item["sequence"] for item in sequence],
                [segment["ordinal"] for segment in segments],
            )
            self.assertEqual(
                [item["segment_id"] for item in sequence],
                [segment["segment_id"] for segment in segments],
            )
            self.assertEqual(
                path["graph_target_ids"],
                [
                    target_id
                    for segment in segments
                    for target_id in segment["highlight_target_ids"]
                ],
            )

    def test_basic_ip_route_retains_outer_path_and_resolution_order(
        self,
    ) -> None:
        payload = self._trace("router-to-router")

        self.assertTrue(payload["reachable"])
        self.assertEqual(payload["route_type"], "ipv4_unicast")
        self.assertEqual(payload["route_family"], "ipv4_unicast")
        self.assertEqual(payload["multipath"]["mode"], "single_active")
        self.assertEqual(payload["multipath"]["candidate_count"], 1)
        self.assertEqual(
            [_path_behavior(path)[:10] for path in payload["paths"]],
            [
                (
                    (
                        "route-path:inventory:"
                        "generic-ipv4_unicast-default-ipv4_unicast:"
                        "node-a:node-b"
                    ),
                    "forwarding_observed",
                    "primary",
                    "resolved",
                    "selected",
                    None,
                    True,
                    True,
                    "selected_primary",
                    ("node-a", "transit-p-1", "node-b"),
                )
            ],
        )
        self.assertNotIn("packet_trace", payload["paths"][0])
        self.assert_ordered_route_contract(payload)

    def test_mpls_and_srv6_packet_stacks_preserve_ordered_actions(
        self,
    ) -> None:
        mpls = self._trace("packet-sr-mpls-php")
        srv6 = self._trace("packet-srv6-encap")

        self.assertEqual(
            [
                (
                    item[1],
                    item[2],
                    item[3],
                    item[4],
                    item[5],
                    item[6],
                )
                for item in _packet_behavior(mpls["paths"][0])
            ],
            [
                (
                    "Push transport label",
                    "continue",
                    ("transport-label", "inner-ipv4"),
                    ("transport-label",),
                    (),
                    (),
                ),
                (
                    "Swap transport label",
                    "continue",
                    ("transport-label", "inner-ipv4"),
                    (),
                    ("transport-label",),
                    (),
                ),
                (
                    "Penultimate-hop pop transport label",
                    "continue",
                    ("inner-ipv4",),
                    (),
                    (),
                    ("transport-label",),
                ),
                (
                    "Remove service encapsulation and deliver",
                    "deliver",
                    ("inner-ipv4",),
                    (),
                    (),
                    (),
                ),
            ],
        )
        self.assertEqual(
            [
                (
                    item[1],
                    item[3],
                    item[4],
                    item[5],
                    item[6],
                )
                for item in _packet_behavior(srv6["paths"][0])
            ],
            [
                (
                    "Encapsulate with outer IPv6 and SRH",
                    ("outer-ipv6", "srh", "inner-ipv6"),
                    ("outer-ipv6", "srh"),
                    (),
                    (),
                ),
                (
                    "Advance SRv6 segment list",
                    ("outer-ipv6", "srh", "inner-ipv6"),
                    (),
                    ("outer-ipv6", "srh"),
                    (),
                ),
                (
                    "Decapsulate SRv6 and deliver",
                    ("inner-ipv6",),
                    (),
                    (),
                    ("outer-ipv6", "srh"),
                ),
            ],
        )
        self.assert_ordered_route_contract(mpls)
        self.assert_ordered_route_contract(srv6)

    def test_single_active_and_all_active_multipath_keep_all_candidates(
        self,
    ) -> None:
        single = self._trace("single-active-primary")
        all_active = self._trace("all-active-ecmp")

        self.assertEqual(
            (
                single["multipath"]["mode"],
                single["multipath"]["candidate_count"],
                single["multipath"]["active_path_count"],
            ),
            ("single_active", 2, 1),
        )
        self.assertEqual(
            [
                (
                    path["role"],
                    path["active"],
                    path["alternative_state"],
                    tuple(path["node_sequence"]),
                )
                for path in single["paths"]
            ],
            [
                (
                    "primary",
                    True,
                    "selected_primary",
                    ("node-a", "transit-p-1", "node-b"),
                ),
                (
                    "standby",
                    False,
                    "eligible_standby",
                    ("node-a", "transit-p-2", "node-b"),
                ),
            ],
        )
        self.assertEqual(
            (
                all_active["multipath"]["mode"],
                all_active["multipath"]["candidate_count"],
                all_active["multipath"]["active_path_count"],
                all_active["multipath"]["primary_path_id"],
            ),
            ("all_active", 2, 2, None),
        )
        self.assertEqual(
            [
                (
                    path["role"],
                    path["active"],
                    path["primary"],
                    path["alternative_state"],
                    tuple(path["node_sequence"]),
                )
                for path in all_active["paths"]
            ],
            [
                (
                    "ecmp",
                    True,
                    False,
                    "ecmp_member",
                    ("node-a", "transit-p-1", "node-b"),
                ),
                (
                    "ecmp",
                    True,
                    False,
                    "ecmp_member",
                    ("node-a", "transit-p-2", "node-b"),
                ),
            ],
        )

    def test_terminal_candidates_distinguish_loops_policy_and_dead_paths(
        self,
    ) -> None:
        expectations = {
            "cross-node-forwarding-loop": (
                "consistent_cycle_detected",
                "cycle",
                "selected",
                "forwarding_loop",
                ("node-a", "transit-p-1", "node-b", "transit-p-1"),
            ),
            "recursive-resolution-cycle": (
                "consistent_cycle_detected",
                "cycle",
                "selected",
                "recursive_resolution_cycle",
                ("node-a", "node-a", "node-a"),
            ),
            "evpn-split-horizon-block": (
                "consistent_policy_blocked",
                "policy_blocked",
                "ineligible_policy",
                "split_horizon_same_scope",
                ("node-b", "transit-p-2", "node-e"),
            ),
        }
        for scenario_id, expected in expectations.items():
            with self.subTest(scenario_id=scenario_id):
                payload = self._trace(scenario_id)
                path = payload["paths"][0]
                self.assertFalse(payload["reachable"])
                self.assertEqual(
                    (
                        payload["consistency"]["state"],
                        path["result"],
                        path["eligibility"],
                        path["terminal_reason"],
                        tuple(path["node_sequence"]),
                    ),
                    expected,
                )

        failover = self._trace("evpn-es-withdraw-failover")
        self.assertTrue(failover["reachable"])
        self.assertEqual(
            [
                (
                    path["result"],
                    path["eligibility"],
                    path["terminal_reason"],
                    path["active"],
                )
                for path in failover["paths"]
            ],
            [
                ("unusable", "ineligible_dead", "evpn_es_withdrawn", False),
                ("resolved", "selected", None, True),
            ],
        )

    def test_transit_start_uses_endpoint_reachability_for_both_directions(
        self,
    ) -> None:
        payload = self._trace(
            "transit-start-endpoint-reachability",
            direction="both",
        )

        forward = payload["traces"]["forward"]
        reverse = payload["traces"]["reverse"]
        self.assertEqual(
            tuple(forward["paths"][0]["node_sequence"]),
            ("transit-p-1", "node-b"),
        )
        self.assertEqual(
            tuple(reverse["paths"][0]["node_sequence"]),
            ("node-b", "transit-p-2", "node-a"),
        )
        self.assertNotIn(
            forward["trace_start"]["node_id"],
            reverse["paths"][0]["node_sequence"],
        )
        validation = payload["bidirectional_validation"]
        self.assertEqual(
            (
                validation["criterion"],
                validation["endpoint_state"],
                validation["forward_reaches_destination"],
                validation["reverse_reaches_source"],
                validation["path_relation"]["state"],
                validation["path_relation"]["reason"],
                validation["reverse_must_visit_forward_start"],
            ),
            (
                "source_destination_endpoint_reachability",
                "bidirectionally_reachable",
                True,
                True,
                "not_comparable",
                "forward_starts_inside_flow_path",
                False,
            ),
        )
        self.assertTrue(payload["consistency"]["consistent"])

        one_way = self._trace("site-b-site-c-one-way", direction="both")
        one_way_validation = one_way["bidirectional_validation"]
        self.assertEqual(
            (
                one_way_validation["endpoint_state"],
                one_way_validation["forward_reaches_destination"],
                one_way_validation["reverse_reaches_source"],
                one_way["traces"]["forward"]["reachable"],
                one_way["traces"]["reverse"]["reachable"],
            ),
            ("one_way_reachable", True, False, True, False),
        )
        self.assertFalse(one_way["consistency"]["consistent"])

    def test_semantic_order_and_presentation_targets_are_repeatable(
        self,
    ) -> None:
        """Repeat queries to guard deterministic UI-facing ordering."""

        requests = (
            ("single-active-primary", {}),
            ("evpn-es-withdraw-failover", {}),
            ("packet-vpn-over-vpn", {}),
            ("site-b-site-c-one-way", {"direction": "both"}),
        )
        for scenario_id, request in requests:
            with self.subTest(scenario_id=scenario_id):
                first = self._trace(scenario_id, **request)
                second = self._trace(scenario_id, **request)
                first_traces = first.get("traces", {})
                second_traces = second.get("traces", {})

                self.assertEqual(
                    [_path_behavior(path) for path in first["paths"]],
                    [_path_behavior(path) for path in second["paths"]],
                )
                self.assertEqual(
                    [
                        target["target_id"]
                        for target in first["interaction_targets"]
                    ],
                    [
                        target["target_id"]
                        for target in second["interaction_targets"]
                    ],
                )
                for direction in ("forward", "reverse"):
                    if direction not in first_traces:
                        continue
                    self.assertEqual(
                        [
                            _path_behavior(path)
                            for path in first_traces[direction]["paths"]
                        ],
                        [
                            _path_behavior(path)
                            for path in second_traces[direction]["paths"]
                        ],
                    )
                if "packet_trace" in first["paths"][0]:
                    self.assertEqual(
                        _packet_behavior(first["paths"][0]),
                        _packet_behavior(second["paths"][0]),
                    )
                self.assert_ordered_route_contract(first)


if __name__ == "__main__":
    unittest.main()
