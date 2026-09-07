"""Small demo packet-profile checks; no generated archive is needed."""

from __future__ import annotations

import unittest

from rsl_demo_generator.catalog import COVERAGE_CASES
from rsl_demo_plugin import GENERATED_PROJECTION_POLICY
from rsl_demo_plugin.advanced_trace import (
    ADVANCED_TRACE_SCENARIOS,
    build_packet_transitions,
)
from rsl_demo_plugin.scenario_registry import SCENARIO_BY_ID

from router_dump_analyzer.plugin_api import (
    ForwardingPacketDisposition,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingTransitionOrigin,
)
from router_dump_analyzer.route_trace_core import evaluate_forwarding_packet_trace


class DemoPacketProfileBoundaryTests(unittest.TestCase):
    def test_truncated_profiles_preserve_nonterminal_prefixes(self) -> None:
        profiles = {
            str(scenario["packet_profile_id"])
            for scenario in ADVANCED_TRACE_SCENARIOS
        }
        for profile_id in sorted(profiles):
            for direction in ("forward", "reverse"):
                nodes = ("node-a", "transit-p-1", "transit-p-2", "node-b")
                if direction == "reverse":
                    nodes = tuple(reversed(nodes))
                step_ids = tuple(f"step:{node}" for node in nodes)
                initial, complete = build_packet_transitions(
                    profile_id=profile_id,
                    step_ids=step_ids,
                    node_ids=nodes,
                    direction=direction,
                )
                for prefix_count in range(1, len(complete)):
                    with self.subTest(
                        profile=profile_id,
                        direction=direction,
                        prefix_count=prefix_count,
                    ):
                        prefix_initial, prefix = build_packet_transitions(
                            profile_id=profile_id,
                            step_ids=step_ids[:prefix_count],
                            node_ids=nodes[:prefix_count],
                            direction=direction,
                        )
                        self.assertEqual(prefix_initial, initial)
                        self.assertEqual(prefix, complete[:prefix_count])
                        self.assertTrue(
                            all(
                                item.disposition
                                is ForwardingPacketDisposition.CONTINUE
                                for item in prefix
                            )
                        )
                        self.assertEqual(
                            evaluate_forwarding_packet_trace(
                                prefix_initial, prefix
                            ).outcome,
                            "continuation_required",
                        )

    def test_forced_alternate_path_performs_php_before_delivery(self) -> None:
        for direction in ("forward", "reverse"):
            nodes = ("node-a", "transit-p-2", "node-b")
            if direction == "reverse":
                nodes = tuple(reversed(nodes))
            step_ids = tuple(f"step:{node}" for node in nodes)
            with self.subTest(direction=direction):
                initial, transitions = build_packet_transitions(
                    profile_id="sr-mpls-php",
                    step_ids=step_ids,
                    node_ids=nodes,
                    direction=direction,
                    steering_profile_id="force-alternate-p2",
                )
                evaluation = evaluate_forwarding_packet_trace(
                    initial, transitions
                )
                self.assertEqual(len(transitions), 3)
                self.assertEqual(evaluation.outcome, "deliver")
                self.assertEqual(evaluation.continuity, "complete")
                self.assertIs(
                    transitions[0].origin,
                    ForwardingTransitionOrigin.USER_FORCED,
                )
                self.assertEqual(
                    transitions[1].action_label,
                    "Penultimate-hop pop transport label",
                )
                self.assertEqual(
                    evaluation.transitions[1].diff.removed_layer_ids,
                    ("transport-label",),
                )
                self.assertEqual(transitions[-1].after, initial)
                self.assertIs(
                    transitions[-1].disposition,
                    ForwardingPacketDisposition.DELIVER,
                )
                for prefix_count in (1, 2):
                    _, prefix = build_packet_transitions(
                        profile_id="sr-mpls-php",
                        step_ids=step_ids[:prefix_count],
                        node_ids=nodes[:prefix_count],
                        direction=direction,
                        steering_profile_id="force-alternate-p2",
                    )
                    self.assertEqual(prefix, transitions[:prefix_count])
                    self.assertEqual(
                        evaluate_forwarding_packet_trace(initial, prefix).outcome,
                        "continuation_required",
                    )

    def test_forced_wrappers_remain_on_truncated_prefixes(self) -> None:
        for steering_profile_id, wrapper_id in (
            ("force-outer-ipv4", "forced-outer-ipv4"),
            ("force-mid-wrapper", "forced-mid-wrapper"),
        ):
            for direction in ("forward", "reverse"):
                nodes = ("node-a", "transit-p-1", "transit-p-2", "node-b")
                if direction == "reverse":
                    nodes = tuple(reversed(nodes))
                step_ids = tuple(f"step:{node}" for node in nodes)
                with self.subTest(
                    steering_profile=steering_profile_id, direction=direction
                ):
                    initial, complete = build_packet_transitions(
                        profile_id="sr-mpls-php",
                        step_ids=step_ids,
                        node_ids=nodes,
                        direction=direction,
                        steering_profile_id=steering_profile_id,
                    )
                    _, prefix = build_packet_transitions(
                        profile_id="sr-mpls-php",
                        step_ids=step_ids[:3],
                        node_ids=nodes[:3],
                        direction=direction,
                        steering_profile_id=steering_profile_id,
                    )
                    self.assertEqual(prefix, complete[:3])
                    self.assertIn(
                        wrapper_id,
                        {layer.layer_id for layer in prefix[-1].after.layers},
                    )
                    self.assertEqual(
                        evaluate_forwarding_packet_trace(initial, prefix).outcome,
                        "continuation_required",
                    )

    def _build(
        self, profile_id: str, direction: str
    ) -> tuple[ForwardingPacketState, tuple[ForwardingPacketTransition, ...]]:
        nodes = ("node-a", "transit-p-1", "node-b")
        if direction == "reverse":
            nodes = tuple(reversed(nodes))
        return build_packet_transitions(
            profile_id=profile_id,
            step_ids=tuple(f"step:{node}" for node in nodes),
            node_ids=nodes,
            direction=direction,
        )

    def test_mtu_profiles_cover_fit_equality_and_incomparable_bases(self) -> None:
        for profile_id, size_bytes, outcome in (
            ("mtu-fit", 1440, "fits"),
            ("mtu-exact", 1500, "fits"),
            ("mtu-incomparable", 1510, "unknown_basis_mismatch"),
            ("mtu-drop", 1510, "exceeds"),
        ):
            for direction in ("forward", "reverse"):
                with self.subTest(profile=profile_id, direction=direction):
                    initial, transitions = self._build(profile_id, direction)
                    evaluation = evaluate_forwarding_packet_trace(
                        initial, transitions
                    )
                    first = evaluation.transitions[0]
                    self.assertEqual(first.mtu.outcome, outcome)
                    self.assertEqual(first.mtu.size_bytes, size_bytes)
                    self.assertEqual(first.mtu.limit_bytes, 1500)
                    self.assertEqual(first.diff.added_layer_ids, ("outer-ipv4",))
                    self.assertEqual(evaluation.continuity, "complete")
                    is_drop = profile_id == "mtu-drop"
                    self.assertEqual(
                        evaluation.outcome, "drop" if is_drop else "deliver"
                    )
                    self.assertIs(
                        first.transition.disposition,
                        ForwardingPacketDisposition.DROP
                        if is_drop
                        else ForwardingPacketDisposition.CONTINUE,
                    )
                    self.assertTrue(
                        all(
                            transition.origin
                            is ForwardingTransitionOrigin.NODE_PLUGIN
                            for transition in transitions
                        )
                    )
                    self.assertEqual(
                        first.mtu.excess_bytes,
                        10 if is_drop else 0 if outcome == "fits" else None,
                    )
                    outer = dict(first.transition.after.layers[0].fields)
                    self.assertEqual(
                        (outer["source"], outer["destination"]),
                        ("192.0.2.1", "198.51.100.1")
                        if direction == "forward"
                        else ("198.51.100.1", "192.0.2.1"),
                    )
                    if not is_drop:
                        self.assertEqual(transitions[-1].after, initial)

    def test_incomplete_capture_survives_later_complete_delivery(self) -> None:
        for direction in ("forward", "reverse"):
            with self.subTest(direction=direction):
                initial, transitions = self._build(
                    "native-ip-incomplete", direction
                )
                evaluation = evaluate_forwarding_packet_trace(initial, transitions)
                self.assertTrue(initial.complete)
                self.assertFalse(transitions[0].after.complete)
                self.assertEqual(transitions[0].after, transitions[1].before)
                self.assertTrue(transitions[-1].after.complete)
                self.assertEqual(evaluation.continuity, "unknown_incomplete")
                self.assertEqual(evaluation.outcome, "deliver")
                self.assertEqual(
                    [item.diff.complete for item in evaluation.transitions],
                    [False, False, True],
                )

    def test_new_packet_profiles_have_generated_catalog_declarations(self) -> None:
        cases = {case.case_id: case for case in COVERAGE_CASES}
        for profile_id in (
            "mtu-fit", "mtu-exact", "mtu-incomparable", "native-ip-incomplete",
        ):
            scenario_id = f"packet-{profile_id}"
            with self.subTest(scenario_id=scenario_id):
                case = cases[scenario_id]
                self.assertEqual(case.category, "packet")
                self.assertEqual(case.packet_profile_id, profile_id)
                self.assertEqual(case.expected_outcome, "resolved")
                self.assertEqual(
                    SCENARIO_BY_ID[scenario_id]["packet_profile_id"], profile_id
                )
                declaration = GENERATED_PROJECTION_POLICY.packet_declaration(
                    scenario_id=scenario_id, profile_id=profile_id
                )
                self.assertEqual(declaration["executor_profile_id"], profile_id)
                self.assertEqual(declaration["scenario_id"], scenario_id)


if __name__ == "__main__":
    unittest.main()
