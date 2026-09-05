from __future__ import annotations

import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.plugin_api import (
    ForwardingMtuConstraint,
    ForwardingPacketDisposition,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingTransitionOrigin,
)
from tests.test_packet_trace_core import packet, transition


class RoutePacketProjectionTests(unittest.TestCase):
    @staticmethod
    def _attach(
        initial: ForwardingPacketState,
        declared: ForwardingPacketTransition,
        *,
        prefix: tuple[ForwardingPacketTransition, ...] = (),
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        service = object.__new__(MultiNodeRouteService)
        service.policy = SimpleNamespace(packet_trace_schema_version="test.v1")
        transitions = (*prefix, declared)
        service._packet_transition_builder = lambda **_kwargs: (initial, transitions)
        segments = [
            {
                "segment_id": step_id,
                "node_id": f"node-{ordinal}",
                "ordinal": ordinal,
                "segment_kind": "node_resolution",
                "state": {},
                "route_resolution": {},
                "active": True,
                "observed": True,
                "counterfactual": False,
                "confidence": 1.0,
                "completeness": {
                    "state": "complete", "end_to_end_resolved": True,
                    "observed": True,
                },
                "interaction_target_ids": [],
                "plugin_provenance": [],
                "issue_refs": [],
            }
            for ordinal, step_id in enumerate(
                (*[item.step_id for item in transitions], "unvisited")
            )
        ]
        path = {
            "path_id": "path:test", "segments": segments,
            "active": True, "issue_refs": [],
        }
        issues: list[dict[str, Any]] = []
        service._attach_packet_trace(
            path, profile_id="opaque-plugin-profile", direction="forward",
            steering_profile_id="none", issues=issues,
        )
        return path, issues

    def test_identical_incomplete_packet_json_does_not_claim_complete_continuity(
        self,
    ) -> None:
        incomplete = packet((), 64, complete=False)
        path, issues = self._attach(
            incomplete,
            transition(
                "deliver", incomplete, incomplete,
                disposition=ForwardingPacketDisposition.DELIVER,
            ),
        )
        trace = path["packet_trace"]
        self.assertEqual(trace["outcome"], "deliver")
        self.assertEqual(trace["continuity"], "unknown_incomplete")
        self.assertFalse(trace["continuity_complete"])
        self.assertIsNone(trace["transitions"][0]["continuity_valid"])
        self.assertFalse(trace["transitions"][0]["diff"]["complete"])
        self.assertEqual(issues, [])

    def test_generic_drops_do_not_invent_an_mtu_failure(self) -> None:
        state = packet((), 64)
        comparable = ForwardingMtuConstraint(
            basis_contract_id=state.size.basis_contract_id, limit_bytes=128
        )
        for case, snapshot, constraint, expected_outcome in (
            ("undeclared", state, None, "not_declared"),
            ("below", state, comparable, "fits"),
            ("equal", state, replace(comparable, limit_bytes=64), "fits"),
            (
                "other_basis", state,
                replace(comparable, basis_contract_id="other.size.v1", limit_bytes=1),
                "unknown_basis_mismatch",
            ),
            (
                "incomplete_constraint", state,
                replace(comparable, complete=False, limit_bytes=1), "unknown",
            ),
            ("missing_size", replace(state, size=None), comparable, "unknown"),
            (
                "incomplete_size",
                replace(state, size=replace(state.size, complete=False)),
                replace(comparable, limit_bytes=1), "unknown",
            ),
        ):
            with self.subTest(case=case):
                declared = replace(
                    transition(
                        "drop", snapshot, snapshot,
                        disposition=ForwardingPacketDisposition.DROP,
                        mtu=constraint,
                    ),
                    action_contract_id="vendor.access-policy.reject.v1",
                    action_label="Rejected by node-local access policy",
                )
                path, issues = self._attach(snapshot, declared)
                terminal, suffix = path["segments"]
                serialized = path["packet_trace"]["transitions"][0]
                self.assertEqual(serialized["mtu"]["outcome"], expected_outcome)
                self.assertEqual(
                    serialized["transition"]["action_contract_id"],
                    declared.action_contract_id,
                )
                self.assertEqual(
                    serialized["transition"]["action_label"], declared.action_label
                )
                self.assertEqual(path["result"], "dropped")
                self.assertEqual(path["terminal_reason"], "plugin_declared_packet_drop")
                self.assertEqual(terminal["segment_kind"], "packet_drop")
                self.assertEqual(terminal["state"]["terminal"], "packet_drop")
                self.assertEqual(terminal["phase"], "packet_drop_decision")
                self.assertEqual(terminal["route_resolution"]["phase"], terminal["phase"])
                self.assertFalse(path["active"])
                self.assertFalse(suffix["active"])
                self.assertEqual(suffix["completeness"]["state"], "not_traversed")
                self.assertEqual(len(issues), 1)
                self.assertEqual(issues[0]["ownership"], "node_plugin_disposition")
                self.assertNotIn("MTU", issues[0]["summary"])
                self.assertNotIn("exceeds", issues[0]["detail"])
                self.assertIn(issues[0]["issue_id"], terminal["issue_refs"])
                self.assertIn(issues[0]["issue_id"], path["issue_refs"])

    def test_exact_over_limit_drop_retains_mtu_diagnostics(self) -> None:
        state = packet((), 64)
        path, issues = self._attach(
            state,
            transition(
                "drop", state, state,
                disposition=ForwardingPacketDisposition.DROP,
                mtu=ForwardingMtuConstraint(
                    basis_contract_id=state.size.basis_contract_id, limit_bytes=63
                ),
            ),
        )
        terminal, suffix = path["segments"]
        serialized = path["packet_trace"]["transitions"][0]
        self.assertEqual(serialized["mtu"]["outcome"], "exceeds")
        self.assertEqual(serialized["mtu"]["excess_bytes"], 1)
        self.assertEqual(path["result"], "dropped")
        self.assertEqual(path["terminal_reason"], "mtu_exceeded_after_encapsulation")
        self.assertEqual(terminal["segment_kind"], "packet_mtu_drop")
        self.assertEqual(terminal["phase"], "packet_mtu_decision")
        self.assertFalse(suffix["active"])
        self.assertEqual(suffix["completeness"]["state"], "not_traversed")
        self.assertEqual(len(issues), 1)
        self.assertEqual(
            issues[0]["ownership"], "core_size_comparison_node_plugin_disposition"
        )

    def test_exceeding_mtu_does_not_override_a_non_drop_disposition(self) -> None:
        state = packet((), 64)
        path, issues = self._attach(
            state,
            transition(
                "deliver", state, state,
                disposition=ForwardingPacketDisposition.DELIVER,
                mtu=ForwardingMtuConstraint(
                    basis_contract_id=state.size.basis_contract_id, limit_bytes=63
                ),
            ),
        )
        self.assertEqual(path["packet_trace"]["outcome"], "deliver")
        self.assertEqual(path["segments"][0]["segment_kind"], "node_resolution")
        self.assertTrue(path["active"])
        self.assertEqual(issues, [])

    def test_user_forced_drop_is_not_observed_node_plugin_evidence(self) -> None:
        state = packet((), 64)
        for constraint in (
            None,
            ForwardingMtuConstraint(
                basis_contract_id=state.size.basis_contract_id, limit_bytes=63
            ),
        ):
            with self.subTest(mtu=constraint):
                forced = replace(
                    transition(
                        "forced", state, state,
                        disposition=ForwardingPacketDisposition.DROP,
                        mtu=constraint,
                    ),
                    origin=ForwardingTransitionOrigin.USER_FORCED,
                    actor_id="opaque.actor:do-not-interpret",
                    forced_rule_id="opaque.rule:reject",
                )
                path, issues = self._attach(state, forced)
                terminal = path["segments"][0]
                serialized = path["packet_trace"]["transitions"][0]
                self.assertTrue(path["counterfactual"])
                self.assertFalse(path["observed"])
                self.assertFalse(terminal["completeness"]["observed"])
                self.assertFalse(terminal["state"]["selected_active_by_plugin"])
                self.assertEqual(terminal["segment_kind"], "packet_drop")
                self.assertEqual(path["terminal_reason"], "user_forced_packet_drop")
                self.assertEqual(issues[0]["ownership"], "user_forced_disposition")
                self.assertFalse(issues[0]["observed"])
                self.assertTrue(issues[0]["counterfactual"])
                self.assertNotIn("MTU policy", issues[0]["summary"])
                self.assertEqual(serialized["transition"]["actor_id"], forced.actor_id)
                self.assertEqual(
                    serialized["transition"]["forced_rule_id"], forced.forced_rule_id
                )
                self.assertEqual(
                    serialized["mtu"]["outcome"],
                    "exceeds" if constraint else "not_declared",
                )

    def test_plugin_drop_after_forced_prefix_is_still_counterfactual(self) -> None:
        state = packet((), 64)
        forced = replace(
            transition("forced", state, state),
            origin=ForwardingTransitionOrigin.USER_FORCED,
            actor_id="opaque.actor:steer",
            forced_rule_id="opaque.rule:forward",
        )
        path, issues = self._attach(
            state,
            transition(
                "drop", state, state,
                disposition=ForwardingPacketDisposition.DROP,
            ),
            prefix=(forced,),
        )
        self.assertTrue(path["counterfactual"])
        self.assertFalse(path["observed"])
        for segment in path["segments"]:
            self.assertFalse(segment["completeness"]["observed"])
            self.assertFalse(segment["observed"])
            self.assertTrue(segment["counterfactual"])
        self.assertEqual(issues[0]["ownership"], "node_plugin_disposition")
        self.assertFalse(issues[0]["observed"])
        self.assertTrue(issues[0]["counterfactual"])

    def test_counterfactual_segment_attribution_applies_to_every_disposition(
        self,
    ) -> None:
        state = packet((), 64)
        observed = transition("observed-prefix", state, state)
        forced = replace(
            transition("forced", state, state),
            origin=ForwardingTransitionOrigin.USER_FORCED,
            actor_id="opaque.actor:steer",
            forced_rule_id="opaque.rule:forward",
        )
        for disposition in ForwardingPacketDisposition:
            with self.subTest(disposition=disposition):
                downstream = transition(
                    "downstream", state, state, disposition=disposition
                )
                path, _issues = self._attach(
                    state, downstream, prefix=(observed, forced)
                )
                prefix, *affected = path["segments"]
                self.assertTrue(prefix["completeness"]["observed"])
                self.assertTrue(prefix["observed"])
                self.assertFalse(prefix["counterfactual"])
                for segment in affected:
                    self.assertFalse(segment["completeness"]["observed"])
                    self.assertFalse(segment["observed"])
                    self.assertTrue(segment["counterfactual"])
                serialized = path["packet_trace"]["transitions"]
                self.assertTrue(serialized[1]["counterfactual"])
                self.assertFalse(serialized[2]["counterfactual"])
                self.assertEqual(
                    serialized[2]["transition"]["origin"], "node_plugin"
                )
                self.assertEqual(
                    serialized[2]["transition"]["actor_id"], downstream.actor_id
                )
                self.assertEqual(path["packet_trace"]["outcome"], (
                    "continuation_required"
                    if disposition is ForwardingPacketDisposition.CONTINUE
                    else disposition.value
                ))


if __name__ == "__main__":
    unittest.main()
