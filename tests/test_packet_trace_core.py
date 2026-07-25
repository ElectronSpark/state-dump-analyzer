from __future__ import annotations

import unittest
from itertools import product

from router_dump_analyzer.plugin_api import (
    ForwardingMtuConstraint,
    ForwardingPacketDisposition,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingSizeObservation,
    ForwardingStepRequest,
    ForwardingStepResult,
    ForwardingSteeringRule,
    ForwardingTransitionOrigin,
    ForwardingTraversalStateKey,
    ResourceKey,
    StatusPerspectiveRef,
)
from router_dump_analyzer.route_trace_core import (
    RouteTraceContractError,
    apply_forwarding_steering_rule,
    detect_forwarding_cycle,
    diff_forwarding_packet_states,
    evaluate_forwarding_mtu,
    evaluate_forwarding_packet_trace,
    evaluate_forwarding_packet_transition,
    select_forwarding_steering_rule,
    validate_forwarding_step_result,
)


def layer(
    layer_id: str,
    contract_id: str,
    label: str,
    *,
    size_bytes: int,
    fields: tuple[tuple[str, object], ...] = (),
    complete: bool = True,
) -> ForwardingPacketLayer:
    return ForwardingPacketLayer(
        layer_id=layer_id,
        contract_id=contract_id,
        label=label,
        fields=fields,  # type: ignore[arg-type]
        size_bytes=size_bytes,
        complete=complete,
    )


def packet(
    layers: tuple[ForwardingPacketLayer, ...],
    size_bytes: int,
    *,
    basis: str = "example.wire-size.v1",
    complete: bool = True,
) -> ForwardingPacketState:
    return ForwardingPacketState(
        layers=layers,
        size=ForwardingSizeObservation(
            basis_contract_id=basis,
            size_bytes=size_bytes,
        ),
        complete=complete,
    )


def transition(
    step_id: str,
    before: ForwardingPacketState,
    after: ForwardingPacketState,
    *,
    disposition: ForwardingPacketDisposition = (
        ForwardingPacketDisposition.CONTINUE
    ),
    mtu: ForwardingMtuConstraint | None = None,
) -> ForwardingPacketTransition:
    return ForwardingPacketTransition(
        transition_id=f"transition:{step_id}",
        step_id=step_id,
        before=before,
        after=after,
        action_contract_id="example.packet-action.v1",
        action_label="Example packet action",
        disposition=disposition,
        origin=ForwardingTransitionOrigin.NODE_PLUGIN,
        actor_id="example.forwarding-plugin",
        mtu=mtu,
    )


class ForwardingPacketContractTests(unittest.TestCase):
    def test_layer_fields_are_canonical_and_state_requires_unique_ids(self) -> None:
        item = layer(
            "inner-ip",
            "example.ipv4.v1",
            "Inner IPv4",
            size_bytes=20,
            fields=(("ttl", 64), ("destination", "203.0.113.8")),
        )
        self.assertEqual(
            [name for name, _value in item.fields],
            ["destination", "ttl"],
        )
        with self.assertRaisesRegex(ValueError, "identifiers must be unique"):
            ForwardingPacketState(layers=(item, item))
        with self.assertRaisesRegex(ValueError, "Boolean"):
            layer(
                "bad",
                "example.ipv4.v1",
                "Bad",
                size_bytes=20,
                fields=(("df", True),),  # type: ignore[arg-type]
            )

    def test_structural_diff_does_not_interpret_protocol_names(self) -> None:
        inner = layer(
            "inner-ip",
            "vendor.private-ip.v3",
            "Inner payload",
            size_bytes=20,
        )
        transport = layer(
            "transport",
            "vendor.opaque-stack-entry.v7",
            "Transport entry 16002",
            size_bytes=4,
            fields=(("value", 16002),),
        )
        before = packet((inner,), 1_420)
        pushed = packet((transport, inner), 1_424)
        swapped = packet(
            (
                layer(
                    "transport",
                    "vendor.opaque-stack-entry.v7",
                    "Transport entry 16003",
                    size_bytes=4,
                    fields=(("value", 16003),),
                ),
                inner,
            ),
            1_424,
        )
        popped = packet((inner,), 1_420)

        self.assertEqual(
            diff_forwarding_packet_states(before, pushed).added_layer_ids,
            ("transport",),
        )
        self.assertEqual(
            diff_forwarding_packet_states(before, pushed).moved_layer_ids,
            (),
        )
        self.assertTrue(diff_forwarding_packet_states(before, pushed).complete)
        self.assertEqual(
            diff_forwarding_packet_states(pushed, swapped).changed_layer_ids,
            ("transport",),
        )
        self.assertEqual(
            diff_forwarding_packet_states(swapped, popped).removed_layer_ids,
            ("transport",),
        )
        self.assertEqual(
            diff_forwarding_packet_states(swapped, popped).moved_layer_ids,
            (),
        )
        reordered = packet((inner, transport), 1_424)
        self.assertEqual(
            diff_forwarding_packet_states(swapped, reordered).moved_layer_ids,
            ("inner-ip", "transport"),
        )
        service = layer(
            "service",
            "vendor.service.v1",
            "Service",
            size_bytes=4,
        )
        fully_reordered = diff_forwarding_packet_states(
            packet((transport, service, inner), 1_428),
            packet((inner, service, transport), 1_428),
        )
        self.assertEqual(
            fully_reordered.moved_layer_ids,
            ("inner-ip", "service", "transport"),
        )

        relabeled_inner = layer(
            "inner-ip",
            "vendor.private-ip.v3",
            "Different presentation text",
            size_bytes=20,
        )
        relabeled = packet((relabeled_inner,), 1_420)
        relabeled_diff = diff_forwarding_packet_states(before, relabeled)
        self.assertFalse(relabeled_diff.changed)
        self.assertEqual(before, relabeled)

        incomplete_inner = layer(
            "inner-ip",
            "vendor.private-ip.v3",
            "Incomplete inner payload",
            size_bytes=20,
            complete=False,
        )
        incomplete = packet((incomplete_inner,), 1_420)
        self.assertFalse(
            diff_forwarding_packet_states(before, incomplete).complete
        )

    def test_mtu_comparison_requires_the_same_complete_basis(self) -> None:
        state = packet((), 1_500)
        fitting = ForwardingMtuConstraint(
            basis_contract_id="example.wire-size.v1",
            limit_bytes=1_500,
        )
        too_small = ForwardingMtuConstraint(
            basis_contract_id="example.wire-size.v1",
            limit_bytes=1_492,
        )
        other_basis = ForwardingMtuConstraint(
            basis_contract_id="example.l3-size.v1",
            limit_bytes=1_500,
        )
        self.assertEqual(evaluate_forwarding_mtu(state, fitting).outcome, "fits")
        exceeded = evaluate_forwarding_mtu(state, too_small)
        self.assertEqual(exceeded.outcome, "exceeds")
        self.assertEqual(exceeded.excess_bytes, 8)
        self.assertEqual(
            evaluate_forwarding_mtu(state, other_basis).outcome,
            "unknown_basis_mismatch",
        )
        incomplete = ForwardingPacketState(
            layers=(),
            size=ForwardingSizeObservation(
                basis_contract_id="example.wire-size.v1",
                size_bytes=1_500,
                complete=False,
            ),
        )
        self.assertEqual(
            evaluate_forwarding_mtu(incomplete, fitting).outcome,
            "unknown",
        )

    def test_mtu_does_not_silently_choose_fragment_or_drop(self) -> None:
        state = packet((), 1_600)
        mtu = ForwardingMtuConstraint(
            basis_contract_id="example.wire-size.v1",
            limit_bytes=1_500,
        )
        continued = transition("egress", state, state, mtu=mtu)
        evaluated = evaluate_forwarding_packet_transition(continued)
        self.assertEqual(evaluated.mtu.outcome, "exceeds")
        self.assertIs(
            evaluated.transition.disposition,
            ForwardingPacketDisposition.CONTINUE,
        )

    def test_forced_rule_is_exact_bounded_and_counterfactual(self) -> None:
        inner = layer(
            "inner",
            "example.ipv4.v1",
            "IPv4",
            size_bytes=20,
        )
        before = packet((inner,), 1_420)
        forced_after = packet(
            (
                layer(
                    "outer",
                    "example.ipv4.v1",
                    "Forced outer IPv4",
                    size_bytes=20,
                ),
                inner,
            ),
            1_440,
        )
        base = transition("node-a:lookup-1", before, before)
        rule = ForwardingSteeringRule(
            rule_id="force-tunnel",
            target_step_id=base.step_id,
            action_contract_id="example.force-tunnel.v1",
            reason="exercise the alternate tunnel",
            priority=10,
            expected_before=before,
            packet_after=forced_after,
        )
        selected = select_forwarding_steering_rule(
            step_id=base.step_id,
            packet_state=before,
            rules=(rule,),
        )
        self.assertIs(selected, rule)
        forced = apply_forwarding_steering_rule(
            base,
            rule,
            actor_id="user:demo",
        )
        self.assertIs(
            forced.origin,
            ForwardingTransitionOrigin.USER_FORCED,
        )
        self.assertEqual(forced.forced_rule_id, rule.rule_id)
        self.assertTrue(
            evaluate_forwarding_packet_transition(forced).counterfactual
        )
        self.assertEqual(forced.after, forced_after)
        self.assertEqual(base.after, before)

        tied = ForwardingSteeringRule(
            rule_id="force-other",
            target_step_id=base.step_id,
            action_contract_id="example.force-other.v1",
            reason="ambiguous tie",
            priority=10,
            disposition=ForwardingPacketDisposition.PUNT,
        )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "ambiguous rules",
        ):
            select_forwarding_steering_rule(
                step_id=base.step_id,
                packet_state=before,
                rules=(rule, tied),
            )

        long_reason_rule = ForwardingSteeringRule(
            rule_id="long-reason",
            target_step_id=base.step_id,
            action_contract_id="example.user-force.v1",
            reason="r" * 500,
            packet_after=forced_after,
        )
        long_reason_result = apply_forwarding_steering_rule(
            base,
            long_reason_rule,
        )
        self.assertEqual(len(long_reason_result.action_label), 160)
        self.assertTrue(long_reason_result.action_label.endswith("…"))

    def test_trace_continuity_is_strict_only_for_complete_snapshots(self) -> None:
        first = packet((), 1_400)
        second = packet(
            (
                layer(
                    "outer",
                    "example.ipv4.v1",
                    "Outer IPv4",
                    size_bytes=20,
                ),
            ),
            1_420,
        )
        wrong = packet((), 1_401)
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "continuity mismatch",
        ):
            evaluate_forwarding_packet_trace(
                first,
                (
                    transition("one", first, second),
                    transition("two", wrong, wrong),
                ),
            )

        incomplete_wrong = ForwardingPacketState(
            layers=wrong.layers,
            size=wrong.size,
            complete=False,
        )
        result = evaluate_forwarding_packet_trace(
            first,
            (
                transition("one", first, second),
                transition(
                    "two",
                    incomplete_wrong,
                    incomplete_wrong,
                    disposition=ForwardingPacketDisposition.UNKNOWN,
                ),
            ),
        )
        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.continuity, "unknown_incomplete")

    def test_dispositions_distinguish_terminal_branching_and_continuation(
        self,
    ) -> None:
        state = packet((), 64)
        for disposition in (
            ForwardingPacketDisposition.DELIVER,
            ForwardingPacketDisposition.DROP,
            ForwardingPacketDisposition.PUNT,
            ForwardingPacketDisposition.REPLICATE,
            ForwardingPacketDisposition.UNKNOWN,
        ):
            with self.subTest(disposition=disposition):
                result = evaluate_forwarding_packet_trace(
                    state,
                    (
                        transition(
                            disposition.value,
                            state,
                            state,
                            disposition=disposition,
                        ),
                    ),
                )
                self.assertEqual(result.outcome, disposition.value)
                self.assertIs(result.terminal_disposition, disposition)

        continuation = evaluate_forwarding_packet_trace(
            state,
            (transition("continue", state, state),),
        )
        self.assertEqual(
            continuation.outcome, "continuation_required"
        )
        self.assertIsNone(continuation.terminal_disposition)

    def test_trace_rejects_transitions_after_a_terminal_disposition(self) -> None:
        state = packet((), 64)
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "must not follow a terminal disposition",
        ):
            evaluate_forwarding_packet_trace(
                state,
                (
                    transition(
                        "deliver",
                        state,
                        state,
                        disposition=ForwardingPacketDisposition.DELIVER,
                    ),
                    transition(
                        "impossible-suffix",
                        state,
                        state,
                        disposition=ForwardingPacketDisposition.DROP,
                    ),
                ),
            )

    def test_incomplete_packet_identity_cannot_prove_a_cycle(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )
        forwarding_object = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="FIB",
            parts=(("index", 1),),
        )
        complete_packet = packet((), 64)
        incomplete_packet = ForwardingPacketState(
            layers=(),
            size=complete_packet.size,
            complete=False,
        )
        incomplete_size_packet = ForwardingPacketState(
            layers=(),
            size=ForwardingSizeObservation(
                basis_contract_id="example.wire-size.v1",
                size_bytes=64,
                complete=False,
            ),
        )

        def state(value: ForwardingPacketState) -> ForwardingTraversalStateKey:
            return ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=forwarding_object,
                packet_state=value,
            )

        self.assertIsNotNone(
            detect_forwarding_cycle((state(complete_packet), state(complete_packet)))
        )
        self.assertIsNone(
            detect_forwarding_cycle(
                (state(incomplete_packet), state(incomplete_packet))
            )
        )
        self.assertFalse(incomplete_size_packet.identity_complete)
        self.assertIsNone(
            detect_forwarding_cycle(
                (
                    state(incomplete_size_packet),
                    state(incomplete_size_packet),
                )
            )
        )

        incomplete_policy_state = ForwardingTraversalStateKey(
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=forwarding_object,
            packet_state=complete_packet,
            policy_scopes_complete=False,
        )
        self.assertIsNone(
            detect_forwarding_cycle(
                (incomplete_policy_state, incomplete_policy_state)
            )
        )

    def test_step_result_invariants_and_request_validation(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )
        forwarding_object = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="FIB",
            parts=(("index", 1),),
        )
        alternate = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("index", 2),),
        )
        before = packet((), 64)
        continued = transition("step-1", before, before)
        delivered = transition(
            "step-1",
            before,
            before,
            disposition=ForwardingPacketDisposition.DELIVER,
        )

        valid_continue = ForwardingStepResult(
            step_id="step-1",
            transition=continued,
            selected_candidate=None,
            next_forwarding_object=forwarding_object,
        )
        self.assertFalse(valid_continue.terminal)
        for terminal_disposition in (
            ForwardingPacketDisposition.DELIVER,
            ForwardingPacketDisposition.DROP,
            ForwardingPacketDisposition.PUNT,
            ForwardingPacketDisposition.REPLICATE,
            ForwardingPacketDisposition.UNKNOWN,
        ):
            terminal_transition = transition(
                "step-1",
                before,
                before,
                disposition=terminal_disposition,
            )
            terminal_result = ForwardingStepResult(
                step_id="step-1",
                transition=terminal_transition,
                selected_candidate=None,
                next_forwarding_object=None,
                terminal=True,
            )
            self.assertTrue(terminal_result.terminal)

        with self.assertRaisesRegex(ValueError, "requires a next"):
            ForwardingStepResult(
                step_id="step-1",
                transition=continued,
                selected_candidate=None,
                next_forwarding_object=None,
            )
        with self.assertRaisesRegex(ValueError, "must be terminal"):
            ForwardingStepResult(
                step_id="step-1",
                transition=delivered,
                selected_candidate=None,
                next_forwarding_object=None,
            )
        with self.assertRaisesRegex(ValueError, "must not provide a next"):
            ForwardingStepResult(
                step_id="step-1",
                transition=delivered,
                selected_candidate=None,
                next_forwarding_object=forwarding_object,
                terminal=True,
            )
        with self.assertRaisesRegex(ValueError, "lookup context"):
            ForwardingStepResult(
                step_id="step-1",
                transition=delivered,
                selected_candidate=None,
                next_forwarding_object=None,
                next_lookup_context=(("vrf", "blue"),),
                terminal=True,
            )

        rule = ForwardingSteeringRule(
            rule_id="force-alternate",
            target_step_id="step-1",
            action_contract_id="example.force-alternate.v1",
            reason="exercise the alternate next hop",
            selected_candidate=alternate,
        )
        request = ForwardingStepRequest(
            step_id="step-1",
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=forwarding_object,
            packet_state=before,
            steering_rules=(rule,),
        )
        forced = apply_forwarding_steering_rule(continued, rule)
        valid = ForwardingStepResult(
            step_id="step-1",
            transition=forced,
            selected_candidate=alternate,
            next_forwarding_object=forwarding_object,
        )
        self.assertIs(validate_forwarding_step_result(request, valid), valid)

        wrong_candidate = ForwardingStepResult(
            step_id="step-1",
            transition=forced,
            selected_candidate=forwarding_object,
            next_forwarding_object=forwarding_object,
        )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "selected candidate",
        ):
            validate_forwarding_step_result(request, wrong_candidate)

        mismatched_before = packet((), 65)
        mismatched_transition = transition(
            "step-1",
            mismatched_before,
            mismatched_before,
        )
        mismatched_result = ForwardingStepResult(
            step_id="step-1",
            transition=mismatched_transition,
            selected_candidate=None,
            next_forwarding_object=forwarding_object,
        )
        plain_request = ForwardingStepRequest(
            step_id="step-1",
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=forwarding_object,
            packet_state=before,
        )
        self.assertIs(
            validate_forwarding_step_result(plain_request, valid_continue),
            valid_continue,
        )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "without a matching steering rule",
        ):
            validate_forwarding_step_result(plain_request, valid)
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "before state",
        ):
            validate_forwarding_step_result(
                plain_request,
                mismatched_result,
            )


class ForwardingPacketScenarioMatrixTests(unittest.TestCase):
    """Cover the packet forms advertised by the demo without protocol branches."""

    @staticmethod
    def profiles() -> dict[str, tuple[ForwardingPacketLayer, ...]]:
        inner_v4 = layer(
            "inner-ipv4",
            "example.ipv4.v1",
            "Inner IPv4",
            size_bytes=20,
            fields=(("ttl", 64),),
        )
        inner_v6 = layer(
            "inner-ipv6",
            "example.ipv6.v1",
            "Inner IPv6",
            size_bytes=40,
            fields=(("hop_limit", 64),),
        )
        return {
            "native-ip": (inner_v4,),
            "sr-mpls": (
                layer(
                    "transport-label",
                    "example.mpls-label.v1",
                    "Transport label 16002",
                    size_bytes=4,
                    fields=(("label", 16002),),
                ),
                inner_v4,
            ),
            "mpls-l3vpn": (
                layer(
                    "transport-label",
                    "example.mpls-label.v1",
                    "Transport label 16002",
                    size_bytes=4,
                    fields=(("label", 16002),),
                ),
                layer(
                    "vpn-label",
                    "example.mpls-label.v1",
                    "VPN label 24001",
                    size_bytes=4,
                    fields=(("label", 24001),),
                ),
                inner_v4,
            ),
            "srv6": (
                layer(
                    "outer-ipv6",
                    "example.ipv6.v1",
                    "Outer IPv6",
                    size_bytes=40,
                ),
                layer(
                    "srh",
                    "example.srv6-srh.v1",
                    "SRH",
                    size_bytes=40,
                    fields=(
                        (
                            "sid_list",
                            (
                                "2001:db8:100::1",
                                "2001:db8:200::1",
                            ),
                        ),
                        ("segments_left", 1),
                    ),
                ),
                inner_v6,
            ),
            "ipv6-over-ipv4": (
                layer(
                    "outer-ipv4",
                    "example.ipv4.v1",
                    "Outer IPv4",
                    size_bytes=20,
                ),
                inner_v6,
            ),
            "vpn-over-vpn": (
                layer(
                    "transport-label",
                    "example.mpls-label.v1",
                    "Transport label",
                    size_bytes=4,
                ),
                layer(
                    "outer-ipv6",
                    "example.ipv6.v1",
                    "Outer IPv6",
                    size_bytes=40,
                ),
                layer(
                    "udp",
                    "example.udp.v1",
                    "UDP",
                    size_bytes=8,
                ),
                layer(
                    "vxlan",
                    "example.vxlan.v1",
                    "Outer tenant VXLAN",
                    size_bytes=8,
                    fields=(("vni", 10320),),
                ),
                layer(
                    "ethernet",
                    "example.ethernet.v1",
                    "Tenant Ethernet",
                    size_bytes=14,
                ),
                layer(
                    "vpn-label",
                    "example.mpls-label.v1",
                    "Inner VPN label",
                    size_bytes=4,
                ),
                inner_v4,
            ),
        }

    def test_profiles_cover_fit_equal_and_exceeding_mtu(self) -> None:
        for (profile_name, layers), delta in product(
            self.profiles().items(),
            (-1, 0, 1),
        ):
            with self.subTest(profile=profile_name, mtu_delta=delta):
                size = 1_400 + sum(item.size_bytes or 0 for item in layers)
                state = packet(layers, size)
                mtu = ForwardingMtuConstraint(
                    basis_contract_id="example.wire-size.v1",
                    limit_bytes=size + delta,
                )
                outcome = evaluate_forwarding_mtu(state, mtu).outcome
                self.assertEqual(
                    outcome,
                    "exceeds" if delta == -1 else "fits",
                )

    def test_each_profile_round_trips_through_encap_transit_and_decap(self) -> None:
        payload = layer(
            "payload",
            "example.payload.v1",
            "Application payload",
            size_bytes=0,
        )
        initial = packet((payload,), 1_200)
        for profile_name, layers in self.profiles().items():
            with self.subTest(profile=profile_name):
                encapsulated = packet((*layers, payload), 1_200 + sum(
                    item.size_bytes or 0 for item in layers
                ))
                transit_layers = list(encapsulated.layers)
                if transit_layers:
                    first = transit_layers[0]
                    transit_layers[0] = ForwardingPacketLayer(
                        layer_id=first.layer_id,
                        contract_id=first.contract_id,
                        label=f"{first.label} (transit)",
                        fields=first.fields,
                        size_bytes=first.size_bytes,
                        complete=first.complete,
                    )
                transited = packet(
                    tuple(transit_layers),
                    encapsulated.size.size_bytes,  # type: ignore[union-attr]
                )
                delivered = packet((payload,), 1_200)
                result = evaluate_forwarding_packet_trace(
                    initial,
                    (
                        transition("ingress", initial, encapsulated),
                        transition("transit", encapsulated, transited),
                        transition(
                            "egress",
                            transited,
                            delivered,
                            disposition=ForwardingPacketDisposition.DELIVER,
                        ),
                    ),
                )
                self.assertEqual(result.outcome, "deliver")
                self.assertEqual(result.continuity, "complete")
                self.assertEqual(
                    result.transitions[-1].transition.after,
                    initial,
                )


if __name__ == "__main__":
    unittest.main()
