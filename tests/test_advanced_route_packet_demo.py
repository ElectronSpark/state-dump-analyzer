from __future__ import annotations

import unittest
from uuid import UUID

from fastapi.testclient import TestClient

from router_dump_analyzer_demo.app import app
from router_dump_analyzer_demo.multi_node_route import MultiNodeRouteDemo
from router_dump_analyzer_demo_plugins.advanced_trace import (
    ADVANCED_TRACE_SCENARIOS,
)
from router_dump_analyzer.plugin_api import (
    Evidence,
    ForwardingMtuConstraint,
    ForwardingPacketDisposition,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingSizeObservation,
    ForwardingTransitionOrigin,
    Quality,
    ResolutionContribution,
    ResourceKey,
    TopologyEndpointReference,
    TopologyMatchReference,
)
from router_dump_analyzer.route_trace_core import (
    evaluate_forwarding_packet_transition,
)


class AdvancedRoutePacketSerializationTests(unittest.TestCase):
    def test_demo_adapter_preserves_typed_references_evidence_and_mtu_source(
        self,
    ) -> None:
        interface = ResourceKey(
            namespace="demo",
            node="node-a",
            layer="hardware",
            kind="INTERFACE",
            parts=(("ifindex", 17),),
        )
        evidence = Evidence(
            artifact_id=UUID("00000000-0000-0000-0000-000000000017"),
            locator="interfaces[17]",
            raw_timestamp_ns=1_234,
            clock_domain="node-a-wall",
            excerpt_sha256="1" * 64,
        )
        contribution = ResolutionContribution(
            phase="egress_mtu",
            text="Interface state supplied the exact wire-size limit.",
            quality=Quality.EXACT,
            resource_references=(interface,),
            topology_references=(
                TopologyEndpointReference(
                    match=TopologyMatchReference(
                        matcher_id="demo.interface.exact.v1",
                        arguments={"ifindex": 17},
                        resolved_candidates=(interface,),
                    ),
                ),
            ),
            evidence=(evidence,),
        )
        state = ForwardingPacketState(
            layers=(
                ForwardingPacketLayer(
                    layer_id="outer-ip",
                    contract_id="demo.ipv4.v1",
                    label="Outer IPv4",
                ),
            ),
            size=ForwardingSizeObservation(
                basis_contract_id="demo.wire-size.v1",
                size_bytes=1_500,
            ),
        )
        transition = ForwardingPacketTransition(
            transition_id="transition:node-a",
            step_id="segment:node-a",
            before=state,
            after=state,
            action_contract_id="demo.forward.v1",
            action_label="Forward unchanged",
            disposition=ForwardingPacketDisposition.CONTINUE,
            origin=ForwardingTransitionOrigin.NODE_PLUGIN,
            actor_id="demo.node-a.forwarding",
            mtu=ForwardingMtuConstraint(
                basis_contract_id="demo.wire-size.v1",
                limit_bytes=1_500,
                resource=interface,
            ),
            contributions=(contribution,),
        )

        serialized = MultiNodeRouteDemo._packet_transition_json(
            evaluate_forwarding_packet_transition(transition),
            segment={
                "segment_id": "segment:node-a",
                "node_id": "node-a",
                "highlight_target_ids": ["node-member:member:node-a"],
                "interaction_target_ids": [],
            },
        )

        self.assertTrue(serialized["diff"]["complete"])
        self.assertEqual(
            serialized["transition"]["mtu_constraint"]["resource"],
            {
                "namespace": "demo",
                "node": "node-a",
                "layer": "hardware",
                "kind": "INTERFACE",
                "parts": [{"name": "ifindex", "value": 17}],
            },
        )
        serialized_contribution = serialized["transition"]["contributions"][0]
        self.assertEqual(
            serialized_contribution["resource_references"][0]["node"],
            "node-a",
        )
        self.assertEqual(
            serialized_contribution["topology_references"][0]["match"][
                "arguments"
            ],
            {"ifindex": 17},
        )
        self.assertEqual(
            serialized_contribution["topology_references"][0]["match"][
                "resolved_candidates"
            ][0]["parts"],
            [{"name": "ifindex", "value": 17}],
        )
        self.assertEqual(
            serialized_contribution["evidence"],
            [
                {
                    "artifact_id": (
                        "00000000-0000-0000-0000-000000000017"
                    ),
                    "locator": "interfaces[17]",
                    "raw_timestamp_ns": 1_234,
                    "clock_domain": "node-a-wall",
                    "excerpt_sha256": "1" * 64,
                },
            ],
        )

    def test_boundary_continuity_and_diff_completeness_remain_local(
        self,
    ) -> None:
        complete = ForwardingPacketState(layers=())
        different = ForwardingPacketState(
            layers=(
                ForwardingPacketLayer(
                    layer_id="ip",
                    contract_id="demo.ipv4.v1",
                    label="IPv4",
                ),
            ),
        )
        incomplete = ForwardingPacketState(layers=(), complete=False)

        self.assertTrue(
            MultiNodeRouteDemo._packet_boundary_continuity(
                complete,
                complete,
            )
        )
        self.assertFalse(
            MultiNodeRouteDemo._packet_boundary_continuity(
                complete,
                different,
            )
        )
        self.assertIsNone(
            MultiNodeRouteDemo._packet_boundary_continuity(
                complete,
                incomplete,
            )
        )

        transition = ForwardingPacketTransition(
            transition_id="transition:incomplete",
            step_id="segment:incomplete",
            before=incomplete,
            after=complete,
            action_contract_id="demo.forward.v1",
            action_label="Continue from incomplete capture",
            disposition=ForwardingPacketDisposition.CONTINUE,
            origin=ForwardingTransitionOrigin.NODE_PLUGIN,
            actor_id="demo.node-a.forwarding",
        )
        evaluation = evaluate_forwarding_packet_transition(transition)
        self.assertFalse(evaluation.diff.complete)


class AdvancedRoutePacketDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def _trace(
        self,
        scenario_id: str,
        *,
        direction: str = "forward",
        steering_profile_id: str = "observed",
    ) -> dict[str, object]:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": scenario_id,
                "direction": direction,
                "steering_profile_id": steering_profile_id,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    @staticmethod
    def _packet_layer(
        state: dict[str, object],
        layer_id: str,
    ) -> dict[str, object]:
        return next(
            layer
            for layer in state["layers"]  # type: ignore[index]
            if layer["layer_id"] == layer_id
        )

    def test_capabilities_advertise_packet_contract_and_steering(self) -> None:
        response = self.client.get(
            "/v1/topologies/routes/capabilities"
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        scenario_ids = {
            item["scenario_id"] for item in payload["scenarios"]
        }
        self.assertTrue(
            {
                item["scenario_id"] for item in ADVANCED_TRACE_SCENARIOS
            }.issubset(scenario_ids)
        )
        self.assertEqual(
            payload["packet_trace"]["layer_order"],
            "outermost_to_innermost",
        )
        self.assertTrue(
            payload["packet_trace"][
                "user_forced_results_are_counterfactual"
            ]
        )
        self.assertEqual(
            {
                item["profile_id"] for item in payload["steering_profiles"]
            },
            {
                "observed",
                "force-alternate-p2",
                "force-outer-ipv4",
                "force-mid-wrapper",
            },
        )

    def test_every_advanced_profile_executes_independently_both_ways(
        self,
    ) -> None:
        for scenario in ADVANCED_TRACE_SCENARIOS:
            scenario_id = str(scenario["scenario_id"])
            with self.subTest(scenario_id=scenario_id):
                payload = self._trace(scenario_id, direction="both")
                for key in ("forward_trace", "reverse_trace"):
                    trace = payload[key]
                    path = trace["paths"][0]
                    packet_trace = path["packet_trace"]
                    self.assertEqual(
                        packet_trace["continuity"], "complete"
                    )
                    self.assertGreater(
                        len(packet_trace["transitions"]), 0
                    )
                    segment_ids = {
                        item["segment_id"] for item in path["segments"]
                    }
                    for item in packet_trace["transitions"]:
                        self.assertIn(
                            item["transition"]["step_id"],
                            segment_ids,
                        )
                        self.assertEqual(
                            item["transition"]["step_id"],
                            item["segment_id"],
                        )
                        self.assertIs(
                            item["continuity_valid"],
                            True,
                        )
                        self.assertIn(
                            "complete",
                            item["diff"],
                        )
                if scenario_id == "packet-mtu-drop":
                    self.assertEqual(
                        payload["bidirectional_validation"]["state"],
                        "both_unreachable",
                    )
                else:
                    self.assertEqual(
                        payload["bidirectional_validation"]["state"],
                        "symmetric_reachable",
                    )

    def test_every_profile_has_directional_packet_identity_and_continuity(
        self,
    ) -> None:
        ipv4_endpoints = {
            "forward": ("192.0.2.10", "198.51.100.20"),
            "reverse": ("198.51.100.20", "192.0.2.10"),
        }
        ipv6_endpoints = {
            "forward": ("2001:db8:10::10", "2001:db8:20::20"),
            "reverse": ("2001:db8:20::20", "2001:db8:10::10"),
        }
        ipv6_profiles = {
            "packet-srv6-encap",
            "packet-ipv6-over-ipv4",
        }
        for scenario in ADVANCED_TRACE_SCENARIOS:
            scenario_id = str(scenario["scenario_id"])
            payload = self._trace(scenario_id, direction="both")
            for direction, trace_key in (
                ("forward", "forward_trace"),
                ("reverse", "reverse_trace"),
            ):
                with self.subTest(
                    scenario_id=scenario_id,
                    direction=direction,
                ):
                    path = payload[trace_key]["paths"][0]
                    packet_trace = path["packet_trace"]
                    transitions = packet_trace["transitions"]
                    self.assertEqual(
                        packet_trace["initial_state"],
                        transitions[0]["transition"]["before"],
                    )
                    for current, following in zip(
                        transitions,
                        transitions[1:],
                    ):
                        self.assertEqual(
                            current["transition"]["after"],
                            following["transition"]["before"],
                        )
                    self.assertEqual(
                        packet_trace["continuity"], "complete"
                    )
                    expected_disposition = (
                        "drop"
                        if scenario_id == "packet-mtu-drop"
                        else "deliver"
                    )
                    self.assertEqual(
                        transitions[-1]["transition"]["disposition"],
                        expected_disposition,
                    )

                    layer_id = (
                        "inner-ipv6"
                        if scenario_id in ipv6_profiles
                        else "inner-ipv4"
                    )
                    inner = self._packet_layer(
                        packet_trace["initial_state"],
                        layer_id,
                    )
                    expected_source, expected_destination = (
                        ipv6_endpoints[direction]
                        if scenario_id in ipv6_profiles
                        else ipv4_endpoints[direction]
                    )
                    self.assertEqual(
                        inner["fields"]["source"], expected_source
                    )
                    self.assertEqual(
                        inner["fields"]["destination"],
                        expected_destination,
                    )

    def test_directional_outer_tunnel_and_srv6_endpoints_are_independent(
        self,
    ) -> None:
        cases = {
            "packet-ipv6-over-ipv4": {
                "layer_id": "outer-ipv4",
                "forward": ("192.0.2.1", "198.51.100.1"),
                "reverse": ("198.51.100.1", "192.0.2.1"),
            },
            "packet-mtu-drop": {
                "layer_id": "outer-ipv4",
                "forward": ("192.0.2.1", "198.51.100.1"),
                "reverse": ("198.51.100.1", "192.0.2.1"),
            },
            "packet-vpn-over-vpn": {
                "layer_id": "outer-ipv6",
                "forward": ("2001:db8:100::a", "2001:db8:100::b"),
                "reverse": ("2001:db8:100::b", "2001:db8:100::a"),
            },
        }
        for scenario_id, case in cases.items():
            payload = self._trace(scenario_id, direction="both")
            for direction, trace_key in (
                ("forward", "forward_trace"),
                ("reverse", "reverse_trace"),
            ):
                with self.subTest(
                    scenario_id=scenario_id,
                    direction=direction,
                ):
                    first_after = payload[trace_key]["paths"][0][
                        "packet_trace"
                    ]["transitions"][0]["transition"]["after"]
                    outer = self._packet_layer(
                        first_after,
                        str(case["layer_id"]),
                    )
                    expected_source, expected_destination = case[direction]
                    self.assertEqual(
                        outer["fields"]["source"], expected_source
                    )
                    self.assertEqual(
                        outer["fields"]["destination"],
                        expected_destination,
                    )
                    if scenario_id == "packet-vpn-over-vpn":
                        tenant = self._packet_layer(
                            first_after,
                            "tenant-ethernet",
                        )
                        tenant_endpoints = {
                            "forward": (
                                "02:00:00:00:00:0a",
                                "02:00:00:00:00:0b",
                            ),
                            "reverse": (
                                "02:00:00:00:00:0b",
                                "02:00:00:00:00:0a",
                            ),
                        }
                        tenant_source, tenant_destination = (
                            tenant_endpoints[direction]
                        )
                        self.assertEqual(
                            tenant["fields"]["source"], tenant_source
                        )
                        self.assertEqual(
                            tenant["fields"]["destination"],
                            tenant_destination,
                        )

        srv6 = self._trace("packet-srv6-encap", direction="both")
        srv6_expectations = {
            "forward": (
                "2001:db8:100::a",
                ["2001:db8:100::1", "2001:db8:200::b"],
            ),
            "reverse": (
                "2001:db8:200::b",
                ["2001:db8:200::1", "2001:db8:100::a"],
            ),
        }
        for direction, trace_key in (
            ("forward", "forward_trace"),
            ("reverse", "reverse_trace"),
        ):
            transitions = srv6[trace_key]["paths"][0]["packet_trace"][
                "transitions"
            ]
            source, sid_list = srv6_expectations[direction]
            encap = transitions[0]["transition"]["after"]
            advanced = transitions[1]["transition"]["after"]
            outer = self._packet_layer(encap, "outer-ipv6")
            srh = self._packet_layer(encap, "srh")
            final_outer = self._packet_layer(advanced, "outer-ipv6")
            self.assertEqual(outer["fields"]["source"], source)
            self.assertEqual(outer["fields"]["destination"], sid_list[0])
            self.assertEqual(srh["fields"]["sid_list"], sid_list)
            self.assertEqual(
                final_outer["fields"]["destination"], sid_list[1]
            )

    def test_native_ip_delivery_does_not_consume_an_extra_ttl(self) -> None:
        payload = self._trace("packet-native-ip", direction="both")
        for trace_key in ("forward_trace", "reverse_trace"):
            transitions = payload[trace_key]["paths"][0]["packet_trace"][
                "transitions"
            ]
            self.assertEqual(
                [
                    self._packet_layer(
                        item["transition"]["after"],
                        "inner-ipv4",
                    )["fields"]["ttl"]
                    for item in transitions
                ],
                [63, 62, 62],
            )
            self.assertEqual(
                transitions[-1]["transition"]["before"],
                transitions[-1]["transition"]["after"],
            )
            self.assertEqual(
                transitions[-1]["diff"]["changed_layer_ids"], []
            )

    def test_protocol_profiles_retain_ordered_stack_semantics(self) -> None:
        mpls = self._trace("packet-sr-mpls-php")
        mpls_transitions = mpls["paths"][0]["packet_trace"]["transitions"]
        self.assertEqual(
            [
                item["transition"]["action_label"]
                for item in mpls_transitions
            ],
            [
                "Push transport label",
                "Swap transport label",
                "Penultimate-hop pop transport label",
                "Remove service encapsulation and deliver",
            ],
        )
        self.assertEqual(
            [
                layer["label"]
                for layer in mpls_transitions[0]["transition"]["after"][
                    "layers"
                ]
            ],
            ["Transport label 16002", "Inner IPv4"],
        )
        self.assertEqual(
            mpls_transitions[2]["diff"]["removed_layer_ids"],
            ["transport-label"],
        )

        nested = self._trace("packet-vpn-over-vpn")
        nested_layers = [
            layer["label"]
            for layer in nested["paths"][0]["packet_trace"]["transitions"][
                0
            ]["transition"]["after"]["layers"]
        ]
        self.assertEqual(
            nested_layers,
            [
                "Transport label 16002",
                "VPN label 24001",
                "Outer IPv6 underlay",
                "UDP tunnel",
                "Nested VXLAN VPN",
                "Tenant Ethernet",
                "Inner IPv4",
            ],
        )

        srv6 = self._trace("packet-srv6-encap")
        srv6_transitions = srv6["paths"][0]["packet_trace"]["transitions"]
        self.assertEqual(
            [
                layer["label"]
                for layer in srv6_transitions[0]["transition"]["after"][
                    "layers"
                ]
            ],
            ["Outer IPv6", "SRH · 2 SIDs", "Inner IPv6"],
        )
        self.assertEqual(
            srv6_transitions[1]["transition"]["after"]["layers"][1][
                "fields"
            ]["segments_left"],
            0,
        )

    def test_mtu_arithmetic_and_drop_semantics_remain_separate(self) -> None:
        payload = self._trace("packet-mtu-drop")
        path = payload["paths"][0]
        transition = path["packet_trace"]["transitions"][0]

        self.assertEqual(transition["mtu"]["outcome"], "exceeds")
        self.assertEqual(transition["mtu"]["size_bytes"], 1510)
        self.assertEqual(transition["mtu"]["limit_bytes"], 1500)
        self.assertEqual(transition["mtu"]["excess_bytes"], 10)
        self.assertEqual(
            transition["transition"]["disposition"], "drop"
        )
        self.assertEqual(path["result"], "dropped")
        self.assertFalse(payload["reachable"])
        self.assertEqual(
            payload["endpoint_reachability"]["state"], "not_reached"
        )
        self.assertTrue(
            any(
                item["ownership"]
                == "core_size_comparison_node_plugin_disposition"
                for item in payload["issues"]
            )
        )

    def test_user_steering_is_bounded_and_counterfactual(self) -> None:
        observed = self._trace("packet-forced-steering")
        alternate = self._trace(
            "packet-forced-steering",
            direction="both",
            steering_profile_id="force-alternate-p2",
        )
        wrapped = self._trace(
            "packet-forced-steering",
            direction="both",
            steering_profile_id="force-outer-ipv4",
        )
        mid_wrapped = self._trace(
            "packet-forced-steering",
            direction="both",
            steering_profile_id="force-mid-wrapper",
        )

        self.assertEqual(
            observed["paths"][0]["node_sequence"],
            ["node-a", "transit-p-1", "transit-p-2", "node-b"],
        )
        self.assertEqual(
            alternate["paths"][0]["node_sequence"],
            ["node-a", "transit-p-2", "node-b"],
        )
        for payload in (alternate, wrapped, mid_wrapped):
            self.assertTrue(payload["counterfactual"])
            for trace_key in ("forward_trace", "reverse_trace"):
                path = payload[trace_key]["paths"][0]
                forced = next(
                    item
                    for item in path["packet_trace"]["transitions"]
                    if item["counterfactual"]
                )
                self.assertTrue(path["counterfactual"])
                self.assertTrue(path["packet_trace"]["counterfactual"])
                self.assertEqual(
                    forced["transition"]["origin"], "user_forced"
                )
                self.assertIsNotNone(
                    forced["transition"]["forced_rule_id"]
                )
        wrapper_layers = wrapped["paths"][0]["packet_trace"][
            "transitions"
        ][0]["transition"]["after"]["layers"]
        self.assertEqual(wrapper_layers[0]["layer_id"], "forced-outer-ipv4")
        self.assertEqual(
            wrapped["paths"][0]["packet_trace"]["continuity"], "complete"
        )
        forced_endpoints = {
            "forward_trace": ("203.0.113.10", "203.0.113.20"),
            "reverse_trace": ("203.0.113.20", "203.0.113.10"),
        }
        for trace_key, expected in forced_endpoints.items():
            first_after = wrapped[trace_key]["paths"][0]["packet_trace"][
                "transitions"
            ][0]["transition"]["after"]
            wrapper = self._packet_layer(
                first_after,
                "forced-outer-ipv4",
            )
            self.assertEqual(wrapper["fields"]["source"], expected[0])
            self.assertEqual(
                wrapper["fields"]["destination"], expected[1]
            )
        mid_transitions = mid_wrapped["paths"][0]["packet_trace"][
            "transitions"
        ]
        self.assertFalse(mid_transitions[0]["counterfactual"])
        self.assertTrue(mid_transitions[1]["counterfactual"])
        self.assertEqual(
            mid_transitions[1]["transition"]["after"]["layers"][0][
                "layer_id"
            ],
            "forced-mid-wrapper",
        )
        self.assertNotIn(
            "forced-mid-wrapper",
            {
                layer["layer_id"]
                for layer in mid_transitions[-1]["transition"]["after"][
                    "layers"
                ]
            },
        )

    def test_invalid_or_unadvertised_steering_is_rejected(self) -> None:
        unknown = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "packet-forced-steering",
                "steering_profile_id": "not-advertised",
            },
        )
        unsupported = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "packet-native-ip",
                "steering_profile_id": "force-alternate-p2",
            },
        )

        self.assertEqual(unknown.status_code, 422, unknown.text)
        self.assertEqual(unsupported.status_code, 422, unsupported.text)

    def test_legacy_basic_ip_and_mpls_scenarios_do_not_gain_packet_ir(
        self,
    ) -> None:
        for scenario_id in ("router-to-router", "single-active-primary"):
            with self.subTest(scenario_id=scenario_id):
                payload = self._trace(scenario_id)
                self.assertTrue(payload["paths"])
                self.assertNotIn("packet_trace", payload["paths"][0])


if __name__ == "__main__":
    unittest.main()
