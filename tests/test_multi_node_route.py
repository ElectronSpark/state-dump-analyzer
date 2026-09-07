from __future__ import annotations

import copy
import unittest
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient
from rsl_demo_plugin.topology_contract import DEMO_TOPOLOGY_ID

from router_dump_analyzer.canonical import canonical_opaque_value
from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.multi_node_topology import MultiNodeTopologyService
from router_dump_analyzer.plugin_api import (
    ForwardingCandidateConstraint,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
    ForwardingTraversalStateKey,
    KeyAtom,
    ResourceKey,
    StatusPerspectiveRef,
)
from router_dump_analyzer.route_trace_core import (
    RouteTraceContractError,
    detect_forwarding_cycle,
    evaluate_endpoint_reachability_pair,
    evaluate_forwarding_constraint,
    evaluate_forwarding_policy,
    evaluate_forwarding_traversal,
)
from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
    query_all_route_table_rows,
)


def _typed_boundary_resource_ref(
    node_id: str,
    local_resource_id: str,
) -> dict[str, object]:
    return {
        "member_id": f"member:{node_id}",
        "node_id": node_id,
        "revision_id": f"revision:{node_id}",
        "local_resource_id": local_resource_id,
        "typed_resource_key": {
            "namespace": "test",
            "node": node_id,
            "layer": "underlay",
            "kind": "INTERFACE",
            "parts": [
                {
                    "name": "name",
                    "value": {"type": "string", "value": local_resource_id},
                }
            ],
        },
        "plugin_instance_id": f"member:{node_id}/topology",
        "projection_id": "test.topology",
        "status_perspective_id": "test.observed",
    }


def _typed_boundary_endpoint(reference: dict[str, object]) -> dict[str, object]:
    return {
        "member_id": reference["member_id"],
        "node_id": reference["node_id"],
        "revision_id": reference["revision_id"],
        "resource_id": reference["local_resource_id"],
        "plugin_instance_id": reference["plugin_instance_id"],
        "projection_id": reference["projection_id"],
        "status_perspective_id": reference["status_perspective_id"],
        "claim_id": f"claim:{reference['node_id']}",
        "resource_ref": copy.deepcopy(reference),
    }


def _typed_boundary_link(
    source_reference: dict[str, object],
    target_reference: dict[str, object],
    *,
    link_id: str = "typed-link",
    directed: bool = True,
    route_trace: str = "include",
) -> dict[str, object]:
    source = _typed_boundary_endpoint(source_reference)
    target = _typed_boundary_endpoint(target_reference)
    return {
        "link_id": link_id,
        "typed_federation": True,
        "federation_complete": True,
        "federation_truncated": False,
        "resolution": "matched",
        "directed": directed,
        "presentation": {"route_trace": route_trace},
        "endpoint_a": source,
        "endpoint_b": target,
        "source": copy.deepcopy(source),
        "target": copy.deepcopy(target),
        "link_type": "ethernet",
        "operational_status": "usable",
        "inference": {"owner": "core_exact_matcher"},
        "plugin_provenance": [],
    }


class RouteTraceCoreCompletenessTests(unittest.TestCase):
    """Focused policy/cycle checks that do not require the demo fixture."""

    def setUp(self) -> None:
        self.candidate = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("id", 7),),
        )
        self.scope = ForwardingPolicyScope(
            contract_id="example.evpn.horizon.v1",
            arguments=(("esi", "00:11"), ("evi", 320)),
        )
        self.other_scope = ForwardingPolicyScope(
            contract_id=self.scope.contract_id,
            arguments=(("esi", "00:12"), ("evi", 320)),
        )
        self.constraint = ForwardingCandidateConstraint(
            constraint_id="evpn-horizon-7",
            kind="exclude_exact_scope",  # type: ignore[arg-type]
            candidate_scope=self.scope,
            traffic_classes=frozenset({"ethernet.bum"}),
        )

    def test_packet_json_preserves_opaque_atom_and_container_types(self) -> None:
        identifier = UUID("7ff7d7dc-88c7-44df-8578-72b049c22500")
        value = (
            identifier,
            str(identifier),
            KeyAtom("uuid", identifier.bytes),
            identifier.bytes,
        )

        encoded = MultiNodeRouteService._packet_value_json(value)

        self.assertEqual(encoded["type"], "tuple")
        self.assertEqual(encoded["items"][0]["type"], "uuid")
        self.assertEqual(encoded["items"][1], str(identifier))
        self.assertEqual(encoded["items"][2]["type"], "key_atom")
        self.assertEqual(encoded["items"][2]["type_tag"], "uuid")
        self.assertEqual(
            encoded["items"][2]["value"]["type"],
            "bytes",
        )
        self.assertEqual(encoded["items"][3]["type"], "bytes")

    def test_policy_scope_requires_ordered_wire_arguments(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "ordered scope arguments",
        ):
            MultiNodeRouteService._declared_policy_scope(
                {
                    "contract_id": "example.scope.v1",
                    "arguments": {"first": 1, "second": 2},
                },
                label="test scope",
            )

        scope = MultiNodeRouteService._declared_policy_scope(
            {
                "contract_id": "example.scope.v1",
                "arguments": [
                    {"name": "second", "value": 2},
                    {"name": "first", "value": 1},
                ],
            },
            label="test scope",
        )
        self.assertEqual(
            scope.arguments,
            (("second", 2), ("first", 1)),
        )

    def test_route_table_row_without_vrf_is_not_assigned_default(self) -> None:
        service = object.__new__(MultiNodeRouteService)
        self.assertIsNone(
            service._generated_route_table_entry(
                {
                    "table_visible": True,
                    "node_id": "node-a",
                    "route_type": "ip",
                    "route_family": "ipv4_unicast",
                }
            )
        )

    def test_candidate_limit_is_enforced_before_materialization(self) -> None:
        service = object.__new__(MultiNodeRouteService)
        projection = {
            "candidate_paths": [
                {
                    "candidate_id": f"candidate:{index}",
                    "path_id": f"path:{index}",
                    "node_sequence": ["node-a"],
                    "selected_active": False,
                    "primary": False,
                    "alternative_state": "inactive_candidate",
                }
                for index in range(
                    MultiNodeRouteService.MAX_CANDIDATE_PATHS + 1
                )
            ]
        }
        with self.assertRaisesRegex(ValueError, "candidate limit"):
            service._generic_paths_from_generated_candidates(
                projection,
                "ip",
                {},
                {},
                {},
            )

    def test_typed_boundary_matching_preserves_direction_and_presentation(self) -> None:
        source_ref = _typed_boundary_resource_ref("node-a", "interface/shared")
        target_ref = _typed_boundary_resource_ref("node-b", "interface/shared")
        included = _typed_boundary_link(source_ref, target_ref)
        ordered_ids = ("interface/shared", "interface/shared")

        self.assertIs(
            MultiNodeRouteService._matching_link(
                [included],
                ordered_ids,
                required_endpoint_refs=(source_ref, target_ref),
            ),
            included,
        )
        self.assertIsNone(
            MultiNodeRouteService._matching_link(
                [included],
                ordered_ids,
                required_endpoint_refs=(target_ref, source_ref),
            )
        )
        wrong_revision = copy.deepcopy(source_ref)
        wrong_revision["revision_id"] = "revision:node-a:other"
        self.assertIsNone(
            MultiNodeRouteService._matching_link(
                [included],
                ordered_ids,
                required_endpoint_refs=(wrong_revision, target_ref),
            )
        )
        undirected = _typed_boundary_link(
            source_ref,
            target_ref,
            directed=False,
        )
        self.assertIs(
            MultiNodeRouteService._matching_link(
                [undirected],
                ordered_ids,
                required_endpoint_refs=(target_ref, source_ref),
            ),
            undirected,
        )
        overlay = _typed_boundary_link(
            source_ref,
            target_ref,
            route_trace="overlay",
        )
        self.assertIsNone(
            MultiNodeRouteService._matching_link(
                [overlay],
                ordered_ids,
                required_endpoint_refs=(source_ref, target_ref),
            )
        )

    def test_malformed_typed_boundary_candidates_fail_closed(self) -> None:
        source_ref = _typed_boundary_resource_ref("node-a", "interface/a")
        target_ref = _typed_boundary_resource_ref("node-b", "interface/b")
        included = _typed_boundary_link(source_ref, target_ref)
        malformed = (
            included | {"presentation": {}},
            included | {"presentation": {"route_trace": "conflict"}},
            included | {"directed": "yes"},
            included | {"typed_federation": False},
            included | {"source": included["target"]},
            included
            | {
                "endpoint_a": {
                    key: value
                    for key, value in included["endpoint_a"].items()
                    if key != "resource_ref"
                }
            },
        )

        for candidate in malformed:
            with self.subTest(candidate=candidate):
                self.assertIsNone(
                    MultiNodeRouteService._matching_link(
                        [candidate],
                        ("interface/a", "interface/b"),
                        required_endpoint_refs=(source_ref, target_ref),
                    )
                )

    def test_boundary_segment_uses_ordered_typed_endpoint_scope(self) -> None:
        source_ref = _typed_boundary_resource_ref("node-a", "interface/a")
        target_ref = _typed_boundary_resource_ref("node-b", "interface/b")
        included = _typed_boundary_link(source_ref, target_ref)
        resources = {
            str(reference["local_resource_id"]): {
                "resource_id": reference["local_resource_id"],
                "node_id": reference["node_id"],
                "member_id": reference["member_id"],
                "resource_ref": reference,
                "label": reference["local_resource_id"],
                "status": "usable",
                "status_class": "usable",
                "plugin_provenance": {},
            }
            for reference in (source_ref, target_ref)
        }
        service = object.__new__(MultiNodeRouteService)
        service.topology = type(
            "TopologyFixture",
            (),
            {
                "route_catalog": lambda self: {
                    "federation_plugin": {
                        "plugin_id": "test.linker",
                        "plugin_run_id": "run-1",
                        "plugin_version": "1.0",
                    }
                }
            },
        )()

        forward = service._boundary_segment(
            "segment:forward",
            1,
            ["interface/a", "interface/b"],
            "typed-link",
            "forward",
            resources,
            {"typed-link": [included]},
            {},
            True,
            True,
            "selected_primary",
            [],
        )
        reverse = service._boundary_segment(
            "segment:reverse",
            1,
            ["interface/b", "interface/a"],
            "typed-link",
            "reverse",
            resources,
            {"typed-link": [included]},
            {},
            True,
            True,
            "selected_primary",
            [],
        )
        overlay = service._boundary_segment(
            "segment:overlay",
            1,
            ["interface/a", "interface/b"],
            "typed-link",
            "overlay",
            resources,
            {
                "typed-link": [
                    _typed_boundary_link(
                        source_ref,
                        target_ref,
                        route_trace="overlay",
                    )
                ]
            },
            {},
            True,
            True,
            "selected_primary",
            [],
        )

        self.assertEqual(forward["completeness"]["state"], "complete")
        self.assertEqual(reverse["completeness"]["state"], "unresolved")
        self.assertEqual(overlay["completeness"]["state"], "unresolved")

    def test_incomplete_ingress_scope_set_is_unknown_unless_exact_match_exists(
        self,
    ) -> None:
        unknown = evaluate_forwarding_constraint(
            candidate=self.candidate,
            constraint=self.constraint,
            ingress_scopes=frozenset({self.other_scope}),
            traffic_class="ethernet.bum",
            ingress_scopes_complete=False,
        )
        blocked = evaluate_forwarding_constraint(
            candidate=self.candidate,
            constraint=self.constraint,
            ingress_scopes=frozenset({self.scope}),
            traffic_class="ethernet.bum",
            ingress_scopes_complete=False,
        )

        self.assertIs(unknown.verdict, ForwardingPolicyVerdict.UNKNOWN)
        self.assertFalse(unknown.ingress_scopes_complete)
        self.assertIs(blocked.verdict, ForwardingPolicyVerdict.BLOCKED)
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(),
                ingress_scopes=frozenset(),
                traffic_class="ethernet.bum",
                ingress_scopes_complete=0,  # type: ignore[arg-type]
            )

    def test_scope_completeness_is_part_of_canonical_traversal_identity(
        self,
    ) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )
        forwarding_object = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="FIB",
            parts=(("index", 101),),
        )
        complete = ForwardingTraversalStateKey(
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=forwarding_object,
            policy_scopes=frozenset({self.scope}),
        )
        incomplete = ForwardingTraversalStateKey(
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=forwarding_object,
            policy_scopes=frozenset({self.scope}),
            policy_scopes_complete=False,
        )

        self.assertNotEqual(complete, incomplete)
        self.assertIsNone(detect_forwarding_cycle((complete, incomplete)))
        report = detect_forwarding_cycle((complete, incomplete, complete))
        self.assertIsNotNone(report)

    def test_traversal_validates_complete_envelope_before_terminal_result(
        self,
    ) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )
        state = ForwardingTraversalStateKey(
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=self.candidate,
        )

        with self.assertRaisesRegex(
            RouteTraceContractError,
            "max_hops must be a non-negative integer",
        ):
            evaluate_forwarding_traversal(
                (),
                max_hops=-1,
                max_recursion=0,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "hop_indices must be a tuple",
        ):
            evaluate_forwarding_traversal(
                (),
                max_hops=0,
                max_recursion=0,
                hop_indices=[],  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "one value per state",
        ):
            evaluate_forwarding_traversal(
                (),
                max_hops=0,
                max_recursion=0,
                recursion_depths=(0,),
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "hop indices must be non-negative integers",
        ):
            evaluate_forwarding_traversal(
                (state, state),
                max_hops=8,
                max_recursion=8,
                hop_indices=(0, True),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "recursion depths must be non-negative integers",
        ):
            evaluate_forwarding_traversal(
                (state, state),
                max_hops=8,
                max_recursion=8,
                recursion_depths=(0, -1),
            )

    def test_valid_cycle_precedes_budget_exhaustion(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )
        state = ForwardingTraversalStateKey(
            member_id="member-a",
            status_perspective=perspective,
            forwarding_object=self.candidate,
        )

        evaluation = evaluate_forwarding_traversal(
            (state, state),
            max_hops=0,
            max_recursion=0,
            hop_indices=(0, 99),
            recursion_depths=(0, 99),
        )

        self.assertEqual(evaluation.outcome, "cycle")
        self.assertEqual(evaluation.stop_step, 1)
        self.assertIsNotNone(evaluation.cycle)

    def test_transit_observation_uses_endpoint_reachability_not_path_reversal(
        self,
    ) -> None:
        evaluation = evaluate_endpoint_reachability_pair(
            forward_reaches_destination=True,
            reverse_reaches_source=True,
            forward_complete=True,
            reverse_complete=True,
            forward_node_sequence=("transit-p-1", "node-b"),
            reverse_node_sequence=("node-b", "transit-p-2", "node-a"),
            forward_start_node_id="transit-p-1",
            traffic_source_node_id="node-a",
        )

        self.assertEqual(evaluation.endpoint_state, "bidirectionally_reachable")
        self.assertEqual(evaluation.comparison_state, "bidirectionally_reachable")
        self.assertTrue(evaluation.consistent)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "forward_starts_inside_flow_path",
        )
        self.assertFalse(evaluation.reverse_must_visit_forward_start)
        self.assertFalse(evaluation.reverse_visits_forward_start)

    def test_reaching_forward_start_does_not_substitute_for_source_endpoint(
        self,
    ) -> None:
        evaluation = evaluate_endpoint_reachability_pair(
            forward_reaches_destination=True,
            reverse_reaches_source=False,
            forward_complete=True,
            reverse_complete=True,
            forward_node_sequence=("transit-p-1", "node-b"),
            reverse_node_sequence=("node-b", "transit-p-1"),
            forward_start_node_id="transit-p-1",
            traffic_source_node_id="node-a",
        )

        self.assertEqual(evaluation.endpoint_state, "one_way_reachable")
        self.assertFalse(evaluation.consistent)
        self.assertTrue(evaluation.reverse_visits_forward_start)

    def test_unknown_direction_is_not_collapsed_into_one_way_reachability(
        self,
    ) -> None:
        evaluation = evaluate_endpoint_reachability_pair(
            forward_reaches_destination=True,
            reverse_reaches_source=None,
            forward_complete=True,
            reverse_complete=False,
        )

        self.assertEqual(evaluation.endpoint_state, "unknown_incomplete")
        self.assertIsNone(evaluation.reverse_reaches_source)
        self.assertFalse(evaluation.consistent)

    def test_empty_policy_validates_every_input_before_permission(self) -> None:
        permitted = evaluate_forwarding_policy(
            candidate=self.candidate,
            constraints=(),
            ingress_scopes=frozenset(),
            traffic_class=None,
        )
        self.assertIs(permitted.verdict, ForwardingPolicyVerdict.PERMITTED)

        with self.assertRaisesRegex(
            RouteTraceContractError,
            "candidate must be a ResourceKey",
        ):
            evaluate_forwarding_policy(
                candidate="not-a-resource-key",  # type: ignore[arg-type]
                constraints=(),
                ingress_scopes=frozenset(),
                traffic_class=None,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "constraints must be a tuple",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=[],  # type: ignore[arg-type]
                ingress_scopes=frozenset(),
                traffic_class=None,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "ForwardingCandidateConstraint values",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(object(),),  # type: ignore[arg-type]
                ingress_scopes=frozenset(),
                traffic_class=None,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "ingress_scopes must be a frozenset",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(),
                ingress_scopes=set(),  # type: ignore[arg-type]
                traffic_class=None,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "ForwardingPolicyScope values",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(),
                ingress_scopes=frozenset({"not-a-scope"}),  # type: ignore[arg-type]
                traffic_class=None,
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "traffic_class must be a string or None",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(),
                ingress_scopes=frozenset(),
                traffic_class=7,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "ingress_scopes_complete must be a boolean",
        ):
            evaluate_forwarding_policy(
                candidate=self.candidate,
                constraints=(),
                ingress_scopes=frozenset(),
                traffic_class=None,
                ingress_scopes_complete=0,  # type: ignore[arg-type]
            )


class MultiNodeRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()
        topology_response = cls.client.post(
            "/v1/topologies/query",
            json={
                "resource_limit": 100,
                "network_segment_limit": 100,
                "segment_attachment_limit": 200,
            },
        )
        if topology_response.status_code != 200:
            raise AssertionError(topology_response.text)
        cls.generated_topology = topology_response.json()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    @classmethod
    def _generated_attachment_resource_id(
        cls,
        node_id: str,
        *,
        shared_with: str,
    ) -> str:
        segment_ids = {
            str(segment["segment_id"])
            for segment in cls.generated_topology["network_segments"]
            if {node_id, shared_with} <= set(segment["node_ids"])
        }
        candidates = sorted(
            {
                str(attachment["resource_id"])
                for attachment in cls.generated_topology["segment_attachments"]
                if attachment["node_id"] == node_id
                and attachment["segment_id"] in segment_ids
                and "/VIRTUAL_INTERFACE/" in attachment["resource_id"]
            }
        )
        if len(candidates) != 1:
            raise AssertionError(
                "expected one generated interface attachment for "
                f"{node_id} shared with {shared_with}, got {candidates}"
            )
        return candidates[0]

    @staticmethod
    def _endpoint_fixture(
        endpoint_id: str,
        *,
        node_id: str = "node-b",
        resource_id: str = "node-b/LOOPBACK/1",
    ) -> tuple[dict[str, object], dict[str, object]]:
        attachment = MultiNodeRouteService._endpoint_attachment(
            endpoint_id=endpoint_id,
            node_id=node_id,
            member_id=f"member:{node_id}",
            resource_id=resource_id,
        )
        endpoint = {
            "endpoint_id": endpoint_id,
            "attachments": [attachment],
            "attachments_complete": True,
        }
        return endpoint, attachment

    @staticmethod
    def _terminal_path(
        *,
        attachment: dict[str, object] | None,
        endpoint_id: str | None,
        classification: str,
        complete: bool = True,
        selected: bool = True,
        sequence: tuple[str, ...] = ("node-a", "node-b"),
    ) -> dict[str, object]:
        return {
            "node_sequence": list(sequence),
            "active": selected,
            "selected_active_by_plugin": selected,
            "primary": selected,
            "completeness": {"end_to_end_resolved": complete},
            "plugin_terminal": {
                "classification": classification,
                "classification_complete": classification != "unknown",
                "endpoint_id": endpoint_id,
                "attachment": attachment,
            },
        }

    def test_exact_terminal_match_rejects_a_different_endpoint_on_same_node(
        self,
    ) -> None:
        target, _target_attachment = self._endpoint_fixture(
            "endpoint:target"
        )
        _other, other_attachment = self._endpoint_fixture(
            "endpoint:other"
        )
        path = self._terminal_path(
            attachment=other_attachment,
            endpoint_id="endpoint:other",
            classification="delivered",
        )

        result = MultiNodeRouteService._annotate_endpoint_reachability(
            [path],
            target,
            {"node_id": "node-a"},
        )

        self.assertFalse(result["reaches_target"])
        terminal = path["terminal_reachability"]
        self.assertFalse(terminal["exact_endpoint_match"])
        self.assertFalse(terminal["exact_attachment_match"])
        self.assertEqual(path["terminal_endpoint_id"], "endpoint:other")

    def test_partial_selected_active_set_is_not_fully_reachable(self) -> None:
        target, attachment = self._endpoint_fixture("endpoint:target")
        reached = self._terminal_path(
            attachment=attachment,
            endpoint_id="endpoint:target",
            classification="delivered",
        )
        failed = self._terminal_path(
            attachment=None,
            endpoint_id=None,
            classification="not_delivered",
        )

        result = MultiNodeRouteService._annotate_endpoint_reachability(
            [reached, failed],
            target,
            {"node_id": "node-a"},
        )

        self.assertEqual(result["state"], "partial_active_reachability")
        self.assertIsNone(result["reaches_target"])
        self.assertFalse(result["all_active_branches_reach"])
        self.assertEqual(result["reached_active_branch_count"], 1)
        self.assertEqual(result["failed_active_branch_count"], 1)

    def test_path_must_begin_at_declared_trace_start(self) -> None:
        target, attachment = self._endpoint_fixture("endpoint:target")
        path = self._terminal_path(
            attachment=attachment,
            endpoint_id="endpoint:target",
            classification="delivered",
            sequence=("transit-p-1", "node-b"),
        )

        with self.assertRaisesRegex(
            ValueError,
            "begin at the declared trace_start",
        ):
            MultiNodeRouteService._annotate_endpoint_reachability(
                [path],
                target,
                {"node_id": "node-a"},
            )

    def test_bidirectional_pair_rejects_reverse_start_outside_destination(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "transit-start-endpoint-reachability",
                "direction": "both",
                "ingress": {"start_id": "start:transit-p-1"},
                "reverse_ingress": {"start_id": "start:transit-p-1"},
            },
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn(
            "reverse trace start must resolve to an available attachment "
            "of flow.destination",
            response.text,
        )

    def test_boundary_link_selection_never_falls_back_to_an_unrelated_candidate(
        self,
    ) -> None:
        candidate = {
            "resolution": "matched",
            "endpoint_a": {"resource_id": "interface/a"},
            "endpoint_b": {"resource_id": "interface/b"},
        }

        self.assertIs(
            MultiNodeRouteService._matching_link(
                [candidate],
                {"interface/a", "interface/b"},
            ),
            candidate,
        )
        self.assertIsNone(
            MultiNodeRouteService._matching_link(
                [candidate],
                {"interface/c", "interface/d"},
            )
        )
        for unsafe in (
            candidate | {"resolution": "ambiguous"},
            candidate
            | {
                "typed_federation": True,
                "federation_complete": False,
                "federation_truncated": False,
            },
            candidate
            | {
                "typed_federation": True,
                "federation_complete": True,
                "federation_truncated": True,
            },
        ):
            self.assertIsNone(
                MultiNodeRouteService._matching_link(
                    [unsafe],
                    {"interface/a", "interface/b"},
                )
            )
        source_ref = _typed_boundary_resource_ref("node-a", "interface/a")
        target_ref = _typed_boundary_resource_ref("node-b", "interface/b")
        authoritative_typed = _typed_boundary_link(source_ref, target_ref)
        self.assertIs(
            MultiNodeRouteService._matching_link(
                [authoritative_typed],
                ("interface/a", "interface/b"),
                required_endpoint_refs=(source_ref, target_ref),
            ),
            authoritative_typed,
        )

    def test_route_terminal_result_uses_declared_disposition_not_reason_text(
        self,
    ) -> None:
        path = {
            "primary": True,
            "active": False,
            "segments": [
                {
                    "ordinal": 1,
                    "segment_id": "segment-1",
                    "active": False,
                    "confidence": 1.0,
                    "completeness": {
                        "state": "terminal_failure",
                        "end_to_end_resolved": False,
                    },
                    "state": {
                        "terminal": "vendor_reason_contains_drop_but_is_not_a_drop",
                        "reason_code": "vendor_reason_contains_drop_but_is_not_a_drop",
                        "terminal_disposition": "unusable",
                    },
                    "highlight_target_ids": [],
                    "interaction_target_ids": [],
                    "plugin_provenance": [],
                    "route_resolution": {},
                }
            ],
        }

        MultiNodeRouteService._refresh_path(path)

        self.assertEqual(path["result"], "unusable")

    def test_cycle_detection_uses_complete_canonical_typed_state(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )

        def state(
            index: int,
            *,
            scopes_complete: bool = True,
        ) -> ForwardingTraversalStateKey:
            return ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=ResourceKey(
                    namespace="test",
                    node="node-a",
                    layer="forwarding",
                    kind="FIB",
                    parts=(("index", index),),
                ),
                lookup_context=(
                    ("destination", "203.0.113.0/24"),
                    ("vrf", "blue"),
                ),
                policy_scopes_complete=scopes_complete,
            )

        first = state(10)
        different_lookup = state(11)
        incomplete = state(10, scopes_complete=False)
        self.assertNotEqual(first, different_lookup)
        self.assertNotEqual(first, incomplete)
        self.assertIsNone(
            detect_forwarding_cycle((first, different_lookup))
        )
        self.assertIsNone(detect_forwarding_cycle((first, incomplete)))

        repeated = evaluate_forwarding_traversal(
            (first, first),
            max_hops=1,
            max_recursion=8,
            hop_indices=(0, 99),
        )
        self.assertEqual(repeated.outcome, "cycle")
        assert repeated.cycle is not None
        self.assertEqual(repeated.cycle.first_seen_step, 0)
        self.assertEqual(repeated.cycle.repeated_at_step, 1)

        exhausted = evaluate_forwarding_traversal(
            (first, different_lookup),
            max_hops=1,
            max_recursion=8,
            hop_indices=(0, 2),
        )
        self.assertEqual(exhausted.outcome, "hop_limit_exceeded")

    def test_typed_cycle_detector_allows_changed_key_revisit(self) -> None:
        perspective = StatusPerspectiveRef(
            perspective_id="hardware.observed",
            plugin_instance_id="member-a/example",
        )

        def state(
            index: int,
            *,
            scopes_complete: bool = True,
        ) -> ForwardingTraversalStateKey:
            return ForwardingTraversalStateKey(
                member_id="member-a",
                status_perspective=perspective,
                forwarding_object=ResourceKey(
                    namespace="test",
                    node="node-a",
                    layer="forwarding",
                    kind="FIB",
                    parts=(("index", index),),
                ),
                lookup_context=(("destination", "203.0.113.8/32"),),
                policy_scopes_complete=scopes_complete,
            )

        first = state(101)
        changed = state(102)
        incomplete = state(101, scopes_complete=False)
        self.assertIsNone(detect_forwarding_cycle((first, changed)))
        self.assertIsNone(detect_forwarding_cycle((first, incomplete)))
        report = detect_forwarding_cycle((first, changed, first))
        self.assertIsNotNone(report)
        assert report is not None
        self.assertEqual(report.first_seen_step, 0)
        self.assertEqual(report.repeated_at_step, 2)
        self.assertEqual(report.cycle_states, (first, changed, first))

    def test_incomplete_declared_identity_cannot_prove_generated_cycle(
        self,
    ) -> None:
        path = {
            "path_id": "test-incomplete-identity",
            "node_sequence": ["node-a", "node-a"],
            "segments": [],
        }
        candidate = {
            "traversal_states": [
                {
                    "visit_index": 0,
                    "node_id": "node-a",
                    "cycle_key": "opaque-repeat",
                    "identity_complete": False,
                },
                {
                    "visit_index": 1,
                    "node_id": "node-a",
                    "cycle_key": "opaque-repeat",
                    "identity_complete": False,
                },
            ],
            "terminal_semantics": {},
        }

        MultiNodeRouteService._project_candidate_traversal(
            path,
            candidate,
            max_hops=64,
            max_recursion=16,
        )

        self.assertNotIn("cycle", path)
        self.assertEqual(
            [
                item["canonical_identity_complete"]
                for item in path["node_occurrences"]
            ],
            [False, False],
        )
        self.assertFalse(path["node_occurrences"][1]["repeated"])

    def test_legacy_multipath_mode_defaults_only_for_unambiguous_single_path(
        self,
    ) -> None:
        self.assertEqual(
            MultiNodeRouteService._route_executor_multipath_mode(
                {},
                selected_count=1,
            ),
            "single_active",
        )
        self.assertEqual(
            MultiNodeRouteService._route_executor_multipath_mode(
                {"multipath_mode": "all_active"},
                selected_count=1,
            ),
            "all_active",
        )
        with self.assertRaisesRegex(
            ValueError,
            "contract v1 omits multipath_mode",
        ):
            MultiNodeRouteService._route_executor_multipath_mode(
                {},
                selected_count=2,
            )

    def test_typed_policy_evaluator_is_exact_and_protocol_neutral(self) -> None:
        candidate = ResourceKey(
            namespace="test",
            node="node-a",
            layer="forwarding",
            kind="NEXTHOP",
            parts=(("id", 7),),
        )
        evpn_scope = ForwardingPolicyScope(
            contract_id="example.evpn.horizon.v1",
            arguments=(("esi", "00:11"), ("evi", 320)),
        )
        other_evpn_scope = ForwardingPolicyScope(
            contract_id=evpn_scope.contract_id,
            arguments=(("esi", "00:12"), ("evi", 320)),
        )
        evpn_constraint = ForwardingCandidateConstraint(
            constraint_id="evpn-horizon-7",
            kind="exclude_exact_scope",  # type: ignore[arg-type]
            candidate_scope=evpn_scope,
            traffic_classes=frozenset({"ethernet.bum"}),
        )
        blocked = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class="ethernet.bum",
        )
        permitted = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({other_evpn_scope}),
            traffic_class="ethernet.bum",
        )
        unknown = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class=None,
        )
        not_applicable = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class="ip.unicast",
        )
        incomplete = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({other_evpn_scope}),
            traffic_class="ethernet.bum",
            ingress_scopes_complete=False,
        )
        incomplete_match = evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=evpn_constraint,
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class="ethernet.bum",
            ingress_scopes_complete=False,
        )
        self.assertIs(blocked.verdict, ForwardingPolicyVerdict.BLOCKED)
        self.assertIs(permitted.verdict, ForwardingPolicyVerdict.PERMITTED)
        self.assertIs(unknown.verdict, ForwardingPolicyVerdict.UNKNOWN)
        self.assertIs(
            not_applicable.verdict,
            ForwardingPolicyVerdict.NOT_APPLICABLE,
        )
        self.assertIs(incomplete.verdict, ForwardingPolicyVerdict.UNKNOWN)
        self.assertFalse(incomplete.ingress_scopes_complete)
        self.assertIs(
            incomplete_match.verdict,
            ForwardingPolicyVerdict.BLOCKED,
        )
        unknown_aggregate = evaluate_forwarding_policy(
            candidate=candidate,
            constraints=(evpn_constraint,),
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class=None,
        )
        not_applicable_aggregate = evaluate_forwarding_policy(
            candidate=candidate,
            constraints=(evpn_constraint,),
            ingress_scopes=frozenset({evpn_scope}),
            traffic_class="ip.unicast",
        )
        incomplete_aggregate = evaluate_forwarding_policy(
            candidate=candidate,
            constraints=(evpn_constraint,),
            ingress_scopes=frozenset({other_evpn_scope}),
            traffic_class="ethernet.bum",
            ingress_scopes_complete=False,
        )
        self.assertIs(
            unknown_aggregate.verdict,
            ForwardingPolicyVerdict.UNKNOWN,
        )
        self.assertIs(
            not_applicable_aggregate.verdict,
            ForwardingPolicyVerdict.NOT_APPLICABLE,
        )
        self.assertIs(
            incomplete_aggregate.verdict,
            ForwardingPolicyVerdict.UNKNOWN,
        )
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            evaluate_forwarding_policy(
                candidate=candidate,
                constraints=(),
                ingress_scopes=frozenset(),
                traffic_class="ethernet.bum",
                ingress_scopes_complete=0,  # type: ignore[arg-type]
            )

        bgp_scope = ForwardingPolicyScope(
            contract_id="example.bgp.learned-from.v1",
            arguments=(
                ("neighbor", "192.0.2.1"),
                ("route_reflector_cluster", 44),
            ),
        )
        bgp_constraint = ForwardingCandidateConstraint(
            constraint_id="bgp-route-reflection-loop-44",
            kind="exclude_exact_scope",  # type: ignore[arg-type]
            candidate_scope=bgp_scope,
            traffic_classes=frozenset({"bgp.route-reflection"}),
        )
        aggregate = evaluate_forwarding_policy(
            candidate=candidate,
            constraints=(bgp_constraint,),
            ingress_scopes=frozenset({bgp_scope}),
            traffic_class="bgp.route-reflection",
        )
        self.assertIs(aggregate.verdict, ForwardingPolicyVerdict.BLOCKED)
        self.assertIs(
            aggregate.decisions[0].verdict,
            ForwardingPolicyVerdict.BLOCKED,
        )

    def test_recursive_cycle_and_recursion_budget_are_distinct(self) -> None:
        cycle_response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "recursive-resolution-cycle"},
        )
        self.assertEqual(cycle_response.status_code, 200, cycle_response.text)
        cycle_trace = cycle_response.json()
        cycle_path = cycle_trace["paths"][0]
        self.assertFalse(cycle_trace["reachable"])
        self.assertEqual(cycle_path["result"], "cycle")
        self.assertEqual(
            cycle_path["terminal_reason"], "recursive_resolution_cycle"
        )
        self.assertEqual(cycle_path["cycle"]["first_step"], 1)
        self.assertEqual(cycle_path["cycle"]["closing_step"], 3)
        self.assertEqual(len(cycle_path["node_occurrences"]), 3)
        self.assertTrue(cycle_path["node_occurrences"][-1]["repeated"])
        cycle_terminal = next(
            item
            for item in cycle_path["segments"]
            if item["state"].get("terminal_disposition") == "cycle"
        )
        self.assertEqual(cycle_terminal["state"]["operational"], "loop_detected")
        self.assertTrue(cycle_trace["consistency"]["consistent"])
        self.assertEqual(cycle_trace["consistency"]["issue_refs"], [])

        limited_response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "recursive-resolution-cycle",
                "max_recursion": 0,
            },
        )
        self.assertEqual(limited_response.status_code, 200, limited_response.text)
        limited_path = limited_response.json()["paths"][0]
        self.assertEqual(limited_path["result"], "recursion_limit_exceeded")
        self.assertEqual(
            limited_path["terminal_reason"], "recursion_limit_exceeded"
        )
        self.assertNotIn("cycle", limited_path)
        self.assertEqual(
            limited_path["resolution_budget"]["kind"], "max_recursion"
        )
        self.assertEqual(
            limited_path["segments"][-1]["state"]["operational"],
            "budget_exhausted",
        )

    def test_core_cycle_detection_is_terminal_without_plugin_loop_disposition(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "recursive-resolution-cycle"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        path = copy.deepcopy(payload["paths"][0])
        candidate = next(
            item
            for item in payload["generated_projection"]["candidate_paths"]
            if item["candidate_id"] == path["generated_candidate_id"]
        )
        for segment in path["segments"]:
            state = segment["state"]
            state.pop("terminal", None)
            state.pop("terminal_disposition", None)
            state["operational"] = "usable"
            segment["active"] = True
            segment["completeness"] = {
                "state": "complete",
                "end_to_end_resolved": True,
                "observed": True,
            }
        path["active"] = True

        MultiNodeRouteService._project_candidate_traversal(
            path,
            candidate,
            max_hops=64,
            max_recursion=16,
        )
        MultiNodeRouteService._refresh_path(path)

        self.assertEqual(path["result"], "cycle")
        self.assertFalse(path["completeness"]["end_to_end_resolved"])
        self.assertFalse(path["active"])
        self.assertEqual(
            path["segments"][-1]["state"]["terminal_disposition"],
            "cycle",
        )
        self.assertEqual(
            path["terminal_reason"],
            "recursive_resolution_cycle",
        )

    def test_plugin_traversal_counters_cannot_bypass_core_budgets(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "recursive-resolution-cycle"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        path = copy.deepcopy(payload["paths"][0])
        candidate = copy.deepcopy(
            payload["generated_projection"]["candidate_paths"][0]
        )
        candidate["traversal_states"][1]["hop_index"] = 0

        with self.assertRaisesRegex(
            ValueError,
            "core-derived hop or recursion",
        ):
            MultiNodeRouteService._project_candidate_traversal(
                path,
                candidate,
                max_hops=64,
                max_recursion=16,
            )

    def test_cross_node_loop_retains_repeated_occurrence_and_closing_link(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "cross-node-forwarding-loop"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        path = response.json()["paths"][0]
        self.assertEqual(path["result"], "cycle")
        self.assertEqual(path["terminal_reason"], "forwarding_loop")
        self.assertEqual(
            path["node_sequence"],
            ["node-a", "transit-p-1", "node-b", "transit-p-1"],
        )
        occurrences = path["node_occurrences"]
        self.assertEqual(len(occurrences), 4)
        self.assertEqual(
            occurrences[-1]["repeats_occurrence_id"],
            occurrences[1]["occurrence_id"],
        )
        closing = [
            item
            for item in path["segments"]
            if item.get("target_occurrence_id")
            == occurrences[-1]["occurrence_id"]
        ]
        self.assertEqual(len(closing), 1)
        self.assertEqual(
            closing[0]["source_occurrence_id"], occurrences[-2]["occurrence_id"]
        )
        self.assertEqual(
            path["segments"][-1]["state"]["operational"], "loop_detected"
        )

        limited = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "cross-node-forwarding-loop",
                "max_hops": 1,
            },
        )
        self.assertEqual(limited.status_code, 200, limited.text)
        limited_path = limited.json()["paths"][0]
        self.assertEqual(limited_path["result"], "hop_limit_exceeded")
        self.assertEqual(
            limited_path["resolution_budget"],
            {"kind": "max_hops", "limit": 1, "observed": 2},
        )
        self.assertNotIn("cycle", limited_path)

    def test_evpn_split_horizon_retains_typed_rejected_candidate(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "evpn-split-horizon-block"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        trace = response.json()
        path = trace["paths"][0]
        self.assertFalse(trace["reachable"])
        self.assertEqual(path["result"], "policy_blocked")
        self.assertEqual(
            path["terminal_reason"], "split_horizon_same_scope"
        )
        self.assertEqual(path["eligibility"], "ineligible_policy")
        decision = path["policy_decisions"][0]
        self.assertEqual(decision["outcome"], "reject")
        self.assertEqual(decision["policy_kind"], "split_horizon")
        self.assertTrue(decision["ingress_scopes_complete"])
        self.assertTrue(decision["provided_by"]["plugin_id"])
        self.assertEqual(len(decision["scope_refs"]), 3)
        self.assertEqual(
            {item["kind"] for item in decision["evidence"]},
            {"ingress_attachment", "egress_attachment", "encapsulation"},
        )
        self.assertEqual(
            path["segments"][-1]["state"]["operational"], "policy_blocked"
        )
        self.assertTrue(trace["consistency"]["consistent"])
        self.assertEqual(trace["consistency"]["issue_refs"], [])
        self.assertEqual(trace["focus"]["result"], "policy_blocked")

    def test_route_trace_budgets_are_validated_and_advertised(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        self.assertEqual(capabilities["default_request"]["max_hops"], 64)
        self.assertEqual(capabilities["default_request"]["max_recursion"], 16)
        self.assertEqual(capabilities["limits"]["maximum_max_hops"], 128)
        self.assertEqual(capabilities["limits"]["maximum_max_recursion"], 64)
        for body in (
            {"max_hops": 0},
            {"max_hops": 129},
            {"max_recursion": -1},
            {"max_recursion": 65},
            {"max_hops": True},
        ):
            with self.subTest(body=body):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=body
                )
                self.assertEqual(response.status_code, 422)

    def test_capabilities_advertise_resolver_ownership_and_alias(self) -> None:
        canonical = self.client.get(
            f"/v1/topology-assemblies/{DEMO_TOPOLOGY_ID}/routes/capabilities"
        )
        alias = self.client.get("/v1/topologies/routes/capabilities")

        self.assertEqual(canonical.status_code, 200)
        self.assertEqual(canonical.json(), alias.json())
        payload = canonical.json()
        self.assertEqual(payload["assembly_id"], DEMO_TOPOLOGY_ID)
        self.assertEqual(payload["default_request"]["resolution_mode"], "best_effort")
        self.assertTrue(
            {item["scenario_id"] for item in payload["scenarios"]}.issuperset(
                {
                "single-active-primary",
                "all-active-ecmp",
                "cross-layer-inconsistent",
                "incomplete-node-resolution",
                "router-to-router",
                "transit-start-endpoint-reachability",
                "site-a-site-c-asymmetric",
                "site-b-site-c-one-way",
                "evpn-mh-all-active",
                "evpn-es-withdraw-failover",
                "evpn-stale-fib-after-withdraw",
                "srv6-all-active",
                "recursive-static-to-external",
                "connected-external-subnet",
                "incomplete-intermediate-resolution",
                }
            )
        )
        self.assertTrue(
            any(
                "route_resolution text" in item
                for item in payload["semantic_ownership"]["node_plugins"]
            )
        )
        self.assertIn(
            payload["default_request"]["destination_id"],
            {
                item["destination_id"]
                for item in payload["destinations"]
            },
        )
        self.assertIn(
            payload["default_request"]["source_id"],
            {item["source_id"] for item in payload["sources"]},
        )
        self.assertEqual(
            payload["federation_resolver"]["plugin_id"],
            "demo.fabric.federation-linker",
        )
        model = payload["network_model"]
        self.assertEqual(
            model["router_count"],
            model["assembly_node_count"],
        )
        self.assertEqual(model["assembly_node_count"], 10)
        self.assertEqual(
            model["physical_connectivity_source"],
            "generated_topology_segment_claims",
        )
        self.assertEqual(model["physical_topology"], "generated_plugin_projection")
        self.assertEqual(
            model["descriptor_source"], "generated_assembly_catalog"
        )
        self.assertEqual(
            len(model["routed_node_ids"]),
            model["router_count"],
        )
        self.assertTrue(model["network_segment_matchers"])
        route_catalog = payload["route_catalog"]
        self.assertTrue(route_catalog)
        self.assertEqual(
            len({item["route_id"] for item in route_catalog}),
            len(route_catalog),
        )
        self.assertTrue(
            set(model["routed_node_ids"]).issubset(
                {item["source_node_id"] for item in route_catalog}
            )
        )
        self.assertTrue(
            all(
                item["descriptor_source"] == "generated_plugin_projection"
                for item in route_catalog
            )
        )
        self.assertGreaterEqual(len(payload["route_types"]), 11)
        self.assertEqual(
            len(payload["start_points"]),
            model["router_count"],
        )
        self.assertIn(
            "start:transit-p-1",
            {item["start_id"] for item in payload["start_points"]},
        )
        self.assertIn("flow", payload["request_contract"])
        self.assertIn("ingress", payload["request_contract"])
        self.assertEqual(
            payload["request_contract"]["bidirectional_criterion"],
            "forward reaches the traffic destination and reverse reaches "
            "the traffic source; reverse need not revisit forward ingress",
        )

    def test_route_table_capabilities_are_descriptors_not_timeless_rows(self) -> None:
        payload = self.client.get("/v1/topologies/routes/capabilities").json()

        self.assertEqual(
            {item["vrf_id"] for item in payload["vrfs"]},
            {"default", "blue", "red", "management"},
        )
        self.assertEqual(
            {item["route_family"] for item in payload["route_families"]},
            {
                "ipv4_unicast",
                "mpls_labeled_unicast",
                "ipv6_unicast",
                "l2vpn_evpn",
                "vpnv4_unicast",
            },
        )
        descriptor = payload["route_tables"]
        self.assertEqual(descriptor["state_location"], "time_bound_query_only")
        self.assertNotIn("items", descriptor)
        self.assertNotIn("entries", descriptor)
        self.assertEqual(
            len(descriptor["available_node_ids"]),
            payload["network_model"]["router_count"],
        )
        red = next(item for item in payload["vrfs"] if item["vrf_id"] == "red")
        self.assertEqual(red["node_ids"], ["node-d", "node-e"])
        self.assertEqual(
            payload["route_table_query_href"], descriptor["query_href"]
        )

    def test_every_advertised_scenario_routing_context_is_executable(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        required = {
            "route_type",
            "vrf_id",
            "vrf",
            "route_family",
            "address_family",
        }
        for scenario in capabilities["scenarios"]:
            with self.subTest(scenario_id=scenario["scenario_id"]):
                self.assertTrue(required <= scenario.keys())
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": scenario["scenario_id"],
                        "direction": "forward",
                        **{field: scenario[field] for field in required},
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                trace = response.json()
                self.assertEqual(trace["route_type"], scenario["route_type"])
                self.assertEqual(trace["vrf_id"], scenario["vrf_id"])
                self.assertEqual(
                    trace["route_family"], scenario["route_family"]
                )
                self.assertEqual(
                    trace["address_family"], scenario["address_family"]
                )

            for direction, context in scenario.get(
                "directional_routing_contexts", {}
            ).items():
                with self.subTest(
                    scenario_id=scenario["scenario_id"], direction=direction
                ):
                    response = self.client.post(
                        "/v1/topologies/routes/trace",
                        json={
                            "scenario_id": scenario["scenario_id"],
                            "direction": direction,
                            **context,
                        },
                    )
                    self.assertEqual(response.status_code, 200, response.text)
                    trace = response.json()
                    for field in (
                        "route_type",
                        "vrf_id",
                        "route_family",
                        "address_family",
                    ):
                        self.assertEqual(trace[field], context[field])

    def test_complex_scenarios_advertise_executable_ui_endpoint_defaults(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        scenarios = {
            item["scenario_id"]: item for item in capabilities["scenarios"]
        }
        expected = {
            "evpn-mh-all-active": (
                "source:node-a",
                "destination:node-e",
            ),
            "evpn-es-withdraw-failover": (
                "source:node-a",
                "destination:node-e",
            ),
            "evpn-stale-fib-after-withdraw": (
                "source:node-a",
                "destination:node-e",
            ),
            "srv6-all-active": (
                "source:node-a",
                "destination:node-e",
            ),
            "recursive-static-to-external": (
                "source:node-a",
                "destination:node-e",
            ),
            "connected-external-subnet": (
                "source:node-e",
                "destination:node-e",
            ),
            "incomplete-intermediate-resolution": (
                "source:node-d",
                "destination:node-b",
            ),
        }
        for scenario_id, (source_id, destination_id) in expected.items():
            with self.subTest(scenario_id=scenario_id):
                scenario = scenarios[scenario_id]
                self.assertEqual(scenario["default_source"], source_id)
                self.assertEqual(scenario["default_destination"], destination_id)
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": scenario_id,
                        "source_id": source_id,
                        "destination_id": destination_id,
                        "direction": "forward",
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)

    def test_route_table_query_covers_every_node_with_generic_and_plugin_fields(self) -> None:
        payload = query_all_route_table_rows(self.client)
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        expected_node_ids = set(
            capabilities["network_model"]["routed_node_ids"]
        )
        self.assertTrue(payload["route_table_context_id"].startswith("rtctx1-"))
        self.assertTrue(payload["topology_context_id"].startswith("tctx1-"))
        self.assertEqual(payload["counts"]["nodes"], len(expected_node_ids))
        self.assertEqual(payload["counts"]["returned"], payload["counts"]["total"])
        self.assertGreaterEqual(payload["counts"]["total"], 100)
        self.assertFalse(payload["page"]["truncated"])
        self.assertEqual(
            {item["node_id"] for item in payload["items"]},
            expected_node_ids,
        )
        required = {
            "route_entry_id",
            "route_entry_ref",
            "node_id",
            "member_id",
            "table_id",
            "vrf_id",
            "address_family",
            "route_family",
            "route_type",
            "prefix",
            "destination",
            "source_protocol",
            "next_hops",
            "egress_interface",
            "metric",
            "preference",
            "active",
            "backup",
            "installed",
            "install_state",
            "resource_refs",
            "basis_time_ns",
            "resolved_time",
            "plugin_provenance",
            "attributes",
            "trace_query",
        }
        for row in payload["items"]:
            self.assertTrue(required <= row.keys())
            self.assertEqual(
                row["route_entry_ref"]["route_entry_id"],
                row["route_entry_id"],
            )
            self.assertEqual(
                row["trace_query"]["route_table_context_id"],
                payload["route_table_context_id"],
            )
            self.assertEqual(
                row["trace_query"]["topology_context_id"],
                payload["topology_context_id"],
            )
            self.assertIn(
                row["trace_query"]["direction"],
                {"forward", "reverse", "both"},
            )
            declared_direction = row["attributes"].get("route_direction")
            if declared_direction in {"forward", "reverse"}:
                self.assertIn(
                    row["trace_query"]["direction"],
                    {declared_direction, "both"},
                )
            self.assertIsInstance(row["next_hops"], list)
            self.assertEqual(
                row["plugin_provenance"]["decision_owner"],
                "node_route_plugin",
            )
        core_evpn = [
            item
            for item in payload["items"]
            if item["node_id"].startswith("transit-")
            and item["route_type"] == "evpn_service"
        ]
        self.assertTrue(core_evpn)
        self.assertTrue(all(not item["active"] for item in core_evpn))
        self.assertTrue(all(not item["installed"] for item in core_evpn))
        self.assertTrue(
            all(not item["forwarding_capable"] for item in core_evpn)
        )
        self.assertTrue(
            all(item["install_state"] == "control_plane_only" for item in core_evpn)
        )
        self.assertTrue(
            all(
                item["plugin_provenance"]["plugin_id"]
                == item["route_entry_ref"]["plugin_id"]
                and item["plugin_provenance"]["ownership"] == "node_plugin"
                and item["plugin_provenance"]["data_kind"]
                == "generated_route_table_row"
                for item in core_evpn
            )
        )

    def test_route_table_query_filters_and_pages_without_losing_context(self) -> None:
        first = self.client.post(
            f"/v1/topology-assemblies/{DEMO_TOPOLOGY_ID}/routes/tables/query",
            json={
                "filters": {
                    "node_ids": ["node-a", "node-b"],
                    "vrf_ids": ["blue"],
                    "route_families": ["l2vpn_evpn"],
                    "active": True,
                },
                "page": {"limit": 3},
            },
        )

        self.assertEqual(first.status_code, 200)
        payload = first.json()
        self.assertEqual(payload["counts"]["nodes"], 2)
        self.assertGreater(payload["counts"]["total"], 3)
        self.assertTrue(payload["page"]["truncated"])
        self.assertEqual(len(payload["items"]), 3)
        self.assertTrue(
            all(
                item["node_id"] in {"node-a", "node-b"}
                and item["vrf_id"] == "blue"
                and item["route_family"] == "l2vpn_evpn"
                for item in payload["items"]
            )
        )
        second = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_ids": ["node-a", "node-b"],
                    "vrf_ids": ["blue"],
                    "route_families": ["l2vpn_evpn"],
                    "active": True,
                },
                "page": {
                    "limit": 3,
                    "cursor": payload["page"]["next_cursor"],
                },
            },
        )
        self.assertEqual(second.status_code, 200)
        following = second.json()
        self.assertEqual(
            following["route_table_context_id"], payload["route_table_context_id"]
        )
        self.assertTrue(
            {item["route_entry_id"] for item in payload["items"]}.isdisjoint(
                {item["route_entry_id"] for item in following["items"]}
            )
        )

    def test_vrf_family_trace_accepts_human_endpoints_and_reports_route_rows(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "router-to-router",
                "source": "10.255.0.1",
                "destination": "10.255.0.3/32",
                "vrf": "blue",
                "route_family": "l2vpn_evpn",
                "route_type": "evpn_service",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["reachable"])
        self.assertEqual(payload["source"]["node_id"], "node-a")
        self.assertEqual(payload["destination"]["node_id"], "node-c")
        self.assertEqual(payload["vrf_id"], "blue")
        self.assertEqual(payload["route_family"], "l2vpn_evpn")
        self.assertEqual(payload["address_family"], "l2vpn")
        self.assertEqual(payload["route_type"], "evpn_service")
        self.assertTrue(payload["route_table_entry_ids"])
        self.assertEqual(
            payload["route_table_entry_ids"],
            [item["route_entry_id"] for item in payload["matched_route_entry_refs"]],
        )
        self.assertTrue(payload["paths"][0]["route_entry_refs"])
        correlations = payload["route_table_entry_correlations"]
        self.assertTrue(
            any(
                item["installed"]
                and item["correlation_role"] == "forwarding_route"
                for item in correlations
            )
        )
        self.assertTrue(
            any(
                not item["installed"]
                and item["correlation_role"] == "control_plane_evidence"
                for item in correlations
            )
        )
        transit_segments = [
            item
            for item in payload["paths"][0]["segments"]
            if str(item.get("node_id") or "").startswith("transit-")
        ]
        self.assertTrue(transit_segments)
        control_evidence_ids = {
            item["route_entry_ref"]["route_entry_id"]
            for item in correlations
            if not item["installed"]
            and item["correlation_role"] == "control_plane_evidence"
        }
        transit_route_entry_ids = {
            reference["route_entry_id"]
            for segment in transit_segments
            for reference in segment["route_entry_refs"]
        }
        self.assertTrue(transit_route_entry_ids)
        self.assertTrue(
            transit_route_entry_ids <= control_evidence_ids
        )
        self.assertTrue(
            any(
                item["kind"] == "route_table_row"
                for item in payload["interaction_targets"]
            )
        )

    def test_a_route_table_row_trace_query_is_directly_executable(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_id": "node-c",
                    "vrf_id": "default",
                    "route_type": "mpls_transport",
                    "destination": {
                        "value": "destination:node-a",
                        "match": "exact",
                    },
                    "active": True,
                }
            },
        ).json()
        row = table["items"][0]

        response = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["trace_mode"], "bidirectional")
        self.assertEqual(payload["direction"], "both")
        self.assertEqual(
            payload["traces"]["forward"]["source"]["node_id"], row["node_id"]
        )
        self.assertEqual(
            payload["traces"]["reverse"]["destination"]["node_id"],
            row["node_id"],
        )
        self.assertEqual(payload["source"]["node_id"], row["node_id"])
        self.assertEqual(
            payload["destination"]["node_id"], row["destination"]["node_id"]
        )
        self.assertEqual(payload["vrf_id"], row["vrf_id"])
        self.assertIn(row["route_entry_id"], payload["route_table_entry_ids"])
        self.assertEqual(
            payload["request"]["route_table_context_id"],
            table["route_table_context_id"],
        )

    def test_inactive_backup_row_is_focused_without_discarding_active_path(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_id": "node-c",
                    "vrf_id": "default",
                    "route_type": "mpls_transport",
                    "destination": {
                        "value": "destination:node-a",
                        "match": "exact",
                    },
                }
            },
        ).json()
        row = next(item for item in table["items"] if item["backup"])

        response = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["reachable"])
        self.assertEqual(payload["multipath"]["candidate_count"], 2)
        self.assertEqual(payload["multipath"]["active_path_count"], 1)
        self.assertTrue(payload["multipath"]["all_candidates_retained"])
        self.assertEqual(payload["focused_path_id"], row["path_id"])
        self.assertFalse(payload["focus"]["active"])
        self.assertEqual(payload["focus"]["alternative_state"], "eligible_standby")
        active = next(item for item in payload["paths"] if item["active"])
        backup = next(
            item
            for item in payload["paths"]
            if item["alternative_state"] == "eligible_standby"
        )
        self.assertTrue(active["primary"])
        self.assertEqual(backup["path_id"], row["path_id"])
        self.assertIn(row["route_entry_id"], payload["route_table_entry_ids"])

    def test_control_plane_only_row_does_not_claim_forwarding_reachability(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_id": "transit-p-2",
                    "vrf_id": "blue",
                    "route_type": "evpn_service",
                    "destination": {
                        "value": "destination:node-c",
                        "match": "exact",
                    },
                }
            },
        ).json()
        row = table["items"][0]
        self.assertEqual(row["install_state"], "control_plane_only")
        self.assertFalse(row["installed"])

        response = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["trace_mode"], "bidirectional")
        self.assertFalse(payload["reachable"])
        self.assertFalse(payload["traces"]["forward"]["reachable"])
        self.assertTrue(payload["traces"]["reverse"]["reachable"])
        self.assertEqual(payload["multipath"]["active_path_count"], 0)
        self.assertIsNone(payload["multipath"]["primary_path_id"])
        self.assertEqual(payload["focused_path_id"], row["path_id"])
        path = payload["paths"][0]
        self.assertFalse(path["active"])
        self.assertFalse(path["forwarding_capable"])
        self.assertEqual(path["alternative_state"], "control_plane_only")
        self.assertIn("direct", path["label"].casefold())
        self.assertEqual(
            payload["traces"]["forward"]["consistency"]["state"],
            "control_plane_only_not_forwarding",
        )
        self.assertEqual(
            payload["bidirectional_validation"]["state"], "one_way_reachable"
        )
        self.assertFalse(payload["consistency"]["consistent"])
        issue = next(
            item for item in payload["issues"] if item["category"] == "forwarding"
        )
        self.assertEqual(issue["route_entry_refs"], [row["route_entry_ref"]])
        self.assertIn(issue["issue_id"], payload["consistency"]["issue_refs"])
        correlation = payload["route_table_entry_correlations"][0]
        self.assertFalse(correlation["installed"])
        self.assertEqual(
            correlation["correlation_role"], "control_plane_evidence"
        )
        target = next(
            item
            for item in payload["interaction_targets"]
            if item["kind"] == "route_table_row"
        )
        self.assertEqual(target["correlation_role"], "control_plane_evidence")

    def test_multihop_control_plane_evidence_is_not_reported_as_a_drop(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_id": "transit-p-1",
                    "vrf_id": "blue",
                    "route_type": "evpn_service",
                    "destination": {
                        "value": "destination:node-c",
                        "match": "exact",
                    },
                }
            },
        ).json()
        row = table["items"][0]
        self.assertEqual(row["install_state"], "control_plane_only")
        self.assertFalse(row["installed"])

        response = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )

        self.assertEqual(response.status_code, 200, response.text)
        forward = response.json()["traces"]["forward"]
        self.assertFalse(forward["reachable"])
        self.assertTrue(forward["complete"])
        self.assertEqual(
            forward["consistency"]["state"],
            "control_plane_only_not_forwarding",
        )
        path = forward["paths"][0]
        self.assertEqual(path["result"], "resolved")
        self.assertIsNone(path["terminal_reason"])
        self.assertFalse(path["forwarding_capable"])
        self.assertEqual(path["alternative_state"], "control_plane_only")
        self.assertEqual(
            [
                segment["node_id"]
                for segment in path["segments"]
                if segment.get("node_id")
            ],
            ["transit-p-1", "transit-p-2", "node-c"],
        )
        self.assertTrue(
            all(
                segment["state"]["operational"] == "usable"
                for segment in path["segments"]
            )
        )
        self.assertNotIn(
            "directional_drop",
            {segment["segment_kind"] for segment in path["segments"]},
        )

    def test_plugin_resource_endpoints_resolve_to_owners(self) -> None:
        node_a_attachment = self._generated_attachment_resource_id(
            "node-a",
            shared_with="transit-p-2",
        )
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "router-to-router",
                "source": {"resource_id": node_a_attachment},
                "destination": (
                    "transit-p-2/control-plane/IP_ROUTING/blue"
                ),
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["source"]["node_id"], "node-a")
        self.assertEqual(payload["destination"]["node_id"], "transit-p-2")
        self.assertTrue(payload["reachable"])

    def test_incompatible_vrf_family_and_unknown_values_are_rejected(self) -> None:
        requests = [
            {
                "scenario_id": "router-to-router",
                "route_type": "evpn_service",
                "route_family": "l2vpn_evpn",
                "vrf": "management",
            },
            {
                "scenario_id": "router-to-router",
                "route_type": "evpn_service",
                "route_family": "ipv4_unicast",
                "vrf": "blue",
            },
            {
                "scenario_id": "router-to-router",
                "route_type": "ipv4_unicast",
                "route_family": "ipv4_unicast",
                "address_family": "ipv6",
            },
            {
                "scenario_id": "router-to-router",
                "source": "not-an-advertised-source",
                "destination": "10.255.0.3",
            },
        ]
        for body in requests:
            with self.subTest(body=body):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=body
                )
                self.assertEqual(response.status_code, 422)

    def test_route_table_context_cannot_be_paired_with_another_topology_context(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query", json={}
        ).json()
        row = table["items"][0]
        other_topology = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "-1000000",
                }
            },
        ).json()
        self.assertNotEqual(
            table["topology_context_id"], other_topology["context_id"]
        )
        request = {
            **row["trace_query"],
            "topology_context_id": other_topology["context_id"],
        }

        response = self.client.post(
            "/v1/topologies/routes/trace", json=request
        )

        self.assertEqual(response.status_code, 422)

    def test_cached_topology_context_rejects_and_never_echoes_other_time_scope(self) -> None:
        relative = self.client.post(
            "/v1/topologies/query", json={"node_ids": ["node-a"]}
        ).json()
        absolute_time = relative["nodes"][0]["resolved_time"]["query_time_ns"]
        absolute_basis = {
            "kind": "absolute_time",
            "clock_domain": "utc",
            "time_ns": absolute_time,
        }
        absolute = self.client.post(
            "/v1/topologies/query",
            json={
                "node_ids": ["node-a"],
                "basis": absolute_basis,
                "clock_policy": "strict",
            },
        ).json()

        contradictory = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": absolute["context_id"],
                "basis": {"kind": "relative_to_watermark", "offset_ns": "0"},
                "clock_policy": "best_effort",
            },
        )
        self.assertEqual(contradictory.status_code, 422)

        canonical = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={"topology_context_id": absolute["context_id"]},
        )
        self.assertEqual(canonical.status_code, 200, canonical.text)
        request = canonical.json()["request"]
        self.assertEqual(request["basis"], absolute_basis)
        self.assertEqual(request["clock_policy"], "strict")

    def test_single_active_retains_primary_and_inactive_standby(self) -> None:
        response = self.client.post(
            f"/v1/topology-assemblies/{DEMO_TOPOLOGY_ID}/routes/trace",
            json={"scenario_id": "single-active-primary"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["multipath"]["mode"], "single_active")
        self.assertTrue(payload["multipath"]["all_candidates_retained"])
        self.assertEqual(payload["multipath"]["candidate_count"], 2)
        self.assertEqual(payload["multipath"]["active_path_count"], 1)
        primary = next(item for item in payload["paths"] if item["primary"])
        standby = next(
            item for item in payload["paths"] if item["alternative_state"] == "eligible_standby"
        )
        self.assertTrue(primary["active"])
        self.assertFalse(standby["active"])
        self.assertEqual(primary["role"], "primary")
        self.assertEqual(primary["result"], "resolved")
        self.assertEqual(primary["eligibility"], "selected")
        self.assertIsNone(primary["terminal_reason"])
        self.assertEqual(standby["role"], "standby")
        self.assertEqual(standby["result"], "resolved")
        self.assertEqual(standby["eligibility"], "eligible_standby")
        self.assertIsNone(standby["terminal_reason"])
        self.assertEqual(payload["focused_path_id"], primary["path_id"])
        self.assertEqual(
            [item["ordinal"] for item in primary["segments"]], [1, 2, 3, 4, 5]
        )
        self.assertEqual(len(primary["route_resolution_sequence"]), 5)

        for path in payload["paths"]:
            resolution_text = " ".join(
                item["route_resolution"]["text"]
                for item in path["route_resolution_sequence"]
            )
            self.assertIn("mpls_transport", resolution_text)
            self.assertIn("example plug-in", resolution_text)
            self.assertIn("Core exact-joins", resolution_text)

        self.assertEqual(
            standby["node_sequence"], ["node-a", "transit-p-2", "node-b"]
        )
        standby_resource_ids = {
            resource_ref["local_resource_id"]
            for segment in standby["segments"]
            for resource_ref in segment["resource_refs"]
        }
        expected_attachment_resource_ids = {
            self._generated_attachment_resource_id(
                "node-a",
                shared_with="transit-p-2",
            ),
            self._generated_attachment_resource_id(
                "transit-p-2",
                shared_with="node-a",
            ),
            self._generated_attachment_resource_id(
                "transit-p-2",
                shared_with="node-b",
            ),
            self._generated_attachment_resource_id(
                "node-b",
                shared_with="transit-p-2",
            ),
        }
        self.assertEqual(
            standby_resource_ids,
            {
                "node-a/control-plane/IP_ROUTING/blue",
                "transit-p-2/control-plane/IP_ROUTING/blue",
                "node-b/control-plane/IP_ROUTING/blue",
            }
            | expected_attachment_resource_ids,
        )
        boundary_segments = [
            segment
            for segment in standby["segments"]
            if segment["segment_kind"] == "inter_node_boundary"
        ]
        self.assertEqual(len(boundary_segments), 2)
        self.assertTrue(
            all(segment["network_segment_id"] for segment in boundary_segments)
        )
        p2_resolution = next(
            segment
            for segment in standby["segments"]
            if segment.get("node_id") == "transit-p-2"
        )["route_resolution"]
        self.assertEqual(
            p2_resolution["provided_by"]["plugin_id"], "demo.example-router"
        )

        target_ids = {item["target_id"] for item in payload["interaction_targets"]}
        targets_by_id = {
            item["target_id"]: item for item in payload["interaction_targets"]
        }
        for path in payload["paths"]:
            expected_graph_targets = [
                target_id
                for segment in path["segments"]
                for target_id in segment["highlight_target_ids"]
            ]
            self.assertEqual(path["graph_target_ids"], expected_graph_targets)
            self.assertTrue(set(path["graph_target_ids"]) <= target_ids)
            for segment in path["segments"]:
                self.assertIn("node_ids", segment)
                self.assertIn("member_ids", segment)
                self.assertTrue(segment["plugin_provenance"])
                self.assertIn("resource_refs", segment)
                self.assertIn("confidence", segment)
                self.assertIn("issue_refs", segment)
                resolution = segment["route_resolution"]
                self.assertIn("plugin_id", resolution["provided_by"])
                self.assertIn("plugin_run_id", resolution["provided_by"])
                if segment["segment_kind"] == "inter_node_boundary":
                    self.assertEqual(
                        resolution["text_source"],
                        "core_exact_join_summary",
                    )
                    self.assertEqual(
                        resolution["core_role"],
                        "validates_plugin_match_and_current_attachments",
                    )
                else:
                    self.assertEqual(
                        resolution["text_source"], "plugin_provided"
                    )
                    self.assertEqual(
                        resolution["core_role"],
                        "orders_and_joins_plugin_steps_only",
                    )
                self.assertTrue(set(resolution["interaction_target_ids"]) <= target_ids)
                self.assertTrue(set(segment["highlight_target_ids"]) <= target_ids)
                self.assertEqual(
                    resolution["highlight_target_ids"],
                    segment["highlight_target_ids"],
                )
                self.assertTrue(
                    all(
                        part["highlight_target_ids"]
                        == segment["highlight_target_ids"]
                        for part in resolution["parts"]
                    )
                )
                if segment["segment_kind"] == "inter_node_boundary":
                    self.assertTrue(segment["network_segment_id"])

        self.assertEqual(
            [
                targets_by_id[segment["highlight_target_ids"][0]]["kind"]
                for segment in primary["segments"]
            ],
            [
                "topology_node",
                "network_segment",
                "topology_node",
                "network_segment",
                "topology_node",
            ],
        )
        self.assertEqual(
            len(
                {
                    primary["segments"][1]["highlight_target_ids"][0],
                    primary["segments"][2]["highlight_target_ids"][0],
                    primary["segments"][3]["highlight_target_ids"][0],
                }
            ),
            3,
            "P1 and its two adjacent domains must remain individually addressable",
        )
        self.assertEqual(
            [
                targets_by_id[segment["highlight_target_ids"][0]]["kind"]
                for segment in standby["segments"]
            ],
            [
                "topology_node",
                "network_segment",
                "topology_node",
                "network_segment",
                "topology_node",
            ],
        )

    def test_route_trace_exact_joins_runtime_tagged_four_level_segment_keys(
        self,
    ) -> None:
        original_topology_query = MultiNodeTopologyService.query
        original_projection = (
            MultiNodeRouteService._generated_projection_for_scenario
        )

        def nested_key(raw_key: object) -> tuple[dict[str, object], str]:
            if (
                not isinstance(raw_key, dict)
                or raw_key.get("type") != "string"
                or not isinstance(raw_key.get("value"), str)
            ):
                raise AssertionError(
                    "generated route fixture must expose tagged string keys"
                )
            return canonical_opaque_value(
                {
                    "scope": [
                        {
                            "domain": {
                                "identity": raw_key["value"],
                            }
                        }
                    ]
                }
            )

        def query_with_nested_keys(
            service: MultiNodeTopologyService,
            request: dict[str, object],
        ) -> dict[str, object]:
            payload = copy.deepcopy(
                original_topology_query(service, request)
            )
            for segment in payload["network_segments"]:
                normalized, typed_key = nested_key(
                    segment["match"]["segment_key"]
                )
                segment["match"]["segment_key"] = normalized
                segment["match"]["typed_key"] = typed_key
                segment["segment_key"] = normalized
            return payload

        def projection_with_nested_keys(
            service: MultiNodeRouteService,
            scenario_id: str,
            direction: str,
            *,
            resolution_mode: str,
            steering_profile_id: str,
        ) -> dict[str, object] | None:
            projection = original_projection(
                service,
                scenario_id,
                direction,
                resolution_mode=resolution_mode,
                steering_profile_id=steering_profile_id,
            )
            if projection is None:
                return None
            payload = copy.deepcopy(projection)
            for decision in payload["forwarding_decisions"]:
                for directional_decisions in decision[
                    "directional_decisions"
                ].values():
                    for directional_decision in directional_decisions:
                        next_hop = directional_decision.get("next_hop")
                        if next_hop is None:
                            continue
                        reference = next_hop["topology_references"][0]
                        arguments = reference["match"]["arguments"]
                        arguments["segment_key"] = nested_key(
                            arguments["segment_key"]
                        )[0]
            return payload

        with (
            patch.object(
                MultiNodeTopologyService,
                "query",
                query_with_nested_keys,
            ),
            patch.object(
                MultiNodeRouteService,
                "_generated_projection_for_scenario",
                projection_with_nested_keys,
            ),
        ):
            response = self.client.post(
                "/v1/topologies/routes/trace",
                json={"scenario_id": "single-active-primary"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        boundaries = [
            segment
            for path in response.json()["paths"]
            for segment in path["segments"]
            if segment["segment_kind"] == "inter_node_boundary"
        ]
        self.assertTrue(boundaries)
        self.assertTrue(
            all(
                segment["generated_connectivity_binding"]["state"]
                == "resolved"
                for segment in boundaries
            )
        )

    def test_route_trace_uses_declared_exact_typed_boundaries_fail_closed(
        self,
    ) -> None:
        original_topology_query = MultiNodeTopologyService.query
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        source_id = next(
            item["source_id"]
            for item in capabilities["sources"]
            if item["node_id"] == "transit-p-1"
        )
        destination_id = next(
            item["destination_id"]
            for item in capabilities["destinations"]
            if item["node_id"] == "transit-p-2"
        )

        for variant in (
            "complete",
            "linker_owner",
            "record_preview_partial",
            "operational_unknown_strict",
            "operational_unknown_best_effort",
            "reversed_directed",
            "overlay",
            "incomplete",
            "truncated",
            "global_incomplete",
            "global_truncated",
            "link_page_truncated",
            "link_page_flag_missing",
        ):
            with self.subTest(variant=variant):
                def query_with_typed_boundaries(
                    service: MultiNodeTopologyService,
                    request: dict[str, object],
                    _variant: str = variant,
                ) -> dict[str, object]:
                    payload = copy.deepcopy(
                        original_topology_query(service, request)
                    )
                    matching_links = [
                        link
                        for link in payload["inter_node_links"]
                        if link.get("typed_federation") is True
                        and {
                            link["endpoint_a"]["node_id"],
                            link["endpoint_b"]["node_id"],
                        }
                        == {"transit-p-1", "transit-p-2"}
                    ]
                    if not matching_links:
                        raise AssertionError(
                            "validated demo projection did not produce the "
                            "declared P1-P2 typed connector"
                        )
                    for link in matching_links:
                        if _variant == "reversed_directed":
                            endpoint_a = copy.deepcopy(link["endpoint_b"])
                            endpoint_b = copy.deepcopy(link["endpoint_a"])
                            link["endpoint_a"] = endpoint_a
                            link["endpoint_b"] = endpoint_b
                            link["source"] = copy.deepcopy(endpoint_a)
                            link["target"] = copy.deepcopy(endpoint_b)
                            link["directed"] = True
                        elif _variant == "overlay":
                            link["presentation"] = {
                                "route_trace": "overlay"
                            }
                        elif _variant == "incomplete":
                            link["federation_complete"] = False
                        elif _variant == "truncated":
                            link["federation_truncated"] = True
                        elif _variant == "linker_owner":
                            link["inference"] = {
                                "owner": "federation_linker_plugin"
                            }
                        elif _variant.startswith("operational_unknown_"):
                            link["operational_status"] = "unknown"
                            link["status"] = "unknown"
                            link["operational"] = {
                                "usable": None,
                                "status": "unknown",
                                "reason": "projected_status_unknown",
                            }
                    if _variant == "global_incomplete":
                        payload["completeness"][
                            "typed_federation_complete"
                        ] = False
                    elif _variant == "global_truncated":
                        payload["completeness"][
                            "typed_federation_truncated"
                        ] = True
                    elif _variant == "link_page_truncated":
                        payload["completeness"][
                            "inter_node_links_truncated"
                        ] = True
                    elif _variant == "link_page_flag_missing":
                        payload["completeness"].pop(
                            "inter_node_links_truncated"
                        )
                    elif _variant == "record_preview_partial":
                        payload["complete"] = False
                        payload["completeness"]["complete"] = False
                        for node in payload["nodes"]:
                            node["complete"] = False
                            node["completeness"] = {
                                "complete": False,
                                "status": "partial",
                                "reasons": [
                                    {
                                        "reason_code": (
                                            "projection_truncated"
                                        )
                                    }
                                ],
                            }
                            node["counts"]["resource_page"][
                                "truncated"
                            ] = True
                            for result in node["plugin_results"]:
                                result["complete"] = False
                                result["counts"]["resources"][
                                    "truncated"
                                ] = True
                    if _variant in {
                        "complete",
                        "linker_owner",
                        "record_preview_partial",
                        "operational_unknown_strict",
                        "operational_unknown_best_effort",
                    }:
                        payload["network_segments"] = []
                        payload["segment_attachments"] = []
                    return payload

                with (
                    patch.object(
                        MultiNodeTopologyService,
                        "query",
                        query_with_typed_boundaries,
                    ),
                ):
                    response = self.client.post(
                        "/v1/topologies/routes/trace",
                        json={
                            "scenario_id": "router-to-router",
                            "source_id": source_id,
                            "destination_id": destination_id,
                            "resolution_mode": (
                                "strict"
                                if variant == "operational_unknown_strict"
                                else "best_effort"
                            ),
                        },
                    )

                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                generated_next_hop = next(
                    decision["next_hop"]
                    for row in payload["generated_projection"][
                        "forwarding_decisions"
                    ]
                    if row["node_id"] == "transit-p-1"
                    for decision in row["directional_decisions"][
                        "forward"
                    ]
                    if decision["next_hop"] is not None
                )
                self.assertEqual(
                    [
                        reference["reference_kind"]
                        for reference in generated_next_hop[
                            "topology_references"
                        ]
                    ],
                    [
                        "connectivity_domain",
                        "typed_inter_node_link",
                    ],
                )
                self.assertNotIn(
                    "link_id",
                    generated_next_hop["topology_references"][1],
                )
                declared_typed_reference = generated_next_hop[
                    "topology_references"
                ][1]
                self.assertEqual(
                    declared_typed_reference["source_endpoint"][
                        "typed_resource_key"
                    ]["node"],
                    "transit-p-1",
                )
                self.assertEqual(
                    declared_typed_reference["target_endpoint"][
                        "typed_resource_key"
                    ]["node"],
                    "transit-p-2",
                )
                boundaries = [
                    segment
                    for path in payload["paths"]
                    for segment in path["segments"]
                    if segment["segment_kind"]
                    == "inter_node_boundary"
                ]
                self.assertEqual(len(boundaries), 1)
                boundary = boundaries[0]
                self.assertEqual(
                    boundary["topology_reference"],
                    declared_typed_reference,
                )
                if variant in {
                    "complete",
                    "linker_owner",
                    "record_preview_partial",
                }:
                    self.assertEqual(
                        boundary["generated_connectivity_binding"][
                            "state"
                        ],
                        "resolved",
                    )
                    self.assertIsNone(boundary["network_segment_id"])
                    self.assertIsNotNone(boundary["topology_link_id"])
                    self.assertEqual(
                        boundary["completeness"]["state"],
                        "complete",
                    )
                    self.assertEqual(len(boundary["resource_refs"]), 2)
                    self.assertTrue(
                        all(
                            reference.get("plugin_instance_id")
                            and reference.get("typed_resource_key")
                            and reference.get("projection_id")
                            and reference.get("status_perspective_id")
                            for reference in boundary["resource_refs"]
                        )
                    )
                    expected_owner = (
                        "federation_linker_plugin"
                        if variant == "linker_owner"
                        else "core_exact_matcher"
                    )
                    self.assertEqual(
                        boundary["graph_presentation"]["semantic_owner"],
                        expected_owner,
                    )
                    self.assertEqual(
                        payload["semantic_ownership"][
                            "boundary_resolution"
                        ],
                        expected_owner,
                    )
                    if variant == "record_preview_partial":
                        self.assertFalse(
                            payload["topology_snapshot"]["complete"]
                        )
                    if variant == "linker_owner":
                        self.assertNotIn(
                            "Core exact-joins",
                            boundary["route_resolution_text"],
                        )
                        self.assertIn(
                            "allowlisted federation linker",
                            boundary["route_resolution_text"],
                        )
                        self.assertEqual(
                            boundary["route_resolution"]["text_source"],
                            "federation_linker_resolution_summary",
                        )
                        self.assertEqual(
                            boundary["route_resolution"]["core_role"],
                            (
                                "validates_allowlisted_linker_typed_boundary"
                            ),
                        )
                    else:
                        self.assertIn(
                            "Core exact-joins",
                            boundary["route_resolution_text"],
                        )
                        self.assertEqual(
                            boundary["route_resolution"]["text_source"],
                            "core_exact_join_summary",
                        )
                elif variant in {
                    "operational_unknown_strict",
                    "operational_unknown_best_effort",
                }:
                    self.assertEqual(
                        boundary["generated_connectivity_binding"]["state"],
                        "resolved",
                    )
                    self.assertIsNotNone(boundary["topology_link_id"])
                    self.assertEqual(
                        boundary["state"]["operational"],
                        "unknown",
                    )
                    self.assertEqual(
                        boundary["state"]["reason_code"],
                        "typed_boundary_operational_status_unknown",
                    )
                    containing_path = next(
                        path
                        for path in payload["paths"]
                        if boundary in path["segments"]
                    )
                    if variant == "operational_unknown_strict":
                        self.assertFalse(boundary["active"])
                        self.assertEqual(
                            boundary["completeness"],
                            {
                                "state": "unresolved",
                                "end_to_end_resolved": False,
                                "observed": False,
                            },
                        )
                        self.assertEqual(
                            containing_path["result"],
                            "unresolved",
                        )
                        self.assertEqual(
                            containing_path["completeness"]["state"],
                            "incomplete",
                        )
                    else:
                        self.assertEqual(
                            boundary["completeness"],
                            {
                                "state": "best_effort_inferred",
                                "end_to_end_resolved": True,
                                "observed": False,
                            },
                        )
                        self.assertEqual(
                            containing_path["completeness"]["state"],
                            "best_effort_resolved",
                        )
                        self.assertFalse(
                            containing_path["completeness"][
                                "observationally_complete"
                            ]
                        )
                        self.assertEqual(
                            boundary["inference"]["trigger_reason_code"],
                            "typed_boundary_operational_status_unknown",
                        )
                else:
                    self.assertEqual(
                        boundary["generated_connectivity_binding"][
                            "state"
                        ],
                        "unresolved",
                    )
                    self.assertIsNone(boundary["topology_link_id"])
                    self.assertEqual(
                        boundary["completeness"]["state"],
                        "unresolved",
                    )
                    expected_reason = {
                        "global_incomplete": (
                            "typed_boundary_federation_incomplete"
                        ),
                        "global_truncated": (
                            "typed_boundary_federation_truncated"
                        ),
                        "link_page_truncated": (
                            "typed_boundary_inter_node_links_truncated"
                        ),
                        "link_page_flag_missing": (
                            "typed_boundary_inter_node_links_truncated"
                        ),
                    }.get(variant)
                    if expected_reason is not None:
                        self.assertEqual(
                            boundary["generated_connectivity_binding"][
                                "reason_code"
                            ],
                            expected_reason,
                        )

    def test_an_inactive_candidate_can_be_focused_without_activating_it(self) -> None:
        standby_id = "route-path:underlay:pe-a-alternate"
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "focus_path_id": standby_id,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["focused_path_id"], standby_id)
        self.assertFalse(payload["focus"]["active"])
        self.assertEqual(payload["focus"]["alternative_state"], "eligible_standby")
        self.assertEqual(payload["focus"]["role"], "standby")
        self.assertEqual(payload["focus"]["result"], "resolved")
        self.assertEqual(payload["focus"]["eligibility"], "eligible_standby")
        self.assertIsNone(payload["focus"]["terminal_reason"])
        focused = next(item for item in payload["paths"] if item["focused"])
        self.assertEqual(focused["path_id"], standby_id)
        self.assertEqual(
            payload["route_resolution_sequence"], focused["route_resolution_sequence"]
        )

    def test_all_active_ecmp_has_multiple_active_members_and_no_single_primary(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "all-active-ecmp"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["multipath"]["mode"], "all_active")
        self.assertEqual(payload["multipath"]["active_path_count"], 2)
        self.assertIsNone(payload["multipath"]["primary_path_id"])
        self.assertTrue(all(item["active"] for item in payload["paths"]))
        self.assertTrue(all(not item["primary"] for item in payload["paths"]))
        self.assertTrue(
            all(item["alternative_state"] == "ecmp_member" for item in payload["paths"])
        )
        self.assertEqual(
            {tuple(item["node_sequence"]) for item in payload["paths"]},
            {
                ("node-a", "transit-p-1", "node-b"),
                ("node-a", "transit-p-2", "node-b"),
            },
        )
        for path in payload["paths"]:
            resolution_text = " ".join(
                item["route_resolution"]["text"]
                for item in path["route_resolution_sequence"]
            )
            self.assertIn("mpls_transport", resolution_text)
            self.assertIn("example plug-in", resolution_text)
            self.assertIn("Core exact-joins", resolution_text)

    def test_generic_route_catalog_reaches_every_ordered_router_pair(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        sources = capabilities["sources"]
        destinations = [
            item
            for item in capabilities["destinations"]
            if item.get("route_participant")
        ]
        results = []
        for source in sources:
            for destination in destinations:
                if source["node_id"] == destination["node_id"]:
                    continue
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": "router-to-router",
                        "source_id": source["source_id"],
                        "destination_id": destination["destination_id"],
                    },
                )
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertTrue(payload["reachable"])
                self.assertEqual(payload["source"]["node_id"], source["node_id"])
                self.assertEqual(
                    payload["destination"]["node_id"], destination["node_id"]
                )
                sequence = payload["paths"][0]["node_sequence"]
                self.assertEqual(sequence[0], source["node_id"])
                self.assertEqual(sequence[-1], destination["node_id"])
                self.assertEqual(len(sequence), len(set(sequence)))
                self.assertLessEqual(len(sequence), len(sources))
                results.append((source["node_id"], destination["node_id"]))
        participant_count = len(sources)
        self.assertEqual(
            len(results),
            participant_count * (participant_count - 1),
        )

    def test_advertised_route_types_report_truthful_nested_node_applicability(
        self,
    ) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        for descriptor in capabilities["route_types"]:
            with self.subTest(route_type=descriptor["route_type"]):
                source_node_id, destination_node_id = (
                    ("node-d", "node-e")
                    if descriptor["route_type"] == "evpn_ip_prefix"
                    else ("transit-p-1", "node-c")
                )
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": "router-to-router",
                        "route_type": descriptor["route_type"],
                        "source": {"node_id": source_node_id},
                        "destination": {"node_id": destination_node_id},
                    },
                )
                if descriptor["route_type"] == "connected":
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertIn("connected", response.text.casefold())
                    continue
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assertEqual(payload["route_type"], descriptor["route_type"])
                self.assertEqual(payload["source"]["node_id"], source_node_id)
                self.assertEqual(
                    payload["destination"]["node_id"], destination_node_id
                )
                self.assertEqual(
                    payload["paths"][0]["route_type"], descriptor["route_type"]
                )
                if descriptor["route_type"] in {
                    "evpn_service",
                    "evpn_mac_ip",
                }:
                    self.assertFalse(payload["reachable"])
                    self.assertEqual(
                        payload["paths"][0]["alternative_state"],
                        "control_plane_only",
                    )
                    self.assertEqual(
                        payload["consistency"]["state"],
                        "control_plane_only_not_forwarding",
                    )
                else:
                    self.assertTrue(payload["reachable"])

    def test_route_table_facets_cover_diverse_plugin_route_semantics(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        expected_types = {
            "ipv4_unicast",
            "ipv6_unicast",
            "connected",
            "static_recursive",
            "isis_underlay",
            "mpls_transport",
            "mpls_l3vpn",
            "srv6_policy",
            "evpn_service",
            "evpn_mac_ip",
            "evpn_ip_prefix",
        }
        self.assertEqual(
            {item["route_type"] for item in capabilities["route_types"]},
            expected_types,
        )
        table = query_all_route_table_rows(self.client)
        self.assertFalse(table["page"]["truncated"])
        self.assertEqual(
            {item["value"] for item in table["facets"]["route_types"]},
            expected_types,
        )
        protocols = {item["value"] for item in table["facets"]["protocols"]}
        self.assertTrue(
            {
                "connected",
                "static",
                "isis-l2",
                "ibgp",
                "ebgp",
                "segment-routing-mpls",
                "bgp-vpnv4",
                "bgp-sr-policy",
                "bgp-evpn",
            }
            <= protocols
        )
        by_type = {}
        for row in table["items"]:
            by_type.setdefault(row["route_type"], row)
        for route_type in expected_types:
            with self.subTest(route_type=route_type):
                row = by_type[route_type]
                self.assertTrue(row["attributes"]["resolution_phases"])

    def test_route_table_rows_expose_plugin_declared_label_and_sid_actions(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={"page": {"limit": 500}},
        ).json()
        by_type = {}
        for row in table["items"]:
            by_type.setdefault(row["route_type"], row)

        transport = by_type["mpls_transport"]
        transport_action = transport["forwarding_actions"][0]
        self.assertEqual(transport_action["kind"], "mpls_label_stack")
        self.assertEqual(transport_action["operation"], "push")
        self.assertEqual(transport_action["order"], "outer_to_inner")
        self.assertEqual(
            transport_action["applies_to_next_hop_id"],
            transport["next_hops"][0]["next_hop_id"],
        )
        self.assertEqual(
            [item["kind"] for item in transport_action["values"]],
            ["sr_mpls_sid"],
        )
        self.assertEqual(
            [item["role"] for item in transport_action["values"]],
            ["transport"],
        )

        l3vpn_action = by_type["mpls_l3vpn"]["forwarding_actions"][0]
        self.assertEqual(
            [item["kind"] for item in l3vpn_action["values"]],
            ["sr_mpls_sid", "mpls_label"],
        )
        self.assertEqual(
            [item["role"] for item in l3vpn_action["values"]],
            ["transport", "vpn"],
        )

        srv6_action = by_type["srv6_policy"]["forwarding_actions"][0]
        self.assertEqual(srv6_action["kind"], "srv6_sid_list")
        self.assertGreaterEqual(len(srv6_action["values"]), 2)
        self.assertTrue(
            all(item["kind"] == "srv6_sid" for item in srv6_action["values"])
        )
        self.assertTrue(
            all(item["value_type"] == "ipv6_address" for item in srv6_action["values"])
        )

        self.assertEqual(by_type["ipv4_unicast"]["forwarding_actions"], [])
        self.assertEqual(by_type["ipv6_unicast"]["forwarding_actions"], [])

    def test_every_route_type_has_an_executable_route_table_trace_action(self) -> None:
        table = query_all_route_table_rows(self.client)
        expected_types = {
            item["route_type"]
            for item in self.client.get(
                "/v1/topologies/routes/capabilities"
            ).json()["route_types"]
        }
        rows = {}
        for row in table["items"]:
            if row["installed"] and row["route_type"] not in rows:
                rows[row["route_type"]] = row
        self.assertEqual(set(rows), expected_types)
        for route_type, row in rows.items():
            with self.subTest(route_type=route_type):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=row["trace_query"]
                )
                self.assertEqual(response.status_code, 200, response.text)
                trace = response.json()
                self.assertEqual(trace["route_type"], route_type)
                self.assertIn(
                    row["route_entry_id"], trace["route_table_entry_ids"]
                )

    def test_evpn_multihoming_all_active_retains_two_real_egresses(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "evpn-mh-all-active"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["multipath"]["mode"], "all_active")
        self.assertEqual(payload["multipath"]["active_path_count"], 2)
        self.assertIsNone(payload["multipath"]["primary_path_id"])
        self.assertEqual(
            {path["destination_node_id"] for path in payload["paths"]},
            {"node-b", "node-e"},
        )
        self.assertEqual(
            {
                (
                    path["destination_node_id"],
                    path["encapsulation"]["remote_vtep"],
                )
                for path in payload["paths"]
            },
            {
                ("node-b", "10.254.0.2"),
                ("node-e", "10.254.0.5"),
            },
        )
        self.assertEqual(len({path["path_id"] for path in payload["paths"]}), 2)

    def test_fixed_scenario_respects_reversed_endpoint_pair(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "direction": "forward",
                "source": {"node_id": "node-b"},
                "destination": {"node_id": "node-a"},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()

        self.assertEqual(payload["direction"], "forward")
        self.assertEqual(payload["flow"]["source"]["node_id"], "node-b")
        self.assertEqual(
            payload["flow"]["destination"]["node_id"],
            "node-a",
        )
        self.assertEqual(
            payload["target_endpoint"]["endpoint_id"],
            payload["destination"]["endpoint_id"],
        )
        self.assertTrue(payload["paths"])
        self.assertTrue(
            all(
                path["node_sequence"][0] == "node-b"
                and path["node_sequence"][-1] == "node-a"
                for path in payload["paths"]
            )
        )
        self.assertTrue(
            all(
                path["generated_forwarding_projection"][
                    "directional_scope"
                ]
                == "reverse"
                for path in payload["paths"]
            )
        )

        counterpart = self.client.post(
            "/v1/topologies/routes/trace",
            json=payload["counterpart_request"],
        )
        self.assertEqual(counterpart.status_code, 200, counterpart.text)
        counterpart_payload = counterpart.json()
        self.assertEqual(counterpart_payload["direction"], "reverse")
        self.assertEqual(
            counterpart_payload["target_endpoint"]["endpoint_id"],
            counterpart_payload["destination"]["endpoint_id"],
        )
        self.assertEqual(
            counterpart_payload["target_endpoint"]["endpoint_id"],
            "endpoint:blue-service-prefix",
        )
        self.assertTrue(
            all(
                path["terminal_reachability"]["target_endpoint_id"]
                == counterpart_payload["target_endpoint"]["endpoint_id"]
                for path in counterpart_payload["paths"]
            )
        )
        self.assertTrue(
            all(
                path["node_sequence"][0] == "node-a"
                and path["node_sequence"][-1] == "node-b"
                for path in counterpart_payload["paths"]
            )
        )

        bidirectional = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "direction": "both",
                "source": {"node_id": "node-b"},
                "destination": {"node_id": "node-a"},
            },
        )
        self.assertEqual(
            bidirectional.status_code,
            200,
            bidirectional.text,
        )
        paired = bidirectional.json()["traces"]
        self.assertEqual(
            paired["forward"]["target_endpoint"]["endpoint_id"],
            paired["forward"]["destination"]["endpoint_id"],
        )
        self.assertEqual(
            paired["reverse"]["target_endpoint"]["endpoint_id"],
            paired["reverse"]["destination"]["endpoint_id"],
        )
        self.assertTrue(
            all(
                path["node_sequence"][0] == "node-b"
                and path["node_sequence"][-1] == "node-a"
                for path in paired["forward"]["paths"]
            )
        )
        self.assertTrue(
            all(
                path["node_sequence"][0] == "node-a"
                and path["node_sequence"][-1] == "node-b"
                for path in paired["reverse"]["paths"]
            )
        )

        ambiguous = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "evpn-mh-all-active",
                "direction": "forward",
                "source": {"node_id": "node-e"},
                "destination": {"node_id": "node-a"},
            },
        )
        self.assertEqual(ambiguous.status_code, 422)
        self.assertIn(
            "multi-attachment destination",
            ambiguous.text,
        )

    def test_evpn_withdraw_retains_a_focusable_dead_candidate(self) -> None:
        initial = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "evpn-es-withdraw-failover"},
        )
        self.assertEqual(initial.status_code, 200, initial.text)
        payload = initial.json()
        dead = next(
            path
            for path in payload["paths"]
            if path["alternative_state"] == "withdrawn_dead"
        )
        selected = next(path for path in payload["paths"] if path["primary"])
        self.assertFalse(dead["active"])
        self.assertEqual(dead["result"], "unusable")
        self.assertEqual(dead["eligibility"], "ineligible_dead")
        self.assertEqual(dead["terminal_reason"], "evpn_es_withdrawn")
        attachments = {
            item["node_id"]: item
            for item in payload["flow"]["destination"]["attachments"]
        }
        self.assertEqual(attachments["node-b"]["state"], "withdrawn")
        self.assertFalse(attachments["node-b"]["can_terminate"])
        self.assertEqual(attachments["node-e"]["state"], "available")
        self.assertTrue(attachments["node-e"]["can_terminate"])
        self.assertTrue(selected["active"])
        focused = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "evpn-es-withdraw-failover",
                "focus_path_id": dead["path_id"],
            },
        )
        self.assertEqual(focused.status_code, 200, focused.text)
        focus = focused.json()["focus"]
        self.assertEqual(focus["path_id"], dead["path_id"])
        self.assertFalse(focus["active"])
        self.assertEqual(focus["terminal_reason"], "evpn_es_withdrawn")

    def test_evpn_stale_fib_reports_typed_cross_layer_divergences(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "evpn-stale-fib-after-withdraw"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["consistency"]["state"], "inconsistent")
        self.assertEqual(
            {path["perspective"] for path in payload["paths"]},
            {"forwarding_observed", "control_expected"},
        )
        self.assertEqual(
            {issue["finding_type"] for issue in payload["issues"]},
            {"next_hop", "egress_interface", "encapsulation", "update_lag"},
        )
        observed = next(
            path
            for path in payload["paths"]
            if path["perspective"] == "forwarding_observed"
        )
        self.assertEqual(observed["result"], "unusable")
        self.assertEqual(observed["terminal_reason"], "stale_fib_to_withdrawn_es")

    def test_srv6_all_active_preserves_distinct_plugin_sid_lists(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "srv6-all-active"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["multipath"]["active_path_count"], 2)
        self.assertIsNone(payload["multipath"]["primary_path_id"])
        sid_lists = {
            tuple(path["encapsulation"]["segment_list"])
            for path in payload["paths"]
        }
        self.assertEqual(len(sid_lists), 2)
        self.assertTrue(
            all(
                path["segments"][0]["phase"] == "tunnel_action"
                for path in payload["paths"]
            )
        )

    def test_static_recursion_and_connected_external_termination_are_explicit(self) -> None:
        recursive = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "recursive-static-to-external"},
        )
        connected = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "connected-external-subnet"},
        )
        self.assertEqual(recursive.status_code, 200, recursive.text)
        self.assertEqual(connected.status_code, 200, connected.text)
        recursive_path = recursive.json()["paths"][0]
        self.assertEqual(
            recursive_path["protocol_chain"],
            ["static", "ibgp", "isis-l2", "connected"],
        )
        self.assertIn(
            "recursive_lookup",
            {segment["phase"] for segment in recursive_path["segments"]},
        )
        connected_payload = connected.json()
        connected_path = connected_payload["paths"][0]
        connected_rows = [
            row
            for row in query_all_route_table_rows(self.client)["items"]
            if row["route_type"] == "connected"
            and row["attributes"].get("scenario_id")
            == "connected-external-subnet"
            and row["active"]
        ]
        self.assertEqual(len(connected_rows), 1)
        declared_attachment = connected_rows[0]["attributes"][
            "connected_attachment"
        ]
        self.assertTrue(connected_payload["reachable"])
        self.assertEqual(connected_path["node_sequence"], ["node-e"])
        self.assertEqual(
            connected_path["egress_resource_id"],
            declared_attachment["resource_id"],
        )
        self.assertEqual(
            declared_attachment["classification"],
            "external",
        )
        self.assertFalse(
            any(
                segment["segment_kind"] == "inter_node_boundary"
                for segment in connected_path["segments"]
            )
        )

    def test_missing_intermediate_resolution_is_strict_or_explicitly_inferred(self) -> None:
        strict = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "incomplete-intermediate-resolution",
                "resolution_mode": "strict",
            },
        )
        best = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "incomplete-intermediate-resolution",
                "resolution_mode": "best_effort",
            },
        )
        self.assertEqual(strict.status_code, 200, strict.text)
        self.assertEqual(best.status_code, 200, best.text)
        strict_payload = strict.json()
        best_payload = best.json()
        self.assertFalse(strict_payload["reachable"])
        self.assertTrue(best_payload["reachable"])
        strict_middle = next(
            segment
            for segment in strict_payload["paths"][0]["segments"]
            if segment.get("node_id") == "transit-p-2"
        )
        best_middle = next(
            segment
            for segment in best_payload["paths"][0]["segments"]
            if segment.get("node_id") == "transit-p-2"
        )
        self.assertEqual(strict_middle["completeness"]["state"], "unresolved")
        self.assertEqual(
            best_middle["completeness"]["state"], "best_effort_inferred"
        )
        self.assertIn("inference", best_middle)

    def test_bidirectional_asymmetry_is_not_a_directional_fault(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "site-a-site-c-asymmetric",
                "direction": "both",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(
            payload["bidirectional_validation"]["state"],
            "asymmetric_reachable",
        )
        self.assertTrue(payload["consistency"]["consistent"])
        self.assertEqual(
            payload["traces"]["forward"]["paths"][0]["node_sequence"],
            ["node-a", "transit-p-2", "node-c"],
        )
        self.assertEqual(
            payload["traces"]["reverse"]["paths"][0]["node_sequence"],
            ["node-c", "transit-p-2", "transit-p-1", "node-a"],
        )
        for direction in ("forward", "reverse"):
            trace = payload["traces"][direction]
            self.assertTrue(trace["consistency"]["consistent"])
            self.assertEqual(
                trace["consistency"]["state"],
                "consistent_with_selected_observations",
            )
            self.assertEqual(trace["consistency"]["issue_refs"], [])
            self.assertEqual(trace["issues"], [])

    def test_transit_start_pair_is_validated_against_traffic_endpoints(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "transit-start-endpoint-reachability",
                "direction": "both",
                "flow": {
                    "source": {"endpoint_id": "endpoint:node-a:loopback"},
                    "destination": {"endpoint_id": "endpoint:node-b:loopback"},
                },
                "ingress": {"start_id": "start:transit-p-1"},
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        forward = payload["traces"]["forward"]
        reverse = payload["traces"]["reverse"]
        self.assertEqual(
            forward["flow"]["source"]["endpoint_id"],
            "endpoint:node-a:loopback",
        )
        self.assertEqual(
            forward["flow"]["destination"]["endpoint_id"],
            "endpoint:node-b:loopback",
        )
        self.assertEqual(forward["trace_start"]["node_id"], "transit-p-1")
        self.assertEqual(
            forward["paths"][0]["node_sequence"],
            ["transit-p-1", "node-b"],
        )
        self.assertTrue(
            forward["endpoint_reachability"]["reaches_target"]
        )
        self.assertEqual(reverse["trace_start"]["node_id"], "node-b")
        self.assertEqual(
            reverse["paths"][0]["node_sequence"],
            ["node-b", "transit-p-2", "node-a"],
        )
        self.assertNotIn(
            "transit-p-1", reverse["paths"][0]["node_sequence"]
        )
        self.assertTrue(
            reverse["endpoint_reachability"]["reaches_target"]
        )
        validation = payload["bidirectional_validation"]
        self.assertEqual(
            validation["criterion"],
            "source_destination_endpoint_reachability",
        )
        self.assertEqual(
            validation["endpoint_state"],
            "bidirectionally_reachable",
        )
        self.assertTrue(validation["consistent"])
        self.assertTrue(validation["forward_reaches_destination"])
        self.assertTrue(validation["reverse_reaches_source"])
        self.assertEqual(
            validation["path_relation"]["state"], "not_comparable"
        )
        self.assertFalse(validation["reverse_must_visit_forward_start"])
        self.assertFalse(validation["reverse_visits_forward_start"])
        self.assertTrue(payload["consistency"]["consistent"])

    def test_same_router_non_source_attachment_is_not_full_endpoint_span(
        self,
    ) -> None:
        node_a_attachment = self._generated_attachment_resource_id(
            "node-a",
            shared_with="transit-p-2",
        )
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "transit-start-endpoint-reachability",
                "direction": "both",
                "flow": {
                    "source": {"endpoint_id": "endpoint:node-a:loopback"},
                    "destination": {
                        "endpoint_id": "endpoint:node-b:loopback"
                    },
                },
                "ingress": {
                    "node_id": "node-a",
                    "resource_id": node_a_attachment,
                },
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        validation = payload["bidirectional_validation"]
        self.assertEqual(
            payload["traces"]["forward"]["trace_start"]["node_id"],
            "node-a",
        )
        self.assertEqual(
            validation["path_relation"]["state"],
            "not_comparable",
        )
        self.assertEqual(
            validation["path_relation"]["reason"],
            "forward_starts_inside_flow_path",
        )
        self.assertTrue(validation["consistent"])

    def test_bidirectional_asymmetric_pair_is_reachable_both_ways(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "site-a-site-c-asymmetric",
                "direction": "both",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["trace_mode"], "bidirectional")
        self.assertEqual(payload["direction"], "both")
        self.assertEqual(
            payload["bidirectional_validation"]["state"],
            "asymmetric_reachable",
        )
        forward = payload["traces"]["forward"]
        reverse = payload["traces"]["reverse"]
        self.assertTrue(forward["reachable"])
        self.assertTrue(reverse["reachable"])
        for trace in (forward, reverse):
            self.assertTrue(trace["consistency"]["consistent"])
            self.assertEqual(
                trace["consistency"]["state"],
                "consistent_with_selected_observations",
            )
            self.assertEqual(trace["consistency"]["issue_refs"], [])
        self.assertEqual(
            forward["paths"][0]["node_sequence"],
            ["node-a", "transit-p-2", "node-c"],
        )
        self.assertEqual(
            reverse["paths"][0]["node_sequence"],
            ["node-c", "transit-p-2", "transit-p-1", "node-a"],
        )
        self.assertEqual(forward["route_type"], "srv6_policy")
        self.assertEqual(forward["route_family"], "ipv6_unicast")
        self.assertEqual(forward["vrf_id"], "blue")
        self.assertEqual(reverse["route_type"], "mpls_transport")
        self.assertEqual(reverse["route_family"], "mpls_labeled_unicast")
        self.assertEqual(reverse["address_family"], "mpls")
        self.assertEqual(reverse["vrf_id"], "default")
        self.assertEqual(
            reverse["paths"][0]["route_type"], reverse["route_type"]
        )
        self.assertTrue(reverse["matched_route_entry_refs"])
        self.assertTrue(reverse["paths"][0]["route_entry_refs"])
        self.assertEqual(payload["forward_trace"], forward)
        self.assertEqual(payload["reverse_trace"], reverse)

    def test_bidirectional_one_way_drop_is_not_hidden_by_best_effort(self) -> None:
        best_effort = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "site-b-site-c-one-way",
                "direction": "both",
                "resolution_mode": "best_effort",
            },
        )
        strict = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "site-b-site-c-one-way",
                "direction": "both",
                "resolution_mode": "strict",
            },
        )

        self.assertEqual(best_effort.status_code, 200)
        self.assertEqual(strict.status_code, 200)
        payload = best_effort.json()
        self.assertEqual(
            payload["bidirectional_validation"]["state"], "one_way_reachable"
        )
        self.assertTrue(payload["traces"]["forward"]["reachable"])
        reverse = payload["traces"]["reverse"]
        self.assertFalse(reverse["reachable"])
        dropped = reverse["paths"][0]
        self.assertEqual(dropped["segments"][-1]["segment_kind"], "directional_drop")
        self.assertEqual(dropped["role"], "primary")
        self.assertEqual(dropped["result"], "dropped")
        self.assertEqual(dropped["eligibility"], "selected")
        self.assertEqual(dropped["terminal_reason"], "dropped")
        self.assertTrue(dropped["graph_target_ids"])
        self.assertEqual(
            dropped["graph_target_ids"],
            [
                target_id
                for segment in dropped["segments"]
                for target_id in segment["highlight_target_ids"]
            ],
        )
        inferred = next(
            item
            for item in reverse["paths"]
            if item["alternative_state"] == "best_effort_possible"
        )
        self.assertFalse(inferred["active"])
        self.assertLess(inferred["confidence"], 0.7)
        self.assertTrue(inferred["inference"]["does_not_override_observed_drop"])
        issue_ids = {item["issue_id"] for item in reverse["issues"]}
        self.assertIn("issue:directional:node-c:node-b:p2-egress-drop", issue_ids)
        strict_reverse = strict.json()["traces"]["reverse"]
        self.assertEqual(len(strict_reverse["paths"]), 1)
        self.assertFalse(strict_reverse["reachable"])

    def test_explicit_plugin_findings_control_consistency_without_catalog_failure(self) -> None:
        materialize = MultiNodeRouteService._materialize_generated_findings
        for affects in (True, False):
            with self.subTest(affects_consistency=affects):
                def declared_findings(paths, projection, issues):
                    detached = dict(projection)
                    detached["consistency_findings"] = [{
                        "finding_id": "test:declared-observation",
                        "issue_id": "issue:test:declared-observation",
                        "category": "vendor_specific_comparison",
                        "finding_type": "opaque_configuration_comparison",
                        "summary": "Provider-declared observation",
                        "candidate_ids": [path["generated_candidate_id"] for path in paths],
                        "path_ids": [path["path_id"] for path in paths],
                        "affects_consistency": affects,
                    }]
                    materialize(paths, detached, issues)

                with patch.object(
                    MultiNodeRouteService,
                    "_materialize_generated_findings",
                    side_effect=declared_findings,
                ):
                    response = self.client.post(
                        "/v1/topologies/routes/trace",
                        json={"scenario_id": "router-to-router"},
                    )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assertEqual(payload["consistency"]["consistent"], not affects)
                self.assertEqual(
                    "issue:test:declared-observation" in payload["consistency"]["issue_refs"],
                    affects,
                )
                self.assertTrue(payload["reachable"])

    def test_cross_layer_disagreement_retains_both_paths_and_marks_issues(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "cross-layer-inconsistent"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["consistency"]["state"], "inconsistent")
        self.assertFalse(payload["consistency"]["consistent"])
        self.assertEqual(
            {item["perspective"] for item in payload["paths"]},
            {"forwarding_observed", "control_expected"},
        )
        issue_ids = {item["issue_id"] for item in payload["issues"]}
        self.assertIn("issue:cross-layer-egress-mismatch", issue_ids)
        self.assertIn("issue:boundary-path-disagreement", issue_ids)
        for path in payload["paths"]:
            self.assertTrue(set(path["issue_refs"]) <= issue_ids)

    def test_bidirectional_endpoint_reachability_does_not_hide_cross_layer_issues(
        self,
    ) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "cross-layer-inconsistent",
                "direction": "both",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(
            payload["endpoint_reachability"]["state"],
            "bidirectionally_reachable",
        )
        self.assertTrue(payload["endpoint_reachability"]["consistent"])
        self.assertEqual(payload["consistency"]["state"], "inconsistent")
        self.assertFalse(payload["consistency"]["consistent"])
        self.assertTrue(payload["consistency"]["endpoint_consistent"])
        self.assertFalse(payload["consistency"]["directional_consistent"])
        self.assertIn(
            "issue:cross-layer-egress-mismatch",
            payload["consistency"]["issue_refs"],
        )

    def test_selected_topology_scope_does_not_fabricate_missing_outer_hop(
        self,
    ) -> None:
        capabilities = self.client.get(
            "/v1/topologies/capabilities"
        ).json()
        nodes_by_id = {
            item["node_id"]: item for item in capabilities["nodes"]
        }
        node_queries = [
            {
                "node_id": node_id,
                "plugin_set_id": nodes_by_id[node_id][
                    "default_plugin_set_id"
                ],
                "projections": nodes_by_id[node_id][
                    "default_projection_selections"
                ],
            }
            for node_id in ("node-a", "node-b", "transit-p-1")
        ]
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "cross-layer-inconsistent",
                "node_queries": node_queries,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        control = next(
            path for path in payload["paths"] if path["perspective"] == "control_expected"
        )
        self.assertEqual(control["completeness"]["state"], "incomplete")
        self.assertFalse(control["completeness"]["end_to_end_resolved"])
        self.assertEqual(
            control["node_sequence"],
            ["node-a", "transit-p-2", "node-b"],
        )
        self.assertTrue(
            payload["route_resolution_evidence"][
                "explicit_projection_filters_removed"
            ]
        )
        self.assertEqual(
            {
                node_id
                for segment in control["segments"]
                for node_id in segment["node_ids"]
            },
            set(control["node_sequence"]),
        )
        local_segments = [
            segment
            for segment in control["segments"]
            if segment["segment_kind"] == "node_resolution"
        ]
        self.assertEqual(len(local_segments), 3)
        unresolved_boundaries = [
            segment
            for segment in control["segments"]
            if segment["segment_kind"] == "inter_node_boundary"
        ]
        self.assertEqual(
            [segment["completeness"]["state"] for segment in unresolved_boundaries],
            ["unresolved", "unresolved"],
        )
        self.assertTrue(
            all(
                segment["network_segment_id"] is None
                and segment["resource_refs"] == []
                and segment["generated_connectivity_binding"]["state"]
                == "unresolved"
                for segment in unresolved_boundaries
            )
        )
        evidence = payload["route_resolution_evidence"]
        self.assertTrue(evidence["auxiliary"])
        self.assertFalse(evidence["replaces_topology_context"])
        self.assertTrue(evidence["explicit_projection_filters_removed"])
        self.assertEqual(
            evidence["topology_context_id"], payload["topology_context_id"]
        )
        self.assertNotEqual(
            evidence["context_id"], payload["topology_context_id"]
        )

    def test_all_active_labels_do_not_imply_a_primary(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "all-active-ecmp"},
        )

        self.assertEqual(response.status_code, 200)
        labels = [path["label"] for path in response.json()["paths"]]
        self.assertTrue(all("primary" not in label.casefold() for label in labels))
        self.assertTrue(all("ECMP member" in label for label in labels))

    def test_best_effort_bridges_missing_step_but_strict_preserves_gap(self) -> None:
        best_effort = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "incomplete-node-resolution",
                "resolution_mode": "best_effort",
            },
        )
        strict = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "incomplete-node-resolution",
                "resolution_mode": "strict",
            },
        )

        self.assertEqual(best_effort.status_code, 200)
        self.assertEqual(strict.status_code, 200)
        best = best_effort.json()
        exact = strict.json()
        inferred = best["paths"][0]["segments"][-1]
        gap = exact["paths"][0]["segments"][-1]
        self.assertTrue(best["complete"])
        self.assertFalse(best["completeness"]["observationally_complete"])
        self.assertEqual(inferred["segment_kind"], "best_effort_bridge")
        self.assertEqual(inferred["completeness"]["state"], "best_effort_inferred")
        self.assertEqual(inferred["inference"]["performed_by"], "core")
        self.assertEqual(
            inferred["inference"]["method"],
            "join_topology_with_contemporaneous_resource_status",
        )
        self.assertLess(inferred["confidence"], 0.7)
        self.assertFalse(exact["complete"])
        self.assertEqual(gap["segment_kind"], "unresolved")
        self.assertEqual(gap["completeness"]["state"], "unresolved")
        self.assertNotIn("inference", gap)

    def test_invalid_scenario_mode_and_focus_are_rejected(self) -> None:
        requests = [
            {"scenario_id": "not-a-scenario"},
            {"resolution_mode": "guess"},
            {"scenario_id": "router-to-router", "source_id": "source:missing"},
            {
                "scenario_id": "router-to-router",
                "destination_id": "destination:missing",
            },
            {"direction": "sideways"},
            {
                "scenario_id": "router-to-router",
                "source_id": "source:node-a",
                "source": {"node_id": "node-b"},
            },
            {
                "scenario_id": "single-active-primary",
                "focus_path_id": "route-path:not-present",
            },
        ]
        for body in requests:
            with self.subTest(body=body):
                response = self.client.post("/v1/topologies/routes/trace", json=body)
                self.assertEqual(response.status_code, 422)

    def test_policy_and_context_aliases_are_executable_and_consistent(self) -> None:
        topology = self.client.post("/v1/topologies/query", json={}).json()
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "incomplete-node-resolution",
                "completeness_policy": "strict",
                "topology_context_id": topology["context_id"],
                "destination_id": "destination:node-b",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["resolution_mode"], "strict")
        self.assertEqual(payload["resolution_policy"], "strict")
        self.assertEqual(payload["completeness_policy"], "strict")
        self.assertEqual(
            payload["requested_context_id"], topology["context_id"]
        )
        self.assertTrue(payload["context_consistency"]["validated"])

        disagreement = self.client.post(
            "/v1/topologies/routes/trace",
            json={"resolution_mode": "strict", "resolution_policy": "best_effort"},
        )
        self.assertEqual(disagreement.status_code, 422)


if __name__ == "__main__":
    unittest.main()
