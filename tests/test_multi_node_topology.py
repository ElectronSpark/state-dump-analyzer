from __future__ import annotations

import json
import re
import subprocess
import unittest
import uuid
from collections import UserDict
from itertools import combinations, permutations
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
    generated_demo_runtime_session,
)

configure_generated_demo_for_tests()

from rsl_demo_plugin.topology_contract import DEMO_TOPOLOGY_ID

from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyRequestError,
    MultiNodeTopologyService,
    _integer_ns,
    _status_view_at,
    _status_window_at,
)
from router_dump_analyzer.plugin_api import FederationMatchState, WorldBasisKind
from router_dump_analyzer.topology_core import (
    resolve_connectivity_domain_reference,
)
from router_dump_analyzer.topology_federation import (
    TopologyProjectionBasisSnapshot,
)

_RUNTIME_SESSION = None


def generated_topology_demo() -> MultiNodeTopologyService:
    if _RUNTIME_SESSION is None:
        raise AssertionError("generated test runtime is not open")
    return _RUNTIME_SESSION.topology_provider.get()


def javascript_function(source: str, name: str) -> str:
    """Return one top-level JavaScript function for focused source assertions."""

    start = source.index(f"function {name}(")
    following = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if following is None else source[
        start : start + 1 + following.start()
    ]


class TypedProjectionTemporalGateTests(unittest.TestCase):
    def test_records_must_cover_the_full_resolved_uncertainty_interval(self) -> None:
        basis = TopologyProjectionBasisSnapshot(
            kind=WorldBasisKind.ABSOLUTE_TIME,
            requested_time_ns=50,
            resolved_at_min_ns=45,
            resolved_at_max_ns=65,
        )

        self.assertTrue(
            MultiNodeTopologyService._typed_record_active_during(
                SimpleNamespace(valid_from_ns=40, valid_to_ns=66),
                basis,
            )
        )
        self.assertIsNone(
            MultiNodeTopologyService._typed_record_active_during(
                SimpleNamespace(valid_from_ns=40, valid_to_ns=60),
                basis,
            )
        )
        self.assertFalse(
            MultiNodeTopologyService._typed_record_active_during(
                SimpleNamespace(valid_from_ns=10, valid_to_ns=45),
                basis,
            )
        )

    def test_bounded_records_are_unknown_when_world_has_no_absolute_bounds(self) -> None:
        basis = TopologyProjectionBasisSnapshot(
            kind=WorldBasisKind.RELATIVE_CAPTURE_VECTOR,
            requested_time_ns=None,
            resolved_at_min_ns=None,
            resolved_at_max_ns=None,
        )

        self.assertIsNone(
            MultiNodeTopologyService._typed_record_active_during(
                SimpleNamespace(valid_from_ns=40, valid_to_ns=60),
                basis,
            )
        )
        self.assertTrue(
            MultiNodeTopologyService._typed_record_active_during(
                SimpleNamespace(valid_from_ns=None, valid_to_ns=None),
                basis,
            )
        )


class TopologyStatusReplayTests(unittest.TestCase):
    def test_status_change_keeps_resource_present_within_validity(self) -> None:
        resource = {
            "valid_from_ns": "100",
            "valid_to_ns": "500",
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [
                {
                    "time_ns": "200",
                    "status": "down",
                    "state": {"reason": "carrier-loss"},
                }
            ],
        }

        before = _status_view_at(resource, 99)
        active = _status_view_at(resource, 250)
        after = _status_view_at(resource, 500)
        self.assertEqual(
            (before["exists"], before["status"], before["state"]),
            (False, "absent", {"generation": 1}),
        )
        self.assertEqual(
            (active["exists"], active["status"], active["state"]),
            (True, "down", {"generation": 1, "reason": "carrier-loss"}),
        )
        self.assertEqual(
            (after["exists"], after["status"], after["state"]),
            (False, "absent", {"generation": 1, "reason": "carrier-loss"}),
        )

    def test_delete_creates_gap_and_add_recreates_resource(self) -> None:
        resource = {
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [
                {
                    "time_ns": "200",
                    "operation": "delete",
                    "status": "withdrawn",
                    "state": {"reason": "withdraw"},
                },
                {
                    "time_ns": "300",
                    "operation": "add",
                    "status": "up",
                    "state": {"generation": 2},
                },
            ],
        }

        deleted = _status_view_at(resource, 250)
        recreated = _status_view_at(resource, 350)
        self.assertEqual(
            (deleted["exists"], deleted["status"], deleted["state"]),
            (False, "absent", {"generation": 1, "reason": "withdraw"}),
        )
        self.assertEqual(
            (recreated["exists"], recreated["status"], recreated["state"]),
            (True, "up", {"generation": 2, "reason": "withdraw"}),
        )

    def test_insert_recreates_a_deleted_resource(self) -> None:
        resource = {
            "initial_status": "up",
            "changes": [
                {"time_ns": "100", "operation": "delete"},
                {
                    "time_ns": "200",
                    "operation": "insert",
                    "status": "restored",
                },
            ],
        }

        deleted = _status_view_at(resource, 150)
        restored = _status_view_at(resource, 250)
        self.assertEqual((deleted["exists"], deleted["status"]), (False, "absent"))
        self.assertEqual((restored["exists"], restored["status"]), (True, "restored"))

    def test_same_timestamp_changes_follow_source_sequence(self) -> None:
        resource = {
            "initial_status": "initial",
            "changes": [
                {
                    "time_ns": "100",
                    "source_sequence": 20,
                    "event_uid": "later",
                    "status": "down",
                },
                {
                    "time_ns": "100",
                    "source_sequence": 10,
                    "event_uid": "earlier",
                    "status": "up",
                },
            ],
        }

        self.assertEqual(_status_view_at(resource, 100)["status"], "down")

    def test_explicit_exists_takes_precedence_over_operation_inference(self) -> None:
        resource = {
            "initial_status": "up",
            "changes": [
                {
                    "time_ns": "200",
                    "operation": "add",
                    "exists": False,
                },
                {
                    "time_ns": "300",
                    "operation": "remove",
                    "exists": True,
                    "status": "restored",
                },
            ],
        }

        deleted = _status_view_at(resource, 250)
        restored = _status_view_at(resource, 350)
        self.assertEqual((deleted["exists"], deleted["status"]), (False, "absent"))
        self.assertEqual((restored["exists"], restored["status"]), (True, "restored"))

    def test_failed_no_op_change_does_not_mutate_lifecycle_or_state(self) -> None:
        resource = {
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [
                {
                    "time_ns": "200",
                    "operation": "delete",
                    "exists": False,
                    "status": "down",
                    "state": {"generation": 2},
                    "outcome": "failed",
                    "state_changed": False,
                }
            ],
        }

        current = _status_view_at(resource, 250)
        self.assertEqual(
            (current["exists"], current["status"], current["state"]),
            (True, "up", {"generation": 1}),
        )

    def test_bounded_clock_window_surfaces_a_crossed_transition(self) -> None:
        resource = {
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [
                {
                    "time_ns": "200",
                    "source_sequence": 1,
                    "status": "down",
                    "state": {"reason": "carrier-loss"},
                }
            ],
        }

        result = _status_window_at(
            resource,
            center_ns=200,
            minimum_ns=190,
            maximum_ns=210,
        )

        self.assertIsNone(result["exists"])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["quality"], "ambiguous")
        self.assertEqual(result["temporal_resolution"], "ambiguous")
        self.assertEqual(
            {item["status"] for item in result["possible_states"]},
            {"up", "down"},
        )
        self.assertEqual(
            result["unknown_fields"][0]["reason_code"],
            "clock_window_crosses_state_transition",
        )

    def test_bounded_clock_window_reports_stable_state_when_no_boundary_crosses(
        self,
    ) -> None:
        resource = {
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [{"time_ns": "500", "status": "down"}],
        }

        result = _status_window_at(
            resource,
            center_ns=200,
            minimum_ns=190,
            maximum_ns=210,
        )

        self.assertTrue(result["exists"])
        self.assertEqual(result["status"], "up")
        self.assertEqual(result["quality"], "best_effort")
        self.assertEqual(
            result["temporal_resolution"],
            "stable_within_clock_window",
        )

    def test_validity_only_transition_is_ambiguous(self) -> None:
        resource = {
            "initial_status": "up",
            "initial_state": {"generation": 1},
            "changes": [
                {
                    "time_ns": "200",
                    "source_sequence": 1,
                    "status": "up",
                    "state": {"generation": 1},
                }
            ],
        }

        result = _status_window_at(
            resource,
            center_ns=200,
            minimum_ns=190,
            maximum_ns=210,
        )

        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(
            {
                (item["valid_from_ns"], item["valid_to_ns"])
                for item in result["possible_states"]
            },
            {(None, "200"), ("200", None)},
        )

    def test_uncomparable_state_fails_closed(self) -> None:
        cyclic_state: dict[str, object] = {"generation": 1}
        cyclic_state["cycle"] = cyclic_state

        result = _status_window_at(
            {
                "initial_status": "up",
                "initial_state": cyclic_state,
            },
            center_ns=200,
            minimum_ns=200,
            maximum_ns=200,
        )

        self.assertIsNone(result["exists"])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["temporal_resolution"], "unknown")
        self.assertEqual(
            result["unknown_fields"][0]["reason_code"],
            "state_comparison_unavailable",
        )

    def test_float_nanoseconds_are_rejected_with_existing_error_contract(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            MultiNodeTopologyRequestError,
            "^basis.time_ns must be an integer nanosecond value$",
        ):
            _integer_ns(1.5, "basis.time_ns")


class MultiNodeTopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global _RUNTIME_SESSION
        configure_generated_demo_for_tests()
        cls.runtime_context = generated_demo_runtime_session()
        _RUNTIME_SESSION = cls.runtime_context.__enter__()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        global _RUNTIME_SESSION
        cls.client_context.__exit__(None, None, None)
        cls.runtime_context.__exit__(None, None, None)
        _RUNTIME_SESSION = None

    def test_capabilities_make_generated_plugin_selections_executable(self) -> None:
        response = self.client.get("/v1/topologies/capabilities")
        alias = self.client.get(
            f"/v1/topology-assemblies/{DEMO_TOPOLOGY_ID}/capabilities"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), alias.json())
        payload = response.json()
        self.assertEqual(payload["assembly_id"], DEMO_TOPOLOGY_ID)
        self.assertEqual(payload["deep_links"]["topology"]["route"], "/")
        self.assertEqual(
            urlparse(payload["deep_links"]["topology"]["href"]).path,
            "/",
        )
        self.assertEqual(len(payload["nodes"]), 10)
        active = [item for item in payload["nodes"] if item["default_selected"]]
        self.assertEqual(
            {item["node_id"] for item in active},
            {
                "node-a",
                "node-b",
                "node-c",
                "node-d",
                "node-e",
                "transit-p-1",
                "transit-p-2",
                "ce-west",
                "ce-east",
                "edge-c",
            },
        )
        plugin_sets = {item["active_plugin_set_id"] for item in active}
        self.assertEqual(len(plugin_sets), 10)
        self.assertTrue(all(item["site"] for item in active))
        self.assertTrue(all(item["roles"] for item in active))
        for node in active:
            installed = {
                item["plugin_set_id"]: item
                for item in node["installed_plugin_sets"]
            }
            self.assertIn(node["active_plugin_set_id"], installed)
            providers = {
                (plugin["plugin_id"], projection["projection_id"]): projection
                for plugin in installed[node["active_plugin_set_id"]]["plugins"]
                for projection in plugin["projections"]
            }
            for selection in node["default_projection_selections"]:
                descriptor = providers[
                    (selection["plugin_id"], selection["projection_id"])
                ]
                self.assertIn(
                    selection["status_perspective_id"],
                    descriptor["supported_status_perspective_ids"],
                )
        self.assertTrue(all(item["available"] for item in payload["nodes"]))
        segment_contract = payload["network_segment_contract"]
        self.assertEqual(segment_contract["contract_version"], "1.0")
        self.assertEqual(
            segment_contract["key_encoding"]["form"],
            "recursive_type_tagged_json",
        )
        self.assertTrue(
            segment_contract["attachment_identity"][
                "plugin_run_id_is_provenance_only"
            ]
        )
        self.assertTrue(segment_contract["resource_preview_independent"])
        self.assertEqual(
            segment_contract["presentation"]["default"], "domain_node"
        )
        self.assertTrue(segment_contract["presentation"]["view_only"])
        self.assertIn("TopologyResourceRecord", segment_contract["plugin_record_model"]["segment"])
        self.assertIn("TopologyLinkRecord", segment_contract["plugin_record_model"]["attachment"])
        ownership = payload["semantic_ownership"]
        self.assertTrue(
            any("bounded grouping" in item for item in ownership["core"])
        )
        self.assertTrue(
            any("VLAN, LAG" in item for item in ownership["plugin"])
        )

    def test_generated_segment_projection_models_shared_and_excluded_domains(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={
                "resource_limit": 100,
                "network_segment_limit": 100,
                "segment_attachment_limit": 200,
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        segments = payload["network_segments"]
        attachments = payload["segment_attachments"]
        self.assertEqual(payload["counts"]["network_segments"], len(segments))
        self.assertEqual(
            payload["counts"]["segment_attachments"], len(attachments)
        )

        core_west = next(
            item for item in segments if item["prefix"] == "10.64.0.0/24"
        )
        self.assertEqual(
            set(core_west["node_ids"]),
            {"node-a", "node-d", "transit-p-1", "transit-p-2"},
        )
        self.assertEqual(core_west["existing_node_count"], 4)
        self.assertEqual(core_west["existing_attachment_count"], 4)
        self.assertTrue(core_west["shared_by_multiple_nodes"])
        self.assertFalse(core_west["semantic_conflict"])
        self.assertEqual(
            core_west["topology_presentation"]["two_participant_shape"],
            "domain_node",
        )

        edge = next(
            item for item in segments if item["prefix"] == "10.64.2.0/31"
        )
        self.assertEqual(set(edge["node_ids"]), {"transit-p-2", "node-c"})
        self.assertEqual(edge["existing_node_count"], 2)
        self.assertEqual(edge["existing_attachment_count"], 2)
        self.assertEqual(edge["returned_attachment_count"], 2)
        self.assertEqual(len(edge["members"]), 2)
        self.assertEqual(
            edge["topology_presentation"]["two_participant_shape"],
            "compact_edge",
        )

        alpha_attachment = next(
            item
            for item in core_west["members"]
            if item["node_id"] == "node-a"
        )
        model = alpha_attachment["attachment_model"]
        self.assertEqual(model["kind"], "vlan_subinterface")
        self.assertEqual(model["components"]["vlan_id"], 310)
        self.assertEqual(
            model["components"]["physical_interfaces"], ["Ethernet1/1"]
        )
        self.assertEqual(alpha_attachment["inference"]["owner"], "plugin")
        self.assertTrue(alpha_attachment["evidence"])

        external = next(
            item for item in segments if item["prefix"] == "198.51.100.0/30"
        )
        self.assertEqual(external["role"], "external")
        self.assertEqual(set(external["node_ids"]), {"node-c", "edge-c"})
        self.assertEqual(
            external["topology_presentation"]["two_participant_shape"],
            "compact_edge",
        )

        management = [
            item for item in segments if item["role"] == "management"
        ]
        self.assertEqual(len(management), 10)
        self.assertTrue(
            all(
                not item["connectivity_enabled"]
                and item["presentation_plane"] == "management"
                for item in management
            )
        )
        loopbacks = [item for item in segments if item["role"] == "loopback"]
        self.assertEqual(len(loopbacks), 10)
        self.assertTrue(all(not item["connectivity_enabled"] for item in loopbacks))

        for segment in segments:
            self.assertIn("typed_key", segment["match"])
            self.assertTrue(segment["segment_id"].startswith("network-segment:"))
            self.assertEqual(segment["semantic_owner"], "plugin")

    def test_generated_multihoming_domains_preserve_attachment_components(self) -> None:
        payload = self.client.post(
            "/v1/topologies/query",
            json={
                "resource_limit": 100,
                "network_segment_limit": 100,
                "segment_attachment_limit": 200,
            },
        ).json()
        by_prefix = {
            item["prefix"]: item
            for item in payload["network_segments"]
            if item["prefix"]
        }
        west_access = by_prefix["172.20.10.0/29"]
        east_access = by_prefix["172.20.20.0/29"]
        self.assertEqual(
            set(west_access["node_ids"]), {"node-a", "node-d", "ce-west"}
        )
        self.assertEqual(
            set(east_access["node_ids"]), {"node-b", "node-e", "ce-east"}
        )
        self.assertEqual(west_access["presentation_plane"], "physical")
        self.assertEqual(east_access["presentation_plane"], "physical")
        self.assertTrue(west_access["connectivity_enabled"])
        self.assertTrue(east_access["connectivity_enabled"])
        for segment, lag_id in (
            (west_access, "ae-west-evpn"),
            (east_access, "ae-east-evpn"),
        ):
            self.assertEqual(segment["role"], "evpn_access")
            self.assertEqual(segment["node_count"], 3)
            self.assertTrue(
                all(
                    member["attachment_model"]["kind"] == "lag"
                    and member["attachment_model"]["components"]["lag_id"]
                    == lag_id
                    and member["attachment_model"]["components"][
                        "physical_interfaces"
                    ]
                    for member in segment["members"]
                )
            )

        core_west = by_prefix["10.64.0.0/24"]
        node_a = next(
            item for item in core_west["members"] if item["node_id"] == "node-a"
        )
        self.assertEqual(node_a["attachment_model"]["kind"], "vlan_subinterface")
        self.assertEqual(
            node_a["attachment_model"]["components"]["vlan_id"], 310
        )

    def test_generated_attachment_validity_is_temporal(self) -> None:
        current = self.client.post(
            "/v1/topologies/query",
            json={"resource_limit": 100},
        ).json()
        attachment = next(
            item
            for item in current["segment_attachments"]
            if item["node_id"] == "node-a"
            and item["attachment_model"]["kind"] == "vlan_subinterface"
        )
        valid_from_ns = int(attachment["validity"]["valid_from_ns"])
        before = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "clock_domain": "utc",
                    "time_ns": str(valid_from_ns - 1),
                },
                "resource_limit": 100,
            },
        ).json()
        at_start = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "clock_domain": "utc",
                    "time_ns": str(valid_from_ns),
                },
                "resource_limit": 100,
            },
        ).json()

        def by_id(payload):
            return next(
                item
                for item in payload["segment_attachments"]
                if item["attachment_id"] == attachment["attachment_id"]
            )

        before_attachment = by_id(before)
        active_attachment = by_id(at_start)
        self.assertFalse(before_attachment["claim_valid_at_basis"])
        self.assertFalse(before_attachment["exists"])
        self.assertTrue(active_attachment["claim_valid_at_basis"])
        self.assertTrue(active_attachment["exists"])

    def test_resource_preview_limit_does_not_prune_topology_claims(self) -> None:
        small_preview = self.client.post(
            "/v1/topologies/query",
            json={
                "resource_limit": 1,
                "network_segment_limit": 100,
                "segment_attachment_limit": 200,
                "inter_node_link_limit": 100,
            },
        )
        full_preview = self.client.post(
            "/v1/topologies/query",
            json={
                "resource_limit": 500,
                "network_segment_limit": 100,
                "segment_attachment_limit": 200,
                "inter_node_link_limit": 100,
            },
        )
        self.assertEqual(small_preview.status_code, 200)
        self.assertEqual(full_preview.status_code, 200)
        small = small_preview.json()
        full = full_preview.json()
        self.assertEqual(
            {item["segment_id"] for item in small["network_segments"]},
            {item["segment_id"] for item in full["network_segments"]},
        )
        self.assertEqual(
            {item["attachment_id"] for item in small["segment_attachments"]},
            {item["attachment_id"] for item in full["segment_attachments"]},
        )
        self.assertEqual(
            {item["link_id"] for item in small["inter_node_links"]},
            {item["link_id"] for item in full["inter_node_links"]},
        )
        self.assertLess(
            sum(len(item["resources"]) for item in small["nodes"]),
            sum(len(item["resources"]) for item in full["nodes"]),
        )
        for node in small["nodes"]:
            self.assertLessEqual(len(node["resources"]), 1)
            page = node["counts"]["resource_page"]
            self.assertEqual(page["returned_count"], len(node["resources"]))
            if page["total_count"] is not None:
                self.assertLessEqual(
                    page["returned_count"],
                    page["total_count"],
                )
                self.assertEqual(
                    page["truncated"],
                    page["returned_count"] < page["total_count"],
                )
            for result in node["plugin_results"]:
                counts = result["counts"]["resources"]
                self.assertEqual(
                    counts["returned_count"],
                    len(result["resources"]),
                )
                if counts["total_count"] is not None:
                    self.assertLessEqual(
                        counts["returned_count"],
                        counts["total_count"],
                    )

    def test_mixed_generated_attachment_statuses_are_degraded(self) -> None:
        demo = generated_topology_demo()
        node_d = demo.nodes_by_id["node-d"]
        projection = node_d["plugin_sets"][0]["plugins"][0]["projections"][0]
        claim = next(
            item
            for item in projection["network_segment_claims"]
            if item["segment_key"] == "subnet:core-west-multi-access"
        )
        resource = next(
            item
            for item in projection["resources"]
            if item["resource_id"] == claim["resource_id"]
        )
        resource["initial_status"] = "down"
        resource["changes"] = []

        payload = demo.query(
            {
                "node_ids": [
                    "node-a",
                    "node-d",
                    "transit-p-1",
                    "transit-p-2",
                ]
            }
        )
        core_west = next(
            item
            for item in payload["network_segments"]
            if item["prefix"] == "10.64.0.0/24"
        )
        self.assertEqual(core_west["operational_status"], "degraded")
        self.assertEqual(
            core_west["status_combination_policy"],
            "all_existing_attachments_usable",
        )
        self.assertEqual(
            {
                item["operational_status"]
                for item in core_west["members"]
            },
            {"usable", "unusable"},
        )

    def test_segment_federation_uses_typed_opaque_keys_not_prefixes(self) -> None:
        demo = generated_topology_demo()
        common_semantics = {
            "network_kind": "l3_subnet",
            "label": "same displayed network",
            "role": "transit",
            "routing_scope": {"kind": "vrf", "id": "blue"},
            "address_family": "ipv4",
            "prefix": "203.0.113.0/24",
            "participates_in_connectivity": True,
            "presentation_group": "physical",
            "coverage_complete": True,
        }

        def claim(segment_key: object, index: int) -> dict[str, object]:
            return {
                "matcher_id": "demo.connectivity-domain-key.exact.v1",
                "segment_key": segment_key,
                "resource_id": f"node-a/INTERFACE/{index}",
                "node_id": "node-a",
                "member_id": "member:node-a",
                "revision_id": "test-revision",
                "plugin_set_id": "test-set",
                "plugin_id": "test.plugin",
                "plugin_instance_id": "test-instance",
                "plugin_run_id": "test-run",
                "plugin_version": "1.0",
                "projection_id": "test.projection",
                "status_perspective_id": "test.observed",
                "usable": True,
                "status": "up",
                "exists": True,
                "quality": "exact",
                "resolved_time": {
                    "basis_kind": "absolute_time",
                    "query_time_ns": "1000",
                },
                "deep_link": {"href": f"/node?resource={index}"},
                "plugin_semantics": common_semantics,
                "attachment_model": {},
                "confidence": {"score": 1.0},
                "inference": {"owner": "plugin"},
                "evidence": [],
            }

        segments, attachments, _, truncated, attachments_truncated = (
            demo._assemble_network_segments(
                [claim(1, 1), claim("1", 2), claim("another-domain", 3)],
                10,
                10,
            )
        )
        self.assertEqual(len(segments), 3)
        self.assertEqual(len(attachments), 3)
        self.assertEqual(len({item["segment_id"] for item in segments}), 3)
        self.assertEqual(len({item["match"]["typed_key"] for item in segments}), 3)
        self.assertFalse(truncated)
        self.assertFalse(attachments_truncated)

        identifier = uuid.UUID("7ff7d7dc-88c7-44df-8578-72b049c22500")
        binary = identifier.bytes
        compound_claims = [
            claim((identifier,), 10),
            claim((str(identifier),), 11),
            claim((binary,), 12),
            claim((str(binary),), 13),
        ]
        compound_segments, compound_attachments, compound_resolutions, _, _ = (
            demo._assemble_network_segments(compound_claims, 10, 10)
        )
        self.assertEqual(len(compound_segments), 4)
        self.assertEqual(len({item["segment_id"] for item in compound_segments}), 4)
        self.assertEqual(
            len({item["match"]["typed_key"] for item in compound_segments}),
            4,
        )
        self.assertTrue(
            all(item["segment_key"]["type"] == "tuple" for item in compound_segments)
        )
        json.dumps(
            {
                "segments": compound_segments,
                "attachments": compound_attachments,
                "resolutions": compound_resolutions,
            }
        )

        nested_key = {
            "vrf": "red",
            "members": [{"site": {"rack": "a"}}],
        }
        source_claim = claim(nested_key, 20)
        source_claim.update(
            {
                "claim_valid_at_basis": True,
                "endpoint_exists_at_basis": True,
            }
        )
        target_claim = claim(nested_key, 21)
        target_claim.update(
            {
                "node_id": "node-b",
                "member_id": "member:node-b",
                "resource_id": "node-b/INTERFACE/21",
                "claim_valid_at_basis": True,
                "endpoint_exists_at_basis": True,
            }
        )
        runtime_segments, runtime_attachments, _, _, _ = (
            demo._assemble_network_segments(
                [source_claim, target_claim],
                10,
                10,
            )
        )
        self.assertEqual(len(runtime_segments), 1)
        runtime_segment = runtime_segments[0]
        binding = resolve_connectivity_domain_reference(
            {
                "network_segments": runtime_segments,
                "segment_attachments": runtime_attachments,
                "completeness": {
                    "network_segments_truncated": False,
                    "segment_attachments_truncated": False,
                },
            },
            {
                "reference_kind": "connectivity_domain",
                "match": {
                    "matcher_id": runtime_segment["match"]["matcher_id"],
                    "matcher_contract_version": runtime_segment["match"][
                        "matcher_contract_version"
                    ],
                    "arguments": {
                        "segment_key": runtime_segment["match"]["segment_key"],
                    },
                },
            },
            source_node_id="node-a",
            target_node_id="node-b",
            source_resource_id="node-a/INTERFACE/20",
            target_resource_id="node-b/INTERFACE/21",
        )
        self.assertTrue(binding.resolved)

        stable_claim = claim("stable-attachment", 14)
        _, first_attachments, _, _, _ = demo._assemble_network_segments(
            [stable_claim], 10, 10
        )
        rerun_claim = dict(stable_claim)
        rerun_claim["plugin_run_id"] = "test-run-2"
        _, rerun_attachments, _, _, _ = demo._assemble_network_segments(
            [rerun_claim], 10, 10
        )
        self.assertEqual(
            first_attachments[0]["attachment_id"],
            rerun_attachments[0]["attachment_id"],
        )

        unknown_claim = claim("unknown", 4)
        unknown_claim["matcher_id"] = "undeclared.matcher"
        unknown_segments, unknown_attachments, resolutions, _, _ = (
            demo._assemble_network_segments([unknown_claim], 10, 10)
        )
        self.assertEqual(unknown_segments, [])
        self.assertEqual(unknown_attachments, [])
        self.assertEqual(
            resolutions[0]["resolution"], "unsupported_matcher_contract"
        )

        node_a_underlay = demo.contract["nodes"][0]["plugin_sets"][0]["plugins"][0][
            "projections"
        ][0]
        node_a_underlay["network_segment_claims"][0][
            "matcher_id"
        ] = "undeclared.matcher"
        result = demo.query({"node_ids": ["node-a"]})
        unresolved = result["completeness"]["unresolved_network_segment_claims"]
        self.assertFalse(result["complete"])
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(
            unresolved[0]["reason_code"],
            "matcher_not_declared_as_exact_connectivity_domain",
        )

    def test_segment_semantics_use_strict_bounded_comparison(self) -> None:
        demo = generated_topology_demo()
        matcher_id = demo.contract["network_segment_matchers"][0][
            "matcher_id"
        ]

        def claim(
            node_id: str,
            index: int,
            semantics: object,
        ) -> dict[str, object]:
            return {
                "matcher_id": matcher_id,
                "segment_key": "strict-semantic-domain",
                "resource_id": f"{node_id}/INTERFACE/{index}",
                "node_id": node_id,
                "member_id": f"member:{node_id}",
                "revision_id": "test-revision",
                "plugin_set_id": "test-set",
                "plugin_id": "test.plugin",
                "plugin_instance_id": "test-instance",
                "plugin_run_id": f"test-run-{index}",
                "plugin_version": "1.0",
                "projection_id": "test.projection",
                "status_perspective_id": "test.observed",
                "usable": True,
                "status": "up",
                "exists": True,
                "quality": "exact",
                "resolved_time": {
                    "basis_kind": "absolute_time",
                    "query_time_ns": "1000",
                },
                "deep_link": {"href": f"/node?resource={index}"},
                "plugin_semantics": semantics,
                "attachment_model": {},
                "confidence": {"score": 1.0},
                "inference": {"owner": "plugin"},
                "evidence": [],
            }

        semantics = {
            "network_kind": 1,
            "role": "plugin-owned-transit",
            "coverage_complete": True,
        }
        differently_typed = {
            **semantics,
            "network_kind": "1",
        }
        segments, _attachments, _resolutions, _truncated, _attachments_truncated = (
            demo._assemble_network_segments(
                [
                    claim("node-a", 1, semantics),
                    claim("node-b", 2, differently_typed),
                ],
                10,
                10,
            )
        )
        self.assertEqual(len(segments), 1)
        self.assertTrue(segments[0]["semantic_conflict"])
        self.assertEqual(
            segments[0]["semantic_conflicts"]["network_kind"],
            [1, "1"],
        )

        cyclic: list[object] = []
        cyclic.append(cyclic)
        invalid_semantics = (
            {"network_kind": b"not-json"},
            {"network_kind": object()},
            {"network_kind": float("nan")},
            {"network_kind": UserDict({"value": 1})},
            {"network_kind": list(range(1_025))},
            {"network_kind": cyclic},
        )
        for index, invalid in enumerate(invalid_semantics, start=10):
            with self.subTest(
                invalid=type(invalid["network_kind"]).__name__
            ), self.assertRaisesRegex(
                MultiNodeTopologyRequestError,
                "plugin_semantics is not safely comparable",
            ):
                demo._assemble_network_segments(
                    [claim("node-a", index, invalid)],
                    10,
                    10,
                )

    def test_only_declared_external_role_has_core_semantics(self) -> None:
        demo = generated_topology_demo()
        matcher_id = demo.contract["network_segment_matchers"][0][
            "matcher_id"
        ]

        def claim(
            segment_key: str,
            role: object,
            coverage_complete: object,
        ) -> dict[str, object]:
            return {
                "matcher_id": matcher_id,
                "segment_key": segment_key,
                "resource_id": f"node-a/INTERFACE/{segment_key}",
                "node_id": "node-a",
                "member_id": "member:node-a",
                "revision_id": "test-revision",
                "plugin_set_id": "test-set",
                "plugin_id": "test.plugin",
                "plugin_instance_id": "test-instance",
                "plugin_run_id": "test-run",
                "plugin_version": "1.0",
                "projection_id": "test.projection",
                "status_perspective_id": "test.observed",
                "usable": True,
                "status": "up",
                "exists": True,
                "quality": "exact",
                "resolved_time": {
                    "basis_kind": "absolute_time",
                    "query_time_ns": "1000",
                },
                "deep_link": {"href": "/node"},
                "plugin_semantics": {
                    "network_kind": "plugin-owned-kind",
                    "role": role,
                    "coverage_complete": coverage_complete,
                },
                "attachment_model": {},
                "confidence": {"score": 1.0},
                "inference": {"owner": "plugin"},
                "evidence": [],
            }

        segments, _attachments, _resolutions, _truncated, _attachments_truncated = (
            demo._assemble_network_segments(
                [
                    claim(
                        "plugin-owned",
                        "vendor-private-transit",
                        True,
                    ),
                    claim("external", "external", True),
                ],
                10,
                10,
            )
        )
        by_key = {item["segment_key"]["value"]: item for item in segments}
        plugin_owned = by_key["plugin-owned"]
        self.assertEqual(
            plugin_owned["role"],
            "vendor-private-transit",
        )
        self.assertFalse(plugin_owned["plugin_asserted_external"])
        self.assertTrue(by_key["external"]["plugin_asserted_external"])

        malformed_values = (
            ("invalid-role", 7, True),
            ("invalid-coverage", "external", "yes"),
        )
        for segment_key, role, coverage in malformed_values:
            with self.subTest(
                segment_key=segment_key
            ), self.assertRaisesRegex(
                MultiNodeTopologyRequestError,
                "invalid plugin_semantics",
            ):
                demo._assemble_network_segments(
                    [claim(segment_key, role, coverage)],
                    10,
                    10,
                )

    def test_default_physical_graph_is_connected_but_not_a_full_mesh(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={"link_limit": 100, "resource_preview_limit": 100},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        active_nodes = {
            item["node_id"] for item in payload["nodes"] if item["available"]
        }
        endpoint_pairs = {
            frozenset((left, right))
            for segment in payload["network_segments"]
            if segment["connectivity_enabled"]
            for left, right in combinations(segment["node_ids"], 2)
        }
        self.assertEqual(len(active_nodes), 10)
        connectivity_segment_count = sum(
            1
            for item in payload["network_segments"]
            if item["connectivity_enabled"]
        )
        self.assertGreater(connectivity_segment_count, 0)
        self.assertLess(
            connectivity_segment_count,
            len(active_nodes) * (len(active_nodes) - 1) // 2,
        )
        self.assertLess(
            len(endpoint_pairs), len(active_nodes) * (len(active_nodes) - 1) // 2
        )
        adjacency = {node_id: set() for node_id in active_nodes}
        for left, right in (tuple(item) for item in endpoint_pairs):
            adjacency[left].add(right)
            adjacency[right].add(left)
        reached = {next(iter(active_nodes))}
        frontier = list(reached)
        while frontier:
            current = frontier.pop()
            for neighbor in adjacency[current] - reached:
                reached.add(neighbor)
                frontier.append(neighbor)
        self.assertEqual(reached, active_nodes)

    def test_absolute_query_federates_generated_projections_and_deep_links(self) -> None:
        capabilities = self.client.get("/v1/topologies/capabilities").json()
        nodes = {item["node_id"]: item for item in capabilities["nodes"]}

        def node_query(node_id: str) -> dict[str, object]:
            node = nodes[node_id]
            selection = node["default_projection_selections"][0]
            return {
                "node_id": node_id,
                "plugin_set_id": node["active_plugin_set_id"],
                "projections": [selection],
            }

        body = {
            "basis": {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": "1759680003030000000",
            },
            "clock_policy": "best_effort",
            "node_queries": [
                node_query(node_id)
                for node_id in ("node-a", "node-b", "transit-p-1")
            ],
        }
        response = self.client.post("/v1/topologies/reconstruct", json=body)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["context_id"].startswith("tctx1-"))
        self.assertEqual(payload["deep_links"]["self"]["route"], "/")
        self.assertEqual(
            urlparse(payload["deep_links"]["self"]["href"]).path,
            "/",
        )
        self.assertTrue(payload["deep_links"]["individual_nodes"])
        for deep_link in payload["deep_links"]["individual_nodes"]:
            self.assertEqual(deep_link["route"], "/node")
            parsed = urlparse(deep_link["href"])
            self.assertEqual(parsed.path, "/node")
            self.assertEqual(parsed.fragment, "temporal-topology")
        self.assertEqual(payload["resolved_basis"]["kind"], "absolute_time")
        self.assertEqual(
            {item["plugin_set_id"] for item in payload["nodes"]},
            {
                "node-a.generated.v1",
                "node-b.generated.v1",
                "transit-p-1.generated.v1",
            },
        )
        self.assertEqual(payload["inter_node_links"], [])
        self.assertTrue(payload["network_segments"])
        self.assertTrue(
            all(
                observation["simultaneity"] == "same_absolute_instant"
                for segment in payload["network_segments"]
                for observation in segment["time_alignment"][
                    "attachment_observations"
                ]
            )
        )
        resource = payload["nodes"][0]["resources"][0]
        self.assertEqual(resource["resource_ref"]["member_id"], "member:node-a")
        self.assertEqual(
            resource["resource_ref"]["revision_id"],
            nodes["node-a"]["revision_id"],
        )
        parameters = parse_qs(urlparse(resource["deep_link"]["href"]).query)
        parsed_resource_link = urlparse(resource["deep_link"]["href"])
        self.assertEqual(parsed_resource_link.path, "/node")
        self.assertEqual(parsed_resource_link.fragment, "timeline")
        self.assertEqual(resource["deep_link"]["route"], "/node")
        self.assertEqual(parameters["plugin_set_id"], ["node-a.generated.v1"])
        self.assertEqual(
            parameters["projection_id"], ["node-a.generated-topology"]
        )
        self.assertEqual(
            parameters["status_perspective_id"],
            ["node-a.generated-observed"],
        )
        self.assertEqual(parameters["context_id"], [payload["context_id"]])

    def test_generated_segment_ids_are_stable_across_node_order(self) -> None:
        node_ids = ("node-a", "transit-p-1", "node-b")
        segment_sets: list[set[str]] = []
        attachment_maps: list[dict[tuple[tuple[str, str], ...], str]] = []
        for node_order in permutations(node_ids):
            response = self.client.post(
                "/v1/topologies/query",
                json={
                    "node_ids": list(node_order),
                    "network_segment_limit": 100,
                    "segment_attachment_limit": 200,
                },
            )
            self.assertEqual(response.status_code, 200)
            segments = response.json()["network_segments"]
            segment_ids = [item["segment_id"] for item in segments]
            self.assertEqual(len(segment_ids), len(set(segment_ids)))
            segment_sets.append(set(segment_ids))
            attachment_maps.append(
                {
                    tuple(
                        sorted(
                            (member["node_id"], member["resource_id"])
                            for member in item["members"]
                        )
                    ): item["segment_id"]
                    for item in segments
                }
            )

        self.assertTrue(
            all(item == segment_sets[0] for item in segment_sets[1:])
        )
        self.assertTrue(
            all(item == attachment_maps[0] for item in attachment_maps[1:])
        )
        shared = next(
            segment_id
            for endpoints, segment_id in attachment_maps[0].items()
            if {node_id for node_id, _ in endpoints}
            == {"node-a", "transit-p-1"}
        )
        self.assertTrue(shared.startswith("network-segment:"))
        primary_endpoints = next(
            endpoints
            for endpoints, segment_id in attachment_maps[0].items()
            if segment_id == shared
        )
        self.assertEqual(
            {node_id for node_id, _ in primary_endpoints},
            {"node-a", "transit-p-1"},
        )

    def test_asymmetric_route_trace_roles_fail_closed(self) -> None:
        demo = generated_topology_demo()

        def claim(
            node_id: str,
            role: str,
            *,
            link_type: str = "ethernet",
        ) -> dict[str, object]:
            return {
                "matcher_id": "test.connector.exact.v1",
                "match_key": "shared-key",
                "member_id": f"member:{node_id}",
                "node_id": node_id,
                "revision_id": "test-revision",
                "resource_id": f"{node_id}/INTERFACE/1",
                "plugin_set_id": f"{node_id}.set",
                "plugin_id": f"test.{node_id}",
                "plugin_instance_id": f"test.{node_id}.instance",
                "plugin_run_id": f"test.{node_id}.run",
                "plugin_version": "1.0",
                "projection_id": f"test.{node_id}.projection",
                "status_perspective_id": f"test.{node_id}.observed",
                "link_type": link_type,
                "directed": False,
                "combination_policy": "all_claims_usable",
                "presentation": {"route_trace": role},
                "usable": True,
                "status": "up",
                "exists": True,
                "resolved_time": {
                    "basis_kind": "absolute_time",
                    "query_time_ns": "1000",
                },
                "deep_link": {"href": f"/node?node_id={node_id}"},
            }

        links, _resolutions, _unmatched, _truncated = demo._join_claims(
            [claim("node-a", "overlay"), claim("node-b", "include")],
            10,
            "test-context",
        )
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["presentation"]["route_trace"], "conflict")
        self.assertEqual(link["projection_role"], "presentation_conflict")
        self.assertEqual(link["operational"]["status"], "unknown")
        self.assertEqual(
            link["operational"]["reason"],
            "plugin_route_trace_role_mismatch",
        )

        script = self.client.get("/assets/topology.js").text
        self.assertIn('routeTraceRole === "include"', script)

        type_links, _resolutions, _unmatched, _truncated = (
            demo._join_claims(
                [
                    claim(
                        "node-a",
                        "include",
                        link_type="ethernet",
                    ),
                    claim(
                        "node-b",
                        "include",
                        link_type="optical",
                    ),
                ],
                10,
                "test-context",
            )
        )
        self.assertEqual(len(type_links), 1)
        type_conflict = type_links[0]
        self.assertEqual(type_conflict["link_type"], "unknown")
        self.assertEqual(
            type_conflict["claimed_link_types"],
            ["ethernet", "optical"],
        )
        self.assertEqual(
            type_conflict["operational"]["reason"],
            "plugin_link_type_mismatch",
        )

        for invalid in ("mirror", "conflict"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                MultiNodeTopologyRequestError,
                "invalid inter-node presentation",
            ):
                demo._join_claims(
                    [
                        claim("node-a", invalid),
                        claim("node-b", "include"),
                    ],
                    10,
                    "test-context",
                )
        malformed = claim("node-a", "include")
        malformed["presentation"] = ["include"]
        with self.assertRaisesRegex(
            MultiNodeTopologyRequestError,
            "invalid inter-node presentation",
        ):
            demo._join_claims(
                [malformed, claim("node-b", "include")],
                10,
                "test-context",
            )

    def test_inter_node_join_uses_typed_bounded_exact_matching(self) -> None:
        demo = generated_topology_demo()

        def claim(
            node_id: str,
            match_key: object,
            resource_suffix: str,
        ) -> dict[str, object]:
            return {
                "matcher_id": "test.connector.exact.v1",
                "match_key": match_key,
                "member_id": f"member:{node_id}",
                "node_id": node_id,
                "revision_id": "test-revision",
                "resource_id": f"{node_id}/INTERFACE/{resource_suffix}",
                "plugin_set_id": f"{node_id}.set",
                "plugin_id": f"test.{node_id}",
                "plugin_instance_id": f"test.{node_id}.instance",
                "plugin_run_id": f"test.{node_id}.run",
                "plugin_version": "1.0",
                "projection_id": f"test.{node_id}.projection",
                "status_perspective_id": f"test.{node_id}.observed",
                "link_type": "ethernet",
                "directed": False,
                "combination_policy": "all_claims_usable",
                "presentation": {"route_trace": "include"},
                "usable": True,
                "status": "up",
                "exists": True,
                "resolved_time": {
                    "basis_kind": "absolute_time",
                    "query_time_ns": "1000",
                },
                "deep_link": {"href": f"/node?node_id={node_id}"},
            }

        links, resolutions, unmatched, truncated = demo._join_claims(
            [
                claim("node-a", "1", "string"),
                claim("node-b", "1", "string"),
                claim("node-a", 1, "integer"),
                claim("node-b", 1, "integer"),
                claim("node-c", "ambiguous", "first"),
                claim("node-a", "ambiguous", "second"),
                claim("node-b", "ambiguous", "third"),
                claim("node-a", "local-only", "unmatched"),
            ],
            100,
            "test-context",
        )

        self.assertFalse(truncated)
        self.assertEqual(len(links), 5)
        self.assertEqual(len({link["link_id"] for link in links}), 5)
        by_key = {
            (item["match_key"], item["candidate_count"]): item
            for item in resolutions
        }
        self.assertTrue(
            {item["resolution"] for item in resolutions}.issubset(
                {state.value for state in FederationMatchState}
            )
        )
        self.assertEqual(by_key[("ambiguous", 3)]["resolution"], "ambiguous")
        self.assertEqual(by_key[("local-only", 0)]["resolution"], "unresolved")
        self.assertEqual(len(unmatched), 1)
        # String "1" and integer 1 have the same display text but remain two
        # exact-match groups and therefore never create cross-type candidates.
        self.assertEqual(
            sum(
                item["candidate_count"]
                for item in resolutions
                if item["match_key"] == "1"
            ),
            2,
        )

        limited_links, limited_resolutions, _unmatched, limited = (
            demo._join_claims(
                [
                    claim("node-c", "ambiguous", "first"),
                    claim("node-a", "ambiguous", "second"),
                    claim("node-b", "ambiguous", "third"),
                ],
                1,
                "test-context",
            )
        )
        self.assertTrue(limited)
        self.assertEqual(len(limited_links), 1)
        self.assertEqual(limited_resolutions[0]["candidate_count"], 3)

    def test_topology_basis_is_strict_and_canonical(self) -> None:
        time_ns = 1_759_680_005_000_000_000
        absolute_requests = (
            {"kind": "absolute_time", "time_ns": time_ns},
            {
                "kind": "absolute_time",
                "timestamp_ns": str(time_ns),
                "clock_domain": "utc",
            },
        )
        absolute_payloads = [
            self.client.post(
                "/v1/topologies/query",
                json={"node_ids": ["node-a"], "basis": basis},
            ).json()
            for basis in absolute_requests
        ]
        self.assertEqual(
            absolute_payloads[0]["context_id"],
            absolute_payloads[1]["context_id"],
        )
        self.assertEqual(
            absolute_payloads[0]["resolved_basis"]["requested"],
            {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": str(time_ns),
            },
        )

        relative_payloads = [
            self.client.post(
                "/v1/topologies/query",
                json={"node_ids": ["node-a"], "basis": basis},
            ).json()
            for basis in (
                {"kind": "relative_to_scope_end"},
                {"kind": "relative_to_watermark", "offset_ns": "0"},
            )
        ]
        self.assertEqual(
            relative_payloads[0]["context_id"],
            relative_payloads[1]["context_id"],
        )
        self.assertEqual(
            relative_payloads[0]["resolved_basis"]["requested"],
            {"kind": "relative_to_watermark", "offset_ns": "0"},
        )

        for invalid_basis in ([], "", 0, False, None):
            with self.subTest(invalid_basis=invalid_basis):
                response = self.client.post(
                    "/v1/topologies/query",
                    json={"node_ids": ["node-a"], "basis": invalid_basis},
                )
                self.assertEqual(response.status_code, 422)
        per_node_invalid = self.client.post(
            "/v1/topologies/query",
            json={
                "node_queries": [
                    {"node_id": "node-a", "basis": []},
                ]
            },
        )
        self.assertEqual(per_node_invalid.status_code, 422)
        invalid_integer_shapes = (
            {"kind": "absolute_time", "time_ns": time_ns + 0.5},
            {"kind": "absolute_time", "time_ns": True},
            {"kind": "absolute_time", "time_ns": f" {time_ns}"},
            {"kind": "relative_to_watermark", "offset_ns": -0.5},
            {"kind": "relative_to_watermark", "offset_ns": False},
            {"kind": "relative_to_watermark", "offset_ns": "- 1"},
        )
        for basis in invalid_integer_shapes:
            with self.subTest(basis=basis):
                response = self.client.post(
                    "/v1/topologies/query",
                    json={"node_ids": ["node-a"], "basis": basis},
                )
                self.assertEqual(response.status_code, 422, response.text)

    def test_node_id_selector_rejects_empty_duplicate_and_conflicting_forms(self) -> None:
        invalid_requests = (
            {"node_ids": []},
            {"node_ids": ["node-a", "node-a"]},
            {
                "node_ids": ["node-a"],
                "node_queries": [{"node_id": "node-b"}],
            },
        )
        for request in invalid_requests:
            with self.subTest(request=request):
                response = self.client.post(
                    "/v1/topologies/query", json=request
                )
                self.assertEqual(response.status_code, 422)

    def test_relative_query_uses_projection_scoped_watermarks(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "-10000000",
                }
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["resolved_basis"]["kind"], "relative_capture_vector"
        )
        self.assertEqual(payload["resolved_basis"]["simultaneity"], "not_implied")
        resolved = [
            item
            for node in payload["nodes"]
            for item in node["resolved_times"]
        ]
        self.assertGreater(len({item["local_time_ns"] for item in resolved}), 1)
        self.assertEqual(
            len({item["local_clock_domain"] for item in resolved}),
            len(resolved),
        )
        for item in resolved:
            scope = item["watermark_scope"]
            self.assertTrue(scope["member_id"].startswith("member:"))
            self.assertTrue(scope["plugin_run_id"].startswith("run:"))
            self.assertIn("plugin_set_id", scope)
            self.assertIn("projection_id", scope)
            self.assertIn("status_perspective_id", scope)

    def test_declared_local_watermark_does_not_require_node_clock(
        self,
    ) -> None:
        original = generated_topology_demo()
        contract = json.loads(json.dumps(original.contract))
        node = next(
            item for item in contract["nodes"] if item["node_id"] == "node-a"
        )
        node["clock"] = None
        plugin = node["plugin_sets"][0]["plugins"][0]
        projection = plugin["projections"][0]
        selection = {
            "plugin_id": plugin["plugin_id"],
            "projection_id": projection["projection_id"],
            "status_perspective_id": projection[
                "default_status_perspective_id"
            ],
        }
        perspective_id = selection["status_perspective_id"]
        projection_id = selection["projection_id"]
        local_watermark = original.capture_ns - 1_000_000
        watermark = {
            "local_time_ns": str(local_watermark),
            "clock_domain": "node-a-local",
            "mapping_method": "plugin_sequence_anchor",
            "quality": "exact",
            "complete": True,
        }
        node["watermarks"] = {
            perspective_id: {projection_id: watermark}
        }
        service = MultiNodeTopologyService(
            contract=contract,
            topology_profiles=original.topology_profiles,
            topology_metadata=original.topology_metadata,
        )
        request = {
            "basis": {
                "kind": "relative_to_watermark",
                "offset_ns": "-100",
            },
            "clock_policy": "strict",
            "node_queries": [
                {
                    "node_id": "node-a",
                    "plugin_set_id": node["active_plugin_set_id"],
                    "projections": [selection],
                }
            ],
        }

        payload = service.query(request)
        resolved = payload["nodes"][0]["resolved_times"][0]

        self.assertEqual(resolved["resolution"], "local_exact")
        self.assertEqual(
            resolved["local_time_ns"],
            str(local_watermark - 100),
        )
        self.assertIsNone(resolved["query_time_ns"])
        self.assertIsNone(resolved["absolute_min_ns"])
        self.assertEqual(
            resolved["watermark_source"],
            "projection_declaration",
        )
        self.assertTrue(payload["nodes"][0]["plugin_results"])

        watermark.update(
            {
                "absolute_min_ns": str(original.capture_ns - 9),
                "absolute_max_ns": str(original.capture_ns + 11),
                "quality": "bounded",
            }
        )
        bounded = service.query(request)["nodes"][0]["resolved_times"][0]
        self.assertEqual(bounded["resolution"], "bounded")
        self.assertEqual(bounded["uncertainty_ns"], "10")
        self.assertEqual(
            bounded["absolute_min_ns"],
            str(original.capture_ns - 109),
        )
        self.assertEqual(
            bounded["absolute_max_ns"],
            str(original.capture_ns - 89),
        )

    def test_generated_member_is_not_silently_dropped(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={
                "node_ids": ["edge-c"],
                "clock_policy": "best_effort",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["completeness"]["incomplete_nodes"], [])
        node = payload["nodes"][0]
        self.assertEqual(node["node_id"], "edge-c")
        self.assertTrue(node["complete"])
        self.assertEqual(
            node["plugin_set_id"],
            "edge-c.generated.v1",
        )

    def test_generated_demo_executes_typed_connector_claims_through_core(self) -> None:
        response = self.client.post("/v1/topologies/query", json={})
        self.assertEqual(response.status_code, 200)
        payload = response.json()

        service = generated_topology_demo()
        self.assertTrue(
            all(
                "typed_topology_projection" not in plugin
                for node in service.contract["nodes"]
                for plugin_set in node["plugin_sets"]
                for plugin in plugin_set["plugins"]
            )
        )

        self.assertGreater(payload["counts"]["typed_connector_claims"], 0)
        self.assertEqual(
            payload["counts"]["unresolved_typed_connector_claims"],
            0,
        )
        typed_links = [
            link
            for link in payload["inter_node_links"]
            if link["link_id"].startswith("typed-federation:")
        ]
        self.assertTrue(typed_links)
        self.assertTrue(
            all(
                link["inference"]["owner"] == "core_exact_matcher"
                and link["inference"]["linker_plugin_id"] is None
                for link in typed_links
            )
        )
        self.assertTrue(payload["completeness"]["typed_federation_complete"])

    def test_single_member_query_preserves_single_sided_segment_claims(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={"node_ids": ["node-a"], "link_limit": 20},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["inter_node_links"], [])
        self.assertEqual(payload["connector_resolutions"], [])
        self.assertTrue(payload["network_segments"])
        self.assertTrue(
            all(
                set(item["node_ids"]).issubset({"node-a"})
                for item in payload["network_segments"]
            )
        )

    def test_context_member_and_node_query_preserve_navigation_context(self) -> None:
        reconstruction = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680005000000000",
                }
            },
        ).json()
        context_id = reconstruction["context_id"]
        member = self.client.get(
            f"/v1/topology-contexts/{context_id}/members/member:node-a"
        )
        self.assertEqual(member.status_code, 200)
        self.assertEqual(member.json()["member"]["node_id"], "node-a")

        node = self.client.post(
            "/v1/topologies/nodes/node-b/query",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680005000000000",
                },
                "plugin_set_id": "node-b.generated.v1",
                "plugin_id": "demo.example-router",
                "projection_id": "node-b.generated-topology",
                "status_perspective_id": "node-b.generated-observed",
            },
        )
        self.assertEqual(node.status_code, 200)
        self.assertEqual(node.json()["node"]["node_id"], "node-b")
        href = node.json()["navigation"]["individual_node"]["href"]
        self.assertIn("plugin_set_id=node-b.generated.v1", href)
        self.assertIn("projection_id=node-b.generated-topology", href)

    def test_relative_node_deep_link_round_trips_without_absolute_time(self) -> None:
        offset_ns = "-1000000"
        response = self.client.post(
            "/v1/topologies/nodes/node-a/query",
            json={
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": offset_ns,
                }
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        href = payload["navigation"]["individual_node"]["href"]
        query = parse_qs(urlparse(href).query)

        self.assertEqual(query["basis_kind"], ["relative_to_watermark"])
        self.assertEqual(query["basis_offset_ns"], [offset_ns])
        self.assertNotIn("time_ns", query)
        self.assertNotIn("offset_ns", query)

        workspace = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={
                key: values[-1]
                for key, values in query.items()
                if key
                in {
                    "plugin_set_id",
                    "plugin_id",
                    "projection_id",
                    "status_perspective_id",
                    "basis_kind",
                    "basis_offset_ns",
                }
            },
        )
        self.assertEqual(workspace.status_code, 200, workspace.text)
        self.assertEqual(
            workspace.json()["node_snapshot"]["basis"],
            {
                "kind": "relative_to_watermark",
                "time_ns": None,
                "offset_ns": offset_ns,
                "clock_domain": "utc",
                "clock_policy": "best_effort",
            },
        )

    def test_frontend_preserves_relative_node_link_as_relative_when_enriching_it(
        self,
    ) -> None:
        offset_ns = "-2000000"
        response = self.client.post(
            "/v1/topologies/nodes/node-a/query",
            json={
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": offset_ns,
                }
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        href = payload["navigation"]["individual_node"]["href"]
        resolved_time = payload["node"]["resolved_time"]["query_time_ns"]
        script = self.client.get("/assets/topology.js").text
        helper = javascript_function(script, "applyNodeNavigationBasis")
        probe = (
            helper
            + "\n"
            + f"const target = new URL({json.dumps(href)}, 'http://127.0.0.1');\n"
            + "applyNodeNavigationBasis("
            + "target, "
            + json.dumps(
                {
                    "kind": "relative_to_watermark",
                    "queryTime": resolved_time,
                }
            )
            + ", "
            + json.dumps(
                {
                    "kind": "relative_to_watermark",
                    "offset_ns": offset_ns,
                }
            )
            + ");\n"
            + "process.stdout.write(target.pathname + target.search + target.hash);\n"
        )
        completed = subprocess.run(
            ["node", "-e", probe],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        enriched_href = completed.stdout
        query = parse_qs(urlparse(enriched_href).query)

        self.assertEqual(query["basis_kind"], ["relative_to_watermark"])
        self.assertEqual(query["basis_offset_ns"], [offset_ns])
        self.assertNotIn("time_ns", query)
        self.assertNotIn("offset_ns", query)

        workspace = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={
                key: values[-1]
                for key, values in query.items()
                if key
                in {
                    "plugin_set_id",
                    "plugin_id",
                    "projection_id",
                    "status_perspective_id",
                    "basis_kind",
                    "basis_offset_ns",
                }
            },
        )
        self.assertEqual(workspace.status_code, 200, workspace.text)

    def test_absolute_node_deep_link_round_trips_without_relative_offset(self) -> None:
        time_ns = "1759680005000000000"
        response = self.client.post(
            "/v1/topologies/nodes/node-a/query",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": time_ns,
                }
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        href = response.json()["navigation"]["individual_node"]["href"]
        query = parse_qs(urlparse(href).query)

        self.assertEqual(query["basis_kind"], ["absolute_time"])
        self.assertEqual(query["time_ns"], [time_ns])
        self.assertNotIn("basis_offset_ns", query)
        self.assertNotIn("offset_ns", query)

        workspace = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={
                key: values[-1]
                for key, values in query.items()
                if key
                in {
                    "plugin_set_id",
                    "plugin_id",
                    "projection_id",
                    "status_perspective_id",
                    "basis_kind",
                    "time_ns",
                }
            },
        )
        self.assertEqual(workspace.status_code, 200, workspace.text)
        self.assertEqual(
            workspace.json()["node_snapshot"]["basis"]["time_ns"],
            time_ns,
        )

    def test_invalid_cross_node_projection_selection_is_rejected(self) -> None:
        response = self.client.post(
            "/v1/topologies/query",
            json={
                "node_queries": [
                    {
                        "node_id": "node-a",
                        "plugin_set_id": "node-a.generated.v1",
                        "projections": [
                            {
                                "plugin_id": "demo.example-router",
                                "projection_id": "node-b.generated-topology",
                            }
                        ],
                    }
                ]
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_page_style_flat_node_plans_and_limit_aliases_are_supported(self) -> None:
        capabilities = self.client.get("/v1/topologies/capabilities").json()
        nodes = {item["node_id"]: item for item in capabilities["nodes"]}
        plans = []
        for node_id in ("node-a", "node-b", "transit-p-1", "edge-c"):
            node = nodes[node_id]
            selection = node["default_projection_selections"][0]
            plans.append(
                (
                    node_id,
                    node["revision_id"],
                    node["active_plugin_set_id"],
                    selection["projection_id"],
                    selection["status_perspective_id"],
                )
            )
        response = self.client.post(
            "/v1/topologies/reconstruct",
            json={
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680005000000000",
                },
                "node_queries": [
                    {
                        "member_id": f"member:{node_id}",
                        "node_id": node_id,
                        "revision_id": revision_id,
                        "plugin_set_id": plugin_set_id,
                        "projection_id": projection_id,
                        "status_perspective_id": perspective_id,
                    }
                    for (
                        node_id,
                        revision_id,
                        plugin_set_id,
                        projection_id,
                        perspective_id,
                    ) in plans
                ],
                "resource_preview_limit": 20,
                "link_limit": 20,
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["nodes"]), 4)
        self.assertEqual(payload["counts"]["inter_node_links"], 0)
        self.assertGreater(payload["counts"]["network_segments"], 0)
        self.assertEqual(
            payload["nodes"][0]["node_query"]["projection_id"],
            "node-a.generated-topology",
        )

    def test_topology_page_is_primary_and_former_route_remains_an_alias(self) -> None:
        primary = self.client.get("/?basis_kind=relative_to_watermark")
        alias = self.client.get("/topology?basis_kind=relative_to_watermark")
        node = self.client.get("/node?node_id=node-a")

        self.assertEqual(primary.status_code, 200)
        self.assertEqual(alias.status_code, 200)
        self.assertEqual(node.status_code, 200)
        self.assertIn("Multi-node topology", primary.text)
        self.assertEqual(primary.text, alias.text)
        self.assertIn("single-node analysis workspace", node.text)
        self.assertIn("20260728-reconstruction-selector-v37", primary.text)
        self.assertIn("control-plane only / not installed", primary.text)
        topology_script = self.client.get("/assets/topology.js")
        topology_styles = self.client.get("/assets/topology.css")
        self.assertIn("pathIsControlPlaneOnly", topology_script.text)
        self.assertIn("Control-plane route is not installed", topology_script.text)
        self.assertIn("NO FIB / not installed", topology_script.text)
        self.assertIn("is-control-plane-only", topology_styles.text)
        for response in (primary, alias, node):
            self.assertIn("no-store", response.headers["cache-control"])

    def test_route_table_renders_searchable_plugin_declared_forwarding_actions(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertIn("Forwarding actions", script.text)
        self.assertIn('colspan="9"', script.text)
        self.assertIn("forwarding action", page.text)
        normalizer = javascript_function(
            script.text, "normalizeRouteForwardingActions"
        )
        for contract in (
            "raw?.forwarding_actions",
            ".slice(0, 8)",
            ".slice(0, 32)",
            "applies_to_next_hop_id",
            "value_type",
        ):
            self.assertIn(contract, normalizer)
        matcher = javascript_function(
            script.text, "routeTableEntryMatchesFilters"
        )
        self.assertIn("forwardingText", matcher)
        self.assertIn("value.kind", matcher)
        markup = javascript_function(
            script.text, "routeTableForwardingMarkup"
        )
        self.assertIn("No forwarding action", markup)
        self.assertIn("mn-forwarding-overflow", markup)
        self.assertIn("action.applies_to_next_hop_id", markup)
        for contract in (
            ".mn-route-table-forwarding",
            ".mn-forwarding-value",
            ".mn-forwarding-overflow",
        ):
            self.assertIn(contract, styles.text)

    def test_device_selector_is_above_the_topology_map(self) -> None:
        page = self.client.get("/")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(page.status_code, 200)
        self.assertLess(
            page.text.index('class="panel mn-filter-panel"'),
            page.text.index('class="mn-map-stack"'),
        )
        self.assertIn("DEVICE SELECTION", page.text)
        self.assertIn("grid-template-columns: minmax(0, 1fr);", styles.text)
        self.assertIn("grid-auto-flow: column;", styles.text)
        self.assertIn("overflow-x: auto;", styles.text)

    def test_topology_page_exposes_optional_element_layers(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(page.status_code, 200)
        self.assertIn('id="mn-topology-element-picker"', page.text)
        self.assertIn('id="mn-topology-element-summary"', page.text)
        self.assertIn(
            'data-topology-element-preset="compact" aria-pressed="true"',
            page.text,
        )
        self.assertIn(
            'data-topology-element-preset="all" aria-pressed="false"',
            page.text,
        )
        for element in (
            "subnets",
            "vlans",
            "interfaces",
            "subinterfaces",
            "lags",
            "external",
        ):
            self.assertIn(f'data-topology-element="{element}"', page.text)
        for element in ("subnets", "interfaces"):
            self.assertIn(
                f'data-topology-element="{element}" checked',
                page.text,
            )

        self.assertIn("TOPOLOGY_ELEMENT_KEYS", script.text)
        self.assertIn("TOPOLOGY_ELEMENT_PRESETS", script.text)
        self.assertIn("topologyElementVisibility", script.text)
        self.assertIn("syncTopologyElementControls", script.text)
        self.assertIn("topologyAttachmentComponents", script.text)
        self.assertIn("renderAttachmentComponents", script.text)
        self.assertIn("topology_layers", script.text)
        self.assertIn("mn-attachment-component", styles.text)
        self.assertIn("is-junction-only", styles.text)
        for contract in (
            "topologyDomainPresentationDecision",
            'requestedShape === "compact_edge"',
            "domain.semantic_conflict !== true",
            "completeMembership",
            "participants.length === 2",
            "mn-compact-domain-hit",
            "data-network-attachment-ids",
            "topologyDomainInspectorItem",
            "bindTopologyInspectorElements",
            "PLUGIN · declared or inferred meaning",
            "CORE · presentation calculation",
        ):
            self.assertIn(contract, script.text)
        self.assertIn('id="mn-topology-hover-card"', page.text)
        self.assertIn("mn-topology-hover-card", styles.text)
        self.assertIn("mn-compact-domain-edge", styles.text)

    def test_topology_overview_ux_contracts_are_wired(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(page.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertEqual(styles.status_code, 200)

        for contract in (
            'id="mn-node-selection-summary"',
            'id="mn-node-index-expand"',
            'aria-controls="mn-node-index"',
            'id="mn-topology-guide"',
            'class="mn-topology-guide-card"',
            'id="mn-map-summary"',
            'id="mn-map-reset" data-graph-action="reset"',
            'data-topology-element="external"',
            'class="mn-route-quality-legend"',
            'aria-label="Route path state legend"',
        ):
            self.assertIn(contract, page.text)
        for label in (
            "Router card",
            "Domain pill",
            "Direct line",
            "External stub",
            "standby / inactive",
            "dead / dropped",
            "VPN context",
        ):
            self.assertIn(label, page.text)

        self.assertIn("topologyFocusedNodeKey", script.text)
        self.assertIn('external: "external networks"', script.text)
        self.assertIn('"All detail layers"', script.text)
        self.assertIn('"Connectivity only"', script.text)

        connectivity_edges = javascript_function(
            script.text, "renderConnectivityEdges"
        )
        self.assertIn("const focusKey = options.focusKey", connectivity_edges)
        self.assertIn("const emphasized = options.emphasized", connectivity_edges)
        self.assertNotIn("state.focusedNodeKey", connectivity_edges)

        direct_links = javascript_function(
            script.text, "visibleDirectTopologyLinks"
        )
        self.assertIn("const planeHasSegments = visibleDomains.length > 0", direct_links)
        self.assertIn("!planeHasSegments", direct_links)
        self.assertIn("link.resolution_only", direct_links)
        self.assertIn('routeTraceRole === "include"', direct_links)

        topology_map = javascript_function(script.text, "renderLinkStatusMap")
        self.assertIn("hiddenExternalDomains", topology_map)
        self.assertIn('topologyElementVisible("external")', topology_map)
        self.assertIn(
            "topologyInspectorItems.set(`node:${node.key}`",
            topology_map,
        )
        self.assertIn(
            'button.dataset.topologyInspectMode = "preview"',
            topology_map,
        )
        self.assertIn("const directLinks = visibleDirectTopologyLinks", topology_map)
        self.assertIn("{ focusKey, emphasized, directLinks }", topology_map)
        self.assertIn("{ showGlobalSelection: false }", topology_map)
        inspector_binding = javascript_function(
            script.text, "bindTopologyInspectorElements"
        )
        self.assertIn(
            'element.dataset.topologyInspectMode === "preview"',
            inspector_binding,
        )
        self.assertIn("if (previewOnly) return", inspector_binding)

        graph_transform = javascript_function(script.text, "applyGraphTransform")
        self.assertIn("stage.dataset.graphDetail", graph_transform)
        self.assertIn('"overview"', graph_transform)
        self.assertIn('"detail"', graph_transform)

        route_mode = javascript_function(script.text, "setRouteGraphMode")
        self.assertIn('if (mode === "all")', route_mode.replace("'", '"'))
        self.assertIn(
            'state.selectedRoutePathIds = { forward: "", reverse: "" };',
            route_mode,
        )

        for contract in (
            ".mn-node-index.is-expanded",
            '#mn-map-stage[data-graph-detail="overview"]',
            '#mn-map-stage[data-graph-detail="detail"]',
            ".mn-topology-guide-card",
            ".mn-map-summary",
            ".mn-route-quality-legend",
        ):
            self.assertIn(contract, styles.text)

    def test_topology_layout_is_generic_deterministic_and_incidence_aware(self) -> None:
        script = self.client.get("/assets/topology.js")

        self.assertEqual(script.status_code, 200)
        builder = javascript_function(script.text, "buildConnectivityLayoutGraph")
        components = javascript_function(script.text, "connectivityLayoutComponents")
        ranks = javascript_function(script.text, "rankConnectivityComponent")
        crossing_reduction = javascript_function(
            script.text, "minimizeConnectivityRankCrossings"
        )
        component_layout = javascript_function(
            script.text, "layoutConnectivityComponent"
        )
        rank_grid = javascript_function(script.text, "connectivityRankGrid")
        layout = javascript_function(script.text, "mapConnectivityLayout")
        signature = javascript_function(
            script.text, "connectivityLayoutSignature"
        )
        geometry_signature = javascript_function(
            script.text, "connectivityLayoutGeometrySignature"
        )
        render = javascript_function(script.text, "renderLinkStatusMap")

        for contract in (
            'const TOPOLOGY_LAYOUT_VERSION = "incidence-v3"',
            "const TOPOLOGY_LAYOUT_SWEEPS = 6",
            "const TOPOLOGY_LAYOUT_MAX_CROSS_ITEMS = 5",
            "const TOPOLOGY_LAYOUT_OUTER_PADDING = 52",
            "buildConnectivityLayoutGraph(",
            "connectivityLayoutComponents(graph)",
            "rankConnectivityComponent(",
            "minimizeConnectivityRankCrossings(",
            "TOPOLOGY_LAYOUT_BAND_GAP",
        ):
            self.assertIn(contract, script.text)
        self.assertIn('kind: "node"', builder)
        self.assertIn('kind: "domain"', builder)
        self.assertIn("compactDecisions", builder)
        self.assertIn("directLinks", builder)
        self.assertIn("remaining.values().next().value", components)
        self.assertIn("connectivityBfsDistances", ranks)
        self.assertIn("sweeps = TOPOLOGY_LAYOUT_SWEEPS", crossing_reduction)
        self.assertIn("mirrored = bandIndex % 2 === 1", component_layout)
        self.assertIn("targetMainSpan", component_layout)
        self.assertIn("TOPOLOGY_LAYOUT_MAX_CROSS_ITEMS", rank_grid)
        self.assertIn("Math.ceil(rank.length / columns)", rank_grid)
        self.assertIn("compactDecisions = []", layout)
        self.assertIn("directLinks = []", layout)
        self.assertIn('"horizontal" : "vertical"', layout)
        self.assertIn('"domain-boxes" : "junctions"', layout)
        self.assertIn("records", signature)
        self.assertIn("].sort()", signature)
        self.assertIn("stableLayoutHash", signature)
        self.assertIn("layoutMode.orientation", signature)
        self.assertIn("layoutMode.domainBoxMode", signature)
        self.assertIn("layoutMode.geometrySignature", signature)
        self.assertIn("dimensions.positions.entries()", geometry_signature)
        self.assertIn("dimensions.domainPositions.entries()", geometry_signature)
        self.assertIn("stableLayoutHash", geometry_signature)
        self.assertIn("compactDecisions,\n    directLinks,", render)
        self.assertIn("connectivityLayoutSignature(", render)
        self.assertIn("connectivityLayoutGeometrySignature(dimensions)", render)
        self.assertIn("TOPOLOGY_LAYOUT_VERSION", render)

        generic_layout_source = builder + ranks + crossing_reduction + component_layout
        for forbidden in (
            "node.label",
            ".device_role",
            ".prefix",
            ".vlan",
            ".protocol",
            ".site",
        ):
            self.assertNotIn(forbidden, generic_layout_source)
        self.assertNotIn("localeCompare", generic_layout_source)

    def test_topology_relationship_context_and_semantic_detail_are_wired(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(page.status_code, 200)
        show = javascript_function(script.text, "showTopologyInspector")
        clear = javascript_function(script.text, "clearTopologyInspector")
        context = javascript_function(
            script.text, "applyTopologyRelationshipContext"
        )
        edges = javascript_function(script.text, "renderConnectivityEdges")

        self.assertIn("expandNodeDomains: state.topologyInspectorPinned", show)
        self.assertIn("clearTopologyRelationshipContext()", clear)
        self.assertIn("state.topologyInspectorPinned && !pinned", show)
        for contract in (
            '"attachment"',
            '"domain"',
            '"link"',
            '"node"',
            "data-network-segment-id",
            "data-network-attachment-id",
            "data-topology-link-id",
            "is-topology-context-related",
            "is-topology-context-muted",
        ):
            self.assertIn(contract, context if contract.startswith('"') else script.text)
        self.assertIn("const originNodeKeys = new Set(facts.nodeKeys)", context)
        self.assertIn("const directlyIncidentItems = new Set()", context)
        self.assertIn("directlyIncidentItems.add(element)", context)
        self.assertIn(
            'if (!expandNodeDomains) return directlyIncidentItems.has(element)',
            context,
        )
        self.assertIn(
            'kind === "domain" || expandNodeDomains',
            context,
        )
        self.assertIn(
            'topologyRelationshipScope = kind === "node"',
            context,
        )
        self.assertIn("topologyContextAttributes", edges)
        self.assertIn("has-topology-relationship-context", styles.text)
        self.assertIn('data-topology-relationship-scope="incident"', styles.text)
        self.assertIn(
            '#mn-map-stage[data-graph-detail="normal"] .mn-attachment-component',
            styles.text,
        )
        self.assertIn(
            '#mn-map-stage[data-graph-detail="detail"] .mn-attachment-component',
            styles.text,
        )
        self.assertIn("pointer-events: none;", styles.text)
        self.assertIn("clamp(640px, 68vh, 700px)", styles.text)
        self.assertIn("arranged from their declared connectivity", page.text)
        self.assertIn("capturePinnedTopologyInspector()", script.text)
        self.assertIn("restorePinnedTopologyInspector(pinnedInspector)", script.text)
        self.assertIn("state.resizeTargets.add(entry.target.id)", script.text)
        self.assertNotIn("requestAnimationFrame(renderMap)", script.text)

    def test_topology_frontend_guards_async_state_and_route_edge_cases(self) -> None:
        script = self.client.get("/assets/topology.js")

        self.assertEqual(script.status_code, 200)
        self.assertNotIn('api("/api/demo")', script.text)
        for contract in (
            "bootstrapFromCapabilities",
            "topologyRequestGeneration",
            "routeRequestGeneration",
            "AbortController",
            "immutableSnapshot",
            "routeEndpointDisplayValue",
            "routeEndpointScopeIssue",
            "sameCanonicalRouteEndpoint",
            "setAdvertisedSelectValue",
            "normalizedRelativeSeconds",
            "pathIsUsableActive",
            "selectedPathEvidence",
            "Selected but unusable",
            "canonicalJson",
            "path?.segments",
            "queryControlsDirty",
            'url.searchParams.set("topology_view"',
            'url.searchParams.set("focus_resource"',
            "outside the reconstructed device set",
        ):
            self.assertIn(contract, script.text)
        self.assertEqual(script.text.count("new ResizeObserver"), 1)
        self.assertIn(
            'return [...new Set([...targetIds, `node-member:${node.member_id}`])]',
            script.text,
        )
        self.assertIn(
            'return [...new Set([...targetIds, `link:${link.link_id}`])]',
            script.text,
        )

    def test_topology_frontend_uses_only_exact_plugin_plan_identifiers(self) -> None:
        script = self.client.get("/assets/topology.js")

        selector = javascript_function(script.text, "pickDeclaredId")
        plan = javascript_function(script.text, "nodePlan")
        self.assertIn("idGetter(item) === requestedId", selector)
        self.assertIn("idGetter(item) === fallbackId", selector)
        self.assertNotIn(".includes(", selector)
        self.assertNotIn("semantic_role", selector)
        self.assertNotIn(".label", selector)
        self.assertIn("pickDeclaredId(", plan)

    def test_route_frontend_requires_explicit_normalized_semantics(self) -> None:
        script = self.client.get("/assets/topology.js")

        self.assertEqual(script.status_code, 200)
        route_table = javascript_function(script.text, "normalizeRouteTableEntry")
        segment = javascript_function(script.text, "normalizeRouteSegment")
        path = javascript_function(script.text, "normalizeRoutePath")
        trace = javascript_function(script.text, "normalizeRouteTrace")
        terminal = javascript_function(script.text, "routeValueIsTerminal")
        usable = javascript_function(script.text, "pathIsUsableActive")
        control_plane = javascript_function(script.text, "pathIsControlPlaneOnly")
        quality = javascript_function(script.text, "routeQualityClasses")
        findings = javascript_function(script.text, "routeFindingsMarkup")

        self.assertIn("installed: explicitRouteBoolean(", route_table)
        self.assertIn("selected: explicitRouteBoolean(", route_table)
        self.assertIn("active: explicitRouteBoolean(", route_table)
        self.assertIn('?? "unknown"', route_table)
        self.assertNotIn("active !== false", route_table)
        self.assertNotIn("raw?.installed ?? raw?.programmed ?? raw?.selected", route_table)

        for normalizer in (segment, path):
            self.assertIn("explicitRouteActivity(raw)", normalizer)
            self.assertIn("explicitRouteSelection(raw)", normalizer)
            self.assertIn("explicitRouteCompleteness(raw)", normalizer)
            self.assertIn("explicitRouteConsistency(raw)", normalizer)
            self.assertIn("explicitRouteDisposition(raw)", normalizer)
            self.assertNotIn(".test(", normalizer)
        self.assertIn('|| "unknown"', path)
        self.assertNotIn('index === 0 ? "primary"', path)
        self.assertNotIn('? "selected"', path)

        self.assertIn("ROUTE_TERMINAL_RESULTS.has", terminal)
        self.assertIn("legacyRouteDisposition", terminal)
        self.assertNotIn("terminal_reason", terminal)
        self.assertNotIn("reason_code", terminal)
        self.assertNotIn(".test(", terminal)
        self.assertIn("path?.forwarding_capable === false", control_plane)
        self.assertNotIn(".test(", control_plane)
        self.assertIn("ROUTE_SELECTED_STATES.has", usable)
        self.assertIn("ROUTE_ACTIVE_STATES.has", usable)
        self.assertIn("routeCompletenessIsUnknown", usable)
        self.assertNotIn(".test(", usable)
        self.assertIn("pathIsInconsistent", quality)
        self.assertIn("pathIsInferred", quality)
        self.assertIn("pathIsUnresolved", quality)
        self.assertNotIn(".test(", quality)

        self.assertIn("raw?.consistency?.issue_refs", trace)
        self.assertNotIn("finding.title", trace)
        self.assertNotIn("finding.message", trace)
        self.assertNotIn(".test(", findings)

    def test_all_path_graph_keeps_candidate_quality_local(self) -> None:
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(script.status_code, 200)
        for contract in (
            "routeSegmentQualityState",
            "routeNodeQualityClasses",
            "applyRouteOverviewNodeQuality",
            "data-route-quality-by-path",
            "data-route-install-gate-by-path",
            "data-route-install-gate",
            "is-route-mixed",
            'edgeDisposition = edge.terminal ? "terminal drop"',
            'edgeDisposition = terminal ? "terminal drop"',
            'M3,2 L3,10 M9,2 L9,10',
            "segments: [segment]",
            "termination_reason: terminal ? terminalReason",
            'status: terminal ? (segment?.status || path?.status || "unknown")',
            'operational: terminal ? (segment?.operational || path?.operational || "unknown")',
        ):
            self.assertIn(contract, script.text)
        self.assertNotIn("memberships.flatMap(routeQualityClasses)", script.text)
        self.assertIn(
            ".mn-map-node.is-route-member.is-route-mixed",
            styles.text,
        )

    def test_directional_asymmetry_is_pair_scoped_and_visible_on_the_map(self) -> None:
        page = self.client.get("/")
        script = self.client.get("/assets/topology.js")
        styles = self.client.get("/assets/topology.css")

        self.assertEqual(page.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertEqual(styles.status_code, 200)
        summary = javascript_function(script.text, "bidirectionalSummary")
        sequence = javascript_function(script.text, "routeSequenceForDirection")
        difference = javascript_function(script.text, "routeDirectionalDifference")
        focused_map = javascript_function(script.text, "renderFocusedRouteMap")
        edges = javascript_function(script.text, "renderEdges")
        findings = javascript_function(script.text, "routeFindingsMarkup")

        self.assertIn('code: "asymmetric"', summary)
        self.assertIn('"bidirectionally_reachable"', summary)
        self.assertIn('"not_comparable"', summary)
        self.assertIn(
            "Path shape is informational and does not make endpoint "
            "reachability inconsistent.",
            summary,
        )
        self.assertNotIn(
            'label: "Asymmetric paths", detail: symmetry.state || '
            '"Reachable directions use different paths", className: "is-inconsistent"',
            summary,
        )
        self.assertIn("forward_node_sequence", sequence)
        self.assertIn("reverse_node_sequence", sequence)
        self.assertIn("path_relation", difference)
        self.assertIn("currentOnlyNodeIds", difference)
        self.assertIn("currentOnlyEdgeKeys", difference)
        self.assertIn("both resolved", difference)
        self.assertIn("renderRouteDirectionalDifference()", focused_map)
        self.assertIn("is-direction-difference", focused_map)
        self.assertIn("routeDirectionDifference", edges)
        self.assertIn("is-direction-difference", edges)
        self.assertIn("No path-local fault", findings)
        self.assertIn("plug-in-provided active paths", findings)
        self.assertIn('id="mn-route-direction-difference"', page.text)
        self.assertIn(".mn-route-direction-difference", styles.text)
        self.assertIn(".mn-route-edge.is-direction-difference", styles.text)
        self.assertIn(
            ".mn-map-node.is-route-member.is-direction-difference",
            styles.text,
        )


if __name__ == "__main__":
    unittest.main()
