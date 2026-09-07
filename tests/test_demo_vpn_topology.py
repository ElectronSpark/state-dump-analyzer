from __future__ import annotations

import unittest
from types import SimpleNamespace

from rsl_demo_generator.assembly import AssemblyConfig, _topology_projection
from rsl_demo_generator.catalog import DEFAULT_SCENARIO_SOURCE, DEMO_NODES
from rsl_demo_plugin.route_policy import _SERVICE_PRESENTATIONS
from rsl_demo_plugin.topology_contract import (
    build_topology_contract,
    build_topology_profiles,
)
from rsl_demo_plugin.typed_topology import _is_typed_point_to_point_claim
from rsl_demo_plugin.vpn_topology import (
    project_vpn_topology_resource,
    vpn_domain_key,
)

from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyService,
    _status_view_at,
)


class DemoVpnTopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            allow_small=True,
        )
        cls.projections = {
            node.node_id: {"topology": _topology_projection(node, config=config)}
            for node in DEMO_NODES
        }
        store = SimpleNamespace(
            assembly=SimpleNamespace(
                revisions=tuple(
                    SimpleNamespace(
                        node_id=node.node_id,
                        revision_id=node.revision_id,
                        label=node.label,
                        event_count=0,
                        resource_count=0,
                        metadata={
                            "site": node.site,
                            "role": node.role,
                            "clock": {"domain": "utc", "offset_ns": 0, "uncertainty_ns": 0},
                        },
                    )
                    for node in DEMO_NODES
                )
            ),
            projection_for_node=cls.projections.__getitem__,
        )
        cls.contract = build_topology_contract(store)
        cls.profiles = build_topology_profiles(cls.contract)
        cls.service = MultiNodeTopologyService(
            contract=cls.contract,
            topology_profiles=cls.profiles,
            topology_metadata={
                "topology_id": "test.vpn-topology",
                "assembly_id": "test.vpn-topology",
                "revision_id": "test.vpn-topology.revision",
                "capture_ns": DEFAULT_SCENARIO_SOURCE.capture_time_ns,
                "timeline_start_ns": DEFAULT_SCENARIO_SOURCE.base_time_ns,
                "timeline_end_ns": DEFAULT_SCENARIO_SOURCE.capture_time_ns,
            },
        )

    def test_saved_service_samples_form_three_separate_domains(self) -> None:
        payload = self.service.query({"network_segment_limit": 100})
        domains = {
            domain["segment_key"]["value"]: domain
            for domain in payload["network_segments"]
            if domain["presentation_plane"] == "vpn"
        }
        expected = {
            vpn_domain_key("mpls_l3vpn", "blue", "65000:100"):
                {"node-a", "node-b", "node-c"},
            vpn_domain_key("mpls_l3vpn", "red", "65000:200"):
                {"node-d", "node-e"},
            vpn_domain_key("evpn_vxlan", "blue", "65000:50100", 50100):
                {"node-a", "node-b", "node-d", "node-e"},
        }
        self.assertEqual(set(domains), set(expected))
        for key, members in expected.items():
            domain = domains[key]
            self.assertEqual(set(domain["node_ids"]), members)
            self.assertEqual(domain["network_kind"], "vpn_service")
            self.assertFalse(domain["connectivity_enabled"])
            self.assertFalse(domain["semantic_conflict"])
            self.assertEqual(
                domain["topology_presentation"]["two_participant_shape"],
                "domain_node",
            )
            self.assertTrue(domain["evidence"])
        blue = domains[vpn_domain_key("mpls_l3vpn", "blue", "65000:100")]
        red = domains[vpn_domain_key("mpls_l3vpn", "red", "65000:200")]
        self.assertEqual(blue["prefix"], red["prefix"])
        self.assertNotEqual(blue["routing_scope"], red["routing_scope"])

    def test_vpn_profile_reuses_projection_without_duplicating_claims(self) -> None:
        by_id = {profile["profile_id"]: profile for profile in self.profiles}
        vpn = by_id["fabric-vpn"]
        self.assertIn("vpn", vpn["presentation_roles"])
        self.assertEqual(
            vpn["projection_by_member"],
            by_id["fabric-underlay"]["projection_by_member"],
        )
        underlay = self.service.query({"profile_id": "fabric-underlay"})
        overlay = self.service.query({"profile_id": "fabric-vpn"})
        self.assertEqual(
            {item["segment_id"] for item in underlay["network_segments"]},
            {item["segment_id"] for item in overlay["network_segments"]},
        )

    def test_vpn_claims_never_become_physical_connectors(self) -> None:
        self.assertEqual(len(DEFAULT_SCENARIO_SOURCE.links), 8)
        for projection in self.projections.values():
            claims = projection["topology"]["claims"]
            for claim in claims:
                if claim["subnet"]["classification"] == "vpn":
                    self.assertFalse(_is_typed_point_to_point_claim(claim))
                    self.assertNotIn("physical_interfaces", claim["components"])
                elif claim["subnet"]["classification"] == "evpn_access":
                    self.assertNotEqual(
                        claim.get("plugin_semantics", {}).get("presentation_group"),
                        "vpn",
                    )

    def test_route_presentation_targets_resolve_to_authored_service_domains(self) -> None:
        domain_keys = {
            claim["segment_key"]
            for projection in self.projections.values()
            for claim in projection["topology"]["claims"]
        }
        for presentation in _SERVICE_PRESENTATIONS.values():
            self.assertLessEqual(
                set(presentation["connectivity_domain_keys"].values()),
                domain_keys,
            )
        self.assertNotEqual(
            _SERVICE_PRESENTATIONS["mpls_l3vpn"]["connectivity_domain_keys"]["blue"],
            _SERVICE_PRESENTATIONS["evpn_service"]["connectivity_domain_keys"]["blue"],
        )

    def test_local_service_history_retains_withdrawal_and_restoration(self) -> None:
        node = next(item for item in self.contract["nodes"] if item["node_id"] == "node-e")
        projection = node["plugin_sets"][0]["plugins"][0]["projections"][0]
        resource = next(
            item for item in projection["resources"]
            if item["properties"].get("service_id") == "blue-evpn"
        )
        changes = resource["changes"]
        self.assertGreaterEqual(len(changes), 2)
        absent_change = next(item for item in changes if item.get("status") == "down")
        restored_change = next(
            item for item in changes
            if item.get("status") == "up"
            and int(item["time_ns"]) > int(absent_change["time_ns"])
        )
        self.assertTrue(_status_view_at(resource, int(absent_change["time_ns"]) - 1)["exists"])
        self.assertTrue(_status_view_at(resource, int(absent_change["time_ns"]))["exists"])
        self.assertEqual(_status_view_at(resource, int(absent_change["time_ns"]))["status"], "down")
        self.assertTrue(_status_view_at(resource, int(restored_change["time_ns"]))["exists"])
        self.assertEqual(_status_view_at(resource, int(restored_change["time_ns"]))["status"], "up")
        during = self.service.query({
            "basis": {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": str(int(absent_change["time_ns"]) + 1),
            },
        })
        domains = {
            item["segment_key"]["value"]: item
            for item in during["network_segments"]
            if item["presentation_plane"] == "vpn"
        }
        evpn = domains[vpn_domain_key("evpn_vxlan", "blue", "65000:50100", 50100)]
        self.assertEqual(evpn["status"], "degraded")
        self.assertEqual(evpn["existing_node_count"], 4)
        for vrf, route_target in (("blue", "65000:100"), ("red", "65000:200")):
            self.assertEqual(
                domains[vpn_domain_key("mpls_l3vpn", vrf, route_target)]["status"],
                "usable",
            )

    def test_identity_is_not_prefix_or_ambiguous_delimiter_matching(self) -> None:
        self.assertNotEqual(
            vpn_domain_key("mpls_l3vpn", "blue:rt:x", "y"),
            vpn_domain_key("mpls_l3vpn", "blue", "x:rt:y"),
        )
        self.assertNotEqual(
            vpn_domain_key("evpn_vxlan", "blue", "65000:100", 100),
            vpn_domain_key("evpn_vxlan", "blue", "65000:100", 101),
        )

    def test_non_service_resource_does_not_gain_vpn_meaning(self) -> None:
        self.assertIsNone(project_vpn_topology_resource(
            node_id="node-a",
            revision_id="test",
            resource={"kind": "VIRTUAL_INTERFACE", "properties": {"vrf": "blue"}},
            valid_from_ns=0,
        ))


if __name__ == "__main__":
    unittest.main()
