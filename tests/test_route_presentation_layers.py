from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "demo"))

from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
)



TOPOLOGY_JS = (
    ROOT / "frontend" / "assets" / "topology.js"
)
CONNECTIVITY_DOMAIN_MATCHER_ID = (
    "demo.connectivity-domain-key.exact.v1"
)


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    following = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start :] if following is None else source[
        start : start + 1 + following.start()
    ]


class RoutePresentationLayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()
        cls.script = TOPOLOGY_JS.read_text(encoding="utf-8")
        capabilities = cls.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        topology = cls.client.post("/v1/topologies/query", json={}).json()
        cls.forwarding_domains = {
            item["segment_id"]: set(item["node_ids"])
            for item in topology["network_segments"]
            if item["connectivity_enabled"]
        }
        cls.routed_node_ids = set(
            capabilities["network_model"]["routed_node_ids"]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def assert_physical_forwarding_geometry(self, path: dict[str, Any]) -> None:
        node_sequence = path["node_sequence"]
        boundaries = [
            segment
            for segment in path["segments"]
            if segment["segment_kind"] == "inter_node_boundary"
        ]
        self.assertGreaterEqual(len(node_sequence), 2)
        self.assertEqual(len(boundaries), len(node_sequence) - 1)
        for index, boundary in enumerate(boundaries):
            segment_id = boundary["network_segment_id"]
            self.assertIn(segment_id, self.forwarding_domains)
            self.assertTrue(
                set(node_sequence[index : index + 2]).issubset(
                    self.forwarding_domains[segment_id]
                )
            )
            self.assertTrue(
                set(boundary["node_ids"]).issubset(self.routed_node_ids)
            )

    def assert_plugin_overlay_contract(self, path: dict[str, Any]) -> None:
        layers = path["presentations"]
        overlays = [item for item in layers if item["role"] == "overlay"]
        self.assertTrue(overlays)
        geometry_ids = {
            str(value)
            for segment in path["segments"]
            for value in (
                segment.get("segment_id"),
                segment.get("topology_link_id"),
            )
            if value
        }
        for overlay in overlays:
            self.assertTrue(overlay["presentation_id"])
            self.assertEqual(overlay["scope"], "path")
            self.assertEqual(overlay["style"], "band")
            self.assertIsInstance(overlay["description"], str)
            self.assertTrue(overlay["description"])
            self.assertIsInstance(overlay["topology_references"], list)
            self.assertTrue(overlay["topology_references"])
            self.assertTrue(
                all(
                    "resource" in reference or "match" in reference
                    for reference in overlay["topology_references"]
                )
            )
            self.assertIsInstance(overlay["anchor_resources"], list)
            self.assertIsInstance(overlay["facts"], dict)
            self.assertTrue(overlay["facts"])
            self.assertEqual(overlay["semantic_owner"], "plugin")
            self.assertEqual(overlay["geometry_role"], "context")
            self.assertIs(
                overlay["participates_in_forwarding_geometry"],
                False,
            )
            self.assertNotIn(overlay["presentation_id"], geometry_ids)

    def test_cross_layer_control_candidate_keeps_physical_outer_path(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "cross-layer-inconsistent"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        control = next(
            path
            for path in payload["paths"]
            if path["perspective"] == "control_expected"
        )

        self.assert_physical_forwarding_geometry(control)
        self.assert_plugin_overlay_contract(control)
        self.assertTrue(
            all(
                segment.get("participates_in_forwarding_geometry", True)
                for segment in control["segments"]
                if segment["segment_kind"] == "inter_node_boundary"
            )
        )
        overlay_targets = [
            target
            for layer in control["presentations"]
            if layer["role"] == "overlay"
            for target in layer.get("topology_targets", [])
        ]
        connectivity_target = next(
            target
            for target in overlay_targets
            if target.get("kind") == "topology_match"
            and target.get("matcher_id") == CONNECTIVITY_DOMAIN_MATCHER_ID
        )
        self.assertEqual(
            connectivity_target["match_key"],
            "vpn:blue:ipv4:10.20.0.0-24",
        )
        self.assertEqual(
            connectivity_target["semantic_owner"],
            "topology_plugin",
        )
        self.assertTrue(connectivity_target["interaction_target_id"])

    def test_evpn_and_mpls_l3vpn_overlays_preserve_physical_boundaries(self) -> None:
        requests = [
            {"scenario_id": "evpn-mh-all-active"},
            {
                "scenario_id": "router-to-router",
                "source_id": "source:node-d",
                "destination_id": "destination:node-e",
                "vrf_id": "red",
                "route_family": "vpnv4_unicast",
                "route_type": "mpls_l3vpn",
            },
        ]
        for request in requests:
            with self.subTest(request=request):
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json=request,
                )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                for path in payload["paths"]:
                    self.assert_physical_forwarding_geometry(path)
                    self.assert_plugin_overlay_contract(path)
                    presentation_ids = {
                        layer["presentation_id"]
                        for layer in path["presentations"]
                    }
                    segment_ids = {
                        str(value)
                        for segment in path["segments"]
                        for value in (
                            segment.get("segment_id"),
                            segment.get("topology_link_id"),
                        )
                        if value
                    }
                    self.assertTrue(presentation_ids.isdisjoint(segment_ids))

    def test_frontend_uses_generic_presentation_contract_without_protocol_inference(self) -> None:
        helpers = {
            name: javascript_function(self.script, name)
            for name in (
                "normalizeRoutePresentationLayer",
                "routePresentationLayers",
                "routeForwardingSegments",
                "routePresentationGroups",
                "showRoutePresentationPreview",
                "bindRoutePresentationElements",
                "bindOverviewPathElements",
            )
        }
        normalizer = helpers["normalizeRoutePresentationLayer"]
        self.assertIn("presentation_id", normalizer)
        self.assertIn("layer_id", normalizer)
        self.assertIn("semantic_owner", normalizer)
        self.assertIn("geometry_role", normalizer)
        self.assertIn("participates_in_forwarding_geometry", normalizer)
        self.assertIn("topology_targets", normalizer)
        self.assertIn("topology_references", normalizer)
        self.assertIn("anchor_resources", normalizer)
        self.assertIn("Object.entries(rawFacts)", normalizer)
        self.assertIn("styleRoles", normalizer)
        self.assertIn("presentations", helpers["routePresentationLayers"])
        self.assertNotIn(
            "presentation_layers",
            helpers["routePresentationLayers"],
        )
        self.assertIn(
            "participates_in_forwarding_geometry",
            helpers["routeForwardingSegments"],
        )
        self.assertIn("geometry_role", helpers["routeForwardingSegments"])
        self.assertIn('layer.scope !== "path"', helpers["routePresentationGroups"])
        self.assertIn('layer.style !== "band"', helpers["routePresentationGroups"])
        for name in ("bindRoutePresentationElements", "bindOverviewPathElements"):
            self.assertIn('addEventListener("mouseenter"', helpers[name])
            self.assertIn('addEventListener("mouseleave"', helpers[name])
        self.assertIn('close?.focus({ preventScroll: true })', helpers["showRoutePresentationPreview"])

        protocol_classifier = re.compile(
            r"\b(?:evpn|vpn|vxlan|mpls|srv6|vni|vrf)\b",
            re.IGNORECASE,
        )
        for name, helper in helpers.items():
            with self.subTest(helper=name):
                self.assertIsNone(protocol_classifier.search(helper))


if __name__ == "__main__":
    unittest.main()
