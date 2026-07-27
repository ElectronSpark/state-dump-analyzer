from __future__ import annotations

import unittest
from urllib.parse import quote

from fastapi.testclient import TestClient

from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
)

configure_generated_demo_for_tests()

from plugin.data import REVISION_ID


class DemoAppTests(unittest.TestCase):
    """Exercise the single generated demo rather than a retired hand-written fixture."""

    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def _workspace(self) -> dict[str, object]:
        response = self.client.get("/v1/nodes/node-a/workspace")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_health_and_single_page_application_are_available(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        health_payload = health.json()
        self.assertEqual(health_payload["mode"], "full-scale-100k-plus")
        self.assertEqual(health_payload["revision_id"], REVISION_ID)
        self.assertGreater(health_payload["event_count"], 0)
        self.assertGreater(health_payload["resource_count"], 0)
        self.assertEqual(
            health_payload["assembly"]["loaded_revision_ids"],
            [REVISION_ID],
        )

        page = self.client.get("/node")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Router State Lab", page.text)
        self.assertIn("single-node analysis workspace", page.text)
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertIn("styles.css?v=20260724-event-selection-v2", page.text)
        self.assertIn("app.js?v=20260724-lane-visibility-v4", page.text)
        self.assertIn('id="correlation-panel-toggle"', page.text)
        self.assertIn('id="correlation-back-to-top"', page.text)
        self.assertIn('id="dashboard-index"', page.text)
        self.assertNotIn('id="resource-detail"', page.text)

        script = self.client.get("/assets/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn("requestGraph", script.text)
        self.assertIn("renderPluginDashboards", script.text)
        self.assertIn("resourceBundleRows", script.text)
        self.assertIn("DASHBOARD_LAYOUT_STORAGE_KEY", script.text)
        self.assertIn("bindCorrelationPanelControls", script.text)
        self.assertIn("no-store", script.headers["cache-control"])
        self.assertEqual(script.headers["pragma"], "no-cache")

    def test_node_workspace_basis_selector_is_unambiguous(self) -> None:
        workspace = self._workspace()
        time_ns = workspace["demo"]["timeline_start_ns"]
        absolute = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={
                "basis_kind": "absolute_time",
                "time_ns": time_ns,
            },
        )
        relative = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={
                "basis_kind": "relative_to_watermark",
                "basis_offset_ns": "-1000",
            },
        )
        self.assertEqual(absolute.status_code, 200, absolute.text)
        self.assertEqual(relative.status_code, 200, relative.text)
        self.assertEqual(
            absolute.json()["node_snapshot"]["basis"],
            {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": time_ns,
                "offset_ns": "0",
                "clock_policy": "best_effort",
            },
        )
        self.assertEqual(
            relative.json()["node_snapshot"]["basis"],
            {
                "kind": "relative_to_watermark",
                "offset_ns": "-1000",
                "time_ns": None,
                "clock_domain": "utc",
                "clock_policy": "best_effort",
            },
        )

        invalid_params = (
            {"basis_kind": "absolute_time"},
            {"basis_kind": "absolute_time", "basis_offset_ns": "-1"},
            {"basis_kind": "relative_to_watermark", "time_ns": time_ns},
            {"time_ns": time_ns, "basis_offset_ns": "-1"},
        )
        for params in invalid_params:
            with self.subTest(params=params):
                response = self.client.get(
                    "/v1/nodes/node-a/workspace",
                    params=params,
                )
                self.assertEqual(response.status_code, 422, response.text)

    def test_frontend_manifest_routes_pages_but_hides_templates_as_assets(
        self,
    ) -> None:
        primary = self.client.get("/")
        alias = self.client.get("/topology")
        node = self.client.get("/node")

        self.assertEqual(primary.status_code, 200)
        self.assertEqual(alias.status_code, 200)
        self.assertEqual(node.status_code, 200)
        self.assertIn("Multi-node", primary.text)
        self.assertEqual(primary.text, alias.text)
        self.assertNotEqual(primary.text, node.text)
        self.assertEqual(self.client.get("/assets/node.html").status_code, 404)
        self.assertEqual(self.client.get("/assets/topology.html").status_code, 404)

    def test_workspace_is_derived_from_the_generated_node_archive(self) -> None:
        payload = self._workspace()
        demo = payload["demo"]
        snapshot = payload["node_snapshot"]
        history = payload["history_transport"]

        self.assertEqual(demo["revision_id"], REVISION_ID)
        self.assertEqual(demo["node"], "node-a")
        self.assertEqual(demo["fixture"], "synthetic-packed-tgz-full-scale")
        self.assertEqual(demo["assembly_id"], snapshot["assembly_id"])
        self.assertEqual(snapshot["source"], "plugin-revision-store")
        self.assertEqual(snapshot["revision_id"], REVISION_ID)
        self.assertEqual(snapshot["event_count"], demo["event_count"])
        self.assertEqual(snapshot["resource_count"], demo["resource_count"])
        self.assertEqual(history["mode"], "server-windowed")
        self.assertEqual(
            history["events"]["total_count"],
            demo["event_count"],
        )
        self.assertEqual(
            history["source_records"]["total_count"],
            demo["source_record_count"],
        )
        self.assertEqual(payload["events"], [])
        self.assertEqual(len(payload["resources"]), demo["resource_count"])
        self.assertTrue(
            all(
                resource["resource_id"].startswith("node-a/")
                for resource in payload["resources"]
            )
        )
        kinds = {resource["kind"] for resource in payload["resources"]}
        self.assertTrue({"ETG", "ETE", "DTE", "NEIGHBOR"} <= kinds)
        self.assertEqual(payload["inventory"]["mode"], "inventory-only")

        gaps = {gap["id"]: gap for gap in payload["gaps"]}
        self.assertEqual(gaps["scale"]["status"], "implemented-demo")
        self.assertIn("trusted assembly", gaps["ingestion"]["detail"])
        self.assertIn(
            "installed example plug-in",
            gaps["plugins"]["detail"],
        )
        self.assertIn(
            "precomputed projections",
            gaps["plugins"]["detail"],
        )
        self.assertIn("IP, MPLS, SR, VPN", gaps["routing"]["detail"])

    def test_single_node_route_choices_and_resolution_are_plugin_declared(
        self,
    ) -> None:
        workspace = self._workspace()
        capability = workspace["route_resolution"]
        self.assertTrue(capability["available"])
        self.assertTrue(capability["plugin_defined"])
        self.assertEqual(capability["scope"], "node")
        self.assertEqual(capability["node_id"], "node-a")
        self.assertEqual(
            capability["provider"]["plugin_id"],
            "demo.example-router",
        )
        self.assertGreater(len(capability["routes"]), 1)
        route = next(
            item
            for item in capability["routes"]
            if item["scenario_id"] == "single-active-primary"
        )
        basis = capability["basis_kinds"][0]["basis_kind"]

        advertised = self.client.get(
            f"/v1/revisions/{REVISION_ID}/routes/capabilities"
        )
        self.assertEqual(advertised.status_code, 200, advertised.text)
        self.assertEqual(
            advertised.json()["default_route_id"],
            capability["default_route_id"],
        )

        resolved = self.client.post(
            f"/v1/revisions/{REVISION_ID}/routes/resolve",
            json={
                "route_id": route["route_id"],
                "basis_kind": basis,
                "time_ns": workspace["demo"]["capture_ns"],
            },
        )
        self.assertEqual(resolved.status_code, 200, resolved.text)
        payload = resolved.json()
        self.assertEqual(payload["route_id"], route["route_id"])
        self.assertEqual(payload["matched_prefix"], route["destination"])
        self.assertEqual(payload["result"], "resolved")
        self.assertEqual(
            payload["plugin_provenance"]["plugin_id"],
            "demo.example-router",
        )
        self.assertTrue(payload["next_hops"])

        unknown = self.client.post(
            f"/v1/revisions/{REVISION_ID}/routes/resolve",
            json={"route_id": "not-advertised", "basis_kind": basis},
        )
        self.assertEqual(unknown.status_code, 422, unknown.text)

        page = self.client.get("/node")
        self.assertNotIn("203.0.113.42", page.text)
        self.assertIn('id="route-choice"', page.text)
        self.assertIn('id="route-basis"', page.text)

    def test_specialized_revision_capabilities_are_not_swallowed_by_catchall(
        self,
    ) -> None:
        generic = self.client.get(
            f"/v1/revisions/{REVISION_ID}/capabilities"
        )
        topology = self.client.get(
            f"/v1/revisions/{REVISION_ID}/topology/capabilities"
        )
        multi_node = self.client.get(
            f"/v1/revisions/{REVISION_ID}/multi-node/capabilities"
        )

        self.assertEqual(generic.status_code, 200, generic.text)
        self.assertIn("implemented", generic.json())
        self.assertEqual(topology.status_code, 200, topology.text)
        self.assertIn("topology_projections", topology.json())
        self.assertEqual(multi_node.status_code, 200, multi_node.text)
        self.assertIn("topology_profiles", multi_node.json())

    def test_global_topology_aliases_follow_the_loaded_generated_assembly(
        self,
    ) -> None:
        workspace = self._workspace()
        assembly_id = workspace["demo"]["assembly_id"]

        topology = self.client.get("/v1/topologies/capabilities")
        routes = self.client.get("/v1/topologies/routes/capabilities")
        route_table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={"page": {"limit": 8}},
        )

        self.assertEqual(topology.status_code, 200, topology.text)
        self.assertEqual(topology.json()["assembly_id"], assembly_id)
        self.assertEqual(routes.status_code, 200, routes.text)
        self.assertEqual(routes.json()["assembly_id"], assembly_id)
        self.assertEqual(route_table.status_code, 200, route_table.text)
        self.assertEqual(route_table.json()["assembly_id"], assembly_id)
        unknown = self.client.get(
            "/v1/topology-assemblies/not-the-loaded-assembly/capabilities"
        )
        self.assertEqual(unknown.status_code, 404, unknown.text)

    def test_advertised_history_urls_accept_opaque_slash_qualified_ids(
        self,
    ) -> None:
        payload = self._workspace()
        demo = payload["demo"]
        history = payload["history_transport"]

        event_page = self.client.post(
            history["events"]["query_endpoint"],
            json={
                "include_normalized": True,
                "source_types": [],
                "limit": 8,
            },
        )
        self.assertEqual(event_page.status_code, 200, event_page.text)
        event_payload = event_page.json()
        self.assertEqual(event_payload["revision_id"], REVISION_ID)
        self.assertEqual(event_payload["total_count"], demo["event_count"])
        self.assertEqual(len(event_payload["items"]), 8)
        self.assertTrue(
            all(item["stream_kind"] == "event" for item in event_payload["items"])
        )

        event_uid = event_payload["items"][0]["uid"]
        self.assertIn("/", event_uid)
        detail_url = history["events"]["detail_endpoint_template"].replace(
            "{event_uid}",
            quote(event_uid, safe=""),
        )
        detail = self.client.get(detail_url)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["event_uid"], event_uid)

        density = self.client.post(
            history["density"]["query_endpoint"],
            json={
                "start_ns": demo["timeline_start_ns"],
                "end_ns": demo["timeline_end_ns"],
                "bin_count": 16,
            },
        )
        self.assertEqual(density.status_code, 200, density.text)
        self.assertEqual(density.json()["total_count"], demo["event_count"])
        self.assertEqual(density.json()["bin_count"], 16)

        encoded_revision_url = (
            f"/v1/revisions/{quote(REVISION_ID, safe='')}/event-log/query"
        )
        encoded = self.client.post(
            encoded_revision_url,
            json={"source_types": [], "limit": 1},
        )
        self.assertEqual(encoded.status_code, 200, encoded.text)
        self.assertEqual(encoded.json()["revision_id"], REVISION_ID)

    def test_generated_timeline_graph_and_range_share_one_revision(self) -> None:
        payload = self._workspace()
        demo = payload["demo"]
        resource_id = demo["initial_focus_resource_id"]
        prefix = f"/v1/revisions/{REVISION_ID}"

        timeline = self.client.post(
            prefix + "/timeline/query",
            json={
                "start_ns": demo["timeline_start_ns"],
                "end_ns": demo["timeline_end_ns"],
                "resource_ids": [resource_id],
            },
        )
        self.assertEqual(timeline.status_code, 200, timeline.text)
        timeline_payload = timeline.json()
        self.assertEqual(timeline_payload["revision_id"], REVISION_ID)
        self.assertEqual(timeline_payload["requested_resource_ids"], [resource_id])
        self.assertEqual(len(timeline_payload["lanes"]), 1)
        self.assertGreater(timeline_payload["event_count"], 0)

        graph = self.client.post(
            prefix + "/graph/query",
            json={
                "time_ns": demo["capture_ns"],
                "focus_resource_id": resource_id,
            },
        )
        self.assertEqual(graph.status_code, 200, graph.text)
        graph_payload = graph.json()
        self.assertEqual(graph_payload["revision_id"], REVISION_ID)
        self.assertTrue(graph_payload["nodes"])
        self.assertIn(
            resource_id,
            {node["id"] for node in graph_payload["nodes"]},
        )

        summary = self.client.post(
            prefix + "/range/summary",
            json={
                "start_ns": demo["timeline_start_ns"],
                "end_ns": demo["timeline_end_ns"],
            },
        )
        self.assertEqual(summary.status_code, 200, summary.text)
        summary_payload = summary.json()
        self.assertEqual(summary_payload["revision_id"], REVISION_ID)
        self.assertEqual(summary_payload["event_count"], demo["event_count"])
        self.assertEqual(len(summary_payload["events"]), demo["event_count"])

    def test_history_middleware_scopes_a_nondefault_slash_revision(self) -> None:
        workspace = self.client.get("/v1/nodes/node-b/workspace")
        self.assertEqual(workspace.status_code, 200, workspace.text)
        payload = workspace.json()
        revision_id = payload["demo"]["revision_id"]
        self.assertNotEqual(revision_id, REVISION_ID)
        self.assertIn("/", revision_id)

        event_page = self.client.post(
            payload["history_transport"]["events"]["query_endpoint"],
            json={"source_types": [], "limit": 2},
        )
        self.assertEqual(event_page.status_code, 200, event_page.text)
        event_payload = event_page.json()
        self.assertEqual(event_payload["revision_id"], revision_id)
        self.assertEqual(
            event_payload["total_count"],
            payload["demo"]["event_count"],
        )
        self.assertTrue(
            all(
                item["uid"].startswith("node-b/")
                for item in event_payload["items"]
            )
        )

    def test_unknown_slash_qualified_revision_is_rejected(self) -> None:
        unknown = quote("unknown/node/revision", safe="")
        response = self.client.post(
            f"/v1/revisions/{unknown}/event-log/query",
            json={"limit": 1},
        )
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(response.json()["detail"], "unknown node revision")


if __name__ == "__main__":
    unittest.main()
