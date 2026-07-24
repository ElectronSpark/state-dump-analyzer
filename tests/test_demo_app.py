from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from router_dump_analyzer.demo_app import app
from router_dump_analyzer.demo_data import REVISION_ID


class DemoAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def test_health_and_single_page_application_are_available(self) -> None:
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["mode"], "illustrative")

        page = self.client.get("/node")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Router State Lab", page.text)
        self.assertIn("Synthetic review fixture", page.text)
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertIn("styles.css?v=20260721-combinatorial-audit-v1", page.text)
        self.assertIn("app.js?v=20260722-scale-stream-v1", page.text)
        self.assertIn('id="correlation-time"', page.text)
        self.assertIn('id="correlation-panel-toggle"', page.text)
        self.assertIn('aria-controls="dependency-graph-content"', page.text)
        self.assertIn('id="correlation-back-to-top"', page.text)
        self.assertIn('id="dashboard-index"', page.text)
        self.assertIn('id="dashboard-modules"', page.text)
        self.assertNotIn('id="resource-detail"', page.text)
        self.assertNotIn("Selected object", page.text)

        script = self.client.get("/assets/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn("requestGraph", script.text)
        self.assertIn("resourceIconMarkup", script.text)
        self.assertIn("renderPluginDashboards", script.text)
        self.assertIn("resource-bundle-table", script.text)
        self.assertIn("resourceBundleRows", script.text)
        self.assertIn("dashboard-index-tree", script.text)
        self.assertIn("DASHBOARD_LAYOUT_STORAGE_KEY", script.text)
        self.assertIn("graphDisplayTimeNs", script.text)
        self.assertIn("markCorrelationPending", script.text)
        self.assertIn("resource-state-hover-facts", script.text)
        self.assertIn("focusGraphLayout", script.text)
        self.assertIn("dependencyRankLayout", script.text)
        self.assertIn("graph-column-headings", script.text)
        self.assertIn("Show all correlations", script.text)
        self.assertIn("bindCorrelationPanelControls", script.text)
        self.assertIn("syncCorrelationBackToTop", script.text)
        self.assertIn("initialFocusResourceId", script.text)
        self.assertNotIn("renderSelectedResource", script.text)
        self.assertIn("no-store", script.headers["cache-control"])
        self.assertEqual(script.headers["pragma"], "no-cache")

    def test_node_workspace_basis_selector_is_unambiguous(self) -> None:
        time_ns = "1759680005000000000"
        absolute = self.client.get(
            "/api/node-demo/node-a",
            params={
                "basis_kind": "absolute_time",
                "time_ns": time_ns,
            },
        )
        relative = self.client.get(
            "/api/node-demo/node-a",
            params={
                "basis_kind": "relative_to_watermark",
                "basis_offset_ns": "-1000",
            },
        )
        self.assertEqual(absolute.status_code, 200, absolute.text)
        self.assertEqual(relative.status_code, 200, relative.text)
        self.assertEqual(
            absolute.json()["node_snapshot"]["resolved_basis"]["requested"],
            {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": time_ns,
            },
        )
        self.assertEqual(
            relative.json()["node_snapshot"]["resolved_basis"]["requested"],
            {
                "kind": "relative_to_watermark",
                "offset_ns": "-1000",
            },
        )

        invalid_params = (
            {"basis_kind": "absolute_time"},
            {
                "basis_kind": "absolute_time",
                "basis_offset_ns": "-1",
            },
            {
                "basis_kind": "relative_to_watermark",
                "time_ns": time_ns,
            },
            {
                "time_ns": time_ns,
                "basis_offset_ns": "-1",
            },
        )
        for params in invalid_params:
            with self.subTest(params=params):
                response = self.client.get(
                    "/api/node-demo/node-a",
                    params=params,
                )
                self.assertEqual(response.status_code, 422, response.text)

    def test_frontend_manifest_routes_pages_but_does_not_publish_templates_as_assets(
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

    def test_demo_dataset_exposes_fixture_and_review_gaps(self) -> None:
        response = self.client.get("/api/demo")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["demo"]["fixture"], "synthetic")
        self.assertIn("MPLS", payload["demo"]["scenario"])
        self.assertEqual(len(payload["events"]), 25)
        self.assertEqual(len(payload["resources"]), 24)
        self.assertGreaterEqual(len(payload["gaps"]), 8)
        self.assertEqual(payload["inventory"]["mode"], "inventory-only")
        self.assertEqual(
            payload["demo"]["timeline_start_ns"], "1759680000010000000"
        )
        self.assertEqual(
            payload["demo"]["timeline_end_ns"], "1759680005500000000"
        )
        self.assertEqual(payload["demo"]["capture_ns"], "1759680006000000000")
        self.assertTrue(
            all(
                isinstance(payload["demo"][field], str)
                for field in ("timeline_start_ns", "timeline_end_ns", "capture_ns")
            )
        )

        kinds = {item["kind"] for item in payload["resources"]}
        self.assertTrue(
            {
                "FORWARDING_GROUP",
                "ETG",
                "ETE",
                "DTE",
                "VIRTUAL_INTERFACE",
                "GLUE",
                "EVPN_ROUTE",
                "ISIS_ADJACENCY",
                "MPLS_LABEL_ENTRY",
                "SRV6_LOCAL_SID",
            }
            <= kinds
        )
        self.assertNotIn("DTG", kinds)
        glue = next(
            item
            for item in payload["kind_descriptors"]
            if item["kind"] == "GLUE"
        )
        self.assertEqual(set(glue["presentation_tags"]), {"connector", "compact"})
        self.assertEqual(glue["icon"]["render_mode"], "stroke")
        self.assertTrue(glue["icon"]["path"])
        self.assertTrue(
            all(descriptor.get("icon", {}).get("path") for descriptor in payload["kind_descriptors"])
        )
        dashboards = payload["schema"]["dashboards"]
        self.assertEqual(len(dashboards), 4)
        self.assertEqual(
            {item["dashboard_id"] for item in dashboards if item["default_open"]},
            {"forwarding-health", "protocol-state"},
        )
        self.assertTrue(
            all(item.get("plugin_defined") for item in dashboards)
        )
        self.assertTrue(
            all(item["movable"] for item in dashboards)
        )

        schema = payload["schema"]
        self.assertEqual(schema["semantic_owner"], "plugin")
        self.assertFalse(schema["core_interprets_domain_types"])
        self.assertEqual(
            kinds,
            {item["kind"] for item in schema["resource_kinds"]},
        )
        self.assertEqual(
            {item["relation_type"] for item in payload["relationship_intervals"]},
            {item["relation_type"] for item in schema["relationship_types"]},
        )
        self.assertEqual(
            {item["link_type"] for item in payload["causal_links"]},
            {item["link_type"] for item in schema["causal_link_types"]},
        )
        resource_table_views = schema["resource_table_views"]
        self.assertEqual(
            [item["view_id"] for item in resource_table_views],
            ["etg-path-bundles"],
        )
        self.assertTrue(resource_table_views[0]["default_selected"])
        self.assertEqual(
            [
                level["relation_types"]
                for level in resource_table_views[0]["levels"]
            ],
            [["owns"], ["next_hop"]],
        )

        failed = [event for event in payload["events"] if event["outcome"] == "failure"]
        self.assertEqual(len(failed), 1)
        self.assertFalse(failed[0]["state_changed"])
        self.assertEqual(failed[0]["effects"], [])

    def test_graph_switches_the_forwarding_group_selected_ete(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/graph/query"
        before = self.client.post(
            path, json={"time_ns": "1759680003019000000"}
        ).json()
        after = self.client.post(
            path, json={"time_ns": "1759680003021000000"}
        ).json()
        source = "data-bridge-layer/FORWARDING_GROUP/fg-blue-east"
        self.assertTrue(all(node.get("icon", {}).get("path") for node in after["nodes"]))

        before_targets = {
            edge["target"]
            for edge in before["edges"]
            if edge["source"] == source and edge["type"] == "selected_egress"
        }
        after_targets = {
            edge["target"]
            for edge in after["edges"]
            if edge["source"] == source and edge["type"] == "selected_egress"
        }
        self.assertEqual(
            before_targets,
            {"data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"},
        )
        self.assertEqual(
            after_targets,
            {"data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2"},
        )

    def test_graph_excludes_resources_outside_their_lifecycle(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/graph/query"
        etg = "data-bridge-layer/ETG/blue/etg-evpn-east"
        retired_ete = "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"
        recreated_route = (
            "control-plane/EVPN_ROUTE/blue/mac-02:00:00:00:00:11"
        )

        cases = [
            ("1759680000129999999", etg, False),
            ("1759680000130000000", etg, True),
            ("1759680004499999999", retired_ete, True),
            ("1759680004500000000", retired_ete, False),
            ("1759680003022000000", recreated_route, False),
            ("1759680003023000000", recreated_route, True),
        ]
        for timestamp_ns, resource_id, expected_present in cases:
            with self.subTest(timestamp_ns=timestamp_ns, resource_id=resource_id):
                payload = self.client.post(
                    path, json={"time_ns": timestamp_ns}
                ).json()
                node_ids = {node["id"] for node in payload["nodes"]}
                self.assertEqual(resource_id in node_ids, expected_present)
                self.assertTrue(
                    all(
                        edge["source"] in node_ids and edge["target"] in node_ids
                        for edge in payload["edges"]
                    )
                )

    def test_correlation_query_for_inactive_root_is_empty(self) -> None:
        resource_id = "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/correlations/query",
            json={
                "time_ns": "1759680004500000000",
                "resource_ids": [resource_id],
                "depth": 5,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["nodes"], [])
        self.assertEqual(response.json()["edges"], [])

    def test_failed_event_is_visible_but_does_not_split_resource_state(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/graph/query"
        before = self.client.post(
            path, json={"time_ns": "1759680003014999999"}
        ).json()
        after = self.client.post(
            path, json={"time_ns": "1759680003015000001"}
        ).json()
        resource_id = "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2"
        before_node = next(node for node in before["nodes"] if node["id"] == resource_id)
        after_node = next(node for node in after["nodes"] if node["id"] == resource_id)

        self.assertEqual(before_node["status_value"], "standby")
        self.assertEqual(after_node["status_value"], "standby")
        self.assertEqual(before_node["state"], after_node["state"])

        timeline_path = f"/v1/revisions/{REVISION_ID}/timeline/query"
        timeline = self.client.post(
            timeline_path,
            json={"resource_ids": [resource_id]},
        ).json()
        self.assertTrue(timeline["selection"]["independent_controls"])
        self.assertEqual([lane["lane_id"] for lane in timeline["lanes"]], [resource_id])
        lane = timeline["lanes"][0]
        failed_mark = next(mark for mark in lane["event_marks"] if mark["outcome"] == "failure")
        self.assertFalse(failed_mark["state_changed"])
        self.assertEqual(failed_mark["effect_type"], "none")
        self.assertGreaterEqual(len(lane["status_intervals"]), 3)

    def test_timeline_returns_filtered_temporal_correlations(self) -> None:
        prefix = f"/v1/revisions/{REVISION_ID}"
        forwarding_group = "data-bridge-layer/FORWARDING_GROUP/fg-blue-east"
        old_ete = "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"
        new_ete = "data-bridge-layer/ETE/etg-evpn-east/ete-srv6-p2"
        dte = "data-bridge-layer/DTE/dte-mpls-16011"
        etg = "data-bridge-layer/ETG/blue/etg-evpn-east"
        ip_routing = "control-plane/IP_ROUTING/blue"
        requested_ids = {
            forwarding_group,
            old_ete,
            new_ete,
            dte,
            etg,
            ip_routing,
        }
        payload = self.client.post(
            prefix + "/timeline/query",
            json={
                "start_ns": "1759680003019000000",
                "end_ns": "1759680004110000000",
                "resource_ids": sorted(requested_ids),
                "cursor_time_ns": 1759680003020000000,
                "range": {
                    "start_ns": 1759680003019000000,
                    "end_ns": 1759680004110000000,
                },
            },
        ).json()

        self.assertEqual(
            {lane["resource_id"] for lane in payload["lanes"]}, requested_ids
        )
        self.assertEqual(
            payload["selection"]["cursor_time_ns"], "1759680003020000000"
        )
        self.assertEqual(
            payload["selection"]["range"],
            {
                "start_ns": "1759680003019000000",
                "end_ns": "1759680004110000000",
            },
        )
        self.assertTrue(
            all(
                {item["source"], item["target"]} <= requested_ids
                for item in payload["relationship_intervals"]
                + payload["relationship_mutations"]
            )
        )
        selected = [
            item
            for item in payload["relationship_intervals"]
            if item["relation_type"] == "selected_egress"
        ]
        self.assertEqual({item["target"] for item in selected}, {old_ete, new_ete})
        next_hops = [
            item
            for item in payload["relationship_intervals"]
            if item["relation_type"] == "next_hop" and item["source"] == dte
        ]
        self.assertEqual({item["target"] for item in next_hops}, {etg, ip_routing})
        for item in selected + next_hops:
            self.assertIsNotNone(item["descriptor"])
            self.assertIn("provenance", item)
            self.assertIn("quality", item)
            self.assertIn("start_event_uid", item)
            self.assertIn("end_event_uid", item)

        mutations = payload["relationship_mutations"]
        self.assertEqual(
            {
                (item["relation_type"], item["operation"])
                for item in mutations
                if item["relation_type"] in {"selected_egress", "next_hop"}
            },
            {
                ("selected_egress", "remove"),
                ("selected_egress", "add"),
                ("next_hop", "remove"),
                ("next_hop", "add"),
            },
        )
        descriptor_types = {
            item["relation_type"]
            for item in payload["relationship_type_descriptors"]
        }
        self.assertTrue({"selected_egress", "next_hop"} <= descriptor_types)

        only_group = self.client.post(
            prefix + "/timeline/query",
            json={
                "start_ns": "1759680003019000000",
                "end_ns": "1759680004110000000",
                "resource_ids": [forwarding_group],
            },
        ).json()
        self.assertEqual(
            [lane["resource_id"] for lane in only_group["lanes"]],
            [forwarding_group],
        )
        self.assertEqual(only_group["relationship_intervals"], [])
        self.assertEqual(only_group["relationship_mutations"], [])

    def test_resource_tables_and_range_summary_are_temporal(self) -> None:
        prefix = f"/v1/revisions/{REVISION_ID}"
        tables = self.client.post(
            prefix + "/resources/query",
            json={
                "time_ns": "1759680004200000000",
                "kinds": ["DTE"],
            },
        ).json()
        dte = next(
            item
            for item in tables["items"]
            if item["resource_id"].endswith("dte-mpls-16011")
        )
        self.assertEqual(dte["state"]["next_hop_mode"], "IP_ROUTING")

        summary = self.client.post(
            prefix + "/range/summary",
            json={
                "start_ns": "1759680003000000000",
                "end_ns": "1759680003600000000",
            },
        ).json()
        self.assertGreater(summary["event_count"], 5)
        self.assertGreater(len(summary["endpoint_diff"]), 1)
        self.assertIn(
            "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
            summary["affected_resources"],
        )
        self.assertIn("highlight", summary["selection_behavior"])
        self.assertTrue(
            all(
                item["relationship_id"]
                and isinstance(item["effective_time_ns"], str)
                for item in summary["relationship_changes"]
            )
        )
        self.assertTrue(
            all(
                item["source"] in summary["affected_resources"]
                and item["target"] in summary["affected_resources"]
                for item in summary["relationship_changes"]
            )
        )

    def test_relationship_bundles_keep_temporary_children_independent(self) -> None:
        prefix = f"/v1/revisions/{REVISION_ID}/resources/query"
        primary = "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1"
        before_response = self.client.post(
            prefix,
            json={
                "time_ns": "1759680004400000000",
                "view_id": "etg-path-bundles",
            },
        )
        self.assertEqual(before_response.status_code, 200)
        before = before_response.json()
        self.assertEqual(before["view_id"], "etg-path-bundles")
        self.assertEqual(before["matched_count"], 2)
        self.assertTrue(
            all(bundle["resource"]["kind"] == "ETG" for bundle in before["bundles"])
        )
        children = [
            child
            for bundle in before["bundles"]
            for child in bundle["children"]
        ]
        self.assertTrue(children)
        self.assertTrue(all(child["resource"]["kind"] == "ETE" for child in children))
        self.assertTrue(
            all(child["relationship"]["type"] == "owns" for child in children)
        )
        self.assertTrue(
            all(
                next_hop["relationship"]["type"] == "next_hop"
                and next_hop["resource"]["kind"] in {"ETG", "IP_ROUTING"}
                for child in children
                for next_hop in child["children"]
            )
        )
        temporary = next(
            child for child in children if child["resource"]["resource_id"] == primary
        )
        self.assertEqual(
            set(temporary["resource"]["resource"]["key"]),
            {"parent_resource_id", "path_id"},
        )
        self.assertEqual(
            temporary["relationship"]["valid_to_ns"],
            "1759680004500000000",
        )

        after = self.client.post(
            prefix,
            json={
                "time_ns": "1759680004600000000",
                "view_id": "etg-path-bundles",
            },
        ).json()
        self.assertNotIn(
            primary,
            {
                child["resource"]["resource_id"]
                for bundle in after["bundles"]
                for child in bundle["children"]
            },
        )

        flat = self.client.post(
            prefix,
            json={
                "time_ns": "1759680004600000000",
                "kinds": ["ETE"],
            },
        ).json()
        retired = next(item for item in flat["items"] if item["resource_id"] == primary)
        self.assertFalse(retired["exists"])

        unknown = self.client.post(
            prefix,
            json={"view_id": "not-declared"},
        )
        self.assertEqual(unknown.status_code, 400)

    def test_route_endpoint_makes_precomputed_status_explicit(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/routes/resolve"
        response = self.client.post(
            path,
            json={
                "destination": "203.0.113.42",
                "basis_kind": "reconstructed_time",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["demo_precomputed"])
        self.assertEqual(payload["quality"], "best_effort")

    def test_temporal_topology_capabilities_expose_plugin_choices_and_two_clocks(self) -> None:
        prefix = f"/v1/revisions/{REVISION_ID}/topology"
        capabilities = self.client.get(prefix + "/capabilities")
        providers = self.client.get(prefix + "/providers")

        self.assertEqual(capabilities.status_code, 200)
        self.assertEqual(providers.status_code, 200)
        payload = capabilities.json()
        self.assertEqual(payload, providers.json())
        self.assertEqual(
            payload["default_projection_id"], "plugin.resource-association"
        )
        self.assertIn(
            "plugin.underlay-connectivity",
            {item["projection_id"] for item in payload["topology_projections"]},
        )
        self.assertEqual(
            {item["node_id"] for item in payload["nodes"]},
            {"node-a", "node-b"},
        )
        self.assertFalse(
            next(item for item in payload["nodes"] if item["node_id"] == "node-b")[
                "resources_available"
            ]
        )
        self.assertEqual(payload["semantic_ownership"]["projection"], "plugin")

    def test_absolute_topology_query_preserves_clock_ambiguity(self) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/topology/query",
            json={
                "topology_projection_id": "plugin.underlay-connectivity",
                "status_perspective_id": "control-plane",
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680003010000000",
                },
                "node_ids": ["node-a", "node-b"],
                "resource_ids": [
                    "control-plane/ISIS_ADJACENCY/pe-a/p-1",
                    "control-plane/ISIS_ADJACENCY/pe-a/p-2",
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["projection_id"], payload["topology_projection_id"]
        )
        self.assertEqual(payload["resolved_basis"]["kind"], "absolute_time")
        self.assertEqual(
            len({item["local_time_ns"] for item in payload["node_times"]}), 2
        )
        p1 = next(
            item
            for item in payload["resources"]
            if item["resource_id"].endswith("ISIS_ADJACENCY/pe-a/p-1")
        )
        self.assertEqual(p1["temporal_resolution"], "ambiguous")
        self.assertIsNone(p1["exists"])
        link = next(
            item
            for item in payload["inferred_connectivity"]
            if item["connectivity_id"] == "underlay:pe-a:p-1"
        )
        self.assertEqual(link["operational"]["status"], "ambiguous")
        self.assertFalse(payload["completeness"]["complete"])
        self.assertIn("node-b", payload["completeness"]["incomplete_nodes"])

    def test_relative_watermark_is_a_non_simultaneous_capture_vector(self) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/state/query",
            json={
                "projection_id": "plugin.resource-association",
                "status_perspective_id": "hardware-driver-plane",
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "-10000000",
                },
                "limit": 3,
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["resolved_basis"]["kind"], "relative_capture_vector"
        )
        self.assertEqual(payload["resolved_basis"]["simultaneity"], "not_implied")
        self.assertEqual(len(payload["node_times"]), 2)
        self.assertEqual(
            len({item["query_time_ns"] for item in payload["node_times"]}), 2
        )
        self.assertLessEqual(len(payload["resources"]), 3)
        self.assertTrue(
            all(item["layer"] == "hardware-driver-plane" for item in payload["resources"])
        )

    def test_temporal_topology_keeps_identity_stable_across_status_perspectives(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/topology/query"
        resource_ids = [
            "control-plane/ISIS_ADJACENCY/pe-a/p-1",
            "data-bridge-layer/VIRTUAL_INTERFACE/vi-p1",
        ]
        common = {
            "projection_id": "plugin.underlay-connectivity",
            "node_ids": ["node-a"],
            "basis": {
                "kind": "absolute_time",
                "clock_domain": "utc",
                "time_ns": "1759680003030000000",
            },
            "resource_ids": resource_ids,
            "include": ["resources", "inferred_connectivity"],
        }
        control = self.client.post(
            path, json={**common, "status_perspective_id": "control-plane"}
        ).json()
        bridge = self.client.post(
            path, json={**common, "status_perspective_id": "data-bridge-layer"}
        ).json()

        self.assertEqual(
            [item["resource_id"] for item in control["resources"]],
            [item["resource_id"] for item in bridge["resources"]],
        )
        self.assertTrue(
            all(item["status_perspective_id"] == "control-plane" for item in control["resources"])
        )
        self.assertTrue(
            all(item["status_perspective_id"] == "data-bridge-layer" for item in bridge["resources"])
        )
        control_by_id = {item["resource_id"]: item for item in control["resources"]}
        bridge_by_id = {item["resource_id"]: item for item in bridge["resources"]}
        self.assertEqual(
            control_by_id["data-bridge-layer/VIRTUAL_INTERFACE/vi-p1"]["status"],
            "unknown",
        )
        self.assertEqual(
            bridge_by_id["control-plane/ISIS_ADJACENCY/pe-a/p-1"]["status"],
            "unknown",
        )
        self.assertEqual(
            [item["connectivity_id"] for item in control["inferred_connectivity"][:2]],
            [item["connectivity_id"] for item in bridge["inferred_connectivity"][:2]],
        )

    def test_absolute_clock_domain_is_validated_and_watermarks_are_projection_scoped(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/topology/query"
        invalid = self.client.post(
            path,
            json={
                "projection_id": "plugin.resource-association",
                "status_perspective_id": "data-bridge-layer",
                "basis": {
                    "kind": "absolute_time",
                    "clock_domain": "tai",
                    "time_ns": "1759680003030000000",
                },
            },
        )
        self.assertEqual(invalid.status_code, 422)

        base = {
            "status_perspective_id": "data-bridge-layer",
            "node_ids": ["node-a"],
            "basis": {"kind": "relative_to_watermark", "offset_ns": "0"},
            "resource_limit": 1,
        }
        association = self.client.post(
            path,
            json={**base, "projection_id": "plugin.resource-association"},
        ).json()
        underlay = self.client.post(
            path,
            json={**base, "projection_id": "plugin.underlay-connectivity"},
        ).json()
        self.assertEqual(
            association["resolved_basis"]["anchor"]["topology_projection_id"],
            "plugin.resource-association",
        )
        self.assertNotEqual(
            association["node_times"][0]["watermark_query_time_ns"],
            underlay["node_times"][0]["watermark_query_time_ns"],
        )

    def test_topology_query_returns_bounded_historical_changes(self) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/topology/query",
            json={
                "projection_id": "plugin.resource-association",
                "status_perspective_id": "data-bridge-layer",
                "node_ids": ["node-a"],
                "basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680003030000000",
                },
                "change_start_ns": "1759680003011000000",
                "change_limit": 3,
                "include": ["resources", "changes"],
                "resource_ids": [
                    "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
                    "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1",
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertLessEqual(len(payload["changes"]), 3)
        self.assertTrue(payload["changes"])
        self.assertTrue(
            all(
                "effective_time_ns" in item and "change_kind" in item
                for item in payload["changes"]
            )
        )
        self.assertEqual(payload["semantic_ownership"]["temporal_query"], "core")

        replay = self.client.post(
            f"/v1/revisions/{REVISION_ID}/topology/changes/query",
            json={
                "topology_projection_id": "plugin.resource-association",
                "status_perspective_id": "data-bridge-layer",
                "node_ids": ["node-a"],
                "start_basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680003011000000",
                    "clock_domain": "utc",
                },
                "end_basis": {
                    "kind": "absolute_time",
                    "time_ns": "1759680003030000000",
                    "clock_domain": "utc",
                },
                "resource_ids": [
                    "data-bridge-layer/FORWARDING_GROUP/fg-blue-east",
                    "data-bridge-layer/ETE/etg-evpn-east/ete-srmpls-p1",
                ],
                "page_size": 3,
            },
        )
        self.assertEqual(replay.status_code, 200)
        replay_payload = replay.json()
        self.assertLessEqual(replay_payload["returned_count"], 3)
        self.assertTrue(replay_payload["changes"])
        self.assertEqual(replay_payload["node_ranges"][0]["node_id"], "node-a")

    def test_temporal_topology_pages_resources_and_bounds_connectivity(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/topology/query"
        request = {
            "projection_id": "plugin.underlay-connectivity",
            "status_perspective_id": "control-plane",
            "node_ids": ["node-a"],
            "basis": {
                "kind": "absolute_time",
                "time_ns": "1759680003030000000",
            },
            "include": ["resources", "inferred_connectivity"],
            "resource_limit": 2,
            "connectivity_limit": 1,
        }
        first_response = self.client.post(path, json=request)
        self.assertEqual(first_response.status_code, 200)
        first = first_response.json()
        self.assertEqual(len(first["resources"]), 2)
        self.assertIsNotNone(first["next_resource_cursor"])
        self.assertTrue(first["counts"]["resources"]["truncated"])
        self.assertEqual(len(first["inferred_connectivity"]), 1)
        self.assertTrue(first["counts"]["inferred_connectivity"]["truncated"])
        self.assertGreater(
            first["counts"]["inferred_connectivity"]["total_count"], 1
        )

        second_request = {
            **request,
            "resource_cursor": first["next_resource_cursor"],
        }
        second_response = self.client.post(path, json=second_request)
        self.assertEqual(second_response.status_code, 200)
        second = second_response.json()
        self.assertEqual(second["counts"]["resources"]["offset"], 2)
        self.assertFalse(
            {item["resource_id"] for item in first["resources"]}
            & {item["resource_id"] for item in second["resources"]}
        )

        mismatched = {
            **second_request,
            "status_perspective_id": "data-bridge-layer",
        }
        self.assertEqual(self.client.post(path, json=mismatched).status_code, 422)

    def test_topology_change_cursor_replays_without_overlap(self) -> None:
        path = f"/v1/revisions/{REVISION_ID}/topology/changes/query"
        request = {
            "topology_projection_id": "plugin.resource-association",
            "status_perspective_id": "data-bridge-layer",
            "node_ids": ["node-a"],
            "start_basis": {
                "kind": "absolute_time",
                "time_ns": "1759680000010000000",
            },
            "end_basis": {
                "kind": "absolute_time",
                "time_ns": "1759680005500000000",
            },
            "page_size": 2,
        }
        first_response = self.client.post(path, json=request)
        self.assertEqual(first_response.status_code, 200)
        first = first_response.json()
        self.assertEqual(first["returned_count"], 2)
        self.assertTrue(first["truncated"])
        self.assertFalse(first["total_count_is_exact"])
        self.assertIsNotNone(first["next_cursor"])

        second_response = self.client.post(
            path,
            json={**request, "cursor": first["next_cursor"]},
        )
        self.assertEqual(second_response.status_code, 200)
        second = second_response.json()
        self.assertEqual(second["counts"]["changes"]["position"], 2)
        self.assertFalse(
            {item["change_id"] for item in first["changes"]}
            & {item["change_id"] for item in second["changes"]}
        )
        ordered = first["changes"] + second["changes"]
        self.assertEqual(
            [int(item["effective_time_ns"]) for item in ordered],
            sorted(int(item["effective_time_ns"]) for item in ordered),
        )

        tampered = first["next_cursor"][:-1] + (
            "0" if first["next_cursor"][-1] != "0" else "1"
        )
        invalid_response = self.client.post(
            path,
            json={**request, "cursor": tampered},
        )
        self.assertEqual(invalid_response.status_code, 422)

    def test_unknown_revision_and_unsupported_destination_are_rejected(self) -> None:
        self.assertEqual(
            self.client.get("/v1/revisions/not-a-revision/events").status_code,
            404,
        )
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/routes/resolve",
            json={"destination": "198.18.0.1"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
