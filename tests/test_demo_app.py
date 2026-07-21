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

        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Router State Lab", page.text)
        self.assertIn("Synthetic review fixture", page.text)
        self.assertIn("no-store", page.headers["cache-control"])
        self.assertIn("styles.css?v=20260720-full-scale-125k", page.text)
        self.assertIn("app.js?v=20260720-source-record-scroll", page.text)
        self.assertIn('id="correlation-time"', page.text)
        self.assertIn('id="dashboard-index"', page.text)
        self.assertIn('id="dashboard-modules"', page.text)
        self.assertNotIn('id="resource-detail"', page.text)
        self.assertNotIn("Selected object", page.text)

        script = self.client.get("/assets/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn("requestGraph", script.text)
        self.assertIn("resourceIconMarkup", script.text)
        self.assertIn("renderPluginDashboards", script.text)
        self.assertIn("dashboard-index-tree", script.text)
        self.assertIn("DASHBOARD_LAYOUT_STORAGE_KEY", script.text)
        self.assertIn("graphDisplayTimeNs", script.text)
        self.assertIn("markCorrelationPending", script.text)
        self.assertIn("resource-state-hover-facts", script.text)
        self.assertIn("focusGraphLayout", script.text)
        self.assertIn("dependencyRankLayout", script.text)
        self.assertIn("graph-column-headings", script.text)
        self.assertIn("Show all correlations", script.text)
        self.assertNotIn("renderSelectedResource", script.text)
        self.assertIn("no-store", script.headers["cache-control"])
        self.assertEqual(script.headers["pragma"], "no-cache")

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
