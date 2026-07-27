from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from router_dump_analyzer.multi_node_topology import MultiNodeTopologyService
from router_dump_analyzer.web import runtime_api
from rsl_demo_generator import (
    COVERAGE_CASES,
    DEMO_NODES,
    AssemblyConfig,
    build_demo_fixture,
)
from rsl_demo_generator.catalog import DEFAULT_SCENARIO_SOURCE
from rsl_demo_generator.assembly import _source_resource_id
from rsl_demo_plugin.topology_contract import (
    build_topology_contract,
    build_topology_metadata,
    build_topology_profiles,
)
from tests.support.generated_demo import (
    generated_demo_application,
    query_all_route_table_rows,
)


EVENTS_PER_NODE = 120
RESOURCES_PER_NODE = 120
ASSEMBLY_ID = "integration.generated-small-v1"
SELECTED_NODE_IDS = tuple(node.node_id for node in DEMO_NODES)
_DEMO_NODE_BY_ID = {node.node_id: node for node in DEMO_NODES}
SELECTED_NODES = tuple(
    _DEMO_NODE_BY_ID[node_id] for node_id in SELECTED_NODE_IDS
)


def _clear_app_caches() -> None:
    runtime_api.reset_runtime_api_caches()


class GeneratedAssemblyApiIntegrationTests(unittest.TestCase):
    """Prove node and fabric APIs read one generated revision assembly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.environment = mock.patch.dict(
            os.environ,
            {
                "ROUTER_DUMP_SEARCH_CACHE_DIR": str(
                    cls.root / "search-cache"
                ),
            },
        )
        cls.environment.start()
        cls.archive = build_demo_fixture(
            cls.root / "small-assembly.tgz",
            config=AssemblyConfig(
                nodes=SELECTED_NODES,
                events_per_node=EVENTS_PER_NODE,
                resources_per_node=RESOURCES_PER_NODE,
                seed=24680,
                allow_small=True,
                assembly_id=ASSEMBLY_ID,
            ),
        )
        _clear_app_caches()
        cls.application = generated_demo_application(cls.archive)
        cls.client_context = TestClient(cls.application)
        cls.client = cls.client_context.__enter__()
        store = cls.application.state.runtime_session.revision_store
        cls.store = store
        cls.route_demo = (
            cls.application.state.runtime_session.route_provider.get()
        )
        cls.descriptors = {
            descriptor.node_id: descriptor
            for descriptor in store.assembly.revisions
        }
        cls.projections = {
            node_id: store.projection_for_node(node_id)
            for node_id in cls.descriptors
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)
        _clear_app_caches()
        _clear_app_caches()
        cls.environment.stop()
        cls.temporary.cleanup()

    def test_node_workspace_uses_generated_revision_and_inventory_counts(
        self,
    ) -> None:
        for node_id, descriptor in self.descriptors.items():
            with self.subTest(node_id=node_id):
                response = self.client.get(f"/v1/nodes/{node_id}/workspace")
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()

                self.assertEqual(payload["demo"]["assembly_id"], ASSEMBLY_ID)
                self.assertEqual(
                    payload["demo"]["revision_id"],
                    descriptor.revision_id,
                )
                self.assertEqual(
                    payload["demo"]["event_count"],
                    descriptor.event_count,
                )
                self.assertEqual(
                    payload["demo"]["resource_count"],
                    descriptor.resource_count,
                )
                self.assertEqual(
                    descriptor.event_count,
                    EVENTS_PER_NODE
                    + len(
                        DEFAULT_SCENARIO_SOURCE.observations_by_node[
                            node_id
                        ]
                    ),
                )
                self.assertEqual(
                    descriptor.resource_count,
                    RESOURCES_PER_NODE
                    + len(DEFAULT_SCENARIO_SOURCE.resources_at(node_id)),
                )
                self.assertEqual(
                    len(payload["resources"]),
                    descriptor.resource_count,
                )
                self.assertEqual(
                    payload["history_transport"]["events"]["total_count"],
                    descriptor.event_count,
                )
                self.assertEqual(
                    payload["node_snapshot"]["revision_id"],
                    descriptor.revision_id,
                )
                self.assertEqual(
                    payload["node_snapshot"]["event_count"],
                    descriptor.event_count,
                )
                self.assertEqual(
                    payload["node_snapshot"]["resource_count"],
                    descriptor.resource_count,
                )
                self.assertEqual(
                    payload["node_snapshot"]["source"],
                    "plugin-revision-store",
                )
                self.assertTrue(
                    all(
                        item["resource_id"].startswith(f"{node_id}/")
                        for item in payload["resources"]
                    )
                )

    def test_saved_history_drives_single_node_past_state(self) -> None:
        source = DEFAULT_SCENARIO_SOURCE
        node = next(item for item in DEMO_NODES if item.node_id == "node-a")
        resource_id = _source_resource_id(
            "node-a",
            "IP_ROUTE",
            "route:blue:198.51.100.0/30",
        )
        service = self.application.state.runtime_session.data_service

        def state(offset_ns: int) -> dict[str, object]:
            return service.resource_state_at(
                resource_id,
                source.base_time_ns + offset_ns + node.clock_offset_ns,
            )

        self.assertFalse(state(29_999_999_999)["exists"])
        created = state(30_000_000_000)
        self.assertTrue(created["exists"])
        self.assertEqual(created["status"], "installed")
        self.assertFalse(state(210_000_000_000)["exists"])
        restored = state(270_000_000_000)
        self.assertTrue(restored["exists"])
        self.assertEqual(restored["state"]["next_hop"], "10.64.0.2")
        self.assertTrue(
            {
                "source_resource_id",
                "source_scenario_id",
                "updated_at_ns",
            }.isdisjoint(restored["state"])
        )

    def test_saved_local_observations_drive_past_topology(self) -> None:
        source = DEFAULT_SCENARIO_SOURCE

        def segment(offset_ns: int, prefix: str) -> dict[str, object]:
            response = self.client.post(
                "/v1/topologies/query",
                json={
                    "basis": {
                        "kind": "absolute_time",
                        "clock_domain": "utc",
                        "time_ns": str(source.base_time_ns + offset_ns),
                    },
                    "resource_limit": 500,
                    "network_segment_limit": 100,
                    "segment_attachment_limit": 500,
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            return next(
                item
                for item in response.json()["network_segments"]
                if item["prefix"] == prefix
            )

        transport_before = segment(90_049_999_999, "10.64.255.0/31")
        transport_diverged = segment(96_000_000_000, "10.64.255.0/31")
        transport_restored = segment(242_500_000_000, "10.64.255.0/31")
        self.assertEqual(transport_before["operational_status"], "usable")
        self.assertEqual(transport_diverged["operational_status"], "degraded")
        self.assertEqual(transport_restored["operational_status"], "usable")

        west_detached = segment(181_000_000_000, "10.64.0.0/24")
        west_restored = segment(304_000_000_000, "10.64.0.0/24")
        self.assertNotIn("node-d", west_detached["node_ids"])
        self.assertIn("node-d", west_restored["node_ids"])

    def test_topology_and_route_tables_share_generated_revisions_and_projections(
        self,
    ) -> None:
        node_ids = list(self.descriptors)
        capabilities_response = self.client.get(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/capabilities"
        )
        self.assertEqual(
            capabilities_response.status_code,
            200,
            capabilities_response.text,
        )
        capabilities = capabilities_response.json()
        self.assertEqual(capabilities["assembly_id"], ASSEMBLY_ID)
        generated_profile = next(
            item
            for item in capabilities["topology_profiles"]
            if item["profile_id"] == "fabric-underlay"
        )
        self.assertEqual(
            generated_profile["presentation_roles"],
            ["underlay"],
        )
        available_members = {
            item["node_id"]: item
            for item in capabilities["nodes"]
            if item["available"]
        }
        self.assertEqual(set(available_members), set(node_ids))
        for node_id, descriptor in self.descriptors.items():
            self.assertEqual(
                available_members[node_id]["revision_id"],
                descriptor.revision_id,
            )
            self.assertEqual(
                available_members[node_id]["default_projection_id"],
                f"{node_id}.generated-topology",
            )

        topology_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/query",
            json={
                "node_ids": node_ids,
                "resource_limit": 500,
                "network_segment_limit": 500,
                "segment_attachment_limit": 4000,
            },
        )
        self.assertEqual(
            topology_response.status_code,
            200,
            topology_response.text,
        )
        topology = topology_response.json()
        self.assertEqual(topology["assembly_id"], ASSEMBLY_ID)
        topology_nodes = {
            item["node_id"]: item for item in topology["nodes"]
        }
        self.assertEqual(set(topology_nodes), set(node_ids))
        attachment_resources_by_node: dict[str, set[str]] = {
            node_id: set() for node_id in node_ids
        }
        for attachment in topology["segment_attachments"]:
            attachment_resources_by_node[attachment["node_id"]].add(
                attachment["resource_id"]
            )
        for node_id, descriptor in self.descriptors.items():
            node = topology_nodes[node_id]
            source_topology = self.projections[node_id]["topology"]
            source_resource_ids = {
                item["resource_id"]
                for item in source_topology["resources"]
            }
            source_claim_resource_ids = {
                item["interface_resource_id"]
                for item in source_topology["claims"]
            }
            returned_resource_ids = {
                item["resource_id"] for item in node["resources"]
            }

            self.assertEqual(node["revision_id"], descriptor.revision_id)
            self.assertTrue(
                source_resource_ids.issubset(returned_resource_ids)
            )
            self.assertTrue(
                source_claim_resource_ids.issubset(
                    attachment_resources_by_node[node_id]
                )
            )
            self.assertTrue(
                any(
                    result["projection_id"]
                    == f"{node_id}.generated-topology"
                    for result in node["plugin_results"]
                )
            )

        route_capabilities_response = self.client.get(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/capabilities"
        )
        self.assertEqual(
            route_capabilities_response.status_code,
            200,
            route_capabilities_response.text,
        )
        route_capabilities = route_capabilities_response.json()
        self.assertEqual(route_capabilities["assembly_id"], ASSEMBLY_ID)
        self.assertIn(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/",
            route_capabilities["route_table_query_href"],
        )
        self.assertIn(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/",
            route_capabilities["trace_href"],
        )

        route_table = query_all_route_table_rows(
            self.client,
            {"node_ids": node_ids},
        )
        self.assertEqual(route_table["assembly_id"], ASSEMBLY_ID)
        self.assertFalse(route_table["page"]["truncated"])
        self.assertTrue(route_table["items"])

        rows_by_node: dict[str, list[dict[str, object]]] = {
            node_id: [] for node_id in node_ids
        }
        for row in route_table["items"]:
            rows_by_node[row["node_id"]].append(row)
        for node_id, descriptor in self.descriptors.items():
            source_route_ids = {
                item["route_id"]
                for item in self.projections[node_id]["routes"]
            }
            returned = rows_by_node[node_id]
            self.assertTrue(returned)
            self.assertTrue(
                {
                    str(item["route_entry_id"])
                    for item in returned
                }.issubset(source_route_ids)
            )
            for item in returned:
                self.assertEqual(
                    item["route_entry_ref"]["assembly_id"],
                    ASSEMBLY_ID,
                )
                self.assertEqual(
                    item["attributes"]["revision_id"],
                    descriptor.revision_id,
                )
                self.assertEqual(
                    item["plugin_provenance"]["data_kind"],
                    "generated_route_table_row",
                )

    def test_generated_topology_is_independent_of_static_contract_nodes(
        self,
    ) -> None:
        dataset = self.store.dataset_for_revision(
            self.store.default_revision_id
        )
        self.assertFalse(hasattr(MultiNodeTopologyService, "_demo_contract"))
        self.assertFalse(
            hasattr(
                MultiNodeTopologyService,
                "for_static_fixture",
            )
        )
        self.assertFalse(
            hasattr(
                MultiNodeTopologyService,
                "for_contract_fixture",
            )
        )
        contract = build_topology_contract(self.store)
        topology_demo = MultiNodeTopologyService(
            contract=contract,
            topology_profiles=build_topology_profiles(contract),
            topology_metadata=build_topology_metadata(
                dict(dataset),
                self.store,
            ),
        )
        capabilities = topology_demo.capabilities()
        snapshot = topology_demo.query(
            {
                "node_ids": list(self.descriptors),
                "resource_limit": 500,
                "network_segment_limit": 500,
                "segment_attachment_limit": 4000,
            }
        )

        self.assertEqual(
            {item["node_id"] for item in capabilities["nodes"]},
            set(self.descriptors),
        )
        self.assertEqual(capabilities["inter_node_matchers"], [])
        self.assertEqual(
            {item["node_id"] for item in snapshot["nodes"]},
            set(self.descriptors),
        )
        self.assertGreater(len(snapshot["segment_attachments"]), 0)

    def test_route_capabilities_use_only_generated_catalog_descriptors(
        self,
    ) -> None:
        response = self.client.get(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/capabilities"
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()

        self.assertTrue(payload["scenarios"])
        self.assertTrue(
            all(
                item["descriptor_source"]
                == "generated_coverage_registry"
                for item in payload["scenarios"]
            )
        )
        self.assertTrue(payload["route_catalog"])
        self.assertTrue(
            all(
                item["descriptor_source"]
                == "generated_plugin_projection"
                for item in payload["route_catalog"]
            )
        )
        for field in ("sources", "start_points", "destinations"):
            self.assertTrue(payload[field])
            self.assertTrue(
                all(
                    item["descriptor_source"]
                    == "generated_assembly_catalog"
                    for item in payload[field]
                )
            )
        self.assertEqual(
            payload["network_model"]["descriptor_source"],
            "generated_assembly_catalog",
        )
        self.assertTrue(payload["route_resolvers"])
        self.assertTrue(
            all(
                item["descriptor_source"]
                == "generated_projection_manifest"
                for item in payload["route_resolvers"]
            )
        )
        self.assertNotIn(
            "demo.alpha.platform",
            {
                item.get("plugin_id")
                for item in payload["route_resolvers"]
            },
        )

    def test_generated_route_capability_ids_and_default_trace_are_consistent(
        self,
    ) -> None:
        response = self.client.get(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/capabilities"
        )
        self.assertEqual(response.status_code, 200, response.text)
        capability = response.json()
        self.assertEqual(
            capability["trace_href"],
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
        )

        scenarios = {
            item["scenario_id"]: item for item in capability["scenarios"]
        }
        sources = {
            item["source_id"]: item for item in capability["sources"]
        }
        starts = {
            item["start_id"]: item for item in capability["start_points"]
        }
        destinations = {
            item["destination_id"]: item
            for item in capability["destinations"]
        }
        route_scenario_ids = {
            item["scenario_id"]
            for item in capability["route_catalog"]
            if item.get("scenario_id")
        }

        default_request = capability["default_request"]
        default_scenario = scenarios[default_request["scenario_id"]]
        self.assertEqual(
            default_scenario["descriptor_source"],
            "generated_coverage_registry",
        )
        self.assertIn(default_request["source_id"], sources)
        self.assertIn(default_request["destination_id"], destinations)
        self.assertIn(default_request["ingress"]["start_id"], starts)
        self.assertEqual(
            default_scenario["default_source"],
            default_request["source_id"],
        )
        self.assertEqual(
            default_scenario["default_destination"],
            default_request["destination_id"],
        )
        self.assertEqual(
            default_scenario["default_start"],
            default_request["ingress"]["start_id"],
        )
        self.assertEqual(
            default_request["source"]["source_id"],
            default_request["source_id"],
        )
        self.assertEqual(
            default_request["destination"]["destination_id"],
            default_request["destination_id"],
        )
        self.assertEqual(
            default_request["flow"]["source"]["source_id"],
            default_request["source_id"],
        )
        self.assertEqual(
            default_request["flow"]["destination"]["destination_id"],
            default_request["destination_id"],
        )
        self.assertEqual(
            default_request["source"]["descriptor_source"],
            "generated_assembly_catalog",
        )
        self.assertEqual(
            default_request["destination"]["descriptor_source"],
            "generated_assembly_catalog",
        )
        self.assertEqual(
            default_request["ingress"]["descriptor_source"],
            "generated_assembly_catalog",
        )
        for field in (
            "route_type",
            "route_family",
            "address_family",
            "vrf_id",
        ):
            self.assertEqual(default_request[field], default_scenario[field])
        self.assertIn(default_request["scenario_id"], route_scenario_ids)

        pair_ids: set[str] = set()
        for pair in capability["directional_pairs"]:
            with self.subTest(pair_id=pair["pair_id"]):
                self.assertNotIn(pair["pair_id"], pair_ids)
                pair_ids.add(pair["pair_id"])
                self.assertEqual(
                    pair["descriptor_source"],
                    "generated_coverage_registry",
                )
                self.assertIn(pair["scenario_id"], scenarios)
                self.assertIn(pair["scenario_id"], route_scenario_ids)
                for direction in ("forward", "reverse"):
                    self.assertIn(
                        pair[direction]["source_id"],
                        sources,
                    )
                    self.assertIn(
                        pair[direction]["destination_id"],
                        destinations,
                    )
        self.assertIn(
            f"generated-pair:{default_request['scenario_id']}",
            pair_ids,
        )

        trace_response = self.client.post(
            capability["trace_href"],
            json=default_request,
        )
        self.assertEqual(
            trace_response.status_code,
            200,
            trace_response.text,
        )
        trace = trace_response.json()
        self.assertEqual(trace["assembly_id"], ASSEMBLY_ID)
        self.assertEqual(
            trace["scenario"]["scenario_id"],
            default_request["scenario_id"],
        )
        self.assertEqual(
            trace["direction"],
            default_request["direction"],
        )
        self.assertTrue(trace["paths"])

    def test_multi_node_apis_fail_closed_without_generated_assembly(
        self,
    ) -> None:
        with mock.patch.object(
            runtime_api,
            "revision_store",
            return_value=None,
        ):
            _clear_app_caches()
            topology = self.client.get("/v1/topologies/capabilities")
            routes = self.client.get(
                "/v1/topologies/routes/capabilities"
            )
        _clear_app_caches()

        self.assertEqual(topology.status_code, 503, topology.text)
        self.assertEqual(routes.status_code, 503, routes.text)
        self.assertIn(
            "analysis input is not open",
            topology.json()["detail"],
        )

    def test_generated_route_row_trace_keeps_scenario_focus_and_revision_evidence(
        self,
    ) -> None:
        route_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/tables/query",
            json={
                "node_ids": list(SELECTED_NODE_IDS),
                "page": {"limit": 500},
            },
        )
        self.assertEqual(
            route_response.status_code,
            200,
            route_response.text,
        )
        route_table = route_response.json()
        selected_row = next(
            item
            for item in route_table["items"]
            if item["node_id"] == "node-a"
            and item["attributes"]["scenario_id"]
            == "single-active-primary"
        )
        self.assertEqual(
            selected_row["trace_query"]["scenario_id"],
            "single-active-primary",
        )
        self.assertEqual(
            selected_row["route_entry_ref"]["assembly_id"],
            ASSEMBLY_ID,
        )
        self.assertEqual(
            selected_row["attributes"]["revision_id"],
            self.descriptors["node-a"].revision_id,
        )

        trace_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
            json=selected_row["trace_query"],
        )
        self.assertEqual(
            trace_response.status_code,
            200,
            trace_response.text,
        )
        trace = trace_response.json()
        forward = trace.get("traces", {}).get("forward", trace)
        self.assertEqual(trace["assembly_id"], ASSEMBLY_ID)
        self.assertEqual(trace["scenario"]["scenario_id"], "single-active-primary")
        self.assertEqual(
            forward["request"]["scenario_id"],
            "single-active-primary",
        )
        focused = next(
            item
            for item in forward["paths"]
            if item["path_id"] == forward["focused_path_id"]
        )
        self.assertTrue(focused["primary"])
        self.assertTrue(focused["active"])
        self.assertEqual(focused["result"], "resolved")
        self.assertTrue(forward["reachable"])
        self.assertTrue(forward["complete"])
        self.assertEqual(
            focused["completeness"],
            {
                "state": "complete",
                "end_to_end_resolved": True,
                "observationally_complete": True,
                "inferred_segment_count": 0,
                "unresolved_segment_count": 0,
            },
        )
        self.assertEqual(
            focused["node_sequence"],
            ["node-a", "transit-p-1", "node-b"],
        )
        boundaries = [
            item
            for item in focused["segments"]
            if item["segment_kind"] == "inter_node_boundary"
        ]
        self.assertEqual(len(boundaries), 2)
        self.assertTrue(
            all(item["topology_link_id"] is None for item in boundaries)
        )
        self.assertTrue(
            all(item["network_segment_id"] for item in boundaries)
        )
        self.assertTrue(
            all(
                len(item["network_segment_attachment_ids"]) == 2
                for item in boundaries
            )
        )
        self.assertTrue(
            all(
                item["generated_connectivity_binding"]["state"]
                == "resolved"
                for item in boundaries
            )
        )

        expected_evidence = {
            item["route_entry_id"]: item
            for item in route_table["items"]
            if item["node_id"] in focused["node_sequence"][:-1]
            and item["attributes"]["scenario_id"]
            == "single-active-primary"
        }
        all_resolution_nodes = {
            node_id
            for path in forward["paths"]
            for node_id in path["node_sequence"][:-1]
        }
        expected_all_evidence = {
            item["route_entry_id"]: item
            for item in route_table["items"]
            if item["node_id"] in all_resolution_nodes
            and item["attributes"]["scenario_id"]
            == "single-active-primary"
        }
        self.assertEqual(
            set(forward["route_table_entry_ids"]),
            set(expected_all_evidence),
        )
        self.assertEqual(
            {
                item["route_entry_id"]
                for item in focused["route_entry_refs"]
            },
            set(expected_evidence),
        )
        self.assertFalse(
            any(
                "all-active-ecmp" in entry_id
                for entry_id in forward["route_table_entry_ids"]
            )
        )
        for entry_id, evidence_row in expected_evidence.items():
            node_id = evidence_row["node_id"]
            self.assertEqual(
                evidence_row["attributes"]["revision_id"],
                self.descriptors[node_id].revision_id,
                entry_id,
            )
            self.assertEqual(
                evidence_row["route_entry_ref"]["assembly_id"],
                ASSEMBLY_ID,
                entry_id,
            )

    def test_generated_forwarding_and_packet_declarations_drive_trace_evidence(
        self,
    ) -> None:
        forwarding_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "direction": "forward",
            },
        )
        self.assertEqual(
            forwarding_response.status_code,
            200,
            forwarding_response.text,
        )
        forwarding = forwarding_response.json()
        projection = forwarding["generated_projection"]
        self.assertEqual(
            projection["validation"],
            {"forwarding": "validated", "packet": "not_applicable"},
        )
        self.assertEqual(
            [item["node_id"] for item in projection["forwarding_decisions"]],
            ["node-a", "transit-p-1", "transit-p-2", "node-b"],
        )
        focused = next(
            path
            for path in forwarding["paths"]
            if path["path_id"] == forwarding["focused_path_id"]
        )
        self.assertTrue(forwarding["reachable"])
        self.assertTrue(forwarding["complete"])
        self.assertTrue(focused["active"])
        self.assertEqual(focused["result"], "resolved")
        self.assertEqual(
            [
                item["forwarding_id"]
                for item in focused["generated_forwarding_decisions"]
            ],
            [
                "node-a/forwarding/single-active-primary",
                "transit-p-1/forwarding/single-active-primary",
                "node-b/forwarding/single-active-primary",
            ],
        )

        packet_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
            json={
                "scenario_id": "packet-native-ip",
                "direction": "forward",
            },
        )
        self.assertEqual(
            packet_response.status_code,
            200,
            packet_response.text,
        )
        packet = packet_response.json()
        packet_path = packet["paths"][0]
        self.assertEqual(
            packet["generated_projection"]["validation"]["packet"],
            "validated",
        )
        self.assertEqual(
            packet_path["packet_trace"]["declared_action_plan"],
            ["lookup", "forward"],
        )
        self.assertEqual(
            packet_path["packet_trace"]["generated_declaration"][
                "declared_by_node_ids"
            ],
            ["node-a", "transit-p-1", "node-b"],
        )
        self.assertEqual(
            packet_path["packet_trace"]["initial_state"]["layers"][0][
                "fields"
            ]["destination"],
            "198.51.100.20",
        )
        self.assertEqual(
            packet_path["packet_trace"]["generated_declaration"][
                "initial_state_binding"
            ],
            "declared_fields_over_executor_layers",
        )
        self.assertTrue(
            all(
                transition["declared_actions"]
                for transition in packet_path["packet_trace"]["transitions"]
            )
        )
        self.assertTrue(
            all(
                transition["transition"]["action_contract_id"]
                == "demo.native-ip.v1"
                for transition in packet_path["packet_trace"]["transitions"]
            )
        )

        mtu_response = self.client.post(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
            json={
                "scenario_id": "packet-mtu-drop",
                "direction": "forward",
            },
        )
        self.assertEqual(mtu_response.status_code, 200, mtu_response.text)
        mtu_path = mtu_response.json()["paths"][0]
        self.assertEqual(mtu_path["packet_trace"]["outcome"], "drop")
        self.assertEqual(
            mtu_path["packet_trace"]["initial_state"]["size"][
                "size_bytes"
            ],
            1490,
        )
        self.assertEqual(
            mtu_path["packet_trace"]["transitions"][0]["mtu"],
            {
                "outcome": "exceeds",
                "size_bytes": 1510,
                "limit_bytes": 1500,
                "excess_bytes": 10,
                "basis_contract_id": "demo.wire-size.v1",
            },
        )

        for scenario_id, declared_profile_id, executor_profile_id in (
            ("packet-sr-mpls-php", "sr-mpls-php", "sr-mpls-php"),
            (
                "packet-forced-steering",
                "forced-steering",
                "sr-mpls-php",
            ),
        ):
            with self.subTest(scenario_id=scenario_id):
                response = self.client.post(
                    f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
                    json={
                        "scenario_id": scenario_id,
                        "direction": "forward",
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                traced = response.json()
                traced_path = traced["paths"][0]
                self.assertEqual(
                    traced_path["packet_profile_id"],
                    declared_profile_id,
                )
                self.assertEqual(
                    traced_path["packet_executor_profile_id"],
                    executor_profile_id,
                )
                declaration = traced_path["packet_trace"][
                    "generated_declaration"
                ]
                self.assertEqual(
                    declaration["packet_profile_id"],
                    declared_profile_id,
                )
                self.assertEqual(
                    declaration["executor_profile_id"],
                    executor_profile_id,
                )
                self.assertEqual(
                    declaration["action_plan_binding"],
                    "declared_transition_contracts_over_executor_semantics",
                )
                self.assertNotIn("action_plan_applied", declaration)
                self.assertTrue(
                    all(
                        transition["transition"][
                            "action_contract_id"
                        ]
                        == f"demo.{executor_profile_id}.v1"
                        for transition in traced_path["packet_trace"][
                            "transitions"
                        ]
                    )
                )
                self.assertEqual(
                    traced["generated_projection"]["evidence_node_ids"],
                    [
                        "node-a",
                        "transit-p-1",
                        "transit-p-2",
                        "node-b",
                    ],
                )
                self.assertTrue(
                    all(
                        segment.get("generated_forwarding_decision")
                        is not None
                        for segment in traced_path["segments"]
                        if segment["segment_kind"] == "node_resolution"
                    )
                )

    def test_missing_or_tampered_generated_forwarding_rows_reject_trace(
        self,
    ) -> None:
        route_demo = self.route_demo
        original = [
            dict(item) for item in route_demo._generated_forwarding_rows
        ]
        endpoint = (
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace"
        )
        try:
            route_demo._generated_forwarding_rows[:] = [
                row
                for row in original
                if not (
                    row.get("scenario_id") == "single-active-primary"
                    and row.get("node_id") == "transit-p-1"
                )
            ]
            missing = self.client.post(
                endpoint,
                json={
                    "scenario_id": "single-active-primary",
                    "direction": "forward",
                },
            )
            self.assertEqual(missing.status_code, 422, missing.text)
            self.assertIn(
                "coverage evidence node transit-p-1",
                missing.json()["detail"],
            )

            route_demo._generated_forwarding_rows[:] = original
            tampered = next(
                row
                for row in route_demo._generated_forwarding_rows
                if row.get("scenario_id") == "single-active-primary"
                and row.get("node_id") == "node-a"
            )
            original_route_id = tampered["route_id"]
            tampered["route_id"] = "node-a/route/tampered"
            rejected = self.client.post(
                endpoint,
                json={
                    "scenario_id": "single-active-primary",
                    "direction": "forward",
                },
            )
            self.assertEqual(rejected.status_code, 422, rejected.text)
            self.assertIn(
                "matching generated route decision",
                rejected.json()["detail"],
            )
            tampered["route_id"] = original_route_id
        finally:
            route_demo._generated_forwarding_rows[:] = [
                dict(item) for item in original
            ]

    def test_missing_generated_domain_attachment_fails_closed(self) -> None:
        route_demo = self.route_demo
        original_query = route_demo.topology.query

        def without_primary_source_attachment(body):
            snapshot = copy.deepcopy(original_query(body))
            core_west = next(
                item
                for item in snapshot["network_segments"]
                if item.get("segment_key", {}).get("value")
                == "subnet:core-west-multi-access"
            )
            snapshot["segment_attachments"] = [
                item
                for item in snapshot["segment_attachments"]
                if not (
                    item["segment_id"] == core_west["segment_id"]
                    and item["node_id"] == "node-a"
                )
            ]
            return snapshot

        with mock.patch.object(
            route_demo.topology,
            "query",
            side_effect=without_primary_source_attachment,
        ):
            response = self.client.post(
                f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace",
                json={
                    "scenario_id": "single-active-primary",
                    "direction": "forward",
                },
            )
        self.assertEqual(response.status_code, 200, response.text)
        traced = response.json()
        focused = next(
            item
            for item in traced["paths"]
            if item["path_id"] == traced["focused_path_id"]
        )
        self.assertFalse(traced["reachable"])
        self.assertFalse(focused["active"])
        affected = next(
            item
            for item in focused["segments"]
            if item["segment_kind"] == "inter_node_boundary"
            and item["generated_connectivity_binding"]["reason_code"]
            == "source_attachment_not_found"
        )
        self.assertFalse(
            affected["completeness"]["end_to_end_resolved"]
        )
        self.assertFalse(affected["completeness"]["observed"])

    def test_missing_or_tampered_generated_packet_cases_reject_trace(
        self,
    ) -> None:
        route_demo = self.route_demo
        original = [
            dict(item) for item in route_demo._generated_packet_cases
        ]
        endpoint = (
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace"
        )
        try:
            route_demo._generated_packet_cases[:] = [
                item
                for item in original
                if not (
                    item.get("scenario_id") == "packet-native-ip"
                    and item.get("_projection_node_id") == "node-a"
                )
            ]
            missing = self.client.post(
                endpoint,
                json={
                    "scenario_id": "packet-native-ip",
                    "direction": "forward",
                },
            )
            self.assertEqual(missing.status_code, 422, missing.text)
            self.assertIn(
                "coverage evidence node node-a",
                missing.json()["detail"],
            )

            route_demo._generated_packet_cases[:] = [
                dict(item) for item in original
            ]
            tampered = next(
                item
                for item in route_demo._generated_packet_cases
                if item.get("scenario_id") == "packet-native-ip"
                and item.get("_projection_node_id") == "node-a"
            )
            tampered["packet_profile_id"] = "tampered-profile"
            rejected = self.client.post(
                endpoint,
                json={
                    "scenario_id": "packet-native-ip",
                    "direction": "forward",
                },
            )
            self.assertEqual(rejected.status_code, 422, rejected.text)
            self.assertIn(
                "packet declarations disagree",
                rejected.json()["detail"],
            )

            route_demo._generated_packet_cases[:] = [
                dict(item) for item in original
            ]
            forced_rows = [
                item
                for item in route_demo._generated_packet_cases
                if item.get("scenario_id") == "packet-forced-steering"
            ]
            for item in forced_rows:
                item["executor_profile_id"] = "native-ip"
            wrong_executor = self.client.post(
                endpoint,
                json={
                    "scenario_id": "packet-forced-steering",
                    "direction": "forward",
                },
            )
            self.assertEqual(
                wrong_executor.status_code,
                422,
                wrong_executor.text,
            )
            self.assertIn(
                "does not match the installed plug-in executor",
                wrong_executor.json()["detail"],
            )
        finally:
            route_demo._generated_packet_cases[:] = [
                dict(item) for item in original
            ]

    def test_every_registered_route_and_packet_case_executes_both_directions(
        self,
    ) -> None:
        capabilities_response = self.client.get(
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/capabilities"
        )
        self.assertEqual(
            capabilities_response.status_code,
            200,
            capabilities_response.text,
        )
        advertised = {
            item["scenario_id"]
            for item in capabilities_response.json()["scenarios"]
        }
        expected = {
            item.case_id
            for item in COVERAGE_CASES
            if "route_resolution" in item.required_capabilities
        }
        self.assertEqual(advertised, expected)

        endpoint = (
            f"/v1/topology-assemblies/{ASSEMBLY_ID}/routes/trace"
        )
        for scenario_id in sorted(advertised):
            for direction in ("forward", "reverse"):
                requests = [
                    {
                        "scenario_id": scenario_id,
                        "direction": direction,
                    }
                ]
                if scenario_id == "site-b-site-c-one-way":
                    requests.append(
                        {
                            "scenario_id": scenario_id,
                            "direction": direction,
                            "resolution_mode": "strict",
                        }
                    )
                if scenario_id == "packet-forced-steering":
                    requests.append(
                        {
                            "scenario_id": scenario_id,
                            "direction": direction,
                            "steering_profile_id": (
                                "force-alternate-p2"
                            ),
                        }
                    )
                for request in requests:
                    with self.subTest(**request):
                        response = self.client.post(
                            endpoint,
                            json=request,
                        )
                        self.assertEqual(
                            response.status_code,
                            200,
                            response.text,
                        )
                        payload = response.json()
                        self.assertTrue(payload["paths"])
                        for path in payload["paths"]:
                            projection = path[
                                "generated_forwarding_projection"
                            ]
                            self.assertEqual(
                                projection["directional_scope"],
                                direction,
                            )
                            self.assertTrue(
                                projection[
                                    "all_rendered_candidates_match"
                                ]
                            )
                            self.assertTrue(
                                path["generated_candidate_id"]
                            )
                            self.assertEqual(
                                len(
                                    path[
                                        "generated_forwarding_decisions"
                                    ]
                                ),
                                len(
                                    path[
                                        "generated_candidate_declaration"
                                    ]["node_sequence"]
                                ),
                            )
                            for segment in path["segments"]:
                                binding = segment.get(
                                    "generated_connectivity_binding"
                                )
                                if binding is None:
                                    continue
                                self.assertEqual(
                                    segment["topology_link_id"],
                                    None,
                                )
                                if scenario_id == "recursive-resolution-cycle":
                                    self.assertEqual(
                                        binding["state"],
                                        "unresolved",
                                    )
                                    self.assertIsNone(
                                        segment["network_segment_id"]
                                    )
                                    self.assertEqual(
                                        segment[
                                            "network_segment_attachment_ids"
                                        ],
                                        [],
                                    )
                                else:
                                    self.assertEqual(
                                        binding["state"],
                                        "resolved",
                                    )
                                    self.assertTrue(
                                        segment["network_segment_id"]
                                    )
                                    self.assertEqual(
                                        len(
                                            segment[
                                                "network_segment_attachment_ids"
                                            ]
                                        ),
                                        2,
                                    )

        terminal_expectations = {
            "recursive-resolution-cycle": "cycle",
            "cross-node-forwarding-loop": "cycle",
            "evpn-split-horizon-block": "policy_blocked",
        }
        for scenario_id, result in terminal_expectations.items():
            for direction in ("forward", "reverse"):
                response = self.client.post(
                    endpoint,
                    json={
                        "scenario_id": scenario_id,
                        "direction": direction,
                    },
                )
                self.assertEqual(
                    response.status_code,
                    200,
                    response.text,
                )
                self.assertEqual(
                    response.json()["paths"][0]["result"],
                    result,
                )

    def test_generated_inventory_routes_cover_every_assembly_member(
        self,
    ) -> None:
        payload = query_all_route_table_rows(
            self.client,
            {"node_ids": list(SELECTED_NODE_IDS)},
        )
        inventory_rows = {
            item["node_id"]: item
            for item in payload["items"]
            if item["attributes"].get("scenario_id") is None
        }
        self.assertEqual(set(inventory_rows), set(SELECTED_NODE_IDS))
        for node_id, row in inventory_rows.items():
            self.assertTrue(row["traceable"], node_id)
            self.assertEqual(
                row["trace_query"].get("scenario_id"),
                "router-to-router",
            )
            self.assertIn(f"{node_id}/route/inventory/", row["route_entry_id"])
            self.assertEqual(row["attributes"]["semantic_owner"], "plugin")


if __name__ == "__main__":
    unittest.main()
