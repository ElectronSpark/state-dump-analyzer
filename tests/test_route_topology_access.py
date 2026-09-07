"""Route reuse through the public topology seam, without private storage."""

from __future__ import annotations

import json
import pickle
import unittest

from router_dump_analyzer.multi_node_route import (
    MultiNodeRouteRequestError,
    MultiNodeRouteService,
    RouteProjectionSet,
    RouteServicePolicy,
)
from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyRequestError,
    MultiNodeTopologyService,
)
from router_dump_analyzer.route_topology import (
    MultiNodeTopologyRequestError as SharedTopologyRequestError,
)
from router_dump_analyzer.route_topology import (
    RouteProjectionSelection,
)
from router_dump_analyzer.value_core import mutable_json_value, snapshot_json_value


def topology_fixture(*, ambiguous=False):
    plugin = {
        "plugin_id": "plugin",
        "version": "1",
        "plugin_instance_id": "instance",
        "plugin_run_id": "run",
        "projections": [
            {
                "projection_id": "p",
                "default_status_perspective_id": "seen",
                "supported_status_perspective_ids": ["seen", "other"],
                "resources": [{"resource_id": "opaque-resource"}],
            }
        ],
    }
    if ambiguous:
        plugin["projections"].append(
            dict(plugin["projections"][0], projection_id="another")
        )
    return MultiNodeTopologyService(
        contract={
            "nodes": [
                {
                    "node_id": "n",
                    "member_id": "member",
                    "revision_id": "r",
                    "label": "Node",
                    "device_family": "opaque",
                    "available": False,
                    "active_plugin_set_id": "set",
                    "plugin_sets": [
                        {"plugin_set_id": "set", "label": "Set", "plugins": [plugin]}
                    ],
                }
            ],
            "network_segment_matchers": [],
            "inter_node_matchers": [],
            "federation_plugin": {
                "plugin_id": "join",
                "plugin_run_id": "join-run",
                "plugin_version": "1",
            },
        },
        topology_profiles=[{"profile_id": "profile"}],
        topology_metadata={
            "topology_id": "topology",
            "assembly_id": "assembly",
            "revision_id": "r",
            "capture_ns": 50,
            "timeline_start_ns": 0,
            "timeline_end_ns": 100,
        },
    )


class AlternateTopology:
    """A read-only archive adapter with no production topology storage names."""

    __slots__ = (
        "assembly_id",
        "topology_id",
        "start_ns",
        "catalog",
        "documents",
        "last",
    )

    def __init__(self, catalog, document):
        self.assembly_id, self.topology_id, self.start_ns = "assembly", "topology", 0
        self.catalog = snapshot_json_value(catalog)
        self.last = document["context_id"]
        self.documents = {self.last: snapshot_json_value(document)}

    def route_catalog(self):
        return self.catalog

    def node_contract(self, node_id):
        return next(
            (node for node in self.catalog["nodes"] if node["node_id"] == node_id), None
        )

    def context_snapshot(self, context_id):
        return self.documents.get(context_id)

    def normalize_node_queries(self, body):
        if "node_queries" in body:
            return snapshot_json_value(body["node_queries"])
        return snapshot_json_value(
            [
                {"node_id": node_id, "plugin_set_id": "set"}
                for node_id in body.get("node_ids", ["n"])
            ]
        )

    def normalize_projection_selection(self, node_id, request):
        if node_id != "n":
            raise MultiNodeTopologyRequestError("unknown topology node")
        return RouteProjectionSelection(
            request.get("plugin_set_id", "set"),
            tuple(
                (
                    item.get("plugin_id", "plugin"),
                    item.get("projection_id", "p"),
                    item.get("status_perspective_id", "seen"),
                )
                for item in request.get("projections", [{}])
            ),
        )

    def normalize_basis(self, basis, field="basis"):
        return mutable_json_value(
            basis or {"kind": "relative_to_watermark", "offset_ns": "0"}
        )

    def capabilities(self):
        return {
            "topology_id": self.topology_id,
            "federation_plugin": mutable_json_value(self.catalog["federation_plugin"]),
            "time_bases": [],
            "clock_policies": [],
        }

    def query(self, body):
        return mutable_json_value(self.documents[self.last])


def route_fixture(topology):
    context = {
        "route_type": "type",
        "route_family": "family",
        "address_family": "address",
        "vrf_id": "vrf",
    }
    scenario = {"scenario_id": "scenario", **context}
    policy = RouteServicePolicy(
        scenarios={"scenario": scenario},
        default_scenario_id="scenario",
        steering_profiles=(),
        packet_transition_builder=lambda **kwargs: (None, []),
        endpoint_profiles={},
        route_type_profiles={},
        route_family_presentations={},
        vrf_aliases={},
        router_value_aliases={},
        route_table_schema_version="table",
        packet_trace_schema_version="packet",
        node_matcher_id="node",
        topology_link_matcher_id="link",
        connectivity_domain_matcher_id="domain",
    )
    projections = RouteProjectionSet(
        projections_by_node={
            "n": {
                "manifest": {"plugin_id": "plugin", "plugin_version": "1"},
                "routes": [
                    {
                        "node_id": "n",
                        "revision_id": "r",
                        "route_id": "entry",
                        **context,
                        "vrf": "vrf",
                        "evidence_resource_ids": ["endpoint"],
                        "destination": "opaque",
                    }
                ],
            }
        },
        revision_ids_by_node={"n": "r"},
        coverage={
            "registry_id": "coverage",
            "cases": [
                {
                    "case_id": "scenario",
                    "generated": True,
                    "required_capabilities": ["route_resolution"],
                    **context,
                    "vrf": "vrf",
                    "source": {"node_id": "n"},
                    "destination": {"node_id": "n"},
                }
            ],
        },
    )
    return MultiNodeRouteService(topology, projections=projections, policy=policy)


class RouteTopologyAccessTests(unittest.TestCase):
    def test_topology_error_compatibility_import_and_pickle(self):
        self.assertIs(MultiNodeTopologyRequestError, SharedTopologyRequestError)
        error = SharedTopologyRequestError("unavailable")
        self.assertIs(
            type(pickle.loads(pickle.dumps(error))), SharedTopologyRequestError
        )
        self.assertIs(
            pickle.loads(
                b"crouter_dump_analyzer.multi_node_topology\nMultiNodeTopologyRequestError\n."
            ),
            SharedTopologyRequestError,
        )

    def test_cached_context_is_immutable_reused_and_detached_from_wire_results(self):
        topology = topology_fixture()
        response = topology.query({})
        context_id = response["context_id"]
        cached = topology.context_snapshot(context_id)
        self.assertIs(cached, topology.context_snapshot(context_id))
        response["nodes"][0]["label"] = "changed by caller"
        self.assertEqual(cached["nodes"][0]["label"], "Node")
        with self.assertRaises(TypeError):
            cached["nodes"][0]["label"] = "changed"
        member = topology.context_member(context_id, "member")
        json.dumps(member)
        member["member"]["label"] = "changed member"
        self.assertEqual(cached["nodes"][0]["label"], "Node")
        for offset in range(1, 33):
            topology.query(
                {"basis": {"kind": "relative_to_watermark", "offset_ns": str(-offset)}}
            )
        self.assertIsNone(topology.context_snapshot(context_id))
        self.assertIsNone(topology.context_snapshot("missing"))

    def test_node_metadata_and_normalized_selection_remain_topology_owned(self):
        topology = topology_fixture()
        node = topology.node_contract("n")
        self.assertIs(node, topology.node_contract("n"))
        self.assertIs(topology.route_catalog(), topology.route_catalog())
        self.assertNotIn(
            "resources", node["plugin_sets"][0]["plugins"][0]["projections"][0]
        )
        with self.assertRaises(TypeError):
            node["plugin_sets"][0]["plugins"][0]["plugin_id"] = "changed"
        self.assertIsNone(topology.node_contract("missing"))
        selected = topology.normalize_projection_selection("n", {})
        self.assertEqual(
            selected, RouteProjectionSelection("set", (("plugin", "p", "seen"),))
        )
        alternate = topology.normalize_projection_selection(
            "n", {"status_perspective_id": "other"}
        )
        self.assertEqual(alternate.projection_ids, (("plugin", "p", "other"),))
        for request in (
            {"plugin_set_id": "missing"},
            {"status_perspective_id": "missing"},
            {"projections": ["p", "p"]},
        ):
            with (
                self.subTest(request=request),
                self.assertRaises(MultiNodeTopologyRequestError),
            ):
                topology.normalize_projection_selection("n", request)
        ambiguous = topology_fixture(ambiguous=True)
        with self.assertRaisesRegex(MultiNodeTopologyRequestError, "exactly one"):
            ambiguous.normalize_projection_selection("n", {"plugin_id": "plugin"})
        self.assertEqual(
            node["plugin_sets"][0]["plugins"][0]["projections"][0]["projection_id"], "p"
        )

    def test_route_tables_use_only_the_declared_alternate_interface(self):
        topology = topology_fixture()
        response = topology.query({})
        alternate = AlternateTopology(topology.route_catalog(), response)
        route = route_fixture(alternate)
        network_metadata = mutable_json_value(alternate.catalog)
        network_metadata["network_segment_matchers"] = [
            {"matcher_id": "domain", "metadata": {"fields": ["site"]}}
        ]
        alternate.catalog = snapshot_json_value(network_metadata)
        capabilities = route.capabilities()
        json.dumps(capabilities)
        network = capabilities["network_model"]
        network["network_segment_matchers"][0]["metadata"]["fields"].append("changed")
        self.assertEqual(
            alternate.route_catalog()["network_segment_matchers"][0]["metadata"][
                "fields"
            ],
            ("site",),
        )
        body = {"topology_context_id": response["context_id"], "node_ids": ["n"]}
        actual = route.route_tables(body)
        expected = route_fixture(topology).route_tables(body)
        self.assertEqual(actual, expected)
        json.dumps(actual)
        self.assertEqual(actual["node_summaries"][0]["member_id"], "member")
        actual["resolved_basis"]["requested"]["offset_ns"] = "-100"
        self.assertEqual(
            alternate.context_snapshot(response["context_id"])["resolved_basis"][
                "requested"
            ]["offset_ns"],
            "0",
        )
        matching = {
            "topology_context_id": response["context_id"],
            "node_queries": [
                {
                    "node_id": "n",
                    "projections": [
                        {
                            "plugin_id": "plugin",
                            "projection_id": "p",
                            "status_perspective_id": "seen",
                        }
                    ],
                }
            ],
        }
        route.route_tables(matching)
        matching["node_queries"][0]["projections"][0]["status_perspective_id"] = "other"
        with self.assertRaisesRegex(MultiNodeRouteRequestError, "projection selection"):
            route.route_tables(matching)
        with self.assertRaisesRegex(MultiNodeRouteRequestError, "node selection"):
            route.route_tables(dict(body, node_ids=["different"]))
        alternate.documents.clear()
        with self.assertRaisesRegex(MultiNodeRouteRequestError, "unknown or expired"):
            route.route_tables(body)


if __name__ == "__main__":
    unittest.main()
