"""Synthetic public query extensions and fail-closed route semantics."""

from __future__ import annotations

import copy
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event

from router_dump_analyzer.multi_node_topology import (
    MultiNodeTopologyRequestError,
    MultiNodeTopologyService,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    PluginCapability,
    PluginManifest,
    ProbeReport,
    ReconstructionSupport,
    TopologyPluginSemanticsDescriptor,
    TopologyUsability,
)
from tests.test_route_topology_access import route_fixture, topology_fixture


def dynamic_topology(provider):
    base = topology_fixture()
    contract = copy.deepcopy(base.contract)
    node = contract["nodes"][0]
    node["available"] = True
    node["clock"] = {
        "local_minus_absolute_ns": 0,
        "uncertainty_ns": 0,
        "clock_domain": "local",
        "mapping_method": "identity",
        "mapping_quality": "exact",
    }
    projection = node["plugin_sets"][0]["plugins"][0]["projections"][0]
    projection["resources"] = []
    projection["usable_statuses"] = ["up"]
    projection["unusable_statuses"] = ["down"]
    return MultiNodeTopologyService(
        contract=contract,
        topology_profiles=base.topology_profiles,
        topology_metadata=base.topology_metadata,
        projection_provider=provider,
    )


class TimeProjection:
    """An ordinary callable, with neither service inheritance nor stores."""

    def __call__(self, query):
        with unittest.TestCase().assertRaises(TypeError):
            query.resolved_time["query_time_ns"] = "99"
        return {
            "resources": [
                {
                    "resource_id": "opaque",
                    "kind": "RESOURCE",
                    "label": "Resource",
                    "initial_status": "up"
                    if int(query.resolved_time["query_time_ns"]) >= 25
                    else "down",
                    "properties": {"revision": query.revision_id},
                }
            ]
        }


class PlainTopologyPlugin:
    """Structural capability implementation, without AnalyzerPluginBase."""

    def __init__(self):
        from tests.test_topology_federation import _schema

        self.schema = _schema(())
        self.manifest = PluginManifest(
            plugin_id="query.plain",
            plugin_version="1",
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("synthetic",),
            supported_software_versions="*",
            capabilities=frozenset({PluginCapability.TOPOLOGY_PROJECTION}),
            reconstruction_default=ReconstructionSupport.EXACT,
        )

    def describe(self):
        return self.schema

    def probe(self, inventory):
        return ProbeReport(None)

    def locate_inputs(self, inventory):
        return ()

    def project_topology(self, request, world):
        from tests.test_topology_federation import _resource, _resource_record

        return (
            replace(
                _resource_record(_resource("node-0", "port")),
                usability=(
                    TopologyUsability.USABLE
                    if world.basis.requested_time_ns >= 25
                    else TopologyUsability.UNUSABLE
                ),
            ),
        )


class QueryProjectionExtensionTests(unittest.TestCase):
    def test_plain_plugin_projects_through_plan_bound_executor_at_query_time(self):
        from tests.test_topology_federation import _coordinator

        plugin = PlainTopologyPlugin()
        coordinator, members, _selections, _worlds = _coordinator((plugin,))
        base = dynamic_topology(lambda query: {})
        contract = copy.deepcopy(base.contract)
        node = contract["nodes"][0]
        node.update(
            node_id="node-0",
            member_id="member-0",
            revision_id="basis-0",
            catalog_revision_id="catalog-0",
        )
        descriptor = node["plugin_sets"][0]["plugins"][0]
        descriptor.update(
            plugin_id=plugin.manifest.plugin_id,
            plugin_instance_id=members[0].instance_id,
        )
        descriptor["projections"] = [
            {
                "projection_id": "gate.graph",
                "default_status_perspective_id": "gate.status",
                "supported_status_perspective_ids": ["gate.status"],
                "resources": [],
            }
        ]
        service = MultiNodeTopologyService(
            contract=contract,
            topology_profiles=base.topology_profiles,
            topology_metadata=base.topology_metadata,
            topology_federation=coordinator,
        )
        for time, expected in ((10, "unusable"), (50, "usable")):
            result = service.query(
                {"basis": {"kind": "absolute_time", "time_ns": str(time)}}
            )
            self.assertTrue(result["complete"], result["nodes"][0]["plugin_results"])
            self.assertEqual(
                result["nodes"][0]["resources"][0]["status_class"], expected
            )

    def test_plain_callable_runs_at_each_resolved_basis_without_shared_mutation(self):
        service = dynamic_topology(TimeProjection())

        def run(time):
            return service.query(
                {
                    "basis": {
                        "kind": "absolute_time",
                        "time_ns": str(time),
                        "clock_domain": "utc",
                    }
                }
            )

        with ThreadPoolExecutor(max_workers=2) as workers:
            past, now = list(workers.map(run, [10, 50]))
        self.assertEqual(past["nodes"][0]["resources"][0]["status_class"], "unusable")
        self.assertEqual(now["nodes"][0]["resources"][0]["status_class"], "usable")
        self.assertNotEqual(past["context_id"], now["context_id"])
        self.assertEqual(
            now["nodes"][0]["resources"][0]["properties"], {"revision": "r"}
        )
        self.assertEqual(
            service.contract["nodes"][0]["plugin_sets"][0]["plugins"][0]["projections"][
                0
            ]["resources"],
            [],
        )

    def test_invalid_references_identity_overrides_and_bounds_fail_explicitly(self):
        for facts in (
            {"projection_id": "different"},
            {
                "local_links": [
                    {
                        "link_id": "link",
                        "source_resource_id": "missing",
                        "target_resource_id": "missing",
                    }
                ]
            },
            {
                "connector_claims": [
                    {
                        "resource_id": "missing",
                        "matcher_id": "matcher",
                        "match_key": "key",
                        "link_type": "link",
                    }
                ]
            },
            {
                "network_segment_claims": [
                    {
                        "resource_id": "missing",
                        "matcher_id": "matcher",
                        "segment_key": "key",
                    }
                ]
            },
            {"resources": [{}] * 10_001},
            {
                "resources": [
                    {"resource_id": "same", "kind": "RESOURCE", "label": "Resource"},
                    {"resource_id": "same", "kind": "RESOURCE", "label": "Resource"},
                ]
            },
            {
                "resources": [
                    {"resource_id": "resource", "kind": "RESOURCE", "label": "Resource"}
                ],
                "local_links": [
                    {
                        "link_id": "same",
                        "source_resource_id": "resource",
                        "target_resource_id": "resource",
                    },
                    {
                        "link_id": "same",
                        "source_resource_id": "resource",
                        "target_resource_id": "resource",
                    },
                ],
            },
        ):
            with (
                self.subTest(facts=next(iter(facts))),
                self.assertRaisesRegex(
                    MultiNodeTopologyRequestError, "projection provider"
                ),
            ):
                dynamic_topology(lambda _query, facts=facts: facts).query({})

    def test_provider_errors_are_sanitized_and_process_controls_preserved(self):
        def broken(_query):
            raise RuntimeError("private source path")

        with self.assertRaisesRegex(
            MultiNodeTopologyRequestError, "projection provider"
        ) as error:
            dynamic_topology(broken).query({})
        self.assertNotIn("private", str(error.exception))

        def interrupted(_query):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            dynamic_topology(interrupted).query({})

    def test_query_cancellation_after_callback_preserves_cancellation_identity(self):
        from router_dump_analyzer.cancellation import _QUERY_CANCELLED
        from router_dump_analyzer.revision_queries import RevisionQueryCancellationError

        cancelled = Event()

        def cancel(_query):
            cancelled.set()
            return {}

        token = _QUERY_CANCELLED.set(cancelled)
        try:
            with self.assertRaises(RevisionQueryCancellationError):
                dynamic_topology(cancel).query({})
        finally:
            _QUERY_CANCELLED.reset(token)

    def test_route_table_context_is_public_immutable_and_detached(self):
        topology = topology_fixture()
        response = topology.query({})
        route = route_fixture(topology)
        table = route.route_tables({"topology_context_id": response["context_id"]})
        identity = table["route_table_context_id"]
        context = route.route_table_context_snapshot(identity)
        self.assertIs(context, route.route_table_context_snapshot(identity))
        self.assertEqual(context["topology_context_id"], response["context_id"])
        self.assertIsInstance(context["route_entry_ids"], frozenset)
        with self.assertRaises(TypeError):
            context["topology_context_id"] = "other"
        table["topology_context_id"] = "other"
        self.assertEqual(context["topology_context_id"], response["context_id"])
        self.assertIsNone(route.route_table_context_snapshot("missing"))


class InferenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.route = route_fixture(topology_fixture())
        self.attachment = self.route._endpoint_attachment(
            endpoint_id="target",
            node_id="n",
            member_id="member",
            resource_id="endpoint",
        )
        self.target = {
            "endpoint_id": "target",
            "attachments": [self.attachment],
            "attachments_complete": True,
        }

    def path(self, disposition="delivered"):
        return {
            "node_sequence": ["n"],
            "active": True,
            "selected_active_by_plugin": True,
            "completeness": {"end_to_end_resolved": True},
            "result": "resolved",
            "segments": [
                {
                    "node_id": "n",
                    "completeness": {"observed": disposition == "delivered"},
                    "generated_forwarding_state": {"disposition": disposition},
                }
            ],
        }

    def test_unknown_terminal_is_never_promoted_by_attachment_or_resolved_path(self):
        for disposition in ("unresolved", "best_effort_inferred", "forward", "unknown"):
            with self.subTest(disposition=disposition):
                path = self.path(disposition)
                self.route._declare_plugin_terminal_evidence([path], self.target)
                outcome = self.route._annotate_endpoint_reachability(
                    [path], self.target, {"node_id": "n"}
                )
                self.assertEqual(path["plugin_terminal"]["classification"], "unknown")
                self.assertIsNone(outcome["reaches_target"])
        delivered = self.path()
        self.route._declare_plugin_terminal_evidence([delivered], self.target)
        self.assertTrue(
            self.route._annotate_endpoint_reachability(
                [delivered], self.target, {"node_id": "n"}
            )["reaches_target"]
        )

    def test_explicit_unknown_and_incomplete_delivery_are_preserved(self):
        for classification in ("unknown", "delivered"):
            path = self.path()
            declaration = {
                "classification": classification,
                "classification_complete": False,
                "attachment": self.attachment,
                "endpoint_id": "target",
            }
            path["plugin_terminal"] = declaration
            self.route._declare_plugin_terminal_evidence([path], self.target)
            self.assertIs(path["plugin_terminal"], declaration)
            self.assertIsNone(
                self.route._annotate_endpoint_reachability(
                    [path], self.target, {"node_id": "n"}
                )["reaches_target"]
            )

    def test_unknown_attachment_cannot_confirm_terminal_delivery(self):
        for field, value in (("can_terminate", None), ("state", "unknown")):
            with self.subTest(field=field):
                target = copy.deepcopy(self.target)
                target["attachments"][0][field] = value
                path = self.path()
                self.route._declare_plugin_terminal_evidence([path], target)
                self.assertIsNone(
                    self.route._annotate_endpoint_reachability(
                        [path], target, {"node_id": "n"}
                    )["reaches_target"]
                )

    def test_inference_restriction_requires_boolean(self):
        self.assertFalse(
            replace(
                self.route.policy, allow_topology_inference=False
            ).allow_topology_inference
        )
        for value in (0, "false", None):
            with self.assertRaises(ValueError):
                replace(self.route.policy, allow_topology_inference=value)
        for value in (0, "false"):
            with self.assertRaises(ValueError):
                TopologyPluginSemanticsDescriptor(participates_in_connectivity=value)

    def test_any_connectivity_restriction_wins_independently_of_claim_order(self):
        def provider(query):
            return {
                "resources": [
                    {
                        "resource_id": "port",
                        "kind": "RESOURCE",
                        "label": "Port",
                        "initial_status": "up",
                    }
                ],
                "network_segment_claims": [
                    {
                        "matcher_id": "domain",
                        "segment_key": "opaque",
                        "resource_id": "port",
                        "plugin_semantics": {
                            "participates_in_connectivity": query.node_id == "n"
                        },
                    }
                ],
            }

        base = dynamic_topology(provider)
        contract = copy.deepcopy(base.contract)
        other = copy.deepcopy(contract["nodes"][0])
        other.update(node_id="n2", member_id="member2", revision_id="r2")
        contract["nodes"].append(other)
        contract["network_segment_matchers"] = [
            {
                "matcher_id": "domain",
                "match_semantics": "exact_token",
                "result_shape": "connectivity_domain",
                "contract_version": "1",
            }
        ]
        for nodes in (contract["nodes"], list(reversed(contract["nodes"]))):
            service = MultiNodeTopologyService(
                contract={**contract, "nodes": nodes},
                topology_profiles=base.topology_profiles,
                topology_metadata=base.topology_metadata,
                projection_provider=provider,
            )
            result = service.query({})
            self.assertEqual(len(result["network_segments"]), 1)
            self.assertFalse(result["network_segments"][0]["connectivity_enabled"])


class GeneratedInferencePolicyTests(unittest.TestCase):
    def test_plugin_policy_blocks_best_effort_inference_in_real_trace(self):
        from tests.support.generated_demo import generated_demo_runtime_session

        with generated_demo_runtime_session() as session:
            route = session.route_provider.get()
            request = {
                "scenario_id": "incomplete-intermediate-resolution",
                "resolution_mode": "best_effort",
            }
            allowed = route.trace(request)
            self.assertGreater(
                allowed["paths"][0]["completeness"]["inferred_segment_count"], 0
            )
            self.assertFalse(allowed["reachable"])
            self.assertIsNone(allowed["endpoint_reachability"]["reaches_target"])
            original = route.policy
            route.policy = replace(original, allow_topology_inference=False)
            try:
                denied = route.trace(request)
                self.assertFalse(denied["reachable"])
                self.assertFalse(
                    any(
                        segment["completeness"]["state"] == "best_effort_inferred"
                        for path in denied["paths"]
                        for segment in path["segments"]
                    )
                )
                observed = route.trace({"scenario_id": "single-active-primary"})
                self.assertTrue(observed["reachable"])
            finally:
                route.policy = original


if __name__ == "__main__":
    unittest.main()
