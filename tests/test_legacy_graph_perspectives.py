from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.ingestion import _build_dataset
from router_dump_analyzer.observation_reconstruction import canonical_resource_identity
from router_dump_analyzer.plugin_api import (
    DumpInventory,
    PluginSchema,
    PropertyPatch,
    RelationshipTypeDescriptor,
    StatusPerspectiveRef,
    TimelineTimeBasis,
)
from router_dump_analyzer.web import runtime_api
from tests.support.normalized_data import static_data_service
from tests.test_revision_world import _relationship, _resource, _snapshot


def _graph_dataset(*, indexed: bool):
    root, child, future = (_resource(name) for name in ("root", "child", "future"))
    snapshots = (
        _snapshot(root, 10, PropertyPatch(), locator="root"),
        _snapshot(
            child,
            10,
            PropertyPatch(set_values={"x": "intended"}),
            locator="child-p",
            perspective_ref=StatusPerspectiveRef("p"),
        ),
        _snapshot(
            child,
            20,
            PropertyPatch(set_values={"x": "actual"}),
            locator="child-q",
            perspective_ref=StatusPerspectiveRef("q"),
        ),
        _snapshot(future, 40, PropertyPatch(), locator="future"),
    )
    relationships = (
        _relationship(root, child, "link", 10, True, PropertyPatch(), locator="link"),
        _relationship(
            child, future, "link", 10, True, PropertyPatch(), locator="future-link"
        ),
    )
    dataset = _build_dataset(
        plugin_id="test.plugin",
        inventory=DumpInventory(None, ()),
        schema=PluginSchema(
            resource_kinds=(),
            relationship_types=(
                RelationshipTypeDescriptor("link", "Link", True, True),
            ),
        ),
        revision_id="revision",
        node_id="node-a",
        snapshots=snapshots,
        relationship_observations=relationships,
        relationship_collections=(),
        events=(),
        source_records=(),
        diagnostics=(),
        timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
        timeline_clock_domain=None,
    )
    dataset["kind_descriptors"] = [{"kind": "item", "properties": [{"name": "x"}]}]
    dataset["demo"] = {"capture_ns": "30"}
    records = {item["resource_id"]: item for item in dataset["resources"]}
    identifiers = {
        name: canonical_resource_identity(resource)[0]
        for name, resource in (("root", root), ("child", child), ("future", future))
    }
    if indexed:
        dataset["_scale_runtime"] = SimpleNamespace(
            resource_by_id=records,
            initial_resource_ids=[identifiers["root"]],
            lifecycle_by_resource={
                identifier: [
                    item
                    for item in dataset["lifecycle_intervals"]
                    if item["resource"] == identifier
                ]
                for identifier in records
            },
            state_by_resource={
                identifier: [
                    item
                    for item in dataset["state_intervals"]
                    if item["resource"] == identifier
                ]
                for identifier in records
            },
            relationships_by_endpoint={
                identifier: [
                    item
                    for item in dataset["relationship_intervals"]
                    if identifier in (item["source"], item["target"])
                ]
                for identifier in records
            },
        )
    return dataset, identifiers


class LegacyGraphPerspectiveTests(unittest.TestCase):
    def test_graph_preserves_ambiguous_node_and_edges_without_future_resources(self):
        dataset, identifiers = _graph_dataset(indexed=False)
        service = static_data_service(dataset)
        with patch.object(runtime_api, "_data_service", return_value=service):
            payload = runtime_api._graph_payload(30)
            before_overlap = runtime_api._graph_payload(15)
        nodes = {item["id"]: item for item in payload["nodes"]}
        self.assertEqual(set(nodes), {identifiers["root"], identifiers["child"]})
        self.assertTrue(nodes[identifiers["root"]]["exists"])
        self.assertIsNone(nodes[identifiers["child"]]["exists"])
        self.assertEqual(nodes[identifiers["child"]]["quality"], "ambiguous")
        self.assertEqual(nodes[identifiers["child"]]["status"], "unknown")
        self.assertEqual(nodes[identifiers["child"]]["state"], {})
        self.assertEqual(
            {(edge["source"], edge["target"]) for edge in payload["edges"]},
            {(identifiers["root"], identifiers["child"])},
        )
        earlier_child = next(
            item
            for item in before_overlap["nodes"]
            if item["id"] == identifiers["child"]
        )
        self.assertTrue(earlier_child["exists"])
        self.assertEqual(earlier_child["state"], {"x": "intended"})

    def test_correlation_keeps_ambiguous_roots_and_neighbors_in_both_history_modes(
        self,
    ):
        for indexed in (False, True):
            dataset, identifiers = _graph_dataset(indexed=indexed)
            service = static_data_service(dataset)
            for root_name in ("root", "child"):
                with (
                    self.subTest(indexed=indexed, root=root_name),
                    patch.object(runtime_api, "_data_service", return_value=service),
                ):
                    payload = runtime_api._correlation_payload(
                        {
                            "time_ns": "30",
                            "resource_ids": [
                                identifiers[root_name],
                                identifiers["future"],
                                "missing",
                            ],
                            "direction": "both",
                            "depth": 2,
                        }
                    )
                nodes = {item["id"]: item for item in payload["nodes"]}
                self.assertEqual(
                    set(nodes), {identifiers["root"], identifiers["child"]}
                )
                self.assertIsNone(nodes[identifiers["child"]]["exists"])
                self.assertEqual(nodes[identifiers["child"]]["quality"], "ambiguous")
                self.assertEqual(nodes[identifiers["child"]]["state"], {})
                self.assertEqual(len(payload["edges"]), 1)
                self.assertEqual(
                    payload["query"]["inactive_resource_ids"], [identifiers["future"]]
                )
                self.assertEqual(payload["query"]["unknown_resource_ids"], ["missing"])
                self.assertEqual(
                    payload["query"]["accepted_resource_ids"], [identifiers[root_name]]
                )


if __name__ == "__main__":
    unittest.main()
