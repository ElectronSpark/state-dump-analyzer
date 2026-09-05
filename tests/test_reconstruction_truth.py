"""Executable historical-state and relationship-presence regression gates."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer import normalized_data, temporal_core
from router_dump_analyzer.plugin_api import PropertyPatch
from router_dump_analyzer.temporal_topology import TemporalTopologyService
from router_dump_analyzer.web import runtime_api
from tests.support.normalized_data import static_data_service
from tests.test_reconstruction_boundaries import _dataset
from tests.test_revision_world import _relationship, _resource, _snapshot


def _index(dataset):
    records = {item["resource_id"]: item for item in dataset["resources"]}
    relationships = dataset["relationship_intervals"] or dataset["relationships"]
    dataset["_scale_runtime"] = SimpleNamespace(
        resource_by_id=records,
        initial_resource_ids=list(records),
        resource_counts={
            kind: sum(r["kind"] == kind for r in records.values())
            for kind in {r["kind"] for r in records.values()}
        },
        resources_by_kind={
            kind: [r for r in records.values() if r["kind"] == kind]
            for kind in {r["kind"] for r in records.values()}
        },
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
        relationships=relationships,
        relationships_by_endpoint={
            identifier: [
                item
                for item in relationships
                if identifier in (item["source"], item["target"])
            ]
            for identifier in records
        },
        events=[],
        event_times=[],
        mutations=[],
        mutation_times=[],
        events_by_resource={},
    )


def _relationship_dataset(present, *, indexed=False, legacy=False, capture=False):
    a, b = _resource("a", kind="group"), _resource("b")
    dataset = _dataset(
        snapshots=tuple(
            _snapshot(resource, 10, PropertyPatch(), locator=str(index))
            for index, resource in enumerate((a, b))
        ),
        relationships=(
            _relationship(a, b, "link", 10, True, PropertyPatch(), locator="add"),
            _relationship(a, b, "link", 20, present, PropertyPatch(), locator="change"),
        ),
    )
    dataset["kind_descriptors"] = [
        {"kind": "item", "properties": []},
        {"kind": "group", "properties": []},
    ]
    dataset["resource_table_view_descriptors"] = [
        {
            "view_id": "tree",
            "root_kinds": ["group"],
            "include_absent": False,
            "levels": [{"relation_types": ["link"], "target_kinds": ["item"]}],
        }
    ]
    dataset["demo"] = {"capture_ns": "30"}
    if legacy:
        for record in (*dataset["relationship_intervals"], *dataset["relationships"]):
            record.pop("present", None)
    if capture:
        dataset["relationships"] = [dict(dataset["relationship_intervals"][-1])]
        dataset["relationships"][0]["type"] = "link"
        dataset["relationship_intervals"] = []
    if indexed:
        _index(dataset)
    return dataset


def _temporal_views(dataset, *, center=30, minimum=30, maximum=30):
    data = static_data_service(dataset)
    service = TemporalTopologyService(
        dataset,
        data.resource_state_at,
        data.relationships_at,
        contract={"nodes": []},
        temporal_metadata={
            "revision_id": "revision",
            "timeline_start_ns": 0,
            "timeline_end_ns": 30,
            "capture_ns": 30,
            "default_node": "node-a",
        },
    )
    projection = {
        "relationship_types": ["link"],
        "connectivity_relation_types": ["link"],
    }
    node_times = [
        {
            "node_id": "node-a",
            "query_time_ns": str(center),
            "resolved_at_min_ns": str(minimum),
            "resolved_at_max_ns": str(maximum),
        }
    ]
    relationships, candidates, metadata = service._relationship_views(
        projection,
        node_times,
        {item["resource_id"] for item in dataset["resources"]},
        10,
        10,
    )
    # Missing status sources cannot accidentally make uncertain connectivity usable.
    service.resource_by_id = {}
    connectivity = service._inferred_connectivity(
        projection,
        {"usable_statuses": [], "unusable_statuses": []},
        node_times,
        candidates,
    )
    return relationships, connectivity, metadata


class HistoricalStateTruthTests(unittest.TestCase):
    def test_complete_empty_and_last_field_deletion_do_not_leak_future_state(self):
        resource = _resource("empty")
        histories = (
            ((10, PropertyPatch(complete=True)),),
            (
                (5, PropertyPatch(set_values={"x": "past"})),
                (10, PropertyPatch(remove_fields=("x",))),
            ),
        )
        for history in histories:
            for indexed in (False, True):
                with self.subTest(history=history, indexed=indexed):
                    dataset = _dataset(
                        snapshots=tuple(
                            _snapshot(
                                resource, timestamp, values, locator=str(timestamp)
                            )
                            for timestamp, values in (
                                *history,
                                (20, PropertyPatch(set_values={"x": "future"})),
                            )
                        )
                    )
                    dataset["kind_descriptors"] = [
                        {"kind": "item", "properties": [{"name": "x"}]}
                    ]
                    if indexed:
                        _index(dataset)
                    service = static_data_service(dataset)
                    identifier = dataset["resources"][0]["resource_id"]
                    for timestamp in (10, 15, 19):
                        selected = service.resource_state_at(identifier, timestamp)
                        self.assertEqual(selected["state"], {})
                        self.assertTrue(selected["exists"])
                        self.assertEqual(
                            (selected["valid_from_ns"], selected["valid_to_ns"]),
                            ("10", "20"),
                        )
                    self.assertEqual(
                        service.resource_state_at(identifier, 20)["state"],
                        {"x": "future"},
                    )

    def test_legacy_resource_without_state_history_retains_capture_fallback(self):
        for indexed in (False, True):
            dataset = _dataset(
                snapshots=(
                    _snapshot(
                        _resource("legacy"),
                        10,
                        PropertyPatch(set_values={"x": 1}),
                        locator="legacy",
                    ),
                )
            )
            dataset["kind_descriptors"] = [
                {"kind": "item", "properties": [{"name": "x"}]}
            ]
            dataset["state_intervals"] = []
            if indexed:
                _index(dataset)
            identifier = dataset["resources"][0]["resource_id"]
            self.assertEqual(
                static_data_service(dataset).resource_state_at(identifier, 30)["state"],
                {"x": 1},
            )


class RelationshipPresenceTruthTests(unittest.TestCase):
    def test_false_is_excluded_and_unknown_is_preserved_by_reads_graph_and_tables(self):
        for indexed in (False, True):
            for capture in (False, True):
                for present in (False, None, True):
                    with self.subTest(
                        indexed=indexed, capture=capture, present=present
                    ):
                        dataset = _relationship_dataset(
                            present, indexed=indexed, capture=capture
                        )
                        service = static_data_service(dataset)
                        expected_count = 0 if present is False else 1
                        rows = service.relationships_at(30)
                        self.assertEqual(len(rows), expected_count)
                        for row in rows:
                            self.assertIs(row["present"], present)
                        root = next(
                            r["resource_id"]
                            for r in dataset["resources"]
                            if r["kind"] == "group"
                        )
                        with patch.object(
                            runtime_api, "_data_service", return_value=service
                        ):
                            graphs = (
                                runtime_api._graph_payload(30),
                                runtime_api._correlation_payload(
                                    {
                                        "time_ns": "30",
                                        "resource_ids": [root],
                                        "depth": 2,
                                    }
                                ),
                            )
                        for graph in graphs:
                            self.assertEqual(len(graph["edges"]), expected_count)
                            for edge in graph["edges"]:
                                self.assertIs(edge["present"], present)
                                self.assertEqual(
                                    edge["possible_presence"],
                                    [False, True] if present is None else [True],
                                )
                                if present is None:
                                    self.assertEqual(edge["quality"], "ambiguous")
                        children = service.resources_at(30, view_id="tree")["bundles"][
                            0
                        ]["children"]
                        self.assertEqual(len(children), expected_count)

    def test_temporal_topology_does_not_promote_interval_membership_to_presence(self):
        for indexed in (False, True):
            for present in (False, None, True):
                with self.subTest(indexed=indexed, present=present):
                    dataset = _relationship_dataset(present, indexed=indexed)
                    relationships, connectivity, metadata = _temporal_views(dataset)
                    expected_count = 0 if present is False else 1
                    self.assertEqual(len(relationships), expected_count)
                    self.assertEqual(len(connectivity), expected_count)
                    self.assertEqual(metadata["total_count"], expected_count)
                    for relationship in relationships:
                        self.assertIs(relationship["present"], present)
                        self.assertEqual(
                            relationship["possible_presence"],
                            [False, True] if present is None else [True],
                        )
                        self.assertEqual(
                            relationship["temporal_resolution"],
                            "ambiguous"
                            if present is None
                            else "stable_within_clock_window",
                        )
                    for connection in connectivity:
                        self.assertIs(connection["exists"], present)
                        if present is None:
                            self.assertIsNone(connection["operational"]["usable"])

    def test_clock_window_crossing_removal_or_unknown_retains_ambiguity(self):
        for indexed in (False, True):
            for present in (False, None):
                with self.subTest(indexed=indexed, present=present):
                    dataset = _relationship_dataset(present, indexed=indexed)
                    relationships, connectivity, _ = _temporal_views(
                        dataset, center=20, minimum=19, maximum=21
                    )
                    self.assertTrue(relationships)
                    for relationship in relationships:
                        self.assertIsNone(relationship["present"])
                        self.assertEqual(
                            relationship["possible_presence"], [False, True]
                        )
                    self.assertTrue(
                        all(item["exists"] is None for item in connectivity)
                    )

    def test_legacy_omitted_presence_means_present_but_explicit_null_does_not(self):
        for indexed in (False, True):
            for capture in (False, True):
                with self.subTest(indexed=indexed, capture=capture):
                    dataset = _relationship_dataset(
                        True, indexed=indexed, legacy=True, capture=capture
                    )
                    service = static_data_service(dataset)
                    self.assertEqual(len(service.relationships_at(30)), 1)
                    with patch.object(
                        runtime_api, "_data_service", return_value=service
                    ):
                        edge = runtime_api._graph_payload(30)["edges"][0]
                    self.assertIs(edge["present"], True)
                    self.assertEqual(edge["possible_presence"], [True])
                    relationships, _, _ = _temporal_views(dataset)
                    self.assertTrue(relationships[0]["present"])
                    self.assertEqual(relationships[0]["possible_presence"], [True])


class SharedIntervalContainmentTests(unittest.TestCase):
    def test_existing_adapters_share_one_half_open_predicate(self):
        self.assertIs(normalized_data.contains_time, temporal_core.contains_time)
        self.assertIs(runtime_api._contains_time, temporal_core.contains_time)
        for timestamp, start, end, expected in (
            (10, "10", "20", True),
            (20, "10", "20", False),
            (-10, "-10", "0", True),
            (0, "-10", "0", False),
            (0, None, None, True),
            (10, "10", "10", False),
        ):
            with self.subTest(timestamp=timestamp, start=start, end=end):
                self.assertIs(
                    temporal_core.contains_time(timestamp, start, end), expected
                )


if __name__ == "__main__":
    unittest.main()
