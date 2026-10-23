from __future__ import annotations

import copy
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.normalized_data import resource_search_text
from tests.support.normalized_data import static_data_service


class ResourceCursorSearchTests(unittest.TestCase):
    def dataset(self):
        descriptors = [{
            "kind": kind, "key_fields": ["id", "hidden"],
            "display_name_fields": ["nested.label"],
            "condition_field": "status",
            "properties": [
                {"name": "next_hop", "searchable": True},
                {"name": "nested", "searchable": True},
                {"name": "nested.secret", "sensitive": True},
                {"name": "hidden", "client_visible": False, "searchable": True},
                {"name": "payload", "searchable": False},
            ],
        } for kind in ("DTE", "ETG")]
        resources = [{
            "resource_id": f"r-{index}", "kind": kind, "layer": layer,
            "label": f"Resource {index}", "key": {"id": index, "hidden": "private-key"},
            "state": {"next_hop": "snapshot", "hidden": "private-state"},
        } for index, (kind, layer) in enumerate((
            ("DTE", "one"), ("DTE", "two"), ("ETG", "one"), ("ETG", "two"),
        ))]
        lifecycle = {record["resource_id"]: [{"valid_from_ns": "10", "valid_to_ns": "40"}]
                     for record in resources}
        lifecycle["r-3"] = []  # Unknown presence remains searchable as unknown.
        states = {record["resource_id"]: [{
            "valid_from_ns": start, "valid_to_ns": end, "status": status,
            "status_class": "healthy", "properties": {
                "next_hop": hop, "hidden": "private-state",
                "nested": [{"label": "Straße", "secret": "private-nested"}],
                "nested.label": "literal-label",
            },
        } for start, end, status, hop in (("10", "20", "up", "primary"),
                                         ("20", "30", "down", "fallback"))]
                  for record in resources}
        # Overlapping independent perspectives must not invent an applied state.
        states["r-2"] = [dict(states["r-2"][0], perspective_ref={"perspective_id": "observed"}),
                         dict(states["r-2"][0], perspective_ref={"perspective_id": "intended"})]
        return {"resources": resources, "kind_descriptors": descriptors,
                "_scale_runtime": SimpleNamespace(
                    resources=resources,
                    resource_by_id={record["resource_id"]: record for record in resources},
                    lifecycle_by_resource=lifecycle, state_by_resource=states,
                    resource_search=SimpleNamespace(get_or_build=lambda _time, build: build()),
                )}

    def test_search_projection_matches_public_view_oracle_at_boundaries(self):
        dataset = self.dataset()
        service = static_data_service(dataset)
        descriptors = {row["kind"]: row for row in dataset["kind_descriptors"]}
        for timestamp in (9, 10, 19, 20, 29, 30, 39, 40):
            views = {row["resource_id"]: service.resource_state_at(row["resource_id"], timestamp)
                     for row in dataset["resources"]}
            texts = {row["resource_id"]: resource_search_text(
                row, views[row["resource_id"]], descriptors[row["kind"]],
            ) for row in dataset["resources"]}
            for needle in ("r-", "strasse", "literal-label", "primary", "fallback",
                           "down", "unknown", "false", "private-"):
                for layers in (None, {"one"}):
                    with self.subTest(timestamp=timestamp, needle=needle, layers=layers):
                        matching = [row for row in dataset["resources"]
                                    if (not layers or row["layer"] in layers)
                                    and needle in texts[row["resource_id"]]]
                        expected = [row for row in matching if row["kind"] == "DTE"]
                        actual = service.resources_at(timestamp, search=needle, kinds={"DTE"},
                                                      layers=layers, limit=1, offset=1)
                        self.assertEqual(actual["items"], [views[row["resource_id"]] for row in expected[1:2]])
                        self.assertEqual(actual["matched_count"], len(expected))
                        self.assertEqual(actual["counts_by_kind"], dict(Counter(row["kind"] for row in matching)))
                        self.assertEqual(actual["next_offset"], 2 if len(expected) > 2 else None)

    def test_search_does_not_publish_unmatched_non_searchable_state(self):
        class Unvisited(dict):
            def items(self):
                raise AssertionError("unmatched non-searchable state was traversed")

        dataset = self.dataset()
        for record in dataset["resources"]:
            record["state"]["payload"] = Unvisited(secret="not-a-search-field")
        for history in dataset["_scale_runtime"].state_by_resource.values():
            for interval in history:
                interval["properties"]["payload"] = Unvisited(secret="not-a-search-field")
        service = static_data_service(dataset)
        with patch.object(service, "load_dataset", wraps=service.load_dataset) as loader:
            result = service.resources_at(20, search="unmatched-token")
        self.assertEqual(result["items"], [])
        self.assertEqual(loader.call_count, 1)

    def test_search_results_own_their_published_nested_state(self):
        dataset = self.dataset()
        before = copy.deepcopy(dataset["_scale_runtime"].state_by_resource)
        service = static_data_service(dataset)
        first = service.resources_at(20, search="fallback")
        first["items"][0]["state"]["nested"][0]["label"] = "changed"
        second = service.resources_at(20, search="fallback")
        self.assertEqual(dataset["_scale_runtime"].state_by_resource, before)
        self.assertEqual(second["items"][0]["state"]["nested"][0]["label"], "Straße")


if __name__ == "__main__":
    unittest.main()
