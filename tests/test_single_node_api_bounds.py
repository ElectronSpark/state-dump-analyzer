from __future__ import annotations

import unittest
from collections import Counter, defaultdict
from typing import Any
from unittest.mock import patch

from fastapi import HTTPException

from router_dump_analyzer.web import runtime_api as demo_app
from plugin import data as demo_data
from plugin.data import REVISION_ID
from router_dump_analyzer.plugin_api import (
    ResourceTableRelationLevelDescriptor,
    ResourceTableViewDescriptor,
)
from plugin.scale_data import ScaleRuntime
from tests.support.generated_demo import generated_demo_runtime_session
from tests.support.normalized_data import static_data_service


def scale_dataset(
    resources: list[dict[str, Any]],
    *,
    events: list[dict[str, Any]] | None = None,
    relationships: list[dict[str, Any]] | None = None,
    lifecycle_by_resource: dict[str, list[dict[str, Any]]] | None = None,
    state_by_resource: dict[str, list[dict[str, Any]]] | None = None,
    resource_table_views: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    events = sorted(events or [], key=lambda item: int(item["timestamp_ns"]))
    relationships = relationships or []
    resource_by_id = {item["resource_id"]: item for item in resources}
    resources_by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for resource in resources:
        resources_by_kind[resource["kind"]].append(resource)
    if lifecycle_by_resource is None:
        lifecycle_by_resource = {
            identifier: [
                {
                    "resource": identifier,
                    "valid_from_ns": "0",
                    "valid_to_ns": None,
                    "start_event_uid": None,
                    "end_event_uid": None,
                }
            ]
            for identifier in resource_by_id
        }
    if state_by_resource is None:
        state_by_resource = {identifier: [] for identifier in resource_by_id}
    relationships_by_endpoint = {
        identifier: [] for identifier in resource_by_id
    }
    for relationship in relationships:
        relationships_by_endpoint[relationship["source"]].append(relationship)
        if relationship["target"] != relationship["source"]:
            relationships_by_endpoint[relationship["target"]].append(relationship)
    events_by_resource = {identifier: [] for identifier in resource_by_id}
    for event in events:
        identifiers = list(event.get("affected_resources", []))
        identifiers.extend(
            effect.get("resource_id")
            for effect in event.get("effects", [])
            if effect.get("resource_id")
        )
        for identifier in dict.fromkeys(identifiers):
            if identifier in events_by_resource:
                events_by_resource[identifier].append(event)
    runtime = ScaleRuntime(
        resources=resources,
        resource_by_id=resource_by_id,
        resources_by_kind=dict(resources_by_kind),
        resource_counts=dict(Counter(item["kind"] for item in resources)),
        events=events,
        event_by_uid={item["event_uid"]: item for item in events},
        event_times=[int(item["timestamp_ns"]) for item in events],
        events_by_resource=events_by_resource,
        lifecycle_by_resource=lifecycle_by_resource,
        state_by_resource=state_by_resource,
        relationships=relationships,
        relationships_by_endpoint=relationships_by_endpoint,
        mutations=[],
        mutation_times=[],
        mutations_by_endpoint={identifier: [] for identifier in resource_by_id},
        initial_resource_ids=list(resource_by_id)[:4],
    )
    relation_types = sorted(
        {
            str(item.get("relation_type", item.get("type", "related_to")))
            for item in relationships
        }
    )
    return {
        "_scale_runtime": runtime,
        "demo": {
            "revision_id": REVISION_ID,
            "timeline_start_ns": "0",
            "timeline_end_ns": "1000",
            "capture_ns": "1000",
        },
        "resources": resources,
        "events": events,
        "source_records": [],
        "source_record_descriptors": [],
        "kind_descriptors": [
            {"kind": kind, "label": kind}
            for kind in sorted(resources_by_kind)
        ],
        "relationship_descriptors": [
            {"relation_type": relation_type, "label": relation_type}
            for relation_type in relation_types
        ],
        "relationship_mutations": [],
        "resource_table_view_descriptors": resource_table_views or [],
    }


def resource(identifier: str, kind: str = "TEST") -> dict[str, Any]:
    return {
        "resource_id": identifier,
        "kind": kind,
        "layer": "test",
        "label": identifier,
        "state": {"status": "up"},
    }


class SingleNodeApiBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime_context = generated_demo_runtime_session()
        cls.runtime_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime_context.__exit__(None, None, None)

    def test_generated_resource_kind_requires_plugin_owned_descriptor(self) -> None:
        dataset = scale_dataset([resource("test/RESOURCE/one")])
        dataset["kind_descriptors"] = []

        with self.assertRaisesRegex(
            RuntimeError,
            "lacks a resource descriptor for kind 'TEST'",
        ):
            static_data_service(dataset).resources_at(0)

    def test_missing_resource_label_falls_back_to_opaque_identity(self) -> None:
        identifier = "test/ETG/opaque/identity"
        record = resource(identifier, "TEST")
        record.pop("label")
        dataset = scale_dataset([record])

        payload = static_data_service(dataset).resources_at(0)

        self.assertEqual(payload["items"][0]["label"], identifier)

    def test_resource_search_reuses_one_safe_timestamp_projection(self) -> None:
        resources = [
            resource(f"test/RESOURCE/{index:04d}")
            for index in range(250)
        ]
        dataset = scale_dataset(resources)
        from router_dump_analyzer import normalized_data

        with patch.object(
            normalized_data,
            "resource_search_text",
            wraps=normalized_data.resource_search_text,
        ) as project_search_text:
            service = static_data_service(dataset)
            first = service.resources_at(0, search="resource/00")
            second = service.resources_at(0, search="resource/01")

        self.assertEqual(first["matched_count"], 100)
        self.assertEqual(second["matched_count"], 100)
        self.assertEqual(project_search_text.call_count, len(resources))

    def test_correlation_caps_and_deduplicates_roots_before_traversal(self) -> None:
        resources = [resource(f"test/ROOT/{index:02d}") for index in range(12)]
        dataset = scale_dataset(resources)
        requested = [item["resource_id"] for item in resources]
        requested.insert(2, requested[0])
        with patch.object(demo_app, "load_dataset", return_value=dataset), patch.object(
            demo_data, "load_demo_dataset", return_value=dataset
        ):
            payload = demo_app._correlation_payload(
                {
                    "time_ns": "0",
                    "resource_ids": requested,
                    "depth": 0,
                    "max_nodes": 3,
                }
            )

        self.assertEqual(len(payload["nodes"]), 3)
        self.assertEqual(payload["max_nodes"], 3)
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["query"]["accepted_resource_ids"], requested[:2] + [requested[3]])
        self.assertEqual(len(payload["query"]["requested_resource_ids"]), 12)
        self.assertEqual(len(payload["query"]["dropped_resource_ids"]), 9)
        self.assertTrue(payload["query"]["roots_truncated"])

    def test_dense_timeline_returns_no_more_than_requested_glyphs(self) -> None:
        identifier = "test/RESOURCE/dense"
        events = [
            {
                "event_uid": f"event-{index:04d}",
                "timestamp_ns": str(index),
                "event_type": "resource.modify",
                "action": "modify",
                "outcome": "success",
                "affected_resources": [identifier],
                "effects": [
                    {
                        "resource_id": identifier,
                        "effect_type": "modify",
                        "state_changed": True,
                    }
                ],
                "attributes": {},
            }
            for index in range(1000)
        ]
        dataset = scale_dataset([resource(identifier)], events=events)
        body = {
            "start_ns": "0",
            "end_ns": "999",
            "resource_ids": [identifier],
            "max_glyphs": 5,
            "viewport_pixels": 2,
            "cluster_window_ns": 0,
        }
        with patch.object(
            demo_app,
            "load_dataset",
            return_value=dataset,
        ), patch.object(
            demo_data,
            "load_demo_dataset",
            return_value=dataset,
        ), patch.object(
            demo_app,
            "_require_revision",
            return_value=None,
        ):
            first = demo_app.timeline_query(REVISION_ID, body.copy())
            second = demo_app.timeline_query(REVISION_ID, body.copy())

        self.assertEqual(first["mark_count"], 1000)
        self.assertEqual(first["glyphs"]["effective_max_glyphs"], 5)
        self.assertLessEqual(first["glyphs"]["glyph_count"], 5)
        self.assertEqual(sum(item["count"] for item in first["clusters"]), 1000)
        self.assertTrue(first["glyphs"]["detail_truncated"])
        self.assertTrue(all(len(item["items"]) <= 50 for item in first["clusters"]))
        self.assertTrue(
            all(item["event_uids"][-1] == item["last_event_uid"] for item in first["clusters"])
        )
        self.assertEqual(
            [item["cluster_id"] for item in first["clusters"]],
            [item["cluster_id"] for item in second["clusters"]],
        )

    def test_relationship_history_reserves_child_lanes_and_discloses_truncation(self) -> None:
        roots = [f"test/ETG/{index:02d}" for index in range(60)]
        children = [f"test/ETE/{index:02d}" for index in range(60)]
        resources = [resource(identifier, "ETG") for identifier in roots]
        resources.extend(resource(identifier, "ETE") for identifier in children)
        relationships = [
            {
                "relationship_id": f"owns-{index:02d}",
                "source": roots[index],
                "target": children[index],
                "relation_type": "owns",
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "quality": "exact",
            }
            for index in range(60)
        ]
        dataset = scale_dataset(resources, relationships=relationships)
        with patch.object(
            demo_app,
            "load_dataset",
            return_value=dataset,
        ), patch.object(
            demo_data,
            "load_demo_dataset",
            return_value=dataset,
        ), patch.object(
            demo_app,
            "_require_revision",
            return_value=None,
        ):
            payload = demo_app.timeline_query(
                REVISION_ID,
                {
                    "start_ns": "0",
                    "end_ns": "1000",
                    "resource_ids": roots,
                    "relationship_history_roots": roots,
                },
            )

        expansion = payload["relationship_history_expansion"]
        self.assertEqual(len(payload["lanes"]), 100)
        self.assertEqual(len(expansion["accepted_base_ids"]), 50)
        self.assertEqual(len(expansion["dropped_base_ids"]), 10)
        self.assertEqual(len(expansion["accepted_resource_ids"]), 50)
        self.assertEqual(len(expansion["dropped_resource_ids"]), 10)
        self.assertEqual(len(expansion["dropped_root_ids"]), 10)
        self.assertTrue(expansion["truncated"])

    def test_range_endpoint_diff_is_not_starved_by_status_segment_budget(self) -> None:
        noisy = "test/RESOURCE/a-noisy"
        changed = "test/RESOURCE/z-changed"
        noisy_states = [
            {
                "resource": noisy,
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "status": "up",
                "properties": {"status": "up", "sample": index},
            }
            for index in range(501)
        ]
        changed_states = [
            {
                "resource": changed,
                "valid_from_ns": "0",
                "valid_to_ns": "50",
                "status": "down",
                "properties": {"status": "down"},
            },
            {
                "resource": changed,
                "valid_from_ns": "50",
                "valid_to_ns": None,
                "status": "up",
                "properties": {"status": "up"},
            },
        ]
        event = {
            "event_uid": "range-event",
            "timestamp_ns": "10",
            "event_type": "range.change",
            "action": "modify",
            "outcome": "success",
            "affected_resources": [noisy, changed],
            "effects": [],
        }
        dataset = scale_dataset(
            [resource(noisy), resource(changed)],
            events=[event],
            state_by_resource={noisy: noisy_states, changed: changed_states},
        )
        payload = static_data_service(dataset).range_summary(0, 100)

        self.assertIn(changed, {item["resource_id"] for item in payload["endpoint_diff"]})
        self.assertEqual(payload["endpoint_diff_evaluated_count"], 2)
        self.assertEqual(len(payload["status_segments"]), 500)
        self.assertTrue(payload["truncated"]["status_segments"])

    def test_resource_bundle_deduplicates_relationship_identity_and_bounds_recursion(self) -> None:
        root_id = "test/PARENT/root"
        child_ids = [f"test/CHILD/{index}" for index in range(4)]
        resources = [resource(root_id, "PARENT")]
        resources.extend(resource(identifier, "CHILD") for identifier in child_ids)
        relationships = [
            {
                "relationship_id": "same-1",
                "source": root_id,
                "target": child_ids[0],
                "relation_type": "owns",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            },
            {
                "relationship_id": "same-1",
                "source": root_id,
                "target": child_ids[0],
                "relation_type": "owns",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            },
            {
                "relationship_id": "same-2",
                "source": root_id,
                "target": child_ids[0],
                "relation_type": "owns",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            },
        ]
        relationships.extend(
            {
                "relationship_id": f"owns-{index}",
                "source": root_id,
                "target": child_id,
                "relation_type": "owns",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            }
            for index, child_id in enumerate(child_ids[1:], start=1)
        )
        view = {
            "view_id": "bounded-tree",
            "label": "Bounded tree",
            "description": "Synthetic bounded tree",
            "root_kinds": ["PARENT"],
            "levels": [
                {
                    "label": "Children",
                    "relation_types": ["owns"],
                    "target_kinds": ["CHILD"],
                    "direction": "outgoing",
                }
            ],
            "max_roots": 10,
            "max_children_per_node": 10,
            "max_nodes": 3,
        }
        dataset = scale_dataset(
            resources,
            relationships=relationships,
            resource_table_views=[view],
        )
        payload = static_data_service(dataset).resources_at(
            0,
            view_id="bounded-tree",
        )

        bundle = payload["bundles"][0]
        self.assertEqual(bundle["child_count"], 5)
        self.assertEqual(len(bundle["children"]), 2)
        self.assertEqual(bundle["truncated_child_count"], 3)
        self.assertEqual(payload["returned_node_count"], 3)
        self.assertEqual(payload["traversal_node_limit"], 3)
        self.assertTrue(payload["traversal_truncated"])

    def test_zero_time_and_malformed_shapes_are_handled_explicitly(self) -> None:
        dataset = scale_dataset([resource("test/RESOURCE/zero")])
        with patch.object(
            demo_app,
            "load_dataset",
            return_value=dataset,
        ), patch.object(
            demo_app,
            "_require_revision",
            return_value=None,
        ), patch.object(
            demo_data,
            "load_demo_dataset",
            return_value=dataset,
        ):
            at_zero = demo_app.resource_tables_at(
                REVISION_ID,
                time_ns=0,
                kind=[],
                layer=[],
                search=None,
                view=None,
                limit=500,
                offset=0,
            )
            self.assertEqual(at_zero["time_ns"], "0")

            invalid_calls = (
                lambda: demo_app.timeline_query(REVISION_ID, {"start_ns": None}),
                lambda: demo_app.resource_tables_query(REVISION_ID, {"time_ns": None}),
                lambda: demo_app.selected_range_summary(REVISION_ID, {"end_ns": []}),
                lambda: demo_app._correlation_payload({"resource_ids": None}),
                lambda: demo_app._correlation_payload({"depth": "--1"}),
                lambda: demo_app._correlation_payload({"depth": "9" * 5_000}),
                lambda: demo_app.timeline_query(
                    REVISION_ID,
                    {"record_lane_rules": "not-an-array"},
                ),
            )
            for invalid_call in invalid_calls:
                with self.subTest(call=invalid_call):
                    with self.assertRaises(HTTPException) as caught:
                        invalid_call()
                    self.assertEqual(caught.exception.status_code, 422)

    def test_plugin_resource_table_node_budget_is_validated(self) -> None:
        level = ResourceTableRelationLevelDescriptor(
            label="Children",
            relation_types=("owns",),
        )
        descriptor = ResourceTableViewDescriptor(
            view_id="bounded-tree",
            label="Bounded tree",
            description="Generic core traversal budget",
            root_kinds=("PARENT",),
            levels=(level,),
            max_nodes=25,
        )
        self.assertEqual(descriptor.max_nodes, 25)
        with self.assertRaisesRegex(ValueError, "max_nodes"):
            ResourceTableViewDescriptor(
                view_id="unbounded-tree",
                label="Unbounded tree",
                description="Invalid traversal budget",
                root_kinds=("PARENT",),
                levels=(level,),
                max_nodes=5_001,
            )
        with self.assertRaisesRegex(ValueError, "max_nodes"):
            ResourceTableViewDescriptor(
                view_id="boolean-budget",
                label="Boolean budget",
                description="Boolean integers are not traversal budgets",
                root_kinds=("PARENT",),
                levels=(level,),
                max_nodes=True,
            )


if __name__ == "__main__":
    unittest.main()
