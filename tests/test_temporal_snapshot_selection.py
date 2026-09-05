"""Small interval-reader integration cases for temporal topology queries."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.plugin_api import PropertyPatch, StatusPerspectiveRef
from router_dump_analyzer.temporal_topology import (
    TemporalTopologyRequestError,
    TemporalTopologyService,
)
from tests.support.normalized_data import static_data_service
from tests.test_reconstruction_boundaries import _dataset
from tests.test_reconstruction_truth import _index
from tests.test_revision_world import _resource, _snapshot


def _fixture(rows, *, indexed=False, named=False, events=(), qualified_reader=True):
    resource = _resource("x")
    dataset = _dataset(
        snapshots=tuple(
            _snapshot(
                resource,
                time,
                PropertyPatch(set_values=state, complete=True),
                locator=str(index),
                perspective_ref=StatusPerspectiveRef(perspective) if named else None,
            )
            for index, (time, state, perspective) in enumerate(rows)
        )
    )
    dataset["kind_descriptors"] = [
        {
            "kind": "item",
            "properties": [{"name": name} for name in ("x", "status", "generation")],
        }
    ]
    identifier = dataset["resources"][0]["resource_id"]
    dataset["events"] = [
        dict(event, resource_id=identifier, affected_resources=[identifier])
        for event in events
    ]
    if indexed:
        _index(dataset)
        runtime = dataset["_scale_runtime"]
        runtime.events = dataset["events"]
        runtime.event_times = [int(event["timestamp_ns"]) for event in runtime.events]
        runtime.events_by_resource = {identifier: runtime.events}
    data = static_data_service(dataset)
    perspectives = [
        {
            "perspective_id": name,
            "layer": resource.layer,
            "usable_statuses": ["up"],
            "unusable_statuses": ["down"],
        }
        for name in (("observed", "intended", "missing") if named else ("observed",))
    ]
    service = TemporalTopologyService(
        dataset,
        data.resource_state_at,
        data.relationships_at,
        perspective_state_reader=(
            lambda rid, time, ref: data.resource_state_at(
                rid, time, perspective_ref=ref
            )
        )
        if qualified_reader
        else None,
        contract={
            "default_projection_id": "p",
            "default_status_perspective_id": "observed",
            "topology_projections": [
                {
                    "projection_id": "p",
                    "resource_kinds": ["item"],
                    "supported_status_perspective_ids": [
                        p["perspective_id"] for p in perspectives
                    ],
                }
            ],
            "status_perspectives": perspectives,
            "nodes": [
                {
                    "node_id": "node-a",
                    "resources_available": True,
                    "clocks": {
                        "default": {
                            "clock_domain": "utc",
                            "local_minus_absolute_ns": 0,
                            "uncertainty_ns": 0,
                            "method": "identity",
                            "quality": "exact",
                        }
                    },
                }
            ],
        },
        temporal_metadata={
            "revision_id": "revision",
            "timeline_start_ns": 10,
            "timeline_end_ns": 100,
            "capture_ns": 100,
            "default_node": "node-a",
        },
    )
    return dataset, data, service, identifier


def _query(service, time, perspective="observed"):
    return service.query(
        {
            "basis": {"kind": "absolute_time", "time_ns": str(time)},
            "projection_id": "p",
            "status_perspective_id": perspective,
            "include": ["resources"],
        }
    )["resources"][0]


def _event(uid, time, sequence, values, operation="modify"):
    return {
        "event_uid": uid,
        "timestamp_ns": time,
        "source_sequence": sequence,
        "layer": "control",
        "action": operation,
        "state_changed": True,
        "properties": values,
    }


class TemporalSnapshotSelectionTests(unittest.TestCase):
    def test_public_query_selects_later_and_empty_snapshots(self):
        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                _, data, service, identifier = _fixture(
                    [
                        (10, {"x": "old"}, "observed"),
                        (20, {"x": "new"}, "observed"),
                        (30, {}, "observed"),
                    ],
                    indexed=indexed,
                )
                for time, expected in (
                    (15, {"x": "old"}),
                    (20, {"x": "new"}),
                    (25, {"x": "new"}),
                    (30, {}),
                ):
                    actual = _query(service, time)
                    self.assertEqual(actual["state"], expected)
                    self.assertEqual(
                        actual["state"],
                        data.resource_state_at(identifier, time)["state"],
                    )
                self.assertEqual(_query(service, 15)["valid_to_ns"], "20")

    def test_lifecycle_gap_and_recreation_do_not_borrow_snapshot_existence(self):
        for indexed in (False, True):
            dataset, _, service, identifier = _fixture(
                [
                    (10, {"x": "old"}, "observed"),
                    (40, {"x": "new"}, "observed"),
                ],
                indexed=indexed,
            )
            lifecycle = [
                {"resource": identifier, "valid_from_ns": "10", "valid_to_ns": "20"},
                {"resource": identifier, "valid_from_ns": "40", "valid_to_ns": "50"},
            ]
            dataset["lifecycle_intervals"] = lifecycle
            if indexed:
                dataset["_scale_runtime"].lifecycle_by_resource[identifier] = lifecycle
            for time, exists in (
                (9, False),
                (10, True),
                (20, False),
                (39, False),
                (40, True),
                (50, False),
            ):
                self.assertIs(_query(service, time)["exists"], exists)
            self.assertEqual(_query(service, 15)["valid_to_ns"], "20")
            self.assertEqual(_query(service, 30)["valid_from_ns"], "20")
            self.assertEqual(_query(service, 30)["valid_to_ns"], "40")

    def test_interior_snapshot_transition_is_not_missed_when_endpoints_agree(self):
        for indexed in (False, True):
            _, _, service, identifier = _fixture(
                [
                    (10, {"x": "a"}, "observed"),
                    (20, {"x": "b"}, "observed"),
                    (30, {"x": "a"}, "observed"),
                ],
                indexed=indexed,
            )
            result = service._state_with_uncertainty(
                service.resource_by_id[identifier],
                "node-a",
                {
                    "query_time_ns": "15",
                    "resolved_at_min_ns": "11",
                    "resolved_at_max_ns": "39",
                    "uncertainty_ns": "28",
                },
                service._perspective("observed"),
            )
            self.assertEqual(result["quality"], "ambiguous")
            self.assertEqual(
                {item["state"]["x"] for item in result["possible_states"]}, {"a", "b"}
            )

    def test_same_layer_perspectives_are_selected_independently(self):
        for indexed in (False, True):
            _, data, service, identifier = _fixture(
                [
                    (10, {"x": "observed-old"}, "observed"),
                    (20, {}, "observed"),
                    (10, {"x": "intended"}, "intended"),
                ],
                indexed=indexed,
                named=True,
            )
            self.assertIsNone(data.resource_state_at(identifier, 25)["exists"])
            self.assertEqual(_query(service, 25)["state"], {})
            self.assertEqual(
                _query(service, 25, "intended")["state"], {"x": "intended"}
            )
            missing = _query(service, 25, "missing")
            self.assertIsNone(missing["exists"])
            self.assertEqual(missing["status"], "unknown")

    def test_legacy_reader_cannot_pick_a_named_perspective(self):
        _, _, service, _ = _fixture(
            [
                (10, {"x": "observed"}, "observed"),
            ],
            named=True,
            qualified_reader=False,
        )
        self.assertIsNone(_query(service, 25)["exists"])

    def test_later_snapshot_supersedes_old_events_and_seeds_ordered_new_events(self):
        for indexed in (False, True):
            _, _, service, identifier = _fixture(
                [
                    (10, {"x": "initial"}, "observed"),
                    (20, {"x": "snapshot"}, "observed"),
                ],
                indexed=indexed,
                events=[
                    _event("old", 15, 1, {"x": "stale"}),
                    _event("first", 25, 10, {"x": "first"}),
                    _event("second", 25, 20, {"x": "second"}),
                ],
            )
            self.assertEqual(_query(service, 24)["state"], {"x": "snapshot"})
            self.assertEqual(_query(service, 25)["state"], {"x": "second"})
            changes, _ = service._changes(
                {"relationship_types": []},
                service._perspective("observed"),
                25,
                26,
                {identifier},
                10,
                after=None,
                position=0,
            )
            self.assertEqual(changes[0]["before"]["state"], {"x": "snapshot"})
            self.assertEqual(changes[0]["after"]["state"], {"x": "first"})
            self.assertEqual(changes[1]["before"]["state"], {"x": "first"})
            self.assertEqual(changes[1]["after"]["state"], {"x": "second"})

    def test_qualified_reader_preserves_exception_boundary(self):
        _, _, service, _ = _fixture([(10, {}, "observed")], named=True)

        class PluginFailure(BaseException):
            pass

        def fail(*args):
            raise PluginFailure("private failure")

        service.perspective_state_reader = fail
        with self.assertRaisesRegex(
            TemporalTopologyRequestError, "perspective state read failed"
        ):
            _query(service, 25)
        for error in (KeyboardInterrupt(), SystemExit(), GeneratorExit()):

            def control(*args):
                raise error

            service.perspective_state_reader = control
            with self.assertRaises(type(error)):
                _query(service, 25)

    def test_same_time_snapshot_and_event_without_order_remains_unknown(self):
        _, _, service, _ = _fixture(
            [
                (10, {"x": "initial"}, "observed"),
                (20, {}, "observed"),
            ],
            events=[_event("unordered", 20, 1, {"x": "event"})],
        )
        result = _query(service, 25)
        self.assertIsNone(result["exists"])
        self.assertEqual(
            result["unknown_fields"][0]["reason_code"], "snapshot_event_order_unknown"
        )

    def test_unqualified_history_cannot_fill_two_same_layer_views(self):
        _, _, service, _ = _fixture([(10, {"x": "unqualified"}, "observed")])
        service.contract["status_perspectives"].append(
            dict(service._perspective("observed"), perspective_id="intended")
        )
        self.assertIsNone(_query(service, 25)["exists"])

    def test_stable_nonzero_clock_window_is_not_exact(self):
        _, _, service, identifier = _fixture([(10, {"x": "stable"}, "observed")])
        result = service._state_with_uncertainty(
            service.resource_by_id[identifier],
            "node-a",
            {
                "query_time_ns": "25",
                "resolved_at_min_ns": "20",
                "resolved_at_max_ns": "30",
                "uncertainty_ns": "10",
            },
            service._perspective("observed"),
        )
        self.assertEqual(result["quality"], "best_effort")

    def test_exact_producer_qualifiers_do_not_alias_equal_local_ids(self):
        dataset, data, service, identifier = _fixture(
            [
                (10, {"x": "first"}, "observed"),
                (10, {"x": "second"}, "intended"),
            ],
            named=True,
        )
        for interval, producer in zip(dataset["state_intervals"], ("first", "second")):
            interval["perspective_ref"] = {
                "perspective_id": "observed",
                "plugin_instance_id": producer,
                "schema_digest": "a" * 64,
            }
        ambiguous = data.resource_state_at(
            identifier, 25, perspective_ref=StatusPerspectiveRef("observed")
        )
        self.assertIsNone(ambiguous["exists"])
        for producer in ("first", "second"):
            reference = StatusPerspectiveRef("observed", producer, "a" * 64)
            expected = data.resource_state_at(identifier, 25, perspective_ref=reference)
            perspective = dict(
                service._perspective("observed"),
                plugin_instance_id=producer,
                schema_digest="a" * 64,
            )
            actual = service._perspective_state_at(
                service.resource_by_id[identifier], perspective, 25, []
            )
            self.assertEqual(actual["state"], expected["state"])

    def test_demo_factory_wires_the_qualified_reader(self):
        from rsl_demo_plugin.session import DemoTemporalProvider

        dataset, data, template, _ = _fixture(
            [
                (10, {"x": "observed"}, "observed"),
                (10, {"x": "intended"}, "intended"),
            ],
            named=True,
        )
        source = SimpleNamespace(load_dataset=lambda revision: dataset)
        with (
            patch(
                "rsl_demo_plugin.session.build_demo_plugin_contract",
                return_value=template.contract,
            ),
            patch(
                "rsl_demo_plugin.session.build_temporal_metadata",
                return_value=template.temporal_metadata,
            ),
        ):
            service = DemoTemporalProvider(source).for_revision("test/revision", data)
        self.assertEqual(_query(service, 25)["state"], {"x": "observed"})
        self.assertEqual(_query(service, 25, "intended")["state"], {"x": "intended"})


if __name__ == "__main__":
    unittest.main()
