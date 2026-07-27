"""Regression tests for the full-scale loader's lazy temporal indexes."""

from __future__ import annotations

import unittest
from collections import defaultdict

from rsl_demo_plugin.scale_data import (
    _LazyIntervalMap,
    _ScaleTemporalIndex,
    _add_history_only_resources,
    _compact_event,
    _icon_descriptor,
    _resource_record,
    _scale_projection_capabilities,
    _status_class,
)
from rsl_demo_plugin.temporal_contract import (
    build_demo_plugin_contract,
)
from rsl_demo_generator._scale import _plugin_schema


RESOURCE_ID = "data-bridge-layer/DTE/blue/dte-000001"
SNAPSHOT_ID = "control-plane/EVPN_ES/es-00001"


def event(
    uid: str,
    timestamp_ns: int,
    *,
    outcome: str,
    effect_type: str,
    after: dict[str, str],
    state_changed: bool = True,
    effect_fields: dict[str, object] | None = None,
) -> dict[str, object]:
    effect = {
        "resource_id": RESOURCE_ID,
        "kind": "DTE",
        "effect_type": effect_type,
        "state_changed": state_changed,
        "after": after,
    }
    effect.update(effect_fields or {})
    return _compact_event(
        {
            "event_uid": uid,
            "timestamp_ns": str(timestamp_ns),
            "source_sequence": timestamp_ns,
            "event_name": "resource_update",
            "action": effect_type,
            "outcome": outcome,
            "state_changed": state_changed,
            "layer": "data-bridge-layer",
            "resource_id": RESOURCE_ID,
            "resource_kind": "DTE",
            "resource": RESOURCE_ID,
            "effects": [effect],
            "properties": {},
            "result": {"updateStatus": "Ok" if outcome == "success" else "Error"},
        }
    )


class LazyScaleTemporalIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.create = event(
            "event-create",
            10,
            outcome="success",
            effect_type="create",
            after={"status": "active", "next_hop": "etg-a"},
        )
        self.failure = event(
            "event-failure",
            20,
            outcome="failure",
            effect_type="update",
            after={"status": "down", "next_hop": "etg-b"},
        )
        self.update = event(
            "event-update",
            30,
            outcome="success",
            effect_type="update",
            after={"next_hop": "etg-c"},
        )
        self.resources = {
            RESOURCE_ID: {
                "resource_id": RESOURCE_ID,
                "state": {"status": "programmed", "next_hop": "snapshot-etg"},
            },
            SNAPSHOT_ID: {
                "resource_id": SNAPSHOT_ID,
                "state": {"status": "up", "esi": "00:01"},
            },
        }
        events_by_resource = {
            RESOURCE_ID: [self.create, self.failure, self.update],
        }
        self.index = _ScaleTemporalIndex(self.resources, events_by_resource)
        self.lifecycle = _LazyIntervalMap(
            self.resources,
            self.index.lifecycle_intervals,
        )
        self.states = _LazyIntervalMap(self.resources, self.index.state_intervals)

    def test_state_intervals_honor_explicit_effects_independent_of_outcome(self) -> None:
        intervals = self.states[RESOURCE_ID]

        self.assertIs(intervals, self.states[RESOURCE_ID])
        self.assertEqual(len(intervals), 3)
        self.assertEqual(intervals[0]["valid_from_ns"], "10")
        self.assertEqual(intervals[0]["valid_to_ns"], "20")
        self.assertEqual(intervals[0]["properties"]["next_hop"], "etg-a")
        self.assertEqual(intervals[1]["valid_from_ns"], "20")
        self.assertEqual(intervals[1]["valid_to_ns"], "30")
        self.assertEqual(intervals[1]["properties"]["next_hop"], "etg-b")
        self.assertEqual(intervals[1]["status"], "down")
        self.assertEqual(intervals[2]["valid_from_ns"], "30")
        self.assertIsNone(intervals[2]["valid_to_ns"])
        self.assertEqual(intervals[2]["properties"]["next_hop"], "etg-c")
        self.assertEqual(intervals[2]["status"], "down")

    def test_failed_event_without_declared_state_change_does_not_mutate(self) -> None:
        ignored = event(
            "event-failure-without-change",
            20,
            outcome="failure",
            effect_type="update",
            after={"status": "down", "next_hop": "etg-b"},
            state_changed=False,
        )
        index = _ScaleTemporalIndex(
            self.resources,
            {RESOURCE_ID: [self.create, ignored, self.update]},
        )

        intervals = index.state_intervals(RESOURCE_ID)

        self.assertEqual(len(intervals), 2)
        self.assertEqual(intervals[0]["valid_to_ns"], "30")
        self.assertEqual(intervals[1]["properties"]["next_hop"], "etg-c")
        self.assertEqual(intervals[1]["status"], "active")

    def test_failed_explicit_lifecycle_effects_are_not_discarded(self) -> None:
        failed_delete = event(
            "event-delete",
            20,
            outcome="failure",
            effect_type="delete",
            after={},
        )
        recreate = event(
            "event-recreate",
            30,
            outcome="success",
            effect_type="create",
            after={"status": "active", "next_hop": "etg-c"},
        )
        index = _ScaleTemporalIndex(
            self.resources,
            {RESOURCE_ID: [self.create, failed_delete, recreate]},
        )

        lifecycle = index.lifecycle_intervals(RESOURCE_ID)
        states = index.state_intervals(RESOURCE_ID)

        self.assertEqual(
            [(item["valid_from_ns"], item["valid_to_ns"]) for item in lifecycle],
            [("10", "20"), ("30", None)],
        )
        self.assertEqual(
            [(item["valid_from_ns"], item["valid_to_ns"]) for item in states],
            [("10", "20"), ("30", None)],
        )

    def test_condition_class_aliases_survive_without_a_condition(self) -> None:
        for field, declared_class in (
            ("condition_class", "degraded"),
            ("status_class", "error"),
        ):
            with self.subTest(field=field):
                update = event(
                    f"event-{field}",
                    20,
                    outcome="success",
                    effect_type="update",
                    after={"next_hop": "etg-b"},
                    effect_fields={field: declared_class},
                )
                effect = update["effects"][0]
                index = _ScaleTemporalIndex(
                    self.resources,
                    {RESOURCE_ID: [self.create, update]},
                )

                self.assertNotIn("condition", effect)
                self.assertEqual(effect["status_class"], declared_class)
                self.assertEqual(
                    index.state_intervals(RESOURCE_ID)[-1]["status_class"],
                    declared_class,
                )

    def test_public_condition_class_precedes_compatibility_alias(self) -> None:
        update = event(
            "event-condition-class-precedence",
            20,
            outcome="success",
            effect_type="update",
            after={"next_hop": "etg-b"},
            effect_fields={
                "condition_class": "degraded",
                "status_class": "healthy",
            },
        )

        self.assertEqual(update["effects"][0]["status_class"], "degraded")

    def test_lifecycle_and_snapshot_fallback_match_eager_contract(self) -> None:
        lifecycle = self.lifecycle[RESOURCE_ID]
        snapshot = self.states[SNAPSHOT_ID]

        self.assertEqual(lifecycle[0]["valid_from_ns"], "10")
        self.assertEqual(lifecycle[0]["start_event_uid"], "event-create")
        self.assertEqual(lifecycle[0]["quality"], "exact")
        self.assertEqual(snapshot[0]["quality"], "observed_snapshot")
        self.assertEqual(snapshot[0]["properties"]["esi"], "00:01")
        sentinel = object()
        self.assertIs(self.states.get("missing", sentinel), sentinel)

    def test_compactor_retains_explicit_state_payloads_independent_of_outcome(self) -> None:
        self.assertEqual(
            self.create["effects"][0]["after"]["next_hop"],
            "etg-a",
        )
        self.assertEqual(
            self.failure["effects"][0]["after"]["next_hop"],
            "etg-b",
        )

    def test_history_only_resource_is_cataloged_for_past_reconstruction(
        self,
    ) -> None:
        temporary_id = "control-plane/IP_ROUTE/history-probe"
        created = _compact_event(
            {
                "event_uid": "history-create",
                "timestamp_ns": "10",
                "event_name": "route_create",
                "action": "create",
                "outcome": "success",
                "state_changed": True,
                "layer": "control-plane",
                "resource_id": temporary_id,
                "resource_kind": "IP_ROUTE",
                "effects": [
                    {
                        "resource_id": temporary_id,
                        "kind": "IP_ROUTE",
                        "effect_type": "create",
                        "state_changed": True,
                        "condition": "installed",
                        "after": {
                            "status": "installed",
                            "next_hop": "transit-p-1",
                        },
                    }
                ],
            }
        )
        deleted = _compact_event(
            {
                "event_uid": "history-delete",
                "timestamp_ns": "20",
                "event_name": "route_delete",
                "action": "delete",
                "outcome": "success",
                "state_changed": True,
                "layer": "control-plane",
                "resource_id": temporary_id,
                "resource_kind": "IP_ROUTE",
                "effects": [
                    {
                        "resource_id": temporary_id,
                        "kind": "IP_ROUTE",
                        "effect_type": "delete",
                        "state_changed": True,
                        "after": {},
                    }
                ],
            }
        )
        resources: list[dict[str, object]] = []
        resource_by_id: dict[str, dict[str, object]] = {}
        resources_by_kind = defaultdict(list)

        _add_history_only_resources(
            resources,
            resource_by_id,
            resources_by_kind,
            {temporary_id: [created, deleted]},
        )

        self.assertIn(temporary_id, resource_by_id)
        self.assertFalse(resource_by_id[temporary_id]["snapshot_present"])
        index = _ScaleTemporalIndex(
            resource_by_id,
            {temporary_id: [created, deleted]},
        )
        self.assertEqual(
            [
                (item["valid_from_ns"], item["valid_to_ns"])
                for item in index.lifecycle_intervals(temporary_id)
            ],
            [("10", "20")],
        )


class ScaleKindDescriptorTests(unittest.TestCase):
    def test_generated_schema_is_the_authoritative_kind_descriptor(self) -> None:
        scale = {
            "ETG": {
                "kind": "ETG",
                "layer": "data-bridge-layer",
                "key_fields": ["vrf", "service_id"],
                "display_name_fields": ["service_id"],
                "default_table_fields": ["status", "overlay_destination"],
                "condition_field": "status",
                "presentation_tags": ["forwarding"],
                "icon": {"path": "M 2 2 L 22 22"},
            }
        }

        descriptor = _icon_descriptor("ETG", scale)

        self.assertEqual(descriptor["key_fields"], ["vrf", "service_id"])
        self.assertEqual(descriptor["display_name_fields"], ["service_id"])
        self.assertEqual(
            descriptor["default_table_fields"],
            ["status", "overlay_destination"],
        )
        self.assertEqual(descriptor["condition_field"], "status")
        self.assertEqual(descriptor["layer"], "data-bridge-layer")
        self.assertEqual(descriptor["icon"], scale["ETG"]["icon"])
        self.assertEqual(descriptor["presentation_tags"], ["forwarding"])
        self.assertEqual(
            descriptor["display_name"],
            "Encapsulation Tunnel Group",
        )

    def test_sparse_generated_descriptor_receives_only_generic_defaults(
        self,
    ) -> None:
        descriptor = _icon_descriptor(
            "DTE",
            {"DTE": {"kind": "DTE", "layer": "data-bridge-layer"}},
        )

        self.assertEqual(descriptor["key_fields"], [])
        self.assertEqual(
            descriptor["default_table_fields"],
            ["status", "oper_state", "next_hop"],
        )
        self.assertEqual(descriptor["condition_field"], "status")
        self.assertNotIn("icon", descriptor)
        self.assertEqual(
            descriptor["display_name"],
            "Decapsulation Tunnel Entry",
        )

    def test_scale_plugin_declares_usable_fields_for_every_kind(self) -> None:
        descriptors = _plugin_schema()["resource_kinds"]

        self.assertEqual(
            {item["kind"] for item in descriptors},
            {
                "ETG",
                "ETE",
                "DTE",
                "EVPN_ES",
                "NEIGHBOR",
                "VIRTUAL_INTERFACE",
                "IP_ROUTING",
                "IP_ROUTE",
                "ADJACENCY",
            },
        )
        for descriptor in descriptors:
            with self.subTest(kind=descriptor["kind"]):
                self.assertTrue(descriptor["key_fields"])
                self.assertTrue(descriptor["display_name_fields"])
                self.assertTrue(descriptor["default_table_fields"])
                self.assertTrue(descriptor["properties"])
                self.assertEqual(descriptor["condition_field"], "status")
                self.assertIn("status", descriptor["default_table_fields"])
                declared = {
                    item["name"] for item in descriptor["properties"]
                } | set(descriptor["key_fields"])
                presented = {
                    *descriptor.get("display_name_fields", ()),
                    *descriptor.get("default_table_fields", ()),
                    *descriptor.get("default_timeline_fields", ()),
                    descriptor["condition_field"],
                }
                self.assertLessEqual(presented, declared)

    def test_generated_schema_keeps_fixture_metadata_server_side(self) -> None:
        descriptors = _plugin_schema()["resource_kinds"]
        declared = {
            item["name"]
            for descriptor in descriptors
            for item in descriptor["properties"]
        }

        self.assertIn("next_hop", declared)
        self.assertTrue(
            {
                "source_resource_id",
                "source_scenario_id",
                "updated_at_ns",
            }.isdisjoint(declared)
        )


class ScaleProjectionCapabilityTests(unittest.TestCase):
    def test_missing_or_declared_scale_capabilities_default_to_safe_omission(
        self,
    ) -> None:
        legacy = _scale_projection_capabilities({})
        declared = _scale_projection_capabilities(_plugin_schema())

        for capabilities in (legacy, declared):
            self.assertTrue(
                capabilities["resource_association_topology"]["available"]
            )
            self.assertFalse(capabilities["underlay_topology"]["available"])
            self.assertFalse(capabilities["route_resolution"]["available"])

    def test_scale_contract_does_not_expose_underlay_without_owned_evidence(
        self,
    ) -> None:
        capabilities = _scale_projection_capabilities(_plugin_schema())
        contract = build_demo_plugin_contract(
            {
                "demo": {
                    "node": "router-state-lab-100k",
                    "capture_ns": "1759680600000000000",
                },
                "relationship_descriptors": [
                    {
                        "relation_type": "uses_interface",
                        "plugin_defined": True,
                    },
                    {
                        "relation_type": "has_neighbor",
                        "plugin_defined": True,
                    },
                ],
                "projection_capabilities": capabilities,
            }
        )

        self.assertEqual(
            [
                projection["projection_id"]
                for projection in contract["topology_projections"]
            ],
            ["plugin.resource-association"],
        )
        self.assertEqual(
            contract["topology_projections"][0]["static_connectivity"],
            [],
        )


class PackedFixturePluginResourceRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.legacy_values = (
            "PLUGIN_NEIGHBOR",
            "routing/PLUGIN_NEIGHBOR/blue/42",
            "routing",
            "blue",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "up",
            "up",
            "",
            "192.0.2.42",
        )

    def test_generic_json_preserves_typed_plugin_keys_and_state(self) -> None:
        record = _resource_record(
            self.legacy_values,
            key_json=(
                '{"vrf":"red","protocol":"isis","peer_id":'
                '{"type":"opaque_uint","value":42}}'
            ),
            state_json=(
                '{"status":"established","hold_time_seconds":30,'
                '"capabilities":["sr-mpls","srv6"]}'
            ),
        )

        self.assertEqual(record["key"]["vrf"], "red")
        self.assertEqual(
            record["key"]["peer_id"],
            {"type": "opaque_uint", "value": 42},
        )
        self.assertEqual(record["state"]["hold_time_seconds"], 30)
        self.assertEqual(record["state"]["neighbor"], "192.0.2.42")
        self.assertEqual(record["state"]["status"], "established")
        self.assertEqual(record["status"], "established")

    def test_legacy_rows_still_load_without_json_columns(self) -> None:
        record = _resource_record(self.legacy_values)

        self.assertEqual(record["key"], {"vrf": "blue"})
        self.assertEqual(record["state"]["neighbor"], "192.0.2.42")
        self.assertEqual(record["status"], "up")

    def test_generic_columns_require_json_objects(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "KEY_JSON must contain a JSON object"):
            _resource_record(self.legacy_values, key_json='["not", "an", "object"]')
        with self.assertRaisesRegex(RuntimeError, "STATE_JSON must contain valid JSON"):
            _resource_record(self.legacy_values, state_json="{broken")

    def test_fixture_status_vocabulary_is_normalized_by_the_plugin_adapter(self) -> None:
        self.assertEqual(_status_class("reachable"), "healthy")
        self.assertEqual(_status_class("restored"), "healthy")
        self.assertEqual(_status_class("degraded"), "degraded")
        self.assertEqual(_status_class("withdrawn"), "error")
        self.assertEqual(_status_class("vendor-failover-ready"), "unknown")


if __name__ == "__main__":
    unittest.main()
