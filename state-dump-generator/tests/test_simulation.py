from __future__ import annotations

import unittest

from state_dump_generator.simulation import (
    compile_scenario,
    reconstruct_scenario,
)


def base_scenario() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scenario_id": "temporal",
        "name": "Temporal",
        "seed": 7,
        "capture_time_ns": 20_000_000_000,
        "nodes": [
            {
                "node_id": "r1",
                "kind": "router",
                "clock": {"offset_ns": -1_000_000},
            },
            {
                "node_id": "r2",
                "kind": "router",
                "clock": {"offset_ns": 2_000_000},
            },
        ],
        "media": [
            {
                "medium_id": "private-wire",
                "state": "up",
                "attachments": [
                    {"node_id": "r1", "port_id": "xe0"},
                    {"node_id": "r2", "port_id": "eth1"},
                ],
            }
        ],
        "events": [],
    }


class SimulationTests(unittest.TestCase):
    def test_as_of_reconstruction_replays_create_modify_failed_and_delete(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "create",
                "timestamp_ns": 1_000_000_000,
                "kind": "resource-upsert",
                "node_id": "r1",
                "resource_id": "route:history-probe",
                "resource_type": "route",
                "status": "installed",
                "properties": {"next_hop": "192.0.2.1"},
            },
            {
                "event_id": "modify",
                "timestamp_ns": 2_000_000_000,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "route:history-probe",
                "resource_type": "route",
                "status": "installed",
                "properties": {"next_hop": "192.0.2.2"},
            },
            {
                "event_id": "failed",
                "timestamp_ns": 3_000_000_000,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "route:history-probe",
                "resource_type": "route",
                "status": "down",
                "outcome": "failed",
                "properties": {"next_hop": "discard"},
            },
            {
                "event_id": "delete",
                "timestamp_ns": 4_000_000_000,
                "kind": "resource-delete",
                "node_id": "r1",
                "resource_id": "route:history-probe",
                "resource_type": "route",
            },
        ]

        before = reconstruct_scenario(value, at_time_ns=999_999_999)
        self.assertNotIn(
            "route:history-probe",
            {
                item["resource_id"]
                for item in before["node_plans"]["r1"]["final_state"]
            },
        )

        created = reconstruct_scenario(value, at_time_ns=1_000_000_000)
        created_route = next(
            item
            for item in created["node_plans"]["r1"]["final_state"]
            if item["resource_id"] == "route:history-probe"
        )
        self.assertEqual(created_route["properties"]["next_hop"], "192.0.2.1")

        modified = reconstruct_scenario(value, at_time_ns=2_000_000_000)
        modified_route = next(
            item
            for item in modified["node_plans"]["r1"]["final_state"]
            if item["resource_id"] == "route:history-probe"
        )
        self.assertEqual(modified_route["properties"]["next_hop"], "192.0.2.2")

        failed = reconstruct_scenario(value, at_time_ns=3_000_000_000)
        failed_route = next(
            item
            for item in failed["node_plans"]["r1"]["final_state"]
            if item["resource_id"] == "route:history-probe"
        )
        self.assertEqual(failed_route["status"], "installed")
        self.assertEqual(failed_route["properties"]["next_hop"], "192.0.2.2")
        self.assertFalse(failed["node_plans"]["r1"]["logs"][-1]["state_changed"])

        deleted = reconstruct_scenario(value, at_time_ns=4_000_000_000)
        self.assertNotIn(
            "route:history-probe",
            {
                item["resource_id"]
                for item in deleted["node_plans"]["r1"]["final_state"]
            },
        )
        self.assertEqual(len(deleted["node_plans"]["r1"]["logs"]), 4)

    def test_private_truth_precedes_delayed_and_stale_node_observations(self) -> None:
        value = base_scenario()
        value["media"][0]["attachments"][0]["resource_id"] = (  # type: ignore[index]
            "interface-id:r1-uplink"
        )
        value["events"] = [
            {
                "event_id": "physical-down",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "private-wire",
                "status": "down",
                "propagation": {
                    "mode": "best-effort",
                    "delay_ms": 100,
                    "cadence": "serial",
                    "outcomes": {"r1": "success", "r2": "stale"},
                },
            }
        ]

        truth_only = reconstruct_scenario(value, at_time_ns=5_000_000_000)
        self.assertEqual(
            truth_only["private_truth"]["media"][0]["state"],
            "down",
        )
        self.assertFalse(
            truth_only["private_truth"]["exported_to_node_dumps"]
        )
        self.assertEqual(
            truth_only["private_truth"]["media"][0]["attachments"][0][
                "resource_id"
            ],
            "interface-id:r1-uplink",
        )
        self.assertEqual(truth_only["node_plans"]["r1"]["logs"], [])
        self.assertEqual(truth_only["node_plans"]["r2"]["logs"], [])

        first_observation = reconstruct_scenario(
            value,
            at_time_ns=5_150_000_000,
        )
        r1_interface = next(
            item
            for item in first_observation["node_plans"]["r1"]["final_state"]
            if item["resource_id"] == "interface-id:r1-uplink"
        )
        r2_interface = next(
            item
            for item in first_observation["node_plans"]["r2"]["final_state"]
            if item["resource_id"] == "interface:eth1"
        )
        self.assertEqual(r1_interface["status"], "down")
        self.assertEqual(r2_interface["status"], "up")
        self.assertEqual(first_observation["node_plans"]["r2"]["logs"], [])

        stale_observation = reconstruct_scenario(
            value,
            at_time_ns=5_200_000_000,
        )
        r2_interface = next(
            item
            for item in stale_observation["node_plans"]["r2"]["final_state"]
            if item["resource_id"] == "interface:eth1"
        )
        self.assertEqual(r2_interface["status"], "up")
        self.assertEqual(
            stale_observation["node_plans"]["r2"]["logs"][-1]["outcome"],
            "stale",
        )
        self.assertFalse(
            stale_observation["node_plans"]["r2"]["logs"][-1]["state_changed"]
        )

    def test_explicit_attachment_projection_excludes_authoring_metadata(self) -> None:
        value = base_scenario()
        attachment = value["media"][0]["attachments"][0]  # type: ignore[index]
        attachment["properties"] = {
            "layout_group": "private-editor-group",
            # A private ID is allowed in authoring-only metadata because the
            # explicit projection envelope prevents it from crossing.
            "apparently_safe_key": "private-wire",
        }
        attachment["node_local_observation"] = {
            "resource_id": "interface:r1-uplink.310",
            "resource_type": "virtual-interface",
            "properties": {
                "interface_name": "xe0.310",
                "subnet_prefix": "192.0.2.0/31",
                "vlan_id": 310,
            },
        }
        value["events"] = [
            {
                "event_id": "physical-down",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "private-wire",
                "status": "down",
                "propagation": {
                    "mode": "best-effort",
                    "delay_ms": 1,
                    "targets": ["r1"],
                    "outcomes": {"r1": "success"},
                },
            }
        ]

        plan = reconstruct_scenario(
            value,
            at_time_ns=5_010_000_000,
        )["node_plans"]["r1"]
        interface = next(
            item
            for item in plan["final_state"]
            if item["resource_id"] == "interface:r1-uplink.310"
        )
        self.assertEqual(interface["resource_type"], "virtual-interface")
        self.assertEqual(
            interface["properties"],
            {
                "admin_status": "up",
                "oper_status": "down",
                "interface_name": "xe0.310",
                "subnet_prefix": "192.0.2.0/31",
                "vlan_id": 310,
            },
        )
        self.assertEqual(
            plan["logs"][-1]["properties"]["subnet_prefix"],
            "192.0.2.0/31",
        )
        serialized = repr(plan)
        self.assertNotIn("layout_group", serialized)
        self.assertNotIn("private-editor-group", serialized)
        self.assertNotIn("private-wire", serialized)

    def test_private_medium_id_is_rejected_inside_explicit_local_evidence(self) -> None:
        value = base_scenario()
        attachment = value["media"][0]["attachments"][0]  # type: ignore[index]
        attachment["properties"] = {
            "apparently_safe_key": "authoring-only-value",
        }
        attachment["node_local_observation"] = {
            "resource_id": "interface:r1-uplink",
            "properties": {
                "apparently_safe_key": "private-wire",
            },
        }

        with self.assertRaisesRegex(
            ValueError,
            "private physical medium identifier",
        ):
            compile_scenario(value)

    def test_final_compile_is_the_final_reconstruction_node_plan(self) -> None:
        value = base_scenario()
        self.assertEqual(
            compile_scenario(value),
            reconstruct_scenario(value)["node_plans"],
        )

    def test_exported_timestamps_share_the_node_clock_domain(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "local-change",
                "timestamp_ns": 1_000_000_000,
                "order": 17,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "route:clock-probe",
                "resource_type": "route",
                "status": "installed",
            }
        ]

        plan = reconstruct_scenario(value, at_time_ns=1_000_000_000)[
            "node_plans"
        ]["r1"]
        event = plan["logs"][-1]
        resource = next(
            item
            for item in plan["final_state"]
            if item["resource_id"] == "route:clock-probe"
        )
        self.assertEqual(plan["captured_at_ns"], 999_000_000)
        self.assertEqual(event["timestamp_ns"], 999_000_000)
        self.assertEqual(event["source_sequence"], 17)
        self.assertNotIn("absolute_timestamp_ns", event)
        self.assertEqual(resource["updated_at_ns"], 999_000_000)

    def test_failed_parent_does_not_default_to_successful_propagation(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "failed-parent",
                "timestamp_ns": 1_000_000_000,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "route:propagation-probe",
                "resource_type": "route",
                "status": "installed",
                "outcome": "failed",
                "propagation": {
                    "mode": "best-effort",
                    "delay_ms": 1,
                },
            }
        ]

        result = reconstruct_scenario(value, at_time_ns=1_100_000_000)
        remote = result["node_plans"]["r2"]
        self.assertEqual(remote["logs"][-1]["outcome"], "failed")
        self.assertFalse(remote["logs"][-1]["state_changed"])
        self.assertNotIn(
            "route:propagation-probe",
            {item["resource_id"] for item in remote["final_state"]},
        )

    def test_as_of_time_must_be_inside_the_saved_capture(self) -> None:
        value = base_scenario()
        for invalid in (-1, 20_000_000_001, True, 1.5):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "at_time_ns"):
                    reconstruct_scenario(value, at_time_ns=invalid)

    def test_past_edits_replay_to_the_final_snapshot(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "create",
                "timestamp_ns": 1_000_000_000,
                "kind": "resource-upsert",
                "node_id": "r1",
                "resource_id": "route:blue",
                "resource_type": "route",
                "status": "installed",
                "properties": {"next_hop": "192.0.2.1"},
            },
            {
                "event_id": "modify",
                "timestamp_ns": 2_000_000_000,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "route:blue",
                "resource_type": "route",
                "status": "installed",
                "properties": {"next_hop": "192.0.2.2"},
            },
        ]
        plan = compile_scenario(value)["r1"]
        route = next(
            item for item in plan["final_state"] if item["resource_id"] == "route:blue"
        )
        self.assertEqual(route["properties"]["next_hop"], "192.0.2.2")
        self.assertEqual(len(plan["logs"]), 2)

    def test_link_truth_can_diverge_from_one_router_observation(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "physical-down",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "private-wire",
                "status": "down",
                "propagation": {
                    "mode": "best-effort",
                    "delay_ms": 100,
                    "outcomes": {"r1": "success", "r2": "stale"},
                },
            }
        ]
        plans = compile_scenario(value)
        r1 = next(
            item
            for item in plans["r1"]["final_state"]
            if item["resource_id"] == "interface:xe0"
        )
        r2 = next(
            item
            for item in plans["r2"]["final_state"]
            if item["resource_id"] == "interface:eth1"
        )
        self.assertEqual(r1["status"], "down")
        self.assertEqual(r2["status"], "up")
        self.assertFalse(plans["r2"]["logs"][0]["state_changed"])

    def test_failed_local_update_does_not_change_state(self) -> None:
        value = base_scenario()
        value["nodes"][0]["initial_resources"] = [  # type: ignore[index]
            {
                "resource_id": "neighbor:1",
                "resource_type": "neighbor",
                "status": "up",
            }
        ]
        value["events"] = [
            {
                "event_id": "failed-withdraw",
                "timestamp_ns": 3_000_000_000,
                "kind": "status",
                "node_id": "r1",
                "resource_id": "neighbor:1",
                "status": "down",
                "outcome": "failed",
            }
        ]
        plan = compile_scenario(value)["r1"]
        neighbor = next(
            item
            for item in plan["final_state"]
            if item["resource_id"] == "neighbor:1"
        )
        self.assertEqual(neighbor["status"], "up")
        self.assertFalse(plan["logs"][0]["state_changed"])

    def test_delay_is_deterministic_and_capture_bounded(self) -> None:
        value = base_scenario()
        value["capture_time_ns"] = 5_050_000_000
        value["events"] = [
            {
                "event_id": "late",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "private-wire",
                "status": "down",
                "propagation": {
                    "mode": "best-effort",
                    "delay_ms": 100,
                    "jitter_ms": 20,
                },
            }
        ]
        first = compile_scenario(value)
        second = compile_scenario(value)
        self.assertEqual(first, second)
        self.assertEqual(first["r1"]["logs"], [])
        self.assertEqual(first["r2"]["logs"], [])

    def test_physical_truth_does_not_propagate_without_explicit_request(self) -> None:
        value = base_scenario()
        value["events"] = [
            {
                "event_id": "truth-only",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "private-wire",
                "status": "down",
            }
        ]
        plans = compile_scenario(value)
        self.assertEqual(plans["r1"]["logs"], [])
        self.assertEqual(plans["r2"]["logs"], [])
        r1_interface = next(
            item
            for item in plans["r1"]["final_state"]
            if item["resource_id"] == "interface:xe0"
        )
        self.assertEqual(r1_interface["status"], "up")

    def test_resource_remove_alias_deletes_state(self) -> None:
        value = base_scenario()
        value["nodes"][0]["initial_resources"] = [  # type: ignore[index]
            {
                "resource_id": "route:blue",
                "resource_type": "route",
                "status": "installed",
            }
        ]
        value["events"] = [
            {
                "event_id": "remove",
                "timestamp_ns": 3_000_000_000,
                "kind": "resource_remove",
                "node_id": "r1",
                "resource_id": "route:blue",
            }
        ]
        plan = compile_scenario(value)["r1"]
        self.assertNotIn(
            "route:blue",
            {item["resource_id"] for item in plan["final_state"]},
        )


if __name__ == "__main__":
    unittest.main()
