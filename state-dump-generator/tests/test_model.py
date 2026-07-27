from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from state_dump_generator.model import (
    SCHEMA_ID,
    load_scenario,
    new_scenario,
    scenario_from_dict,
    validate_scenario,
)


def scenario() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scenario_id": "link-flap",
        "name": "Link flap",
        "seed": 42,
        "capture_time_ns": 20_000_000_000,
        "nodes": [
            {"node_id": "r1", "name": "R1", "kind": "router"},
            {"node_id": "r2", "name": "R2", "kind": "router"},
        ],
        "media": [
            {
                "medium_id": "wire-1",
                "kind": "point-to-point",
                "state": "up",
                "attachments": [
                    {"node_id": "r1", "port_id": "xe-0/0/0"},
                    {"node_id": "r2", "port_id": "Ethernet1"},
                ],
            }
        ],
        "events": [
            {
                "event_id": "down",
                "timestamp_ns": 5_000_000_000,
                "kind": "link-state",
                "target_id": "wire-1",
                "status": "down",
                "propagation": {"mode": "best-effort", "delay_ms": 100},
            }
        ],
    }


class ScenarioModelTests(unittest.TestCase):
    def test_blank_project_contains_no_topology(self) -> None:
        blank = new_scenario()
        self.assertEqual(blank["schema_id"], SCHEMA_ID)
        self.assertEqual(blank["nodes"], [])
        self.assertEqual(blank["media"], [])

    def test_aliases_normalize_and_validate(self) -> None:
        value = scenario()
        value["media"][0]["attachments"][0]["local_resource_id"] = (  # type: ignore[index]
            "port-resource:r1-xe0"
        )
        value["media"][0]["attachments"][0]["properties"] = {  # type: ignore[index]
            "subnet_prefix": "192.0.2.0/31",
            "vlan_id": 310,
        }
        value["links"] = value.pop("media")
        value["timeline"] = value.pop("events")
        document = scenario_from_dict(value)
        self.assertEqual(document.media[0]["medium_id"], "wire-1")
        self.assertEqual(
            document.media[0]["attachments"][0]["resource_id"],
            "port-resource:r1-xe0",
        )
        self.assertEqual(
            document.media[0]["attachments"][0][
                "node_local_observation"
            ],
            {
                "resource_id": "port-resource:r1-xe0",
                "resource_type": "interface",
                "properties": {
                    "subnet_prefix": "192.0.2.0/31",
                    "vlan_id": 310,
                },
            },
        )
        self.assertTrue(validate_scenario(document)["ok"])

    def test_explicit_attachment_export_keeps_authoring_metadata_private(self) -> None:
        value = scenario()
        attachment = value["media"][0]["attachments"][0]  # type: ignore[index]
        attachment["properties"] = {
            "canvas_note": "only the scenario editor needs this",
            "apparently_safe_key": "wire-1",
        }
        attachment["node_local_observation"] = {
            "resource_id": "interface:r1-core",
            "resource_type": "virtual-interface",
            "observed_state": "up",
            "properties": {
                "interface_name": "xe-0/0/0.310",
                "subnet_prefix": "192.0.2.0/31",
                "vlan_id": 310,
            },
        }

        document = scenario_from_dict(value)
        normalized = document.media[0]["attachments"][0]
        self.assertEqual(
            normalized["properties"]["apparently_safe_key"],
            "wire-1",
        )
        self.assertEqual(
            normalized["node_local_observation"]["properties"]["vlan_id"],
            310,
        )
        self.assertTrue(validate_scenario(document)["ok"])

    def test_unknown_attachment_and_capture_cut_are_rejected(self) -> None:
        value = scenario()
        value["media"][0]["attachments"][0]["node_id"] = "missing"  # type: ignore[index]
        value["events"][0]["timestamp_ns"] = 30_000_000_000  # type: ignore[index]
        report = validate_scenario(value)
        self.assertFalse(report["ok"])
        text = " ".join(item["message"] for item in report["errors"])
        self.assertIn("unknown node", text)
        self.assertIn("after the final snapshot", text)

    def test_saved_document_round_trips(self) -> None:
        document = scenario_from_dict(scenario())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "project.json"
            import json

            path.write_text(
                json.dumps(document.to_dict()),
                encoding="utf-8",
            )
            loaded = load_scenario(path)
        self.assertEqual(loaded, document)

    def test_windows_bom_project_loads(self) -> None:
        document = scenario_from_dict(scenario())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "project.json"
            import json

            path.write_text(
                json.dumps(document.to_dict()),
                encoding="utf-8-sig",
            )
            loaded = load_scenario(path)
        self.assertEqual(loaded, document)

    def test_file_boundary_and_dump_targets_are_validated(self) -> None:
        value = scenario()
        value["schema_id"] = "some-other-format/v1"
        report = validate_scenario(value)
        self.assertFalse(report["ok"])
        self.assertIn("unsupported schema_id", report["errors"][0]["message"])

        value = scenario()
        value["nodes"].append(  # type: ignore[union-attr]
            {"node_id": "host-1", "kind": "host"}
        )
        value["events"].append(  # type: ignore[union-attr]
            {
                "event_id": "host-event",
                "timestamp_ns": 6_000_000_000,
                "kind": "status",
                "node_id": "host-1",
                "resource_id": "interface:eth0",
            }
        )
        value["events"].append(  # type: ignore[union-attr]
            {
                "event_id": "missing-node",
                "timestamp_ns": 7_000_000_000,
                "kind": "log",
            }
        )
        report = validate_scenario(value)
        text = " ".join(item["message"] for item in report["errors"])
        self.assertIn("must target a dump-producing node", text)
        self.assertIn("require a dump-producing node", text)

    def test_output_boundary_and_clock_are_validated_before_generation(self) -> None:
        value = scenario()
        value["nodes"][0]["initial_resources"] = [  # type: ignore[index]
            {
                "resource_id": "interface:xe0",
                "properties": {"ground_truth": {"peer": "r2"}},
            }
        ]
        value["media"][0]["attachments"][0]["properties"] = {  # type: ignore[index]
            "physical_topology": {"peer": "r2"}
        }
        value["nodes"][1]["clock"] = {  # type: ignore[index]
            "offset_ns": -30_000_000_000,
            "uncertainty_ns": 0,
        }
        report = validate_scenario(value)
        text = " ".join(item["message"] for item in report["errors"])
        self.assertIn("private authoring truth", text)
        self.assertGreaterEqual(text.count("private authoring truth"), 2)
        self.assertIn("snapshot timestamp negative", text)


if __name__ == "__main__":
    unittest.main()
