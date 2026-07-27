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

WEB_APP_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "state_dump_generator"
    / "web"
    / "app.js"
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
                "properties": {},
            },
        )
        self.assertEqual(
            document.media[0]["attachments"][0]["properties"],
            {
                "subnet_prefix": "192.0.2.0/31",
                "vlan_id": 310,
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

    def test_serial_and_wave_horizons_warn_before_observations_are_cut(
        self,
    ) -> None:
        for cadence, node_count, capture_time_ns in (
            ("serial", 2, 5_150_000_000),
            ("waves", 3, 5_140_000_000),
        ):
            with self.subTest(cadence=cadence):
                value = scenario()
                value["capture_time_ns"] = capture_time_ns
                value["nodes"] = [
                    {
                        "node_id": f"r{index}",
                        "name": f"R{index}",
                        "kind": "router",
                    }
                    for index in range(1, node_count + 1)
                ]
                value["media"][0]["attachments"] = [  # type: ignore[index]
                    {
                        "node_id": f"r{index}",
                        "port_id": f"Ethernet{index}",
                    }
                    for index in range(1, node_count + 1)
                ]
                value["events"][0]["propagation"]["cadence"] = cadence  # type: ignore[index]

                report = validate_scenario(value)
                self.assertTrue(report["ok"])
                self.assertEqual(len(report["warnings"]), 1)
                self.assertIn(
                    "after capture",
                    report["warnings"][0]["message"],
                )

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

    def test_web_save_writes_an_explicit_local_observation(self) -> None:
        source = WEB_APP_PATH.read_text(encoding="utf-8")
        start = source.index("function canonicalAttachment(endpoint)")
        end = source.index("\nfunction canonicalEvent(", start)
        function_source = source[start:end]

        self.assertIn("node_local_observation: {", function_source)
        self.assertIn(
            "suppliedObservation.resource_id",
            function_source,
        )
        self.assertIn(
            "suppliedObservation.local_resource_id",
            function_source,
        )
        self.assertIn("properties: observationProperties", function_source)
        self.assertNotIn(
            "attachment.node_local_observation = structuredClone",
            function_source,
        )

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
        value["media"][0]["attachments"][0][  # type: ignore[index]
            "node_local_observation"
        ] = {
            "resource_id": "interface:xe0",
            "properties": {"physical_topology": {"peer": "r2"}},
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
