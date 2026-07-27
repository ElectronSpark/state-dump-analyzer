from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(DEMO_ROOT))

from rsl_demo_generator.catalog import (  # noqa: E402
    DEFAULT_SCENARIO_SOURCE,
    DEMO_LINKS,
    DEMO_NODES,
)
from rsl_demo_generator.scenario_source import (  # noqa: E402
    DEFAULT_SCENARIO_PATH,
    SCENARIO_SCHEMA_ID,
    ScenarioSourceError,
    load_default_scenario_source,
    load_scenario_source,
)


class DemoScenarioSourceTests(unittest.TestCase):
    def test_saved_project_is_the_catalog_source(self) -> None:
        source = load_default_scenario_source()

        self.assertIs(source, DEFAULT_SCENARIO_SOURCE)
        self.assertEqual(DEMO_NODES, source.nodes)
        self.assertEqual(DEMO_LINKS, source.links)
        self.assertEqual(
            tuple(node.node_id for node in source.nodes),
            (
                "node-a",
                "node-b",
                "node-c",
                "node-d",
                "node-e",
                "transit-p-1",
                "transit-p-2",
                "ce-west",
                "ce-east",
                "edge-c",
            ),
        )
        self.assertEqual(len(source.links), 8)
        self.assertEqual(source.defaults.events_per_node, 125_000)
        self.assertEqual(source.defaults.resources_per_node, 7_500)
        self.assertEqual(source.defaults.default_node_id, "node-a")
        self.assertEqual(
            source.capture_time_ns,
            source.base_time_ns + source.capture_offset_ns,
        )

    def test_digest_covers_the_exact_authoring_save(self) -> None:
        source = load_default_scenario_source()
        content = DEFAULT_SCENARIO_PATH.read_bytes()

        self.assertEqual(
            source.sha256,
            hashlib.sha256(content).hexdigest(),
        )
        raw = json.loads(content)
        self.assertEqual(raw["schema_id"], SCENARIO_SCHEMA_ID)
        self.assertNotEqual(
            {
                item["medium_id"]
                for item in raw["media"]
            },
            {link.segment_id for link in source.links},
        )
        attachments = [
            attachment
            for medium in raw["media"]
            for attachment in medium["attachments"]
        ]
        self.assertTrue(
            all("node_local_observation" in item for item in attachments)
        )
        self.assertTrue(all("properties" not in item for item in attachments))

    def test_explicit_history_contains_distinct_temporal_cases(self) -> None:
        source = load_default_scenario_source()
        observations = source.observations
        event_ids = {item.event_id for item in observations}

        self.assertGreaterEqual(len(observations), 20)
        self.assertEqual(len(source.physical_changes), 4)
        self.assertIn("node-a-route-create", event_ids)
        self.assertIn("node-a-route-delete", event_ids)
        self.assertIn("node-a-route-recreate", event_ids)
        self.assertIn("p2-carrier-stale", event_ids)
        self.assertIn("node-d-structural-detach", event_ids)
        self.assertIn("node-d-structural-reattach", event_ids)
        self.assertIn("node-b-failed-next-hop-update", event_ids)
        self.assertTrue(
            any(
                item.outcome in {"failed", "stale"}
                and not item.update_snapshot
                for item in observations
            )
        )
        for node_id, values in source.observations_by_node.items():
            self.assertEqual(
                list(values),
                sorted(
                    values,
                    key=lambda item: (
                        item.relative_time_ns,
                        item.order,
                        item.event_id,
                    ),
                ),
                node_id,
            )
            self.assertTrue(
                all(
                    item.timestamp_ns
                    == source.base_time_ns + item.relative_time_ns
                    for item in values
                )
            )

    def test_authored_resources_reconstruct_across_past_time(self) -> None:
        source = load_default_scenario_source()
        base = source.base_time_ns

        def resources(node_id: str, offset_ns: int) -> dict[str, object]:
            return {
                item.resource_id: item
                for item in source.resources_at(
                    node_id,
                    timestamp_ns=base + offset_ns,
                )
            }

        temporary_route = "route:blue:198.51.100.0/30"
        self.assertNotIn(temporary_route, resources("node-a", 29_999_999_999))
        self.assertEqual(
            resources("node-a", 30_000_000_000)[temporary_route].status,
            "installed",
        )
        self.assertNotIn(temporary_route, resources("node-a", 210_000_000_000))
        self.assertEqual(
            resources("node-a", 270_000_000_000)[temporary_route].status,
            "installed",
        )

        p1_port = "interface:Ethernet3/1"
        self.assertEqual(
            resources("transit-p-1", 90_050_000_000)[p1_port].status,
            "down",
        )
        self.assertEqual(
            resources("transit-p-1", 240_100_000_000)[p1_port].status,
            "up",
        )

    def test_failed_and_stale_observations_preserve_prior_state(self) -> None:
        source = load_default_scenario_source()
        base = source.base_time_ns

        p2 = {
            item.resource_id: item
            for item in source.resources_at(
                "transit-p-2",
                timestamp_ns=base + 108_000_000_000,
            )
        }
        self.assertEqual(
            p2["interface:Ethernet4/1"].status,
            "up",
        )
        self.assertEqual(
            p2["route:blue:203.0.113.0/24"].status,
            "installed",
        )
        node_b = {
            item.resource_id: item
            for item in source.resources_at(
                "node-b",
                timestamp_ns=base + 360_000_000_000,
            )
        }
        failed_route = node_b["route:blue:198.51.100.0/30"]
        self.assertEqual(failed_route.status, "installed")
        self.assertEqual(failed_route.properties["next_hop"], "10.64.1.2")

    def test_loader_rejects_disagreeing_local_evidence(self) -> None:
        value = json.loads(DEFAULT_SCENARIO_PATH.read_text(encoding="utf-8"))
        value["media"][0]["attachments"][1]["node_local_observation"][
            "properties"
        ]["segment_key"] = "different-observed-domain"

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.scenario.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                ScenarioSourceError,
                "disagrees with the other node-local",
            ):
                load_scenario_source(path)

    def test_scenario_is_packaged_with_the_demo_generator(self) -> None:
        project = tomllib.loads(
            (DEMO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        force_include = project["tool"]["hatch"]["build"]["targets"][
            "wheel"
        ]["force-include"]
        self.assertEqual(
            force_include["router-state-lab-default.scenario.json"],
            "rsl_demo_generator/router-state-lab-default.scenario.json",
        )
        self.assertIn(
            "/router-state-lab-default.scenario.json",
            project["tool"]["hatch"]["build"]["targets"]["sdist"][
                "include"
            ],
        )

    def test_independent_authoring_tool_accepts_the_canonical_save(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(
            REPOSITORY_ROOT / "state-dump-generator" / "src"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "state_dump_generator",
                "validate",
                str(DEFAULT_SCENARIO_PATH),
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["ok"], True)

    def test_canonical_save_generates_topology_free_node_dumps(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(
            REPOSITORY_ROOT / "state-dump-generator" / "src"
        )
        raw = json.loads(DEFAULT_SCENARIO_PATH.read_text(encoding="utf-8"))
        private_medium_ids = {
            str(item["medium_id"]).encode()
            for item in raw["media"]
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "assembly.tgz"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "state_dump_generator",
                    "generate",
                    str(DEFAULT_SCENARIO_PATH),
                    "--output",
                    str(output),
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(output, mode="r:gz") as outer:
                node_members = [
                    member
                    for member in outer.getmembers()
                    if member.isfile() and member.name.startswith("nodes/")
                ]
                self.assertEqual(len(node_members), 10)
                nested_content: list[bytes] = []
                for member in node_members:
                    stream = outer.extractfile(member)
                    assert stream is not None
                    with tarfile.open(
                        fileobj=io.BytesIO(stream.read()),
                        mode="r:gz",
                    ) as nested:
                        for child in nested.getmembers():
                            if not child.isfile():
                                continue
                            child_stream = nested.extractfile(child)
                            assert child_stream is not None
                            nested_content.append(child_stream.read())
        combined = b"\n".join(nested_content)
        for private_medium_id in private_medium_ids:
            self.assertNotIn(private_medium_id, combined)
        self.assertNotIn(b"physical_topology", combined)
        self.assertNotIn(b"peer_node", combined)
        self.assertNotIn(b"remote_port", combined)


if __name__ == "__main__":
    unittest.main()
