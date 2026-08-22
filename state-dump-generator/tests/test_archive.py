from __future__ import annotations

import ast
import gzip
import io
import json
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path

from state_dump_generator.archive import (
    ArchiveProjectionError,
    build_assembly_bytes,
    build_node_dump_bytes,
    compile_and_build,
    deterministic_tgz_bytes,
    validate_member_name,
    write_assembly,
)
from state_dump_generator.simulation import reconstruct_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_MEMBER_CONFORMANCE = (
    PROJECT_ROOT
    / "tests"
    / "fixtures"
    / "archive-member-name-conformance.json"
)


def _members(content: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        result: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            assert stream is not None
            result[member.name] = stream.read()
        return result


def _plans() -> dict[str, object]:
    return {
        "node-b": {
            "node_id": "node-b",
            "captured_at_ns": 200,
            "final_state": [
                {
                    "resource_id": "interface:xe-0/0/0",
                    "resource_type": "interface",
                    "status": "up",
                    "properties": {"mtu": 9000},
                }
            ],
            "logs": [
                {
                    "event_id": "b-2",
                    "timestamp_ns": 150,
                    "operation": "neighbor_up",
                    "resource_id": "neighbor:192.0.2.2",
                }
            ],
        },
        "node-a": {
            "node_id": "node-a",
            "captured_at_ns": 200,
            "final_state": [
                {
                    "resource_id": "route:203.0.113.0/24",
                    "resource_type": "route",
                    "status": "installed",
                    "next_hop": "192.0.2.2",
                }
            ],
            "logs": [
                {
                    "event_id": "a-2",
                    "timestamp_ns": 170,
                    "operation": "route_install",
                },
                {
                    "event_id": "a-1",
                    "timestamp_ns": 120,
                    "operation": "neighbor_up",
                },
            ],
        },
    }


class ArchiveTests(unittest.TestCase):
    def test_assembly_is_deterministic_and_contains_several_node_dumps(self) -> None:
        first = build_assembly_bytes(_plans())
        second = build_assembly_bytes(_plans())
        self.assertEqual(first, second)
        self.assertEqual(gzip.decompress(first), gzip.decompress(second))

        outer = _members(first)
        self.assertEqual(
            set(outer),
            {"manifest.json", "nodes/node-a.tgz", "nodes/node-b.tgz"},
        )
        manifest = json.loads(outer["manifest.json"])
        self.assertEqual(manifest["node_count"], 2)
        self.assertEqual(
            [node["node_id"] for node in manifest["nodes"]],
            ["node-a", "node-b"],
        )
        self.assertNotIn("topology", manifest)
        self.assertNotIn("scenario", manifest)

        for member_name in ("nodes/node-a.tgz", "nodes/node-b.tgz"):
            nested = _members(outer[member_name])
            self.assertEqual(
                set(nested),
                {
                    "logs/history.jsonl",
                    "manifest.json",
                    "status/final-state.jsonl",
                    "status/final-state.txt",
                },
            )
            combined = b"\n".join(nested.values()).lower()
            self.assertNotIn(b"physical_topology", combined)
            self.assertNotIn(b"ground_truth", combined)
            self.assertNotIn(b"scenario_id", combined)
            self.assertNotIn(b"global_participants", combined)

    def test_reserved_node_id_gets_a_portable_archive_member_name(self) -> None:
        plan = _plans()["node-a"]
        assert isinstance(plan, dict)
        plan["node_id"] = "CON"

        outer = _members(build_assembly_bytes({"CON": plan}))
        self.assertIn("nodes/node-CON.tgz", outer)
        manifest = json.loads(outer["manifest.json"])
        self.assertEqual(manifest["nodes"][0]["node_id"], "CON")
        self.assertEqual(manifest["nodes"][0]["file"], "nodes/node-CON.tgz")

    def test_history_is_sorted_by_timestamp(self) -> None:
        content = build_node_dump_bytes(_plans()["node-a"])
        history = _members(content)["logs/history.jsonl"].decode("utf-8")
        events = [json.loads(line) for line in history.splitlines()]
        self.assertEqual(
            [event["event_id"] for event in events],
            ["a-1", "a-2"],
        )

    def test_history_preserves_source_order_within_one_timestamp(self) -> None:
        plan = _plans()["node-a"]
        assert isinstance(plan, dict)
        plan["logs"] = [
            {
                "event_id": "lexically-first",
                "timestamp_ns": 120,
                "source_sequence": 20,
            },
            {
                "event_id": "lexically-last",
                "timestamp_ns": 120,
                "source_sequence": 10,
            },
        ]
        content = build_node_dump_bytes(plan)
        history = _members(content)["logs/history.jsonl"].decode("utf-8")
        events = [json.loads(line) for line in history.splitlines()]
        self.assertEqual(
            [event["event_id"] for event in events],
            ["lexically-last", "lexically-first"],
        )

    def test_authoring_truth_is_rejected_recursively(self) -> None:
        plan = _plans()["node-a"]
        assert isinstance(plan, dict)
        plan["logs"][0]["properties"] = {  # type: ignore[index]
            "ground_truth": {"link": "a--b"}
        }
        with self.assertRaisesRegex(
            ArchiveProjectionError,
            "forbidden authoring field",
        ):
            build_node_dump_bytes(plan)

    def test_archive_member_paths_are_safe(self) -> None:
        for unsafe in ("../escape", "/absolute", r"windows\path", "C:/drive"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ArchiveProjectionError):
                    validate_member_name(unsafe)
        with self.assertRaises(ArchiveProjectionError):
            deterministic_tgz_bytes({"../escape": b"bad"})

    def test_archive_member_policy_matches_shared_portability_vectors(
        self,
    ) -> None:
        vectors = json.loads(
            ARCHIVE_MEMBER_CONFORMANCE.read_text(encoding="utf-8")
        )
        for accepted in vectors["accepted"]:
            with self.subTest(accepted=accepted):
                self.assertEqual(accepted, validate_member_name(accepted))
        for rejected in vectors["rejected"]:
            with self.subTest(rejected=rejected):
                with self.assertRaises(ArchiveProjectionError):
                    validate_member_name(rejected)

    def test_output_symlinks_are_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real.tgz"
            real.write_bytes(b"existing")
            linked = root / "linked.tgz"
            try:
                linked.symlink_to(real)
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")
            with self.assertRaisesRegex(ArchiveProjectionError, "link"):
                write_assembly(
                    {
                        "schema_version": 1,
                        "scenario_id": "symlink-output",
                        "name": "Symlink output",
                        "capture_time_ns": 1,
                        "nodes": [{"node_id": "r1", "kind": "router"}],
                        "media": [],
                        "events": [],
                    },
                    linked,
                )
            self.assertEqual(real.read_bytes(), b"existing")

    def test_broken_output_symlink_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linked = root / "broken-output.tgz"
            try:
                linked.symlink_to(root / "missing-target.tgz")
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")
            with self.assertRaisesRegex(ArchiveProjectionError, "link"):
                write_assembly(
                    {
                        "schema_version": 1,
                        "scenario_id": "broken-symlink-output",
                        "name": "Broken symlink output",
                        "capture_time_ns": 1,
                        "nodes": [{"node_id": "r1", "kind": "router"}],
                        "media": [],
                        "events": [],
                    },
                    linked,
                )

    def test_project_has_no_runtime_dependencies_or_analyzer_imports(self) -> None:
        project = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["dependencies"], [])

        forbidden_roots = {
            "demo",
            "plugin",
            "router_dump_analyzer",
        }
        source_root = PROJECT_ROOT / "src" / "state_dump_generator"
        for source in source_root.rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"), source.name)
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".", 1)[0])
            self.assertTrue(
                imported.isdisjoint(forbidden_roots),
                f"{source.name} imports analyzer/demo code: "
                f"{sorted(imported & forbidden_roots)}",
            )

        wheel = project["tool"]["hatch"]["build"]["targets"]["wheel"]
        self.assertEqual(wheel["packages"], ["src/state_dump_generator"])
        self.assertNotIn(
            "force-include",
            wheel,
            "package-owned web assets must not be added to the wheel twice",
        )
        for asset in ("index.html", "app.js", "styles.css"):
            self.assertTrue((source_root / "web" / asset).is_file())

        repository_root = PROJECT_ROOT.parent
        for source in repository_root.rglob("*.py"):
            if source == PROJECT_ROOT or PROJECT_ROOT in source.parents:
                continue
            if any(part in {".git", ".venv", "__pycache__"} for part in source.parts):
                continue
            tree = ast.parse(source.read_text(encoding="utf-8-sig"), str(source))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            self.assertFalse(
                any(
                    name == "state_dump_generator"
                    or name.startswith("state_dump_generator.")
                    for name in imported
                ),
                f"{source} makes the analyzer/demo depend on the standalone generator",
            )

    def test_ui_shaped_project_exports_only_local_interface_identity(self) -> None:
        private_medium_id = "private-authoring-wire-77"
        content = compile_and_build(
            {
                "schema_version": 1,
                "schema_id": "state-dump-generator-scenario/v1",
                "scenario_id": "ui-regression",
                "name": "UI regression",
                "capture_time_ns": 10_000_000_000,
                "nodes": [
                    {"node_id": "r1", "kind": "router"},
                    {"node_id": "r2", "kind": "router"},
                ],
                "media": [
                    {
                        "medium_id": private_medium_id,
                        "state": "up",
                        "attachments": [
                            {"node_id": "r1", "port_id": "xe0"},
                            {"node_id": "r2", "port_id": "eth1"},
                        ],
                    }
                ],
                "events": [
                    {
                        "event_id": "truth-down",
                        "timestamp_ns": 1_000_000_000,
                        "kind": "physical-link-state",
                        "target_type": "medium",
                        "target_id": private_medium_id,
                        "status": "down",
                        "propagation": {
                            "mode": "manual",
                            "materialized": True,
                        },
                    },
                    {
                        "event_id": "r1-observed",
                        "timestamp_ns": 1_100_000_000,
                        "kind": "physical-observation",
                        "node_id": "r1",
                        "resource_id": "interface:xe0",
                        "resource_type": "interface",
                        "operation": "link_down_detected",
                        "status": "down",
                        "properties": {"oper_status": "down"},
                        "message": "Observed local carrier down on xe0.",
                    },
                ],
            }
        )
        outer = _members(content)
        nested_bytes = b"\n".join(
            b"\n".join(_members(payload).values())
            for name, payload in outer.items()
            if name.startswith("nodes/")
        )
        self.assertNotIn(private_medium_id.encode("utf-8"), nested_bytes)
        self.assertIn(b"interface:xe0", nested_bytes)

    def test_authoring_attachment_properties_never_enter_node_dump(self) -> None:
        private_medium_id = "private-property-wire"
        scenario = {
            "schema_version": 1,
            "scenario_id": "private-property-regression",
            "name": "Private property regression",
            "capture_time_ns": 1,
            "nodes": [{"node_id": "r1", "kind": "router"}],
            "media": [
                {
                    "medium_id": private_medium_id,
                    "state": "up",
                    "attachments": [
                        {
                            "node_id": "r1",
                            "port_id": "xe0",
                            "properties": {
                                "apparently_safe_key": private_medium_id,
                                "peer_node": "r2",
                                "remote_port": "xe9",
                            },
                        }
                    ],
                }
            ],
            "events": [],
        }
        content = compile_and_build(scenario)
        outer = _members(content)
        nested_bytes = b"\n".join(
            b"\n".join(_members(payload).values())
            for name, payload in outer.items()
            if name.startswith("nodes/")
        )
        self.assertNotIn(private_medium_id.encode("utf-8"), nested_bytes)
        self.assertNotIn(b"apparently_safe_key", nested_bytes)
        self.assertNotIn(b"peer_node", nested_bytes)
        self.assertNotIn(b"remote_port", nested_bytes)
        self.assertIn(b"interface:xe0", nested_bytes)

    def test_reconstruction_private_truth_is_never_projected_into_archive(self) -> None:
        private_medium_id = "private-reconstruction-wire"
        scenario = {
            "schema_version": 1,
            "scenario_id": "private-preview",
            "name": "Private preview",
            "capture_time_ns": 2_000_000_000,
            "nodes": [{"node_id": "r1", "kind": "router"}],
            "media": [
                {
                    "medium_id": private_medium_id,
                    "state": "up",
                    "attachments": [
                        {
                            "node_id": "r1",
                            "port_id": "xe0",
                            "resource_id": "port-resource:r1-xe0",
                        }
                    ],
                }
            ],
            "events": [
                {
                    "event_id": "truth-down",
                    "timestamp_ns": 1_000_000_000,
                    "kind": "link-state",
                    "target_id": private_medium_id,
                    "status": "down",
                    "propagation": {"mode": "manual"},
                }
            ],
        }
        reconstruction = reconstruct_scenario(
            scenario,
            at_time_ns=1_000_000_000,
        )
        self.assertEqual(
            reconstruction["private_truth"]["media"][0]["medium_id"],
            private_medium_id,
        )

        content = build_assembly_bytes(reconstruction)
        outer = _members(content)
        nested = _members(outer["nodes/r1.tgz"])
        combined = b"\n".join(nested.values())
        self.assertNotIn(private_medium_id.encode("utf-8"), combined)
        self.assertIn(b"port-resource:r1-xe0", combined)


if __name__ == "__main__":
    unittest.main()
