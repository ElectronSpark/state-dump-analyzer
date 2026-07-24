from __future__ import annotations

import sys
import tomllib
import unittest
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Sequence
from uuid import UUID


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from minimal_router_plugin import (  # noqa: E402
    DEVICE_CLOCK,
    PARSER_ID,
    PLATFORM_ID,
    STATUS_FILENAME,
    plugin,
)
from router_dump_analyzer.plugin_api import (  # noqa: E402
    ArtifactInfo,
    ChangeSet,
    DiagnosticSeverity,
    DumpInventory,
    InputParserKind,
    PluginCapability,
    PluginDiagnostic,
    ProbeMatchKind,
    SnapshotObservation,
)
from router_dump_analyzer.plugin_validation import validate_plugin  # noqa: E402


ARTIFACT_ID = UUID("6e966ff4-49f2-41f4-8596-8cf18d3bb8eb")


class MemoryArtifactReader:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        if artifact_id != ARTIFACT_ID:
            raise KeyError(artifact_id)
        return BytesIO(self._content)

    def materialize_private_path(self, artifact_id: UUID) -> str:
        raise AssertionError("the minimal parser does not materialize files")

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        raise AssertionError("the minimal parser does not materialize trees")


def fixture_inventory() -> DumpInventory:
    return DumpInventory(
        node_hint="router-1",
        artifacts=(
            ArtifactInfo(
                artifact_id=ARTIFACT_ID,
                logical_path=PurePosixPath(STATUS_FILENAME),
                parent_artifact_id=None,
                media_type="application/x-ndjson",
                compressed_size=None,
                uncompressed_size=None,
                sha256=None,
            ),
        ),
        metadata={
            "platform": PLATFORM_ID,
            "software_version": "1",
        },
    )


class MinimalPluginTests(unittest.TestCase):
    def test_package_metadata_and_declared_schema(self) -> None:
        metadata = tomllib.loads(
            (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            metadata["project"]["entry-points"]["router_dump_analyzer.plugins"],
            {"minimal_router": "minimal_router_plugin:plugin"},
        )
        self.assertEqual(
            plugin.manifest.capabilities,
            frozenset({PluginCapability.STATUS_PARSE}),
        )
        schema = plugin.describe()
        self.assertEqual([item.kind for item in schema.resource_kinds], ["INTERFACE"])
        self.assertEqual(schema.resource_kinds[0].key_fields, ("ifindex",))
        self.assertEqual(schema.relationship_types, ())

    def test_fixture_parses_to_golden_observations(self) -> None:
        inventory = fixture_inventory()
        report = plugin.probe(inventory)
        self.assertIsNotNone(report.result)
        assert report.result is not None
        self.assertEqual(report.result.match_kind, ProbeMatchKind.EXACT)

        located = tuple(plugin.locate_inputs(inventory))
        self.assertEqual(len(located), 1)
        spec = located[0]
        self.assertEqual(spec.parser_id, PARSER_ID)
        self.assertEqual(spec.parser_kind, InputParserKind.STATUS)
        self.assertEqual(spec.dispatch_hook, "parse_status")
        self.assertEqual(spec.required_capability, PluginCapability.STATUS_PARSE)

        fixture = (PACKAGE_ROOT / "fixtures" / STATUS_FILENAME).read_bytes()
        output = tuple(plugin.parse_status(MemoryArtifactReader(fixture), spec))
        golden = [
            {
                "key": (("ifindex", 7),),
                "time_ns": 1759680000000000000,
                "state": {
                    "name": "xe-0/0/0",
                    "admin_status": "up",
                    "oper_status": "up",
                    "description": "core uplink",
                },
                "condition": "up",
                "condition_class": "healthy",
                "locator": "line:1",
            },
            {
                "key": (("ifindex", 8),),
                "time_ns": 1759680000001000000,
                "state": {
                    "name": "xe-0/0/1",
                    "admin_status": "up",
                    "oper_status": "down",
                    "description": "peer link",
                },
                "condition": "down",
                "condition_class": "error",
                "locator": "line:2",
            },
        ]
        actual = [
            {
                "key": item.resource.parts,
                "time_ns": item.observed_at_min_ns,
                "state": dict(item.state.set_values),
                "condition": item.condition,
                "condition_class": item.condition_class.value,
                "locator": item.evidence.locator,
            }
            for item in output
        ]
        self.assertEqual(actual, golden)
        self.assertTrue(all(item.state.complete for item in output))
        self.assertTrue(
            all(item.evidence.clock_domain == DEVICE_CLOCK for item in output)
        )

    def test_missing_input_and_wrong_version_are_explicit(self) -> None:
        empty = DumpInventory(node_hint="router-1", artifacts=())
        self.assertIsNone(plugin.probe(empty).result)
        missing = tuple(plugin.locate_inputs(empty))
        self.assertEqual(len(missing), 1)
        self.assertIsInstance(missing[0], PluginDiagnostic)
        self.assertEqual(missing[0].code, "minimal.status-input-missing")

        wrong_version = DumpInventory(
            node_hint="router-1",
            artifacts=fixture_inventory().artifacts,
            metadata={
                "platform": PLATFORM_ID,
                "software_version": "9",
            },
        )
        report = plugin.probe(wrong_version)
        self.assertIsNotNone(report.result)
        assert report.result is not None
        self.assertEqual(report.result.match_kind, ProbeMatchKind.NONE)
        validation = validate_plugin(plugin, inventory=wrong_version)
        self.assertFalse(validation.ok)
        self.assertTrue(
            any("returned no match" in error for error in validation.errors)
        )

    def test_malformed_record_is_diagnosed_and_later_input_recovers(self) -> None:
        spec = tuple(plugin.locate_inputs(fixture_inventory()))[0]
        valid = (
            PACKAGE_ROOT / "fixtures" / STATUS_FILENAME
        ).read_bytes().splitlines()[0]
        output = tuple(
            plugin.parse_status(
                MemoryArtifactReader(b'{"kind":"interface"\n' + valid + b"\n"),
                spec,
            )
        )
        self.assertEqual(len(output), 2)
        self.assertIsInstance(output[0], PluginDiagnostic)
        self.assertEqual(output[0].severity, DiagnosticSeverity.ERROR)
        self.assertTrue(output[0].recoverable)
        self.assertIsInstance(output[1], SnapshotObservation)

    def test_validator_accepts_plugin_and_base_supplies_safe_noops(self) -> None:
        result = validate_plugin(plugin, inventory=fixture_inventory())
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.warnings, ())

        inventory = fixture_inventory()
        spec = tuple(plugin.locate_inputs(inventory))[0]
        self.assertEqual(tuple(plugin.parse_ctf(spec, ())), ())
        self.assertEqual(plugin.apply(None, None), ChangeSet())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
