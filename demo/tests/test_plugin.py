from __future__ import annotations

import sys
import unittest
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Sequence
from uuid import UUID


DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(DEMO_ROOT))

from router_dump_analyzer.plugin_api import (  # noqa: E402
    ArtifactInfo,
    DiagnosticSeverity,
    DumpInventory,
    InputParserKind,
    PluginCapability,
    PluginDiagnostic,
    ProbeMatchKind,
    SnapshotObservation,
    SourceRecordEmission,
)
from router_dump_analyzer.plugin_validation import validate_plugin  # noqa: E402
from rsl_demo_plugin import (  # noqa: E402
    DEVICE_CLOCK,
    PARSER_ID,
    PLATFORM_ID,
    STATUS_FILENAME,
    plugin,
    render_conformance_status_fixture,
)


ARTIFACT_ID = UUID("6e966ff4-49f2-41f4-8596-8cf18d3bb8eb")


class MemoryArtifactReader:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        if artifact_id != ARTIFACT_ID:
            raise KeyError(artifact_id)
        return BytesIO(self._content)

    def materialize_private_path(self, artifact_id: UUID) -> str:
        raise AssertionError("the example parser does not materialize files")

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        raise AssertionError("the example parser does not materialize trees")


def fixture_inventory(
    *,
    software_version: str = "1",
) -> DumpInventory:
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
            "software_version": software_version,
        },
    )


class DemoPluginTests(unittest.TestCase):
    def test_schema_probe_and_validator_are_complete(self) -> None:
        self.assertEqual(
            plugin.manifest.capabilities,
            frozenset({PluginCapability.STATUS_PARSE}),
        )
        schema = plugin.describe()
        self.assertEqual([item.kind for item in schema.resource_kinds], ["INTERFACE"])
        self.assertEqual(schema.resource_kinds[0].key_fields, ("ifindex",))
        self.assertEqual(schema.relationship_types, ())
        self.assertEqual(
            schema.source_record_groups[0].copy_action_label,
            "Copy status rows",
        )

        inventory = fixture_inventory()
        report = plugin.probe(inventory)
        self.assertIsNotNone(report.result)
        assert report.result is not None
        self.assertEqual(report.result.match_kind, ProbeMatchKind.EXACT)

        located = tuple(plugin.locate_inputs(inventory))
        self.assertEqual(len(located), 1)
        self.assertEqual(located[0].parser_id, PARSER_ID)
        self.assertEqual(located[0].parser_kind, InputParserKind.STATUS)
        self.assertEqual(located[0].dispatch_hook, "parse_status")
        result = validate_plugin(plugin, inventory=inventory)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.warnings, ())

    def test_fixture_parses_to_retained_records_and_complete_state(self) -> None:
        inventory = fixture_inventory()
        spec = tuple(plugin.locate_inputs(inventory))[0]
        fixture = (DEMO_ROOT / "fixtures" / STATUS_FILENAME).read_bytes()
        self.assertEqual(
            fixture,
            render_conformance_status_fixture(),
            "the checked-in conformance vector drifted from plug-in records",
        )
        output = tuple(plugin.parse_status(MemoryArtifactReader(fixture), spec))
        observations = [
            item for item in output if isinstance(item, SnapshotObservation)
        ]
        retained = [
            item for item in output if isinstance(item, SourceRecordEmission)
        ]

        self.assertEqual(
            [item.resource.parts for item in observations],
            [(("ifindex", 7),), (("ifindex", 8),)],
        )
        self.assertEqual(
            [item.condition_class.value for item in observations],
            ["healthy", "error"],
        )
        self.assertTrue(all(item.state.complete for item in observations))
        self.assertTrue(
            all(item.evidence.clock_domain == DEVICE_CLOCK for item in observations)
        )
        self.assertEqual(len(retained), 2)
        self.assertTrue(retained[0].copy_text.startswith('{"kind":"interface"'))

    def test_missing_malformed_and_incompatible_inputs_are_explicit(self) -> None:
        empty = DumpInventory(node_hint="router-1", artifacts=())
        self.assertIsNone(plugin.probe(empty).result)
        missing = tuple(plugin.locate_inputs(empty))
        self.assertEqual(len(missing), 1)
        self.assertIsInstance(missing[0], PluginDiagnostic)
        self.assertEqual(missing[0].code, "demo.status-input-missing")

        incompatible = plugin.probe(fixture_inventory(software_version="9"))
        self.assertIsNotNone(incompatible.result)
        assert incompatible.result is not None
        self.assertEqual(incompatible.result.match_kind, ProbeMatchKind.NONE)

        spec = tuple(plugin.locate_inputs(fixture_inventory()))[0]
        valid = (
            DEMO_ROOT / "fixtures" / STATUS_FILENAME
        ).read_bytes().splitlines()[0]
        output = tuple(
            plugin.parse_status(
                MemoryArtifactReader(b'{"kind":"interface"\n' + valid + b"\n"),
                spec,
            )
        )
        self.assertEqual(len(output), 3)
        self.assertIsInstance(output[0], PluginDiagnostic)
        self.assertEqual(output[0].severity, DiagnosticSeverity.ERROR)
        self.assertTrue(output[0].recoverable)
        self.assertIsInstance(output[1], SourceRecordEmission)
        self.assertIsInstance(output[2], SnapshotObservation)


if __name__ == "__main__":
    unittest.main()
