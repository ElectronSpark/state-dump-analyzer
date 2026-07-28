from __future__ import annotations

import json
import sys
import tarfile
import unittest
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Sequence
from uuid import UUID

DEMO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = DEMO_ROOT.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
sys.path.insert(0, str(DEMO_ROOT))

from rsl_demo_generator.conformance import (  # noqa: E402
    CTF_MEMBER,
    EXPECTATIONS_MEMBER,
    MALFORMED_STATUS_MEMBER,
    MANIFEST_MEMBER,
    STATUS_MEMBER,
    build_ingestion_conformance_corpus,
    ingestion_temporal_semantic_vector,
)
from rsl_demo_plugin import (  # noqa: E402
    DEVICE_CLOCK,
    PARSER_ID,
    PLATFORM_ID,
    STATUS_FILENAME,
    plugin,
    render_conformance_status_fixture,
)
from rsl_demo_plugin.archive import (  # noqa: E402
    CTF_METADATA_MEMBER,
    CTF_STREAM_MEMBER,
)

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
        retained = [item for item in output if isinstance(item, SourceRecordEmission)]

        self.assertEqual(
            [item.resource.parts for item in observations],
            [
                (("ifindex", 7),),
                (("ifindex", 7),),
                (("ifindex", 8),),
                (("ifindex", 9),),
            ],
        )
        self.assertEqual(
            [item.condition_class.value for item in observations],
            ["healthy", "error", "error", "unknown"],
        )
        self.assertTrue(all(item.state.complete for item in observations))
        self.assertTrue(
            all(item.evidence.clock_domain == DEVICE_CLOCK for item in observations)
        )
        self.assertEqual(len(retained), 4)
        self.assertTrue(retained[0].copy_text.startswith('{"kind":"interface"'))
        self.assertEqual(
            [item.timestamp_ns for item in retained[:2]],
            [1_759_680_000_000_000_000] * 2,
        )
        self.assertEqual(
            [item.attributes["source_sequence"] for item in retained],
            [10, 20, 30, 40],
        )
        self.assertEqual(
            [item.attributes["lifecycle"] for item in retained],
            ["create", "modify", "create", "create"],
        )
        self.assertIsNone(retained[-1].timestamp_ns)
        self.assertIsNone(retained[-1].timestamp_uncertainty_ns)
        self.assertEqual(
            (
                observations[-1].observed_at_min_ns,
                observations[-1].observed_at_max_ns,
                observations[-1].quality.value,
            ),
            (
                1_759_680_000_002_000_000,
                1_759_680_000_002_500_000,
                "best_effort",
            ),
        )

    def test_compact_ingestion_corpus_is_deterministic_and_self_describing(
        self,
    ) -> None:
        first = build_ingestion_conformance_corpus()
        self.assertEqual(first, build_ingestion_conformance_corpus())
        with tarfile.open(fileobj=BytesIO(first), mode="r:gz") as archive:
            members = {
                member.name: archive.extractfile(member).read()
                for member in archive.getmembers()
                if member.isfile()
            }

        manifest = json.loads(members[MANIFEST_MEMBER])
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["large_demo_runtime"], "v1-unchanged")
        self.assertEqual(
            members[STATUS_MEMBER],
            render_conformance_status_fixture(),
        )
        vector = json.loads(members[EXPECTATIONS_MEMBER])
        self.assertEqual(vector, ingestion_temporal_semantic_vector())
        checked_vector = json.loads(
            (
                REPOSITORY_ROOT
                / "state-dump-generator"
                / "tests"
                / "fixtures"
                / "runtime-v2-ingestion-temporal-conformance.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(vector, checked_vector)

        with tarfile.open(
            fileobj=BytesIO(members[CTF_MEMBER]),
            mode="r:gz",
        ) as ctf_archive:
            ctf_names = {
                member.name for member in ctf_archive.getmembers() if member.isfile()
            }
        self.assertIn(CTF_METADATA_MEMBER, ctf_names)
        self.assertIn(CTF_STREAM_MEMBER, ctf_names)

        spec = tuple(plugin.locate_inputs(fixture_inventory()))[0]
        malformed = tuple(
            plugin.parse_status(
                MemoryArtifactReader(members[MALFORMED_STATUS_MEMBER]),
                spec,
            )
        )
        self.assertEqual(len(malformed), 1)
        self.assertIsInstance(malformed[0], PluginDiagnostic)
        self.assertTrue(malformed[0].recoverable)

        unsupported = DumpInventory(
            node_hint="router-1",
            artifacts=(
                ArtifactInfo(
                    artifact_id=ARTIFACT_ID,
                    logical_path=PurePosixPath("capture.pcap"),
                    parent_artifact_id=None,
                    media_type="application/vnd.tcpdump.pcap",
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
        self.assertIsNone(plugin.probe(unsupported).result)

    def test_runtime_v1_status_row_defaults_to_ordered_snapshot(self) -> None:
        legacy_record = {
            "kind": "interface",
            "captured_at_ns": 1_759_680_000_000_000_000,
            "ifindex": 7,
            "name": "xe-0/0/0",
            "admin_status": "up",
            "oper_status": "up",
            "description": "legacy row",
        }
        payload = (
            json.dumps(legacy_record, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        spec = next(iter(plugin.locate_inputs(fixture_inventory())))
        output = tuple(plugin.parse_status(MemoryArtifactReader(payload), spec))
        retained = next(
            item for item in output if isinstance(item, SourceRecordEmission)
        )
        self.assertEqual(retained.attributes["source_sequence"], 1)
        self.assertEqual(retained.attributes["lifecycle"], "snapshot")

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
        valid = (DEMO_ROOT / "fixtures" / STATUS_FILENAME).read_bytes().splitlines()[0]
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
