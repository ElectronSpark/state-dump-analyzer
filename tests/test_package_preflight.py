"""Synthetic package boundaries: plug-in versions, bounded replay, isolation."""

from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from threading import Barrier, Lock
from uuid import uuid4

from router_dump_analyzer.artifact_core import ArtifactLimits
from router_dump_analyzer.ingestion import (
    IngestionCoordinator,
    IngestionError,
    IngestionLimits,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    CtfEventRecord,
    Evidence,
    InputParserKind,
    InputSpec,
    PackageContext,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
    SourceRecordEmission,
    SourceRecordTypeDescriptor,
)
from router_dump_analyzer.plugin_validation import validate_plugin


class SyntheticDecoder:
    def __init__(self):
        self.calls = 0
        self.closed = 0
        self.lock = Lock()

    def iter_ctf(self, reader, spec):
        with self.lock:
            self.calls += 1
        try:
            with reader.open_binary(spec.artifact_ids[0]) as stream:
                rows = json.load(stream)
            for ordinal, row in enumerate(rows):
                yield CtfEventRecord(
                    trace_uid="synthetic",
                    stream_uid="stream",
                    packet_sequence=0,
                    message_ordinal=ordinal,
                    event_name="fixture",
                    timestamp_ns=ordinal,
                    timestamp_uncertainty_ns=0,
                    clock_domain="synthetic-clock",
                    payload=row,
                    evidence=(
                        Evidence(
                            spec.artifact_ids[0],
                            f"record:{ordinal}",
                            ordinal,
                            "synthetic-clock",
                        ),
                    ),
                )
        finally:
            with self.lock:
                self.closed += 1


class VersionedPackagePlugin(AnalyzerPluginBase):
    manifest = PluginManifest(
        plugin_id="test.package",
        plugin_version="1",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("synthetic",),
        supported_software_versions="opaque",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.CTF_PARSE,
                PluginCapability.PACKAGE_PREFLIGHT,
            }
        ),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def __init__(self, *, barrier=None, fault=None):
        self.barrier = barrier
        self.fault = fault
        self.preflights = 0
        self.parses = 0
        self.contexts = []
        self.records = None

    def describe(self):
        return PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            source_record_types=(SourceRecordTypeDescriptor("fixture", "Fixture"),),
        )

    def probe(self, inventory):
        return ProbeReport(
            ProbeResult(1.0, ("synthetic package",), match_kind=ProbeMatchKind.EXACT)
        )

    def locate_inputs(self, inventory):
        # Status is deliberately parsed first although version evidence is CTF.
        for name, kind in (
            ("status.txt", InputParserKind.STATUS),
            ("trace.ctf", InputParserKind.CTF),
        ):
            artifact = next(
                item for item in inventory.artifacts if item.logical_path.name == name
            )
            yield InputSpec(
                (artifact.artifact_id,),
                name,
                inventory.node_hint or "node",
                "fixture",
                name,
                parser_kind=kind,
            )

    def preflight_package(self, inventory, reader, inputs, records):
        self.preflights += 1
        self.records = records
        if self.fault == "invalid-reference":
            next(iter(records.ctf_messages(9)))
        if self.fault in {"overflow", "swallowed-overflow"}:
            try:
                tuple(records.ctf_messages(1))
            except IngestionError:
                if self.fault != "swallowed-overflow":
                    raise
        first = next(iter(records.ctf_messages(1)))
        assert first is next(iter(records.ctf_messages(1)))
        versions = first.payload["versions"]
        if len(versions) != 1:
            raise IngestionError("ambiguous synthetic software version")
        if self.barrier is not None:
            self.barrier.wait(timeout=10)
        evidence = first.evidence
        if self.fault == "invalid-evidence":
            evidence = (replace(evidence[0], artifact_id=uuid4()),)
        return PackageContext(
            {"version": versions[0], "nested": {"items": [1, 2]}}, evidence
        )

    def _context(self, spec):
        self.parses += 1
        context = spec.package_context
        self.contexts.append((spec.node, context))
        assert context is not None
        try:
            context.values["nested"]["items"][0] = 9
        except TypeError:
            pass
        else:
            raise AssertionError("context is mutable")
        return context

    def parse_status(self, reader, spec):
        context = self._context(spec)
        with reader.open_binary(spec.artifact_ids[0]) as stream:
            expected_version = stream.read().decode()
        assert context.values["version"] == expected_version
        yield SourceRecordEmission(
            None, None, "fixture", "status", "status", expected_version, spec.layer
        )

    def parse_ctf(self, spec, messages):
        self._context(spec)
        if self.fault == "early-parser":
            next(iter(messages))
            return
        if self.fault == "swallowed-decoder-error":
            try:
                tuple(messages)
            except IngestionError:
                return
        for message in messages:
            yield SourceRecordEmission(
                message.timestamp_ns,
                0,
                "fixture",
                "trace",
                "fixture",
                str(message.message_ordinal),
                spec.layer,
                evidence=message.evidence,
            )


class PackagePreflightTests(unittest.TestCase):
    def test_preflight_limits_preserve_existing_positional_constructor(self):
        artifact_limits = ArtifactLimits()
        limits = IngestionLimits(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, artifact_limits
        )
        original_names = (
            "max_located_inputs",
            "max_parsed_outputs",
            "max_total_outputs",
            "max_decoder_outputs",
            "max_diagnostics",
            "max_evidence_items",
            "max_subject_references",
            "max_event_links",
            "max_total_value_units",
            "max_total_text_bytes",
            "max_evidence_per_output",
            "max_subjects_per_event",
            "max_event_links_per_record",
        )
        self.assertEqual(
            tuple(getattr(limits, name) for name in original_names), tuple(range(1, 14))
        )
        self.assertIs(limits.artifact_limits, artifact_limits)
        self.assertEqual(limits.max_preflight_records, 4_096)
        self.assertEqual(limits.max_preflight_bytes, 16 * 1024 * 1024)

    def package(self, root: Path, version="v1", versions=None):
        root.mkdir(exist_ok=True)
        (root / "status.txt").write_text(version)
        (root / "trace.ctf").write_text(
            json.dumps(
                [{"versions": versions or [version]}, {"value": 2}, {"value": 3}]
            )
        )
        return root

    def test_preflight_once_before_all_handlers_and_decode_once(self):
        with tempfile.TemporaryDirectory() as directory:
            decoder = SyntheticDecoder()
            plugin = VersionedPackagePlugin()
            result = IngestionCoordinator(trace_decoder=decoder).ingest(
                plugin, self.package(Path(directory))
            )
        self.assertEqual(plugin.preflights, 1)
        self.assertEqual(plugin.parses, 2)
        self.assertIs(plugin.contexts[0][1], plugin.contexts[1][1])
        self.assertEqual((decoder.calls, decoder.closed), (1, 1))
        self.assertEqual(
            [record.message for record in result.source_records], ["v1", "0", "1", "2"]
        )
        with self.assertRaisesRegex(IngestionError, "outside preflight"):
            next(iter(plugin.records.ctf_messages(1)))

    def test_ambiguous_versions_rejected_by_plugin_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin, decoder = VersionedPackagePlugin(), SyntheticDecoder()
            with self.assertRaisesRegex(IngestionError, "ambiguous synthetic"):
                IngestionCoordinator(trace_decoder=decoder).ingest(
                    plugin, self.package(Path(directory), versions=["v1", "v2"])
                )
        self.assertEqual(plugin.parses, 0)
        self.assertEqual(decoder.closed, 1)

    def test_invalid_references_and_evidence_fail_before_parsing(self):
        for fault, text in (
            ("invalid-reference", "unknown input"),
            ("invalid-evidence", "outside its input"),
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                plugin = VersionedPackagePlugin(fault=fault)
                with self.assertRaisesRegex(IngestionError, text):
                    IngestionCoordinator(trace_decoder=SyntheticDecoder()).ingest(
                        plugin, self.package(Path(directory))
                    )
                self.assertEqual(plugin.parses, 0)

    def test_replay_record_and_byte_bounds_cannot_be_swallowed(self):
        for fault, limits in (
            ("overflow", IngestionLimits(max_preflight_records=1)),
            ("swallowed-overflow", IngestionLimits(max_preflight_records=1)),
            (None, IngestionLimits(max_preflight_bytes=8)),
        ):
            with (
                self.subTest(fault=fault, limits=limits),
                tempfile.TemporaryDirectory() as directory,
            ):
                plugin, decoder = (
                    VersionedPackagePlugin(fault=fault),
                    SyntheticDecoder(),
                )
                with self.assertRaisesRegex(IngestionError, "preflight"):
                    IngestionCoordinator(trace_decoder=decoder, limits=limits).ingest(
                        plugin, self.package(Path(directory))
                    )
                self.assertEqual(plugin.parses, 0)
                self.assertEqual(decoder.closed, 1)

    def test_concurrent_packages_share_plugin_but_never_context_or_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin, decoder = (
                VersionedPackagePlugin(barrier=Barrier(2)),
                SyntheticDecoder(),
            )
            coordinator = IngestionCoordinator(trace_decoder=decoder)
            paths = [
                self.package(root / f"p{index}", f"v{index}") for index in range(2)
            ]
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        lambda item: coordinator.ingest(
                            plugin, item[1], node_hint=f"node-{item[0]}"
                        ),
                        enumerate(paths),
                    )
                )
        self.assertEqual((decoder.calls, decoder.closed), (2, 2))
        self.assertEqual(
            [result.source_records[0].message for result in results], ["v0", "v1"]
        )
        contexts = {node: context for node, context in plugin.contexts}
        self.assertIsNot(contexts["node-0"], contexts["node-1"])
        self.assertNotEqual(results[0].revision_id, results[1].revision_id)

    def test_declared_preflight_without_override_fails_validation(self):
        class MissingPreflight(VersionedPackagePlugin):
            preflight_package = AnalyzerPluginBase.preflight_package

        report = validate_plugin(MissingPreflight())
        self.assertFalse(report.ok)
        self.assertTrue(any("preflight_package" in error for error in report.errors))

    def test_foreign_enum_context_is_detached_from_mutable_plugin_singleton(self):
        class VendorVersion(str, Enum):
            CURRENT = "v1"

        class EnumContextPlugin(VersionedPackagePlugin):
            def preflight_package(self, inventory, reader, inputs, records):
                context = super().preflight_package(inventory, reader, inputs, records)
                return replace(
                    context, values={**context.values, "version": VendorVersion.CURRENT}
                )

            def parse_status(self, reader, spec):
                VendorVersion.CURRENT._value_ = "mutated"
                VendorVersion.CURRENT.mutable_metadata = ["changed"]
                assert type(spec.package_context.values["version"]) is str
                yield from super().parse_status(reader, spec)

        with tempfile.TemporaryDirectory() as directory:
            plugin = EnumContextPlugin()
            result = IngestionCoordinator(trace_decoder=SyntheticDecoder()).ingest(
                plugin, self.package(Path(directory))
            )
        self.assertEqual(result.source_records[0].message, "v1")
        self.assertEqual(plugin.contexts[1][1].values["version"], "v1")

    def test_package_context_evidence_obeys_per_output_and_aggregate_limits(self):
        class ExtraEvidencePlugin(VersionedPackagePlugin):
            def preflight_package(self, inventory, reader, inputs, records):
                context = super().preflight_package(inventory, reader, inputs, records)
                return replace(context, evidence=context.evidence * 2)

        for limits, message in (
            (IngestionLimits(max_evidence_per_output=1), "per-output evidence"),
            (IngestionLimits(max_evidence_items=2), "evidence references"),
        ):
            with (
                self.subTest(limits=limits),
                tempfile.TemporaryDirectory() as directory,
            ):
                plugin = ExtraEvidencePlugin()
                with self.assertRaisesRegex(IngestionError, message):
                    IngestionCoordinator(
                        trace_decoder=SyntheticDecoder(), limits=limits
                    ).ingest(plugin, self.package(Path(directory)))
                self.assertEqual(plugin.parses, 0)

    def test_spoofed_mutable_dataclass_context_is_rejected_before_handlers(self):
        @dataclass
        class ForeignRecord:
            status: str

        # Neither a matching module tag nor an exported DTO name grants identity.
        ForeignRecord.__module__ = "router_dump_analyzer.plugin_api"
        ForeignRecord.__name__ = "Evidence"

        class SpoofedContextPlugin(VersionedPackagePlugin):
            def preflight_package(self, inventory, reader, inputs, records):
                context = super().preflight_package(inventory, reader, inputs, records)
                return replace(
                    context,
                    values={**context.values, "foreign": ForeignRecord("before")},
                )

        with tempfile.TemporaryDirectory() as directory:
            plugin, decoder = SpoofedContextPlugin(), SyntheticDecoder()
            with self.assertRaisesRegex(IngestionError, "unsupported record type"):
                IngestionCoordinator(trace_decoder=decoder).ingest(
                    plugin, self.package(Path(directory))
                )
        self.assertEqual(plugin.parses, 0)
        self.assertEqual(decoder.closed, 1)

    def test_selective_mapper_cannot_hide_malformed_decoder_tail(self):
        class MalformedTailDecoder(SyntheticDecoder):
            def iter_ctf(self, reader, spec):
                for message in super().iter_ctf(reader, spec):
                    yield (
                        replace(message, message_ordinal=-1)
                        if message.message_ordinal == 2
                        else message
                    )

        for fault in ("early-parser", "swallowed-decoder-error"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                decoder, plugin = (
                    MalformedTailDecoder(),
                    VersionedPackagePlugin(fault=fault),
                )
                with self.assertRaisesRegex(
                    IngestionError, "message_ordinal|record access failed"
                ):
                    IngestionCoordinator(trace_decoder=decoder).ingest(
                        plugin, self.package(Path(directory))
                    )
                self.assertEqual((decoder.calls, decoder.closed), (1, 1))


if __name__ == "__main__":
    unittest.main()
