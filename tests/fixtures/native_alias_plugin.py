"""Importable vendor-neutral parser exercising the stdlib JSON native aliases."""

from __future__ import annotations

import json
import os
from hashlib import sha256

from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    DiagnosticSeverity,
    DiagnosticStage,
    Evidence,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    PropertyDescriptor,
    PropertyPatch,
    Provenance,
    Quality,
    ReconstructionSupport,
    ResourceKey,
    ResourceKindDescriptor,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordTypeDescriptor,
)


class NativeAliasPlugin(AnalyzerPluginBase):
    manifest = PluginManifest(
        plugin_id="tests.native-json-alias",
        plugin_version="1",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("synthetic",),
        supported_software_versions="1",
        capabilities=frozenset({PluginCapability.STATUS_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self):
        return PluginSchema(
            resource_kinds=(
                ResourceKindDescriptor(
                    kind="COUNTER_WINDOW",
                    label="Counter window",
                    key_fields=("id",),
                    properties=(
                        PropertyDescriptor(
                            "samples",
                            "Samples",
                            "array",
                            items=PropertyDescriptor(
                                "sample",
                                "Sample",
                                "object",
                                properties=tuple(
                                    PropertyDescriptor(
                                        name, name.title(), "integer", nullable=False
                                    )
                                    for name in ("time", "received", "sent")
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            relationship_types=(),
            source_record_types=(
                SourceRecordTypeDescriptor("counter-json", "Counter JSON"),
            ),
        )

    def probe(self, inventory):
        matched = any(
            item.logical_path.name == "counters.json" for item in inventory.artifacts
        )
        return ProbeReport(
            ProbeResult(
                1.0, ("synthetic counter JSON",), match_kind=ProbeMatchKind.EXACT
            )
            if matched
            else None,
        )

    def locate_inputs(self, inventory):
        for item in inventory.artifacts:
            if item.logical_path.name == "counters.json":
                yield InputSpec(
                    (item.artifact_id,),
                    "counter-window",
                    inventory.node_hint or "sample-node",
                    "counter",
                    "tests.native-json.v1",
                    parser_kind=InputParserKind.STATUS,
                )

    def parse_status(self, reader, spec):
        with reader.open_binary(spec.artifact_ids[0]) as stream:
            raw = stream.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("synthetic JSON fixture exceeds its byte limit")
        record = json.loads(raw)
        rendered = json.dumps(record, separators=(",", ":"), sort_keys=True)
        evidence = Evidence(
            spec.artifact_ids[0],
            "json:counter-window",
            record["captured_at_ns"],
            "utc",
            excerpt_sha256=sha256(raw).hexdigest(),
        )
        yield SourceRecordEmission(
            timestamp_ns=record["captured_at_ns"],
            timestamp_uncertainty_ns=0,
            source_type="counter-json",
            source_name="counters.json",
            record_name="counter-window",
            message="Decoded and encoded synthetic counters",
            layer=spec.layer,
            evidence=(evidence,),
            copy_text=rendered,
            attributes={
                "sample_count": len(record["samples"]),
                "parser_pid": os.getpid(),
            },
        )
        yield SnapshotObservation(
            resource=ResourceKey(
                self.manifest.plugin_id,
                spec.node,
                spec.layer,
                "COUNTER_WINDOW",
                (("id", "window"),),
            ),
            observed_at_min_ns=record["captured_at_ns"],
            observed_at_max_ns=record["captured_at_ns"],
            state=PropertyPatch(
                set_values={"samples": record["samples"]}, complete=True
            ),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=evidence,
        )
        yield PluginDiagnostic(
            stage=DiagnosticStage.STATUS_PARSE,
            severity=DiagnosticSeverity.INFO,
            code="JSON_ROUNDTRIP",
            message="Synthetic JSON round trip completed",
            recoverable=True,
            evidence=(evidence,),
            details={"sample_count": len(record["samples"])},
        )
