from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path, PurePosixPath

from fastapi.testclient import TestClient

from router_dump_analyzer.artifact_core import ArtifactBoundaryError
from router_dump_analyzer.ingestion import (
    CORE_INGESTION_RUNTIME_CAPABILITY_ID,
    CoreIngestionRuntime,
    IngestionCoordinator,
    IngestionError,
    IngestionLimits,
    InMemoryRevisionStore,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    ConditionClass,
    CtfEventRecord,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    DomainEvent,
    DumpInventory,
    Evidence,
    InputParserKind,
    InputSpec,
    Outcome,
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
    RelationDirection,
    RelationshipCollectionObservation,
    RelationshipObservation,
    RelationshipTypeDescriptor,
    ResourceKey,
    ResourceKindDescriptor,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordRef,
    SourceRecordTypeDescriptor,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRef,
    StatusPerspectiveRole,
    UnknownField,
)
from router_dump_analyzer.runtime import (
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
    validate_runtime_session,
)


class ParseOnlyPlugin(AnalyzerPluginBase):
    manifest = PluginManifest(
        plugin_id="tests.parse-only",
        plugin_version="1.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("test-os",),
        supported_software_versions="1",
        capabilities=frozenset({PluginCapability.STATUS_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self) -> PluginSchema:
        return PluginSchema(
            resource_kinds=(
                ResourceKindDescriptor(
                    kind="INTERFACE",
                    label="Interface",
                    key_fields=("ifindex",),
                    properties=(
                        PropertyDescriptor(
                            name="name",
                            label="Name",
                            value_type="string",
                        ),
                        PropertyDescriptor(
                            name="oper_status",
                            label="Operational status",
                            value_type="string",
                        ),
                    ),
                    display_name_fields=("name",),
                    condition_field="oper_status",
                ),
            ),
            relationship_types=(),
            source_record_types=(
                SourceRecordTypeDescriptor(
                    source_type="status-json",
                    label="Status JSON",
                ),
            ),
        )

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        matched = any(
            artifact.logical_path.name == "status.jsonl"
            for artifact in inventory.artifacts
        )
        return ProbeReport(
            result=(
                ProbeResult(
                    confidence=1.0,
                    reasons=("status fixture",),
                    match_kind=ProbeMatchKind.EXACT,
                )
                if matched
                else None
            )
        )

    def locate_inputs(self, inventory: DumpInventory):
        for artifact in inventory.artifacts:
            if artifact.logical_path.name == "status.jsonl":
                yield InputSpec(
                    artifact_ids=(artifact.artifact_id,),
                    role="status",
                    node=inventory.node_hint or "router-a",
                    layer="interface",
                    parser_id="tests.status.v1",
                    parser_kind=InputParserKind.STATUS,
                )

    def parse_status(self, reader, spec):
        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            for line_number, line in enumerate(stream, start=1):
                record = json.loads(line)
                timestamp_ns = record["captured_at_ns"]
                evidence = Evidence(
                    artifact_id=artifact_id,
                    locator=f"line:{line_number}",
                    raw_timestamp_ns=timestamp_ns,
                    clock_domain="utc",
                    excerpt_sha256=sha256(line.rstrip()).hexdigest(),
                )
                yield SourceRecordEmission(
                    timestamp_ns=timestamp_ns,
                    timestamp_uncertainty_ns=0,
                    source_type="status-json",
                    source_name="status.jsonl",
                    record_name="interface",
                    message=f"{record['name']}: {record['oper_status']}",
                    layer=spec.layer,
                    attributes={"line": line_number},
                    evidence=(evidence,),
                    copy_text=line.decode("utf-8").rstrip(),
                )
                yield SnapshotObservation(
                    resource=ResourceKey(
                        namespace=self.manifest.plugin_id,
                        node=spec.node,
                        layer=spec.layer,
                        kind="INTERFACE",
                        parts=(("ifindex", record["ifindex"]),),
                    ),
                    observed_at_min_ns=timestamp_ns,
                    observed_at_max_ns=timestamp_ns,
                    state=PropertyPatch(
                        set_values={
                            "name": record["name"],
                            "oper_status": record["oper_status"],
                        },
                        complete=True,
                    ),
                    provenance=Provenance.OBSERVED,
                    quality=Quality.EXACT,
                    evidence=evidence,
                    condition=record["oper_status"],
                    condition_class=ConditionClass.HEALTHY,
                )


class InvalidOutputPlugin(ParseOnlyPlugin):
    def parse_status(self, reader, spec):
        yield object()


class InvalidBoundaryPlugin(ParseOnlyPlugin):
    def __init__(self, failure: str) -> None:
        self.failure = failure

    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if (
                self.failure == "time"
                and isinstance(output, SnapshotObservation)
            ):
                yield replace(output, observed_at_min_ns=1.5)
                return
            if (
                self.failure == "property"
                and isinstance(output, SnapshotObservation)
            ):
                yield replace(
                    output,
                    state=PropertyPatch(
                        set_values={"undeclared": "value"},
                        complete=True,
                    ),
                )
                return
            if (
                self.failure == "cycle"
                and isinstance(output, SourceRecordEmission)
            ):
                cycle: dict[str, object] = {}
                cycle["self"] = cycle
                yield replace(output, attributes=cycle)
                return
            yield output


class DiagnosticPlugin(ParseOnlyPlugin):
    def probe(self, inventory: DumpInventory) -> ProbeReport:
        report = super().probe(inventory)
        return replace(
            report,
            diagnostics=(
                PluginDiagnostic(
                    stage=DiagnosticStage.PROBE,
                    severity=DiagnosticSeverity.WARNING,
                    code="tests.probe-warning",
                    message="Recognized with a harmless warning.",
                    recoverable=True,
                    origin=DiagnosticOrigin.PLUGIN,
                ),
            ),
        )


class AllParserPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.all-parsers",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.TEXT_TRACE_PARSE,
                PluginCapability.CTF_PARSE,
            }
        ),
    )

    def describe(self) -> PluginSchema:
        schema = super().describe()
        return replace(
            schema,
            source_record_types=(
                *schema.source_record_types,
                SourceRecordTypeDescriptor(
                    source_type="text-log",
                    label="Text log",
                ),
                SourceRecordTypeDescriptor(
                    source_type="ctf-event",
                    label="CTF event",
                ),
            ),
        )

    def locate_inputs(self, inventory: DumpInventory):
        yield from super().locate_inputs(inventory)
        for artifact in inventory.artifacts:
            if artifact.logical_path.name == "router.log":
                yield InputSpec(
                    artifact_ids=(artifact.artifact_id,),
                    role="text",
                    node=inventory.node_hint or "router-a",
                    layer="logging",
                    parser_id="tests.text.v1",
                    parser_kind=InputParserKind.TEXT_TRACE,
                )
            elif artifact.logical_path.name == "trace.ctf":
                yield InputSpec(
                    artifact_ids=(artifact.artifact_id,),
                    role="ctf",
                    node=inventory.node_hint or "router-a",
                    layer="logging",
                    parser_id="tests.ctf.v1",
                    parser_kind=InputParserKind.CTF,
                )

    def parse_text_trace(self, reader, spec):
        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            payload = stream.read().decode("utf-8").strip()
        evidence = Evidence(
            artifact_id=artifact_id,
            locator="line:1",
            raw_timestamp_ns=300,
            clock_domain="utc",
        )
        yield SourceRecordEmission(
            timestamp_ns=300,
            timestamp_uncertainty_ns=0,
            source_type="text-log",
            source_name="router.log",
            record_name="message",
            message=payload,
            layer=spec.layer,
            evidence=(evidence,),
        )

    def parse_ctf(self, spec, messages):
        for message in messages:
            assert isinstance(message, CtfEventRecord)
            evidence = message.evidence[0]
            event_uid = b"e" * 32
            yield SourceRecordEmission(
                timestamp_ns=message.timestamp_ns,
                timestamp_uncertainty_ns=message.timestamp_uncertainty_ns,
                source_type="ctf-event",
                source_name="trace.ctf",
                record_name=message.event_name,
                message="decoded CTF event",
                layer=spec.layer,
                matched_event_uid=event_uid,
                evidence=(evidence,),
            )
            yield DomainEvent(
                event_uid=event_uid,
                timestamp_ns=message.timestamp_ns,
                timestamp_uncertainty_ns=message.timestamp_uncertainty_ns,
                source_sequence=message.message_ordinal,
                event_type="decoded-event",
                action="observe",
                outcome=Outcome.SUCCESS,
                attributes=message.payload,
                subjects=(),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                source=SourceRecordRef(
                    source_id="trace.ctf",
                    message_ordinal=message.message_ordinal,
                    trace_uid=message.trace_uid,
                    stream_uid=message.stream_uid,
                ),
                evidence=evidence,
            )


class FakeTraceDecoder:
    def __init__(self) -> None:
        self.calls = 0

    def iter_ctf(self, reader, spec):
        self.calls += 1
        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            self.payload = stream.read()
        yield CtfEventRecord(
            trace_uid="trace-a",
            stream_uid="stream-a",
            packet_sequence=1,
            message_ordinal=9,
            event_name="route_update",
            timestamp_ns=400,
            timestamp_uncertainty_ns=0,
            clock_domain="utc",
            payload={"operation": "insert"},
            evidence=(
                Evidence(
                    artifact_id=artifact_id,
                    locator="ctf:stream=stream-a,message=9",
                    raw_timestamp_ns=400,
                    clock_domain="utc",
                ),
            ),
        )


class RichObservationPlugin(ParseOnlyPlugin):
    def describe(self) -> PluginSchema:
        schema = super().describe()
        return replace(
            schema,
            relationship_types=(
                RelationshipTypeDescriptor(
                    relation_type="member",
                    label="Member",
                    directed=True,
                    structural=True,
                ),
            ),
            status_perspectives=(
                StatusPerspectiveDescriptor(
                    perspective_id="interface-observed",
                    label="Interface observed",
                    layer_id="interface",
                    role=StatusPerspectiveRole.OBSERVED,
                ),
            ),
        )

    def parse_status(self, reader, spec):
        resource = None
        last_evidence = None
        perspective = StatusPerspectiveRef("interface-observed")
        for output in super().parse_status(reader, spec):
            if isinstance(output, SnapshotObservation):
                resource = output.resource
                last_evidence = output.evidence
                if output.observed_at_min_ns == 200:
                    yield replace(
                        output,
                        observed_at_max_ns=240,
                        state=PropertyPatch(
                            unknown_fields=(
                                UnknownField(
                                    name="oper_status",
                                    reason_code="not-captured",
                                    message="second sample omitted status",
                                    evidence=(output.evidence,),
                                ),
                            ),
                            field_quality={
                                "oper_status": Quality.AMBIGUOUS
                            },
                            field_provenance={
                                "oper_status": Provenance.OBSERVED
                            },
                            complete=False,
                        ),
                        quality=Quality.AMBIGUOUS,
                        perspective_ref=perspective,
                    )
                    continue
                yield replace(output, perspective_ref=perspective)
                continue
            yield output
        assert resource is not None
        assert last_evidence is not None
        yield RelationshipObservation(
            source=resource,
            target=resource,
            relation_type="member",
            observed_at_min_ns=150,
            observed_at_max_ns=175,
            present=True,
            attributes=PropertyPatch(
                set_values={"role": "primary"},
                field_quality={"role": Quality.EXACT},
                field_provenance={"role": Provenance.OBSERVED},
            ),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=last_evidence,
            perspective_ref=perspective,
        )
        yield RelationshipObservation(
            source=resource,
            target=resource,
            relation_type="member",
            observed_at_min_ns=250,
            observed_at_max_ns=290,
            present=None,
            attributes=PropertyPatch(),
            provenance=Provenance.OBSERVED,
            quality=Quality.UNKNOWN,
            evidence=last_evidence,
            perspective_ref=perspective,
        )
        yield RelationshipCollectionObservation(
            owner=resource,
            direction=RelationDirection.OUTGOING,
            relation_type="member",
            observed_at_min_ns=250,
            observed_at_max_ns=300,
            complete=True,
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=last_evidence,
            perspective_ref=perspective,
        )


class BadPerspectivePlugin(RichObservationPlugin):
    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if isinstance(output, SnapshotObservation):
                yield replace(
                    output,
                    perspective_ref=StatusPerspectiveRef("undeclared"),
                )
                return
            yield output


class InvalidProbeDiagnosticPlugin(ParseOnlyPlugin):
    def __init__(self, failure: str) -> None:
        self.failure = failure

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        report = super().probe(inventory)
        diagnostic = PluginDiagnostic(
            stage=DiagnosticStage.PROBE,
            severity=DiagnosticSeverity.WARNING,
            code="tests.invalid-diagnostic",
            message="invalid diagnostic boundary",
            recoverable=True,
        )
        if self.failure == "stage":
            diagnostic = replace(diagnostic, stage="probe")
        else:
            diagnostic = replace(diagnostic, recoverable=1)
        return replace(report, diagnostics=(diagnostic,))


class OptionPlugin(ParseOnlyPlugin):
    def __init__(self, option: str) -> None:
        self.option = option

    def locate_inputs(self, inventory: DumpInventory):
        for spec in super().locate_inputs(inventory):
            yield replace(spec, options={"mode": self.option})


class MultiNodePlugin(ParseOnlyPlugin):
    def __init__(self) -> None:
        self.parse_calls = 0

    def locate_inputs(self, inventory: DumpInventory):
        for spec in super().locate_inputs(inventory):
            yield replace(spec, node="router-a")
            yield replace(spec, node="router-b")

    def parse_status(self, reader, spec):
        self.parse_calls += 1
        yield from super().parse_status(reader, spec)


class FixedNodePlugin(ParseOnlyPlugin):
    def locate_inputs(self, inventory: DumpInventory):
        for spec in super().locate_inputs(inventory):
            yield replace(spec, node="router-a")


class InvalidLogicalRootPlugin(ParseOnlyPlugin):
    def locate_inputs(self, inventory: DumpInventory):
        for spec in super().locate_inputs(inventory):
            yield replace(
                spec,
                logical_root=PurePosixPath("unrelated"),
            )


class ScopeEscapePlugin(ParseOnlyPlugin):
    def __init__(self) -> None:
        self.other_artifact_id = None

    def locate_inputs(self, inventory: DumpInventory):
        selected = None
        for artifact in inventory.artifacts:
            if artifact.logical_path.name == "status.jsonl":
                selected = artifact
            else:
                self.other_artifact_id = artifact.artifact_id
        assert selected is not None
        yield InputSpec(
            artifact_ids=(selected.artifact_id,),
            role="status",
            node="router-a",
            layer="interface",
            parser_id="tests.scope.v1",
            parser_kind=InputParserKind.STATUS,
        )

    def parse_status(self, reader, spec):
        assert self.other_artifact_id is not None
        with reader.open_binary(self.other_artifact_id):
            pass
        yield from ()


class UnknownEvidenceEscapePlugin(RichObservationPlugin):
    def __init__(self) -> None:
        self.other_artifact_id = None

    def locate_inputs(self, inventory: DumpInventory):
        for artifact in inventory.artifacts:
            if artifact.logical_path.name != "status.jsonl":
                self.other_artifact_id = artifact.artifact_id
        yield from super().locate_inputs(inventory)

    def parse_status(self, reader, spec):
        assert self.other_artifact_id is not None
        for output in super().parse_status(reader, spec):
            if (
                isinstance(output, SnapshotObservation)
                and output.state.unknown_fields
            ):
                unknown = output.state.unknown_fields[0]
                escaped = replace(
                    unknown,
                    evidence=(
                        replace(
                            output.evidence,
                            artifact_id=self.other_artifact_id,
                        ),
                    ),
                )
                yield replace(
                    output,
                    state=replace(
                        output.state,
                        unknown_fields=(escaped,),
                    ),
                )
                continue
            yield output


class TwoTraceDecoder(FakeTraceDecoder):
    def iter_ctf(self, reader, spec):
        for ordinal in (9, 10):
            for message in super().iter_ctf(reader, spec):
                yield replace(
                    message,
                    message_ordinal=ordinal,
                    timestamp_ns=400 + ordinal,
                )


class InvalidTraceDecoder(FakeTraceDecoder):
    def iter_ctf(self, reader, spec):
        yield object()


class InvalidRequiredIntegerDecoder(FakeTraceDecoder):
    def iter_ctf(self, reader, spec):
        for message in super().iter_ctf(reader, spec):
            yield replace(message, message_ordinal=True)


class TooManySubjectsPlugin(AllParserPlugin):
    def parse_ctf(self, spec, messages):
        resource = ResourceKey(
            namespace=self.manifest.plugin_id,
            node=spec.node,
            layer="interface",
            kind="INTERFACE",
            parts=(("ifindex", 7),),
        )
        for output in super().parse_ctf(spec, messages):
            if isinstance(output, DomainEvent):
                yield replace(output, subjects=(resource, resource))
            else:
                yield output


class DiagnosticFloodPlugin(DiagnosticPlugin):
    def locate_inputs(self, inventory: DumpInventory):
        yield PluginDiagnostic(
            stage=DiagnosticStage.LOCATE,
            severity=DiagnosticSeverity.WARNING,
            code="tests.locate-warning",
            message="second warning",
            recoverable=True,
        )
        yield from super().locate_inputs(inventory)


class TemporalEventPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.temporal-order",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.TEXT_TRACE_PARSE,
            }
        ),
    )

    def locate_inputs(self, inventory: DumpInventory):
        yield from super().locate_inputs(inventory)
        for artifact in inventory.artifacts:
            if artifact.logical_path.name == "router.log":
                yield InputSpec(
                    artifact_ids=(artifact.artifact_id,),
                    role="text",
                    node=inventory.node_hint or "router-a",
                    layer="logging",
                    parser_id="tests.temporal.v1",
                    parser_kind=InputParserKind.TEXT_TRACE,
                )

    def parse_text_trace(self, reader, spec):
        artifact_id = spec.artifact_ids[0]
        evidence = Evidence(
            artifact_id=artifact_id,
            locator="line:1",
            raw_timestamp_ns=100,
            clock_domain="utc",
        )
        for timestamp_ns, source_sequence, event_uid in (
            (None, 0, b"z"),
            (100, 2, b"b"),
            (100, 1, b"c"),
            (100, 1, b"a"),
        ):
            yield DomainEvent(
                event_uid=event_uid,
                timestamp_ns=timestamp_ns,
                timestamp_uncertainty_ns=None,
                source_sequence=source_sequence,
                event_type="ordered-event",
                action="observe",
                outcome=Outcome.SUCCESS,
                attributes={},
                subjects=(),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                source=SourceRecordRef(
                    source_id="router.log",
                    message_ordinal=source_sequence,
                ),
                evidence=evidence,
            )


class CoreIngestionTests(unittest.TestCase):
    def _fixture(self, directory: str) -> Path:
        path = Path(directory) / "status.jsonl"
        path.write_text(
            "\n".join(
                (
                    json.dumps(
                        {
                            "captured_at_ns": 100,
                            "ifindex": 7,
                            "name": "xe-0/0/0",
                            "oper_status": "down",
                        }
                    ),
                    json.dumps(
                        {
                            "captured_at_ns": 200,
                            "ifindex": 7,
                            "name": "xe-0/0/0",
                            "oper_status": "up",
                        }
                    ),
                )
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_coordinator_executes_standard_contract_and_normalizes_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = IngestionCoordinator().ingest(
                ParseOnlyPlugin(),
                self._fixture(directory),
            )

        self.assertEqual(result.node_id, "router-a")
        self.assertTrue(result.revision_id.startswith("ingested/router-a/"))
        self.assertEqual(len(result.snapshots), 2)
        self.assertEqual(len(result.source_records), 2)
        self.assertEqual(len(result.dataset["resources"]), 1)
        self.assertEqual(
            [
                (item["valid_from_ns"], item["valid_to_ns"])
                for item in result.dataset["state_intervals"]
            ],
            [("100", "200"), ("200", None)],
        )
        self.assertEqual(
            result.dataset["resources"][0]["state"]["oper_status"],
            "up",
        )
        self.assertEqual(
            result.dataset["source_records"][0]["copy_text"],
            (
                '{"captured_at_ns": 100, "ifindex": 7, '
                '"name": "xe-0/0/0", "oper_status": "down"}'
            ),
        )
        self.assertEqual(
            result.dataset["inventory"]["mode"],
            "core-ingestion-v2",
        )
        self.assertEqual(
            result.dataset["inventory"]["archive"],
            "router-a core-owned input",
        )
        self.assertGreater(
            result.dataset["inventory"]["compressed_size"],
            0,
        )
        self.assertEqual(
            result.dataset["inventory"]["members"][0]["path"],
            "status.jsonl",
        )
        self.assertEqual(
            result.dataset["inventory"]["members"][0]["kind"],
            "file",
        )
        self.assertGreater(
            result.dataset["inventory"]["members"][0]["size"],
            0,
        )
        self.assertTrue(
            all(
                item.get("area")
                for item in result.dataset["gaps"]
            )
        )
        self.assertNotIn("demo", result.dataset)
        self.assertEqual(
            result.dataset["_ingestion"]["node_id"],
            "router-a",
        )
        self.assertEqual(
            result.dataset["_ingestion"]["matched_event_count"],
            0,
        )

    def test_revision_identity_is_content_stable_and_changes_with_input(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            coordinator = IngestionCoordinator()
            first = coordinator.ingest(ParseOnlyPlugin(), fixture)
            second = coordinator.ingest(ParseOnlyPlugin(), fixture)
            self.assertEqual(first.revision_id, second.revision_id)
            fixture.write_text(
                fixture.read_text(encoding="utf-8").replace(
                    '"oper_status": "up"',
                    '"oper_status": "degraded"',
                ),
                encoding="utf-8",
            )
            third = coordinator.ingest(ParseOnlyPlugin(), fixture)
            self.assertNotEqual(first.revision_id, third.revision_id)
            with_metadata = coordinator.ingest(
                ParseOnlyPlugin(),
                fixture,
                metadata={"capture_profile": "manual"},
            )
            self.assertNotEqual(
                third.revision_id,
                with_metadata.revision_id,
            )

    def test_invalid_parser_output_and_output_overflow_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            with self.assertRaisesRegex(
                IngestionError,
                "unsupported object",
            ):
                IngestionCoordinator().ingest(
                    InvalidOutputPlugin(),
                    fixture,
                )
            with self.assertRaisesRegex(
                IngestionError,
                "configured limit",
            ):
                IngestionCoordinator(
                    limits=IngestionLimits(max_parsed_outputs=1)
                ).ingest(ParseOnlyPlugin(), fixture)

    def test_parser_boundary_rejects_coercive_and_unbounded_values(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            for failure, message in (
                ("time", "integer or null"),
                ("property", "undeclared properties"),
                ("cycle", "reference cycle"),
            ):
                with (
                    self.subTest(failure=failure),
                    self.assertRaisesRegex(IngestionError, message),
                ):
                    IngestionCoordinator().ingest(
                        InvalidBoundaryPlugin(failure),
                        fixture,
                    )

    def test_recoverable_discovery_diagnostics_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = IngestionCoordinator().ingest(
                DiagnosticPlugin(),
                self._fixture(directory),
            )
        self.assertEqual(
            [item.code for item in result.diagnostics],
            ["tests.probe-warning"],
        )
        self.assertEqual(
            result.dataset["summary"]["parse"]["diagnostics"],
            1,
        )
        self.assertEqual(
            result.dataset["diagnostics"][0]["stage"],
            "probe",
        )

    def test_unknown_state_and_relationship_presence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = IngestionCoordinator().ingest(
                RichObservationPlugin(),
                self._fixture(directory),
            )

        resource = result.dataset["resources"][0]
        self.assertNotIn("oper_status", resource["state"])
        self.assertEqual(
            resource["unknown_fields"][0]["reason_code"],
            "not-captured",
        )
        self.assertEqual(
            resource["field_quality"]["oper_status"],
            "ambiguous",
        )
        self.assertEqual(
            resource["field_provenance"]["oper_status"],
            "observed",
        )
        self.assertEqual(result.dataset["relationships"], [])
        relationship_intervals = result.dataset[
            "relationship_intervals"
        ]
        self.assertEqual(
            relationship_intervals[-1]["present"],
            None,
        )
        self.assertEqual(
            relationship_intervals[-1]["observed_at_max_ns"],
            "290",
        )
        self.assertEqual(
            relationship_intervals[-1]["perspective_ref"][
                "perspective_id"
            ],
            "interface-observed",
        )
        self.assertEqual(
            result.dataset["_ingestion"]["timeline_end_ns"],
            "300",
        )
        self.assertFalse(
            result.dataset["runtime_capabilities"][
                "relationship_collection_materialization"
            ]
        )
        self.assertIn(
            "runtime-v2-relationship-collection-materialization",
            {item["id"] for item in result.dataset["gaps"]},
        )

    def test_revision_store_reads_are_detached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = IngestionCoordinator().ingest(
                ParseOnlyPlugin(),
                self._fixture(directory),
            )
        store = InMemoryRevisionStore(
            result,
            plugin_id=ParseOnlyPlugin.manifest.plugin_id,
        )
        result.dataset["resources"][0]["state"]["oper_status"] = "corrupt"
        first = store.dataset_for_revision(result.revision_id)
        first["resources"][0]["state"]["oper_status"] = "mutated"
        second = store.dataset_for_revision(result.revision_id)
        self.assertEqual(
            second["resources"][0]["state"]["oper_status"],
            "up",
        )
        assembly = store.assembly
        assembly.metadata["ingestion"] = "mutated"
        self.assertEqual(
            store.assembly.metadata["ingestion"],
            "core-v2",
        )

    def test_aggregate_budgets_cover_every_untrusted_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(directory)
            (root / "trace.ctf").write_bytes(b"opaque")
            cases = (
                (
                    IngestionCoordinator(
                        limits=IngestionLimits(max_total_outputs=2)
                    ),
                    ParseOnlyPlugin(),
                    fixture,
                    "aggregate output limit",
                ),
                (
                    IngestionCoordinator(
                        limits=IngestionLimits(max_evidence_items=1)
                    ),
                    ParseOnlyPlugin(),
                    fixture,
                    "evidence references",
                ),
                (
                    IngestionCoordinator(
                        limits=IngestionLimits(max_total_value_units=10)
                    ),
                    ParseOnlyPlugin(),
                    fixture,
                    "value-unit limit",
                ),
                (
                    IngestionCoordinator(
                        limits=IngestionLimits(max_total_text_bytes=10)
                    ),
                    ParseOnlyPlugin(),
                    fixture,
                    "text-byte limit",
                ),
                (
                    IngestionCoordinator(
                        limits=IngestionLimits(max_diagnostics=1)
                    ),
                    DiagnosticFloodPlugin(),
                    fixture,
                    "diagnostics exceeded",
                ),
                (
                    IngestionCoordinator(
                        trace_decoder=TwoTraceDecoder(),
                        limits=IngestionLimits(max_decoder_outputs=1),
                    ),
                    AllParserPlugin(),
                    root,
                    "decoder exceeded",
                ),
                (
                    IngestionCoordinator(
                        trace_decoder=TwoTraceDecoder(),
                        limits=IngestionLimits(max_event_links=1),
                    ),
                    AllParserPlugin(),
                    root,
                    "event links exceeded",
                ),
                (
                    IngestionCoordinator(
                        trace_decoder=FakeTraceDecoder(),
                        limits=IngestionLimits(max_subjects_per_event=1),
                    ),
                    TooManySubjectsPlugin(),
                    root,
                    "subject limit",
                ),
            )
            for coordinator, plugin, input_path, message in cases:
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(IngestionError, message),
                ):
                    coordinator.ingest(plugin, input_path)

    def test_diagnostics_perspectives_and_ctf_types_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(directory)
            (root / "trace.ctf").write_bytes(b"opaque")
            for plugin, message in (
                (
                    InvalidProbeDiagnosticPlugin("stage"),
                    "stage is invalid",
                ),
                (
                    InvalidProbeDiagnosticPlugin("bool"),
                    "recoverable must be a boolean",
                ),
                (
                    BadPerspectivePlugin(),
                    "undeclared perspective",
                ),
            ):
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(IngestionError, message),
                ):
                    IngestionCoordinator().ingest(plugin, fixture)
            for decoder, message in (
                (
                    InvalidTraceDecoder(),
                    "exact dependency-free CtfMessage",
                ),
                (
                    InvalidRequiredIntegerDecoder(),
                    "message_ordinal must be a non-negative integer",
                ),
            ):
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(IngestionError, message),
                ):
                    IngestionCoordinator(
                        trace_decoder=decoder
                    ).ingest(AllParserPlugin(), root)

    def test_input_node_root_and_reader_scope_are_enforced_pre_parse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self._fixture(directory)
            (root / "other.txt").write_text(
                "secret",
                encoding="utf-8",
            )
            multi_node = MultiNodePlugin()
            with self.assertRaisesRegex(
                IngestionError,
                "exactly one node",
            ):
                IngestionCoordinator().ingest(multi_node, root)
            self.assertEqual(multi_node.parse_calls, 0)
            with self.assertRaisesRegex(
                IngestionError,
                "outside logical root",
            ):
                IngestionCoordinator().ingest(
                    InvalidLogicalRootPlugin(),
                    root,
                )
            with self.assertRaisesRegex(
                ArtifactBoundaryError,
                "outside this reader scope",
            ):
                IngestionCoordinator().ingest(
                    ScopeEscapePlugin(),
                    root,
                )
            with self.assertRaisesRegex(
                IngestionError,
                "outside its input",
            ):
                IngestionCoordinator().ingest(
                    UnknownEvidenceEscapePlugin(),
                    root,
                )
            with self.assertRaisesRegex(
                IngestionError,
                "match the requested node_hint",
            ):
                IngestionCoordinator().ingest(
                    FixedNodePlugin(),
                    fixture,
                    node_hint="router-b",
                )

    def test_revision_fingerprint_includes_parser_selection_options(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            first = IngestionCoordinator().ingest(
                OptionPlugin("strict"),
                fixture,
            )
            second = IngestionCoordinator().ingest(
                OptionPlugin("best-effort"),
                fixture,
            )
        self.assertNotEqual(first.revision_id, second.revision_id)

    def test_temporal_order_is_timestamp_sequence_identifier_unknown_last(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._fixture(directory)
            (root / "router.log").write_text("events\n", encoding="utf-8")
            result = IngestionCoordinator().ingest(
                TemporalEventPlugin(),
                root,
            )
        self.assertEqual(
            [item["event_uid"] for item in result.dataset["events"]],
            [b"a".hex(), b"c".hex(), b"b".hex(), b"z".hex()],
        )

    def test_all_declared_parser_kinds_have_a_core_dispatch_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._fixture(directory)
            (root / "router.log").write_text("route installed\n", encoding="utf-8")
            (root / "trace.ctf").write_bytes(b"opaque decoder input")
            decoder = FakeTraceDecoder()
            result = IngestionCoordinator(
                trace_decoder=decoder,
            ).ingest(AllParserPlugin(), root)

            self.assertEqual(decoder.calls, 1)
            self.assertEqual(decoder.payload, b"opaque decoder input")
            self.assertEqual(len(result.events), 1)
            self.assertEqual(len(result.source_records), 4)
            self.assertEqual(
                [
                    record["source_type"]
                    for record in result.dataset["source_records"]
                ],
                ["status-json", "status-json", "text-log", "ctf-event"],
            )
            self.assertEqual(
                result.dataset["events"][0]["source_sequence"],
                9,
            )
            self.assertEqual(
                result.dataset["_ingestion"]["matched_event_count"],
                1,
            )

            with self.assertRaisesRegex(
                IngestionError,
                "requires a core TraceDecoder",
            ):
                IngestionCoordinator().ingest(AllParserPlugin(), root)

    def test_parse_only_plugin_launches_without_runtime_open_path(self) -> None:
        plugin = ParseOnlyPlugin()
        runtime = require_plugin_runtime(plugin)
        self.assertIsInstance(runtime, CoreIngestionRuntime)
        self.assertEqual(
            runtime.capability_id,
            CORE_INGESTION_RUNTIME_CAPABILITY_ID,
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            with runtime.open(fixture) as session:
                self.assertIs(validate_runtime_session(session), session)
                self.assertEqual(
                    session.revision_store.default_revision_id,
                    session.data_source.revision_id(
                        session.data_source.load_dataset()
                    ),
                )

            application = create_runtime_application(
                RuntimeApplicationRequest(
                    runtime=runtime,
                    input_path=fixture,
                    serve_frontend=False,
                )
            )
            with TestClient(application) as client:
                response = client.get("/v1/workspace")
                self.assertEqual(response.status_code, 200)
                workspace = response.json()
                self.assertEqual(
                    workspace["workspace"]["node_id"],
                    "router-a",
                )
                self.assertEqual(len(workspace["resources"]), 1)
                self.assertEqual(len(workspace["state_intervals"]), 2)
                capabilities = workspace["workspace"]["capabilities"]
                self.assertTrue(capabilities["historical_state"])
                self.assertEqual(
                    capabilities["historical_state_mode"],
                    "embedded",
                )
                self.assertFalse(capabilities["temporal_state_query"])
                self.assertFalse(capabilities["topology_query"])
                self.assertFalse(capabilities["route_query"])
                self.assertFalse(capabilities["worker_isolation"])
                self.assertFalse(capabilities["execution_timeout"])
                revision_id = workspace["workspace"]["revision_id"]
                advertised = client.get(
                    f"/v1/revisions/{revision_id}/capabilities"
                )
                self.assertEqual(advertised.status_code, 200)
                limitation_ids = {
                    item["id"]
                    for item in advertised.json()["limitations"]
                }
                self.assertIn(
                    "runtime-v2-temporal-query",
                    limitation_ids,
                )
                self.assertIn(
                    "runtime-v2-worker-isolation",
                    limitation_ids,
                )
                routes = client.get(
                    f"/v1/revisions/{revision_id}/routes/capabilities"
                )
                self.assertEqual(routes.status_code, 200)
                self.assertFalse(routes.json()["available"])
                topology = client.get(
                    f"/v1/revisions/{revision_id}/topology/capabilities"
                )
                self.assertEqual(topology.status_code, 501)

            frontend_application = create_runtime_application(
                RuntimeApplicationRequest(
                    runtime=runtime,
                    input_path=fixture,
                    serve_frontend=True,
                )
            )
            with TestClient(frontend_application) as client:
                page = client.get("/")
                self.assertEqual(page.status_code, 200)
                self.assertIn(
                    "text/html",
                    page.headers.get("content-type", ""),
                )

    def test_non_plugin_still_fails_runtime_selection(self) -> None:
        with self.assertRaisesRegex(
            TypeError,
            "does not expose runtime.v1",
        ):
            require_plugin_runtime(object())

    def test_generated_reference_corpus_runs_through_core_ingestion(
        self,
    ) -> None:
        from rsl_demo_generator import build_ingestion_conformance_corpus
        from rsl_demo_plugin import plugin

        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "conformance.tgz"
            corpus.write_bytes(build_ingestion_conformance_corpus())
            result = IngestionCoordinator().ingest(plugin, corpus)

        self.assertEqual(len(result.inventory.artifacts), 8)
        self.assertEqual(len(result.snapshots), 4)
        self.assertEqual(len(result.source_records), 4)
        self.assertEqual(len(result.dataset["resources"]), 3)
        self.assertEqual(
            [
                item["attributes"]["source_sequence"]
                for item in result.dataset["source_records"]
            ],
            [10, 20, 30, 40],
        )
        self.assertEqual(result.diagnostics, ())


if __name__ == "__main__":
    unittest.main()
