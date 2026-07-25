"""A small, complete implementation of the AnalyzerPlugin protocol.

Only status snapshots are advertised. ``AnalyzerPluginBase`` supplies safe
no-ops for event reduction, correlation, consistency, topology, and forwarding,
so the supported surface is easy to audit.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Iterable

from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPlugin,
    AnalyzerPluginBase,
    ArtifactReader,
    ConditionClass,
    DiagnosticSeverity,
    DiagnosticStage,
    DumpInventory,
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
    ResourceKindDescriptor,
    ResourceKey,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordGroupDescriptor,
    SourceRecordTypeDescriptor,
    StatusParseOutput,
)


PLUGIN_ID = "example.minimal-router"
STATUS_FILENAME = "minimal-status.jsonl"
PARSER_ID = "minimal.interface-status.v1"
PLATFORM_ID = "minimal-router-os"
SOFTWARE_VERSION = "1"
DEVICE_CLOCK = "minimal-router-realtime"


def _interface_schema() -> PluginSchema:
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
                        searchable=True,
                    ),
                    PropertyDescriptor(
                        name="admin_status",
                        label="Admin status",
                        value_type="string",
                        indexed=True,
                    ),
                    PropertyDescriptor(
                        name="oper_status",
                        label="Operational status",
                        value_type="string",
                        indexed=True,
                    ),
                    PropertyDescriptor(
                        name="description",
                        label="Description",
                        value_type="string",
                        searchable=True,
                    ),
                ),
                default_timeline_fields=("admin_status", "oper_status"),
                display_name_fields=("name",),
                default_table_fields=(
                    "name",
                    "admin_status",
                    "oper_status",
                    "description",
                ),
                condition_field="oper_status",
                presentation_tags=("interface",),
            ),
        ),
        relationship_types=(),
        source_record_groups=(
            SourceRecordGroupDescriptor(
                group_id="status-input",
                label="Status input",
                description="Decoded status rows retained beside normalized state.",
                copy_action_label="Copy status rows",
            ),
        ),
        source_record_types=(
            SourceRecordTypeDescriptor(
                source_type="status-json",
                label="Status JSON",
                description="Validated JSONL input retained by the example plug-in.",
                color="#66b8ff",
                stream_group="status-input",
            ),
        ),
    )


SCHEMA = _interface_schema()


class MinimalRouterPlugin(AnalyzerPluginBase):
    """Parse the example router's interface status snapshot."""

    manifest = PluginManifest(
        plugin_id=PLUGIN_ID,
        plugin_version="0.1.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=(PLATFORM_ID,),
        supported_software_versions=">=1,<2",
        capabilities=frozenset({PluginCapability.STATUS_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )

    def describe(self) -> PluginSchema:
        return SCHEMA

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        matching = tuple(
            artifact
            for artifact in inventory.artifacts
            if artifact.logical_path.name == STATUS_FILENAME
        )
        if not matching:
            return ProbeReport(result=None)

        declared_platform = inventory.metadata.get("platform")
        declared_version = inventory.metadata.get("software_version")
        exact = (
            declared_platform == PLATFORM_ID
            and declared_version == SOFTWARE_VERSION
        )
        incompatible = (
            declared_platform not in (None, PLATFORM_ID)
            or declared_version not in (None, SOFTWARE_VERSION)
        )
        if exact:
            match_kind = ProbeMatchKind.EXACT
            confidence = 1.0
        elif incompatible:
            match_kind = ProbeMatchKind.NONE
            confidence = 0.0
        else:
            match_kind = ProbeMatchKind.COMPATIBLE
            confidence = 0.7
        return ProbeReport(
            result=ProbeResult(
                confidence=confidence,
                reasons=(
                    f"inventory contains {STATUS_FILENAME}",
                    (
                        f"platform metadata is {declared_platform!r}; "
                        f"expected {PLATFORM_ID!r}"
                    ),
                    (
                        f"software version metadata is {declared_version!r}; "
                        f"expected {SOFTWARE_VERSION!r}"
                    ),
                ),
                detected_platform=PLATFORM_ID,
                detected_software_version=(
                    declared_version
                    if isinstance(declared_version, str)
                    else None
                ),
                match_kind=match_kind,
            )
        )

    def locate_inputs(
        self,
        inventory: DumpInventory,
    ) -> Iterable[InputSpec | PluginDiagnostic]:
        matching = tuple(
            artifact
            for artifact in inventory.artifacts
            if artifact.logical_path.name == STATUS_FILENAME
        )
        if not matching:
            yield PluginDiagnostic(
                stage=DiagnosticStage.LOCATE,
                severity=DiagnosticSeverity.ERROR,
                code="minimal.status-input-missing",
                message=f"Required input {STATUS_FILENAME} was not inventoried.",
                recoverable=False,
            )
            return

        node = inventory.node_hint or "unknown-node"
        for artifact in matching:
            yield InputSpec(
                artifact_ids=(artifact.artifact_id,),
                role="status_snapshot",
                node=node,
                layer="interface",
                parser_id=PARSER_ID,
                parser_kind=InputParserKind.STATUS,
            )

    def parse_status(
        self,
        reader: ArtifactReader,
        spec: InputSpec,
    ) -> Iterable[StatusParseOutput]:
        if len(spec.artifact_ids) != 1:
            yield PluginDiagnostic(
                stage=DiagnosticStage.STATUS_PARSE,
                severity=DiagnosticSeverity.ERROR,
                code="minimal.status-input-count",
                message="The minimal status parser requires exactly one artifact.",
                recoverable=False,
            )
            return

        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                raw = raw_line.strip()
                if not raw or raw.startswith(b"#"):
                    continue

                fallback_evidence = Evidence(
                    artifact_id=artifact_id,
                    locator=f"line:{line_number}",
                    raw_timestamp_ns=None,
                    clock_domain=None,
                    excerpt_sha256=sha256(raw).hexdigest(),
                )
                try:
                    record = json.loads(raw)
                    (
                        timestamp_ns,
                        ifindex,
                        name,
                        admin_status,
                        oper_status,
                        description,
                    ) = self._validated_record(record)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                    yield PluginDiagnostic(
                        stage=DiagnosticStage.STATUS_PARSE,
                        severity=DiagnosticSeverity.ERROR,
                        code="minimal.invalid-status-record",
                        message=f"Could not parse line {line_number}: {error}",
                        recoverable=True,
                        evidence=(fallback_evidence,),
                    )
                    continue

                evidence = Evidence(
                    artifact_id=artifact_id,
                    locator=f"line:{line_number}",
                    raw_timestamp_ns=timestamp_ns,
                    clock_domain=DEVICE_CLOCK,
                    excerpt_sha256=fallback_evidence.excerpt_sha256,
                )
                resource = ResourceKey(
                    namespace=PLUGIN_ID,
                    node=spec.node,
                    layer=spec.layer,
                    kind="INTERFACE",
                    parts=(("ifindex", ifindex),),
                )
                properties = {
                    "name": name,
                    "admin_status": admin_status,
                    "oper_status": oper_status,
                    "description": description,
                }
                yield SourceRecordEmission(
                    timestamp_ns=timestamp_ns,
                    timestamp_uncertainty_ns=0,
                    source_type="status-json",
                    source_name=STATUS_FILENAME,
                    record_name="interface_status",
                    message=f"{name}: admin={admin_status}, oper={oper_status}",
                    layer=spec.layer,
                    copy_text=raw.decode("utf-8"),
                    attributes={"line_number": line_number},
                    evidence=(evidence,),
                )
                yield SnapshotObservation(
                    resource=resource,
                    observed_at_min_ns=timestamp_ns,
                    observed_at_max_ns=timestamp_ns,
                    state=PropertyPatch(
                        set_values=properties,
                        field_quality={
                            field_name: Quality.EXACT
                            for field_name in properties
                        },
                        field_provenance={
                            field_name: Provenance.OBSERVED
                            for field_name in properties
                        },
                        complete=True,
                    ),
                    provenance=Provenance.OBSERVED,
                    quality=Quality.EXACT,
                    evidence=evidence,
                    condition=oper_status,
                    condition_class=self._condition_class(oper_status),
                )

    @staticmethod
    def _validated_record(
        record: object,
    ) -> tuple[int, int, str, str, str, str]:
        if not isinstance(record, dict):
            raise ValueError("record must be a JSON object")
        if record.get("kind") != "interface":
            raise ValueError("kind must be 'interface'")

        timestamp_ns = record.get("captured_at_ns")
        if type(timestamp_ns) is not int:
            raise ValueError("captured_at_ns must be an integer")
        ifindex = record.get("ifindex")
        if type(ifindex) is not int or ifindex < 0:
            raise ValueError("ifindex must be a non-negative integer")

        name = record.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        admin_status = record.get("admin_status")
        oper_status = record.get("oper_status")
        allowed_statuses = {"up", "down", "unknown"}
        if admin_status not in allowed_statuses:
            raise ValueError("admin_status must be up, down, or unknown")
        if oper_status not in allowed_statuses:
            raise ValueError("oper_status must be up, down, or unknown")
        description = record.get("description", "")
        if not isinstance(description, str):
            raise ValueError("description must be a string")
        return (
            timestamp_ns,
            ifindex,
            name,
            admin_status,
            oper_status,
            description,
        )

    @staticmethod
    def _condition_class(oper_status: str) -> ConditionClass:
        if oper_status == "up":
            return ConditionClass.HEALTHY
        if oper_status == "down":
            return ConditionClass.ERROR
        return ConditionClass.UNKNOWN


plugin: AnalyzerPlugin = MinimalRouterPlugin()


__all__ = ["MinimalRouterPlugin", "plugin"]
