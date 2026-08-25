from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.annotation_store import (
    ManualCorrelationEdge,
    ReviewAnnotationKind,
    ReviewRetentionPolicy,
    ReviewSubject,
    ReviewSubjectKind,
)
from router_dump_analyzer.capability_router import (
    CapabilityProviderRegistry,
    CapabilityRouteSelector,
    RevisionSetCapabilityKey,
)
from router_dump_analyzer.control_plane import (
    ControlPlane,
    ControlPlaneError,
    ControlPlaneLimits,
    ControlPlaneScopeError,
    DatasetIntegrityError,
    RetentionObservationMode,
    RevisionConsistencyFindingsPage,
    SubjectResolutionError,
    validate_revision_consistency_dataset,
)
from router_dump_analyzer.ingestion_pipeline import (
    WINDOWS_MAX_STATE_ROOT_UNITS,
    ImportState,
    IngestionStateRootPathError,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
    RetentionHostInventoryCoverage,
    RetentionPolicy,
    _windows_path_units,
)
from router_dump_analyzer.plugin_api import (
    ConditionClass,
    CorrelationWindow,
    DomainEvent,
    Evidence,
    InputParserKind,
    InputSpec,
    Outcome,
    PluginCapability,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    RelationshipDeclaration,
    RelationshipTypeDescriptor,
    ResourceKey,
    SnapshotObservation,
    SourceRecordEmission,
    SourceRecordRef,
    derive_event_uid,
)
from router_dump_analyzer.plugin_composition import PluginCompositionPolicy
from router_dump_analyzer.plugin_composition_deployment import (
    PluginCompositionDeployment,
    PluginCompositionDeploymentContext,
    load_plugin_composition_deployment,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginExecutionPlanAuthority,
    primary_parser_execution_pin,
)
from router_dump_analyzer.private_analysis_promotion import (
    ProposalReviewRetentionReferences,
)
from router_dump_analyzer.session_store import (
    CatalogRetentionPolicy,
    IdempotencyConflict,
)
from tests.test_ingestion import ParseOnlyPlugin


def _fixture_bytes() -> bytes:
    return (
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
        + "\n"
    ).encode()


class _EventPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.control-plane-events",
        capabilities=frozenset({PluginCapability.TEXT_TRACE_PARSE}),
    )

    def locate_inputs(self, inventory):
        for artifact in inventory.artifacts:
            if artifact.logical_path.name == "status.jsonl":
                yield InputSpec(
                    artifact_ids=(artifact.artifact_id,),
                    role="event-log",
                    node=inventory.node_hint or "router-a",
                    layer="interface",
                    parser_id="tests.control-plane.events.v1",
                    parser_kind=InputParserKind.TEXT_TRACE,
                )

    def parse_text_trace(self, reader, spec):
        artifact_id = spec.artifact_ids[0]
        with reader.open_binary(artifact_id) as stream:
            lines = tuple(stream)
        for ordinal, line in enumerate(lines):
            record = json.loads(line)
            timestamp_ns = int(record["captured_at_ns"])
            evidence = Evidence(
                artifact_id=artifact_id,
                locator=f"line:{ordinal + 1}",
                raw_timestamp_ns=timestamp_ns,
                clock_domain="utc",
            )
            source_ref = SourceRecordRef(
                source_id=spec.parser_id,
                message_ordinal=ordinal,
            )
            event_uid = derive_event_uid(
                self.manifest.plugin_id,
                spec.parser_id,
                source_ref,
            )
            resource = ResourceKey(
                namespace=self.manifest.plugin_id,
                node=spec.node,
                layer=spec.layer,
                kind="INTERFACE",
                parts=(("ifindex", int(record["ifindex"])),),
            )
            yield SourceRecordEmission(
                timestamp_ns=timestamp_ns,
                timestamp_uncertainty_ns=0,
                source_type="status-json",
                source_name="status.jsonl",
                record_name="interface-status",
                message=f"{record['name']}: {record['oper_status']}",
                layer=spec.layer,
                matched_event_uid=event_uid,
                evidence=(evidence,),
                copy_text=line.decode("utf-8").rstrip(),
            )
            yield DomainEvent(
                event_uid=event_uid,
                timestamp_ns=timestamp_ns,
                timestamp_uncertainty_ns=0,
                source_sequence=ordinal,
                event_type="interface_status_changed",
                action="modify",
                outcome=Outcome.SUCCESS,
                attributes={"condition": record["oper_status"]},
                subjects=(resource,),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                source=source_ref,
                evidence=evidence,
            )


class _RoutableEventPlugin(_EventPlugin):
    manifest = replace(
        _EventPlugin.manifest,
        plugin_id="tests.control-plane-trusted-inline",
        capabilities=frozenset(
            {
                PluginCapability.TEXT_TRACE_PARSE,
                PluginCapability.CORRELATION,
            }
        ),
    )

    def correlate(self, reader: Any, window: Any) -> tuple[()]:
        del reader, window
        return ()


class _RelationshipProjectionPlugin(ParseOnlyPlugin):
    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.control-plane-relationship-projection",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.RELATIONSHIP_PROJECTION,
            }
        ),
    )

    def describe(self) -> PluginSchema:
        schema = super().describe()
        return replace(
            schema,
            relationship_types=(
                RelationshipTypeDescriptor(
                    relation_type="paired-interface",
                    label="Paired interface",
                    directed=False,
                    structural=True,
                ),
            ),
        )

    def parse_status(self, reader: Any, spec: Any):
        for output in super().parse_status(reader, spec):
            yield output
            if type(output) is not SnapshotObservation:
                continue
            peer_resource = replace(
                output.resource,
                parts=(("ifindex", int(output.resource.parts[0][1]) + 1),),
            )
            yield replace(
                output,
                resource=peer_resource,
                state=PropertyPatch(
                    set_values={
                        **output.state.set_values,
                        "name": f"{output.state.set_values['name']}-peer",
                    },
                    complete=True,
                ),
                evidence=replace(
                    output.evidence,
                    locator=f"{output.evidence.locator}:peer",
                ),
                condition_class=ConditionClass.HEALTHY,
            )

    def project_relationships(self, world: Any):
        states = tuple(world.iter_states())
        if len(states) != 2:
            return ()
        ordered = sorted(states, key=lambda item: item.resource.parts)
        return (
            RelationshipDeclaration(
                source=ordered[0].resource,
                target=ordered[1].resource,
                relation_type="paired-interface",
                attributes=PropertyPatch(
                    set_values={"method": "snapshot-key-adjacency"},
                    complete=True,
                ),
                evidence=(ordered[0].evidence[0], ordered[1].evidence[0]),
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
            ),
        )


class ControlPlaneTests(unittest.TestCase):
    @staticmethod
    def _materialized_consistency_dataset(
        dataset: dict[str, Any],
        descriptor: Any,
        *,
        finding_count: int = 2,
    ) -> tuple[dict[str, Any], Any]:
        value = json.loads(json.dumps(dataset))
        plan = descriptor.execution_plan
        assert plan is not None
        primary = primary_parser_execution_pin(plan)
        consistency_pin = replace(
            primary,
            capabilities=tuple(
                sorted(
                    {
                        *primary.capabilities,
                        PluginCapability.CONSISTENCY_CHECK.value,
                    }
                )
            ),
        )
        plan = replace(
            plan,
            plugins=tuple(
                consistency_pin if pin.instance_id == primary.instance_id else pin
                for pin in plan.plugins
            ),
            plan_digest="",
        )
        metadata = dict(descriptor.metadata)
        metadata["plugin_execution_plan_digest"] = plan.plan_digest
        descriptor = replace(
            descriptor,
            execution_plan=plan,
            metadata=metadata,
        )
        plan_digest = plan.plan_digest
        value["_ingestion"]["plugin_execution_plan_digest"] = plan_digest
        projection_materialization = value.get(
            "relationship_projection_materialization"
        )
        if isinstance(projection_materialization, dict):
            projection_materialization["plan_digest"] = plan_digest
        basis = {
            "kind": "observed_capture_vector",
            "requested_time_ns": None,
            "resolved_at_min_ns": "100",
            "resolved_at_max_ns": "200",
            "capture_ranges": [],
            "provenance": "observed",
            "quality": "exact",
            "clock_domain": None,
            "selector": None,
            "node_resolutions": [],
            "watermark": None,
            "unresolved_reason": None,
        }
        basis_digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )
        value["_ingestion"]["mode"] = "core-ingestion-v3"
        value["_ingestion"]["consistency_materialization_status"] = "complete"
        provider = {
            "member_id": plan.basis_revision_id,
            "node_id": plan.node_id,
            "basis_revision_id": plan.basis_revision_id,
            "plan_digest": plan.plan_digest,
            "instance_id": consistency_pin.instance_id,
            "plugin_id": consistency_pin.plugin_id,
            "plugin_version": consistency_pin.plugin_version,
            "registered_execution_identity": (
                consistency_pin.registered_execution_identity
            ),
            "configuration_digest": consistency_pin.configuration_digest,
            "schema_digest": consistency_pin.schema_digest,
            "package_hash": consistency_pin.artifact.package_hash,
            "capability": PluginCapability.CONSISTENCY_CHECK.value,
            "roles": list(consistency_pin.roles),
        }
        artifact_id = value["inventory"]["members"][0]["artifact_id"]
        finding_payloads = [
            {
                "rule_id": f"rule-{ordinal}",
                "severity": "error",
                "result": "fail",
                "summary": f"Rule {ordinal} failed.",
                "resources": [],
                "resource_references": [],
                "provenance": "reconstructed",
                "quality": "exact",
                "basis": basis,
                "evidence": [
                    {
                        "artifact_id": artifact_id,
                        "locator": f"private-status.dump:{ordinal}",
                        "raw_timestamp_ns": None,
                        "clock_domain": None,
                        "excerpt_sha256": None,
                    }
                ],
                "execution_plan_digest": plan_digest,
                "details": {"ordinal": ordinal, "path": ["a", "b"]},
                "producer": provider,
            }
            for ordinal in range(finding_count)
        ]
        value["findings"] = sorted(
            (
                {
                    **payload,
                    "finding_id": "sha256:"
                    + hashlib.sha256(
                        json.dumps(
                            payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                }
                for payload in finding_payloads
            ),
            key=lambda finding: finding["finding_id"],
        )
        value["consistency_diagnostics"] = []
        value["summary"]["consistency"] = {
            "pass": 0,
            "fail": finding_count,
            "unknown": 0,
        }
        value["consistency_materialization"] = {
            "schema_version": ("router_dump_analyzer.consistency_materialization.v1"),
            "status": "complete",
            "plan_digest": plan_digest,
            "basis": basis,
            "basis_digest": basis_digest,
            "providers": [provider],
            "provider_count": 1,
            "finding_count": finding_count,
            "diagnostic_count": 0,
            "emitted_finding_count": finding_count,
            "emitted_diagnostic_count": 0,
            "duplicate_findings_discarded": 0,
            "duplicate_diagnostics_discarded": 0,
            "world_reads": finding_count,
        }
        return value, descriptor

    def test_trusted_inline_control_plane_is_explicit_atomic_and_keeps_publisher_process(
        self,
    ) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        registry.register(
            _EventPlugin(),
            package_hash="manifest-sha256:" + "c" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            strict_root = Path(directory) / "strict"
            with self.assertRaisesRegex(ValueError, "executable plug-in identities"):
                ControlPlane(strict_root, registry=registry)
            self.assertFalse(strict_root.exists())

            incompatible_root = Path(directory) / "incompatible"
            with self.assertRaisesRegex(ValueError, "plugin_execution_mode='inline'"):
                ControlPlane(
                    incompatible_root,
                    registry=registry,
                    pipeline_limits=PipelineLimits(
                        plugin_execution_mode=PluginExecutionMode.PROCESS,
                    ),
                    allow_inline_only=True,
                )
            self.assertFalse(incompatible_root.exists())

            trusted_root = Path(directory) / "trusted"
            control = ControlPlane(
                trusted_root,
                registry=registry,
                allow_inline_only=True,
            )
            try:
                self.assertTrue(control.allow_inline_only)
                self.assertTrue(control.requires_inline_execution)
                self.assertIs(
                    control.ingestion.limits.plugin_execution_mode,
                    PluginExecutionMode.INLINE,
                )
                self.assertIs(
                    control.ingestion.limits.effective_publisher_execution_mode,
                    PluginExecutionMode.PROCESS,
                )
            finally:
                control.close()

            invalid_root = Path(directory) / "invalid"
            with self.assertRaisesRegex(TypeError, "exact boolean"):
                ControlPlane(
                    invalid_root,
                    registry=registry,
                    allow_inline_only=1,  # type: ignore[arg-type]
                )
            self.assertFalse(invalid_root.exists())

    def test_loaded_manifest_inline_deployment_survives_restart_and_routes_capabilities(
        self,
    ) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        registered = registry.register(
            _RoutableEventPlugin(),
            package_hash="manifest-sha256:" + "d" * 64,
            instance_id="trusted-inline-primary",
        )
        deployment = PluginCompositionDeployment(
            registry,
            CapabilityProviderRegistry.from_primary_registry(registry),
            PluginCompositionPolicy(),
            allow_inline_only=True,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "control"
            contexts: list[PluginCompositionDeploymentContext] = []

            def factory(
                context: PluginCompositionDeploymentContext,
            ) -> PluginCompositionDeployment:
                contexts.append(context)
                return deployment

            module = SimpleNamespace(create_deployment=factory)
            with patch(
                "router_dump_analyzer.plugin_composition_deployment."
                "importlib.import_module",
                return_value=module,
            ):
                loaded = load_plugin_composition_deployment(
                    "tests.trusted_inline_deployment:create_deployment",
                    context=PluginCompositionDeploymentContext(root),
                )

            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0].state_dir, root.resolve())
            control = ControlPlane(
                root,
                registry=loaded.primary_registry,
                plugin_composition_policy=loaded.policy,
                capability_providers=loaded.capability_providers,
                allow_inline_only=loaded.allow_inline_only,
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
            )
            try:
                self.assertIs(
                    control.ingestion.limits.effective_publisher_execution_mode,
                    PluginExecutionMode.PROCESS,
                )
                control.sessions.create_project(
                    "tenant-a",
                    "Project A",
                    project_id="project-a",
                )
                control.sessions.create_workspace(
                    "tenant-a",
                    "project-a",
                    "Workspace A",
                    workspace_id="workspace-a",
                )
                completed = self._ingest(control)
                revision_id = completed.revision_id
                revision = control.sessions.get_revision("tenant-a", revision_id)
                assert revision.execution_plan is not None
                self.assertIs(
                    revision.execution_plan.execution_plan_authority,
                    PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST,
                )
            finally:
                control.close()

            reopened = ControlPlane(
                root,
                registry=loaded.primary_registry,
                plugin_composition_policy=loaded.policy,
                capability_providers=loaded.capability_providers,
                allow_inline_only=loaded.allow_inline_only,
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
            )
            try:
                scope = reopened.scope("tenant-a", "project-a", "workspace-a")
                router = reopened.capability_router_for_revision(scope, revision_id)
                route = router.resolve(
                    CapabilityRouteSelector(PluginCapability.CORRELATION)
                )
                self.assertEqual(route.provider.pin.instance_id, registered.instance_id)
                invocation = route.correlate(
                    object(),  # type: ignore[arg-type]
                    CorrelationWindow(None, None, 1),
                )
                self.assertEqual(
                    invocation.provider.pin.instance_id,
                    registered.instance_id,
                )
                self.assertEqual(invocation.result.causal_links, ())
            finally:
                reopened.close()

    @unittest.skipUnless(os.name == "nt", "exercises the Windows path budget")
    def test_composition_root_rejects_long_state_dir_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            target_units = WINDOWS_MAX_STATE_ROOT_UNITS + 1
            remaining = target_units - _windows_path_units(base) - 1
            self.assertGreater(remaining, 0)
            root = base / ("r" * remaining)
            self.assertEqual(_windows_path_units(root), target_units)

            with self.assertRaises(IngestionStateRootPathError) as raised:
                ControlPlane(
                    root,
                    registry=PluginRegistry((_EventPlugin(),)),
                    pipeline_limits=self._pipeline_limits(),
                )

            self.assertFalse(root.exists())
            self.assertNotIn(str(root), str(raised.exception))

    def test_event_time_preserves_signed_int64_and_bounds_uncertainty(self) -> None:
        self.assertEqual(
            ControlPlane._event_time(
                {"timestamp_ns": "-10", "timestamp_uncertainty_ns": "2"}
            ),
            (-12, -8),
        )
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "interval exceeds signed 64-bit",
        ):
            ControlPlane._event_time(
                {
                    "timestamp_ns": str((1 << 63) - 1),
                    "timestamp_uncertainty_ns": "1",
                }
            )

    def test_composition_root_refuses_to_replace_a_missing_review_authority_key(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = self._control_plane(root)
            control.close()
            connection = sqlite3.connect(
                root / "private-analysis-proposal-reviews.sqlite3"
            )
            try:
                connection.execute(
                    "INSERT INTO proposal_review_decision ("
                    "tenant_id, project_id, workspace_id, decision_id, run_id, "
                    "proposal_id, proposal_digest, result_digest, run_version, "
                    "disposition, state, actor, rationale, request_digest, "
                    "authority_attestation, target_kind, target_id, "
                    "target_document_json, created_at_ns, updated_at_ns, version"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?)",
                    (
                        "tenant-a",
                        "project-a",
                        "workspace-a",
                        "decision-a",
                        "run-a",
                        "proposal-a",
                        "sha256:" + ("1" * 64),
                        "sha256:" + ("2" * 64),
                        1,
                        "reject",
                        "completed",
                        "reviewer-a",
                        "",
                        "sha256:" + ("3" * 64),
                        "hmac-sha256:" + ("4" * 64),
                        None,
                        None,
                        None,
                        1,
                        1,
                        1,
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            key_path = root / ".private-analysis-proposal-review.authority.key"
            self.assertEqual(len(key_path.read_bytes()), 32)
            key_path.unlink()
            with self.assertRaisesRegex(
                ControlPlaneError,
                "proposal-review authority key is missing",
            ):
                ControlPlane(
                    root,
                    registry=PluginRegistry((_EventPlugin(),)),
                    pipeline_limits=self._pipeline_limits(),
                )

    def test_composition_root_refuses_a_missing_key_for_an_empty_existing_store(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = self._control_plane(root)
            control.close()
            database_path = root / "private-analysis-proposal-reviews.sqlite3"
            self.assertGreater(database_path.stat().st_size, 0)
            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM proposal_review_decision"
                    ).fetchone(),
                    (0,),
                )
            finally:
                connection.close()
            (root / ".private-analysis-proposal-review.authority.key").unlink()
            with self.assertRaisesRegex(
                ControlPlaneError,
                "proposal-review authority key is missing",
            ):
                ControlPlane(
                    root,
                    registry=PluginRegistry((_EventPlugin(),)),
                    pipeline_limits=self._pipeline_limits(),
                )

    @staticmethod
    def _pipeline_limits() -> PipelineLimits:
        return PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            lease_seconds=30,
            poll_interval_seconds=0.01,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )

    def _control_plane(
        self,
        root: Path,
        *,
        retention_policy: RetentionPolicy | None = None,
        plugin: Any | None = None,
    ) -> ControlPlane:
        control = ControlPlane(
            root,
            registry=PluginRegistry((plugin or _EventPlugin(),)),
            pipeline_limits=self._pipeline_limits(),
            retention_policy=retention_policy,
            limits=ControlPlaneLimits(
                max_dataset_bytes=1024 * 1024,
                dataset_cache_entries=2,
            ),
        )
        control.sessions.create_project(
            "tenant-a",
            "Project A",
            project_id="project-a",
        )
        control.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace A",
            workspace_id="workspace-a",
        )
        self.addCleanup(control.close)
        return control

    @staticmethod
    def _age_catalog_for_retention(control: ControlPlane) -> None:
        with control.sessions._transaction() as cursor:
            cursor.execute(
                """
                UPDATE fixtures SET created_at_ns = 10
                WHERE tenant_id = ? AND workspace_id = ?
                """,
                ("tenant-a", "workspace-a"),
            )
            cursor.execute(
                """
                UPDATE analysis_revisions SET published_at_ns = 10
                WHERE tenant_id = ? AND workspace_id = ?
                """,
                ("tenant-a", "workspace-a"),
            )
            cursor.execute(
                """
                UPDATE idempotency_keys SET created_at_ns = 10
                WHERE tenant_id = ?
                  AND json_extract(response_json, '$.workspace_id') = ?
                """,
                ("tenant-a", "workspace-a"),
            )

    @staticmethod
    def _catalog_retention_policy(*, enabled: bool = True) -> CatalogRetentionPolicy:
        return CatalogRetentionPolicy(
            enabled=enabled,
            idempotency_before_ns=20,
            revision_before_ns=20,
            fixture_before_ns=20,
        )

    @staticmethod
    def _artifact_pin_count(control: ControlPlane) -> int:
        with control.ingestion._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS pin_count FROM ingestion_artifact_pins
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                """,
                ("tenant-a", "project-a", "workspace-a"),
            ).fetchone()
        assert row is not None
        return int(row["pin_count"])

    def _root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def _ingest(self, control: ControlPlane):
        scope = control.import_scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        control.start()
        admitted = control.ingestion.submit_bytes(
            scope,
            _fixture_bytes(),
            original_name="status.jsonl",
            idempotency_key="fixture-a",
        )
        completed = control.ingestion.wait(
            scope,
            admitted.import_id,
            timeout=10,
        )
        private_diagnostics = []
        if completed.state is not ImportState.COMPLETED:
            with control.ingestion._connect() as connection:
                private_diagnostics = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM ingestion_failure_diagnostics "
                        "WHERE import_id = ? ORDER BY attempt_number",
                        (admitted.import_id,),
                    ).fetchall()
                ]
        self.assertEqual(
            completed.state,
            ImportState.COMPLETED,
            (
                completed.error_message,
                [
                    (event.event_type, event.message, dict(event.payload))
                    for event in control.ingestion.events(
                        scope,
                        admitted.import_id,
                    )
                ],
                private_diagnostics,
            ),
        )
        return completed

    def test_pipeline_publication_is_cataloged_and_reloadable(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        fixture = control.sessions.get_fixture(
            "tenant-a",
            completed.fixture_id,
        )
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        self.assertEqual(fixture.workspace_id, "workspace-a")

        self.assertEqual(
            fixture.metadata["content_type"],
            "application/octet-stream",
        )
        self.assertTrue(revision.revision_id.startswith("revision-"))
        self.assertEqual(revision.revision_id, completed.revision_id)
        self.assertEqual(
            str(revision.metadata["source_revision_id"]).split("/")[0],
            "ingested",
        )
        self.assertEqual(
            revision.identity_digest,
            revision.metadata["dataset_sha256"],
        )

        dataset = control.load_revision_dataset(
            scope,
            revision.revision_id,
        )
        self.assertEqual(dataset["_ingestion"]["node_id"], "router-a")
        dataset["events"].clear()
        reloaded = control.load_revision_dataset(
            scope,
            revision.revision_id,
        )
        self.assertEqual(len(reloaded["events"]), 2)

    def test_revision_relationship_projection_is_verified_and_revision_indexed(
        self,
    ) -> None:
        control = self._control_plane(
            self._root(),
            plugin=_RelationshipProjectionPlugin(),
        )
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")

        loaded = control._load_revision(scope, completed.revision_id)
        dataset = loaded.dataset
        self.assertEqual(
            dataset["relationship_projection_materialization"]["status"],
            "complete",
        )
        self.assertEqual(len(dataset["relationship_declarations"]), 1)
        self.assertEqual(len(dataset["relationship_projection_edges"]), 1)
        edge = dataset["relationship_projection_edges"][0]
        self.assertIn(edge["relationship_id"], loaded.index.relationships)
        self.assertNotIn(edge, dataset["relationships"])
        self.assertNotIn(edge, dataset["relationship_intervals"])

        wrong_key = json.loads(json.dumps(dataset))
        wrong_key["relationship_projection_edges"][0]["source"][
            "typed_resource_key"
        ]["node"] = "forged-node"
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "endpoint does not match its base resource",
        ):
            control._index_dataset(loaded.descriptor, wrong_key)

        wrong_digest = json.loads(json.dumps(dataset))
        wrong_digest["relationship_projection_edges"][0]["quality"] = "ambiguous"
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "materialization is not canonical",
        ):
            control._index_dataset(loaded.descriptor, wrong_digest)

        malformed_artifact_id = json.loads(json.dumps(dataset))
        malformed_artifact_id["relationship_declarations"][0]["contributions"][
            0
        ]["evidence"][0]["artifact_id"] = []
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(loaded.descriptor, malformed_artifact_id)

        wrong_provider_revision = json.loads(json.dumps(dataset))
        wrong_provider_revision["relationship_projection_materialization"][
            "providers"
        ][0]["catalog_revision_id"] = "different-revision"
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "provider is not bound",
        ):
            control._index_dataset(loaded.descriptor, wrong_provider_revision)

        partial = json.loads(json.dumps(dataset))
        partial.pop("relationship_declarations")
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "partial relationship projection",
        ):
            control._index_dataset(loaded.descriptor, partial)

        wrong_summary = json.loads(json.dumps(dataset))
        wrong_summary["summary"]["relationship_projection"][
            "resolved_edge_count"
        ] = 0
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "summary does not match",
        ):
            control._index_dataset(loaded.descriptor, wrong_summary)

    def test_consistency_findings_page_is_indexed_paginated_and_detached(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        loaded = control._load_revision(scope, completed.revision_id)
        dataset, descriptor = self._materialized_consistency_dataset(
            dict(loaded.dataset),
            loaded.descriptor,
        )
        index = control._index_dataset(descriptor, dataset)
        indexed = replace(
            loaded,
            descriptor=descriptor,
            dataset=dataset,
            index=index,
        )

        with patch.object(control, "_load_revision", return_value=indexed) as load:
            first = control.list_revision_consistency_findings(
                scope,
                completed.revision_id,
                limit=1,
            )
            second = control.list_revision_consistency_findings(
                scope,
                completed.revision_id,
                limit=1,
                offset=1,
            )
            beyond_end = control.list_revision_consistency_findings(
                scope,
                completed.revision_id,
                offset=(1 << 53) - 1,
            )

        self.assertIsInstance(first, RevisionConsistencyFindingsPage)
        self.assertEqual(first.total_count, 2)
        self.assertEqual(first.next_offset, 1)
        self.assertEqual(first.items[0]["rule_id"], dataset["findings"][0]["rule_id"])
        self.assertEqual(second.next_offset, None)
        self.assertEqual(second.items[0]["rule_id"], dataset["findings"][1]["rule_id"])
        self.assertEqual(beyond_end.items, ())
        self.assertIsNone(beyond_end.next_offset)
        self.assertEqual(first.materialization["status"], "complete")
        self.assertEqual(load.call_args.args, (scope, completed.revision_id))
        self.assertEqual(
            first.items[0]["evidence"][0]["locator"],
            dataset["findings"][0]["evidence"][0]["locator"],
        )

        with patch.object(control, "_load_revision", return_value=indexed):
            client_page = control.list_revision_consistency_findings_for_client(
                scope,
                completed.revision_id,
                limit=1,
            )
        self.assertEqual(
            client_page.items[0]["evidence"],
            [
                {
                    "artifact_id": dataset["inventory"]["members"][0][
                        "artifact_id"
                    ],
                    "raw_timestamp_ns": None,
                    "clock_domain": None,
                    "excerpt_sha256": None,
                }
            ],
        )
        self.assertNotIn("locator", json.dumps(client_page.materialization))
        self.assertEqual(
            set(client_page.materialization),
            set(dataset["consistency_materialization"]),
        )

        first.items[0]["details"]["ordinal"] = 999  # type: ignore[index]
        first.materialization["status"] = "mutated"  # type: ignore[index]
        self.assertNotEqual(index.findings[0]["details"]["ordinal"], 999)
        self.assertEqual(
            index.consistency_materialization["status"],
            "complete",
        )

    def test_consistency_findings_page_uses_legacy_not_materialized_state(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        loaded = control._load_revision(scope, completed.revision_id)
        dataset = json.loads(json.dumps(loaded.dataset))
        dataset["_ingestion"].pop("mode", None)
        dataset["_ingestion"].pop("consistency_materialization_status", None)
        dataset.pop("consistency_materialization", None)
        dataset.pop("consistency_diagnostics", None)
        dataset["inventory"]["mode"] = "core-ingestion-v2"
        dataset["findings"] = [{"legacy_rule": "vendor.rule"}]
        index = control._index_dataset(loaded.descriptor, dataset)
        indexed = replace(loaded, dataset=dataset, index=index)

        with patch.object(control, "_load_revision", return_value=indexed):
            page = control.list_revision_consistency_findings(
                scope,
                completed.revision_id,
            )

        self.assertEqual(page.materialization["status"], "not_materialized")
        self.assertEqual(page.materialization["finding_count"], 1)
        self.assertIsNone(page.materialization["provider_count"])
        self.assertEqual(page.items, ({"legacy_rule": "vendor.rule"},))

    def test_legacy_consistency_dataset_requires_exact_execution_plan_binding(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        loaded = control._load_revision(scope, completed.revision_id)
        dataset = json.loads(json.dumps(loaded.dataset))
        dataset["_ingestion"].pop("mode", None)
        dataset["_ingestion"].pop("consistency_materialization_status", None)
        dataset.pop("consistency_materialization", None)
        dataset.pop("consistency_diagnostics", None)
        dataset["inventory"]["mode"] = "core-ingestion-v2"

        validate_revision_consistency_dataset(
            dataset,
            execution_plan=loaded.descriptor.execution_plan,
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "lacks its exact"):
            validate_revision_consistency_dataset(dataset, execution_plan=None)

        dataset["_ingestion"]["plugin_execution_plan_digest"] = "sha256:" + ("f" * 64)
        with self.assertRaisesRegex(DatasetIntegrityError, "does not match"):
            validate_revision_consistency_dataset(
                dataset,
                execution_plan=loaded.descriptor.execution_plan,
            )

        dataset["_ingestion"]["plugin_execution_plan_digest"] = None
        findings, envelope = validate_revision_consistency_dataset(
            dataset,
            execution_plan=None,
        )
        self.assertEqual(findings, ())
        self.assertIsNone(envelope["plan_digest"])

    def test_core_ingestion_v3_requires_valid_consistency_materialization(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        loaded = control._load_revision(scope, completed.revision_id)
        dataset, descriptor = self._materialized_consistency_dataset(
            dict(loaded.dataset),
            loaded.descriptor,
        )
        control._index_dataset(descriptor, dataset)

        class ExplodingList(list[object]):
            def __iter__(self):
                raise RuntimeError("materialized array was traversed")

        findings_subclass = json.loads(json.dumps(dataset))
        findings_subclass["findings"] = ExplodingList(
            findings_subclass["findings"]
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "findings"):
            control._index_dataset(descriptor, findings_subclass)

        for required_array in (
            "findings",
            "consistency_diagnostics",
            "diagnostics",
        ):
            with self.subTest(missing_array=required_array):
                missing_array = json.loads(json.dumps(dataset))
                missing_array.pop(required_array)
                with self.assertRaisesRegex(DatasetIntegrityError, required_array):
                    control._index_dataset(descriptor, missing_array)

        for envelope_field in tuple(dataset["consistency_materialization"]):
            with self.subTest(missing_envelope_field=envelope_field):
                partial_envelope = json.loads(json.dumps(dataset))
                partial_envelope["consistency_materialization"].pop(envelope_field)
                with self.assertRaisesRegex(DatasetIntegrityError, "exact schema"):
                    control._index_dataset(descriptor, partial_envelope)

        def recompute_finding(record: dict[str, Any]) -> None:
            payload = dict(record)
            payload.pop("finding_id", None)
            record["finding_id"] = "sha256:" + hashlib.sha256(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

        outside_evidence = json.loads(json.dumps(dataset))
        outside_evidence["findings"][0]["evidence"][0]["artifact_id"] = (
            "00000000-0000-0000-0000-000000000099"
        )
        recompute_finding(outside_evidence["findings"][0])
        outside_evidence["findings"].sort(key=lambda item: item["finding_id"])
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(descriptor, outside_evidence)

        unsafe_details = json.loads(json.dumps(dataset))
        unsafe_details["findings"][0]["details"]["unsafe"] = 1 << 60
        recompute_finding(unsafe_details["findings"][0])
        unsafe_details["findings"].sort(key=lambda item: item["finding_id"])
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(descriptor, unsafe_details)

        empty_key_parts = json.loads(json.dumps(dataset))
        identity = {
            "namespace": "tests",
            "node": "router-a",
            "layer": "test",
            "kind": "ITEM",
            "parts": [],
        }
        resource_id = (
            "tests/router-a/test/ITEM/"
            + hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()[:32]
        )
        empty_key_parts["findings"][0]["resources"] = [resource_id]
        empty_key_parts["findings"][0]["resource_references"] = [
            {"resource_id": resource_id, "typed_resource_key": identity}
        ]
        recompute_finding(empty_key_parts["findings"][0])
        empty_key_parts["findings"].sort(key=lambda item: item["finding_id"])
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(descriptor, empty_key_parts)

        diagnostic_dataset = json.loads(json.dumps(dataset))
        diagnostic_payload = {
            "stage": "consistency",
            "severity": "warning",
            "code": "consistency.warning",
            "message": "Bounded warning",
            "recoverable": True,
            "evidence": [],
            "details": {"ordinal": 0, "items": ["a", "b"]},
            "origin": "plugin",
            "producer": diagnostic_dataset["consistency_materialization"]["providers"][
                0
            ],
        }
        diagnostic = {
            **diagnostic_payload,
            "diagnostic_id": "sha256:"
            + hashlib.sha256(
                json.dumps(
                    diagnostic_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
        diagnostic_dataset["consistency_diagnostics"] = [diagnostic]
        diagnostic_dataset["diagnostics"].append(diagnostic)
        diagnostic_dataset["consistency_materialization"]["diagnostic_count"] = 1
        diagnostic_dataset["consistency_materialization"][
            "emitted_diagnostic_count"
        ] = 1
        control._index_dataset(descriptor, diagnostic_dataset)
        forged_diagnostic_copy = json.loads(json.dumps(diagnostic_dataset))
        forged_diagnostic_copy["diagnostics"][-1]["details"]["ordinal"] = False
        with self.assertRaisesRegex(DatasetIntegrityError, "diagnostic suffix"):
            control._index_dataset(descriptor, forged_diagnostic_copy)

        not_applicable = json.loads(json.dumps(loaded.dataset))
        not_applicable_index = control._index_dataset(
            loaded.descriptor,
            not_applicable,
        )
        self.assertEqual(
            not_applicable_index.consistency_materialization["status"],
            "not_applicable",
        )

        missing = json.loads(json.dumps(dataset))
        missing.pop("consistency_materialization")
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "partial core-ingestion-v3",
        ):
            control._index_dataset(descriptor, missing)

        null_status_marker = json.loads(json.dumps(dataset))
        null_status_marker.pop("consistency_materialization")
        null_status_marker.pop("consistency_diagnostics")
        null_status_marker["_ingestion"].pop("mode")
        null_status_marker["_ingestion"][
            "consistency_materialization_status"
        ] = None
        null_status_marker["inventory"]["mode"] = "core-ingestion-v2"
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "partial core-ingestion-v3",
        ):
            control._index_dataset(descriptor, null_status_marker)

        bad_count = json.loads(json.dumps(dataset))
        bad_count["consistency_materialization"]["finding_count"] = 1
        with self.assertRaisesRegex(DatasetIntegrityError, "finding count"):
            control._index_dataset(descriptor, bad_count)

        unsafe_count = json.loads(json.dumps(dataset))
        unsafe_count["consistency_materialization"]["world_reads"] = 1 << 53
        with self.assertRaisesRegex(DatasetIntegrityError, "exact schema"):
            control._index_dataset(descriptor, unsafe_count)

        bad_plan = json.loads(json.dumps(dataset))
        bad_plan["consistency_materialization"]["plan_digest"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(DatasetIntegrityError, "plan digest"):
            control._index_dataset(descriptor, bad_plan)

        forged_provider = json.loads(json.dumps(dataset))
        forged_provider["consistency_materialization"]["providers"][0][
            "instance_id"
        ] = "forged-provider"
        with self.assertRaisesRegex(DatasetIntegrityError, "exact plan"):
            control._index_dataset(descriptor, forged_provider)

        too_many_providers = json.loads(json.dumps(dataset))
        too_many_providers["consistency_materialization"]["providers"] = [
            too_many_providers["consistency_materialization"]["providers"][0]
        ] * 33
        with self.assertRaisesRegex(DatasetIntegrityError, "durable limit"):
            control._index_dataset(descriptor, too_many_providers)

        class ExplodingProvider(dict[str, object]):
            def get(self, key: str, default: object = None) -> object:
                raise RuntimeError("materialized provider was traversed")

        provider_subclass = json.loads(json.dumps(dataset))
        provider_subclass["consistency_materialization"]["providers"][0] = (
            ExplodingProvider(
                provider_subclass["consistency_materialization"]["providers"][0]
            )
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "array of objects"):
            control._index_dataset(descriptor, provider_subclass)

        forged_producer = json.loads(json.dumps(dataset))
        forged_producer["findings"][0]["producer"]["instance_id"] = "forged-provider"
        forged_payload = dict(forged_producer["findings"][0])
        forged_payload.pop("finding_id")
        forged_producer["findings"][0]["finding_id"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    forged_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        )
        forged_producer["findings"].sort(key=lambda item: item["finding_id"])
        with self.assertRaisesRegex(DatasetIntegrityError, "producer"):
            control._index_dataset(descriptor, forged_producer)

        changed_payload = json.loads(json.dumps(dataset))
        changed_payload["findings"][0]["details"]["ordinal"] = 999
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(descriptor, changed_payload)

        forged_status = json.loads(json.dumps(dataset))
        forged_status["_ingestion"]["consistency_materialization_status"] = (
            "not_applicable"
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "consistency status"):
            control._index_dataset(descriptor, forged_status)

        forged_summary = json.loads(json.dumps(dataset))
        forged_summary["summary"]["consistency"]["pass"] = False
        with self.assertRaisesRegex(DatasetIntegrityError, "consistency summary"):
            control._index_dataset(descriptor, forged_summary)

        forged_basis_copy = json.loads(json.dumps(dataset))
        materialization = forged_basis_copy["consistency_materialization"]
        materialization["basis"]["numeric_alias"] = 0
        materialization["basis_digest"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    materialization["basis"],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        )
        for finding in forged_basis_copy["findings"]:
            finding["basis"]["numeric_alias"] = False
            finding_payload = dict(finding)
            finding_payload.pop("finding_id")
            finding["finding_id"] = (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(
                        finding_payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
            )
        forged_basis_copy["findings"].sort(key=lambda item: item["finding_id"])
        with self.assertRaisesRegex(DatasetIntegrityError, "not canonical"):
            control._index_dataset(descriptor, forged_basis_copy)

    def test_consistency_findings_page_validates_exact_paging_integers(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        control.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace B",
            workspace_id="workspace-b",
        )
        other_scope = control.scope("tenant-a", "project-a", "workspace-b")
        with self.assertRaises(SubjectResolutionError):
            control.list_revision_consistency_findings(
                other_scope,
                completed.revision_id,
            )
        for invalid in (0, 5_001, True, 1.0):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                control.list_revision_consistency_findings(
                    scope,
                    completed.revision_id,
                    limit=invalid,  # type: ignore[arg-type]
                )
        for invalid in (-1, 1 << 53, True, 1.0):
            with self.subTest(offset=invalid), self.assertRaises(ValueError):
                control.list_revision_consistency_findings(
                    scope,
                    completed.revision_id,
                    offset=invalid,  # type: ignore[arg-type]
                )

    def test_published_revision_and_session_build_exact_capability_routers(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        revision = control.sessions.get_revision(
            "tenant-a",
            completed.revision_id,
        )

        single = control.capability_router_for_revision(
            scope,
            revision.revision_id,
        )
        self.assertEqual(single.catalog_revision_id, revision.revision_id)
        self.assertEqual(single.member_id, revision.revision_id)
        self.assertEqual(single.plan, revision.execution_plan)

        session = control.sessions.create_session(
            "tenant-a",
            "workspace-a",
            "Capability routing",
            session_id="capability-session",
        )
        session = control.sessions.put_member(
            "tenant-a",
            session.session_id,
            "router-a/current",
            fixture_id=revision.fixture_id,
            revision_id=revision.revision_id,
            expected_version=session.version,
        )
        revision_set = control.capability_router_for_revision_set(
            scope,
            session_id=session.session_id,
        )
        self.assertEqual(
            revision_set.keys,
            (
                RevisionSetCapabilityKey(
                    revision.revision_id,
                    "router-a/current",
                ),
            ),
        )

        snapshot = control.sessions.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )
        snapshot_set = control.capability_router_for_revision_set(
            scope,
            snapshot_id=snapshot.snapshot_id,
        )
        self.assertEqual(snapshot_set.keys, revision_set.keys)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            control.capability_router_for_revision_set(scope)

    def test_dataset_loading_binds_catalog_dataset_and_full_execution_plan(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        dataset = control.load_revision_dataset(scope, revision.revision_id)
        execution_plan = revision.execution_plan
        assert execution_plan is not None

        dataset_digest_mismatch = json.loads(json.dumps(dataset))
        dataset_digest_mismatch["_ingestion"]["plugin_execution_plan_digest"] = (
            "sha256:" + ("0" * 64)
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "full catalog plan"):
            control._index_dataset(revision, dataset_digest_mismatch)

        missing_catalog_digest = dict(revision.metadata)
        missing_catalog_digest.pop("plugin_execution_plan_digest")
        with self.assertRaisesRegex(DatasetIntegrityError, "full catalog plan"):
            control._index_dataset(
                replace(revision, metadata=missing_catalog_digest),
                dataset,
            )

        changed_basis = replace(
            execution_plan,
            basis_revision_id="ingested/router-a/different-basis",
            plan_digest="",
        )
        changed_basis_metadata = dict(revision.metadata)
        changed_basis_metadata["plugin_execution_plan_digest"] = (
            changed_basis.plan_digest
        )
        changed_basis_dataset = json.loads(json.dumps(dataset))
        changed_basis_dataset["_ingestion"]["plugin_execution_plan_digest"] = (
            changed_basis.plan_digest
        )
        with self.assertRaisesRegex(DatasetIntegrityError, "basis"):
            control._index_dataset(
                replace(
                    revision,
                    execution_plan=changed_basis,
                    metadata=changed_basis_metadata,
                ),
                changed_basis_dataset,
            )

        secondary_pin = replace(
            execution_plan.plugins[0],
            instance_id="secondary.observer",
            roles=("forwarding_observer",),
        )
        multi_provider_plan = replace(
            execution_plan,
            plugins=(*execution_plan.plugins, secondary_pin),
            plan_digest="",
        )
        multi_provider_metadata = dict(revision.metadata)
        multi_provider_metadata["plugin_execution_plan_digest"] = (
            multi_provider_plan.plan_digest
        )
        multi_provider_dataset = json.loads(json.dumps(dataset))
        multi_provider_dataset["_ingestion"]["plugin_execution_plan_digest"] = (
            multi_provider_plan.plan_digest
        )
        multi_provider_dataset["consistency_materialization"]["plan_digest"] = (
            multi_provider_plan.plan_digest
        )
        multi_provider_dataset["relationship_projection_materialization"][
            "plan_digest"
        ] = multi_provider_plan.plan_digest
        control._index_dataset(
            replace(
                revision,
                execution_plan=multi_provider_plan,
                metadata=multi_provider_metadata,
            ),
            multi_provider_dataset,
        )

        planless_metadata = dict(revision.metadata)
        planless_metadata.pop("plugin_execution_plan_digest")
        planless_dataset = json.loads(json.dumps(dataset))
        planless_dataset["_ingestion"].pop("plugin_execution_plan_digest")
        planless_dataset["_ingestion"]["mode"] = "core-ingestion-v2"
        planless_dataset["_ingestion"].pop(
            "consistency_materialization_status",
            None,
        )
        planless_dataset["_ingestion"].pop(
            "relationship_projection_materialization_status",
            None,
        )
        planless_dataset["inventory"]["mode"] = "core-ingestion-v2"
        planless_dataset.pop("consistency_materialization")
        planless_dataset.pop("consistency_diagnostics")
        for field in (
            "relationship_declarations",
            "relationship_projection_diagnostics",
            "relationship_projection_edges",
            "relationship_projection_materialization",
        ):
            planless_dataset.pop(field)
        planless_dataset["summary"].pop("relationship_projection")
        planless_revision = replace(
            revision,
            execution_plan=None,
            metadata=planless_metadata,
        )
        control._index_dataset(planless_revision, planless_dataset)

        mutated_revision = replace(revision)
        assert mutated_revision.execution_plan is not None
        object.__setattr__(
            mutated_revision.execution_plan.plugins[0].artifact,
            "distribution_name",
            "attacker-mutated-distribution",
        )
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "invalid execution plan",
        ):
            control._index_dataset(mutated_revision, dataset)
        with self.assertRaisesRegex(DatasetIntegrityError, "planless"):
            control._index_dataset(planless_revision, dataset)

    def test_dataset_indexing_cancels_during_mapping_list_validation(self) -> None:
        class IndexConstructionCancelled(Exception):
            pass

        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        dataset = control.load_revision_dataset(scope, revision.revision_id)
        template = dataset["events"][0]
        assert isinstance(template, dict)
        late_invalid_events: list[object] = [dict(template) for _ in range(512)]
        late_invalid_events.append(object())
        dataset_with_late_invalid = dict(dataset)
        dataset_with_late_invalid["events"] = late_invalid_events
        checkpoints = 0

        def checkpoint() -> None:
            nonlocal checkpoints
            checkpoints += 1
            if checkpoints == 3:
                raise IndexConstructionCancelled

        with self.assertRaises(IndexConstructionCancelled):
            control._index_dataset(
                revision,
                dataset_with_late_invalid,
                construction_checkpoint=checkpoint,
            )
        self.assertEqual(checkpoints, 3)

    def test_session_catalog_publisher_runs_in_bounded_process(self) -> None:
        control = ControlPlane(
            self._root(),
            registry=PluginRegistry((_EventPlugin(),)),
            pipeline_limits=replace(
                self._pipeline_limits(),
                publisher_execution_mode=PluginExecutionMode.PROCESS,
                publisher_execution_timeout_seconds=5,
            ),
            limits=ControlPlaneLimits(
                max_dataset_bytes=1024 * 1024,
                dataset_cache_entries=2,
            ),
        )
        self.addCleanup(control.close)
        control.sessions.create_project(
            "tenant-a",
            "Project A",
            project_id="project-a",
        )
        control.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace A",
            workspace_id="workspace-a",
        )

        completed = self._ingest(control)

        self.assertEqual(completed.state, ImportState.COMPLETED)
        self.assertIs(
            control.ingestion.limits.effective_publisher_execution_mode,
            PluginExecutionMode.PROCESS,
        )

    def test_scope_and_exact_subject_resolution_fail_closed(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        dataset = control.load_revision_dataset(scope, revision.revision_id)
        event_id = dataset["events"][0]["event_uid"]
        resource = dataset["resources"][0]["resource_id"]
        subjects = control.validate_subjects(
            scope,
            (
                ReviewSubject(
                    revision.revision_id,
                    ReviewSubjectKind.EVENT,
                    event_id,
                    node_id="router-a",
                ),
                ReviewSubject(
                    revision.revision_id,
                    ReviewSubjectKind.RESOURCE,
                    resource,
                ),
                ReviewSubject(
                    revision.revision_id,
                    ReviewSubjectKind.TIME_RANGE,
                    start_ns=100,
                    end_ns=200,
                ),
            ),
        )
        self.assertEqual(len(subjects), 3)
        with self.assertRaises(SubjectResolutionError):
            control.validate_subjects(
                scope,
                (
                    ReviewSubject(
                        revision.revision_id,
                        ReviewSubjectKind.EVENT,
                        "missing",
                    ),
                ),
            )
        with self.assertRaises(SubjectResolutionError):
            control.validate_subjects(
                scope,
                (
                    ReviewSubject(
                        revision.revision_id,
                        ReviewSubjectKind.EVENT,
                        event_id,
                        node_id="wrong-node",
                    ),
                ),
            )
        with self.assertRaises(ControlPlaneScopeError):
            control.scope(
                "tenant-a",
                "wrong-project",
                "workspace-a",
            )

    def test_annotations_and_manual_edges_produce_deterministic_report(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        dataset = control.load_revision_dataset(scope, revision.revision_id)
        event_ids = [str(event["event_uid"]) for event in dataset["events"]]
        subjects = tuple(
            ReviewSubject(
                revision.revision_id,
                ReviewSubjectKind.EVENT,
                event_id,
            )
            for event_id in event_ids
        )
        control.create_annotation(
            scope,
            annotation_id="marker-a",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(subjects[0],),
            author="alice",
            title="Failure starts",
        )
        control.create_correlation(
            scope,
            correlation_id="correlation-a",
            subjects=subjects,
            edges=(
                ManualCorrelationEdge(
                    0,
                    1,
                    "user.followed-by",
                ),
            ),
            author="alice",
            rationale="The interface recovers after the failure.",
        )
        session = control.sessions.create_session(
            "tenant-a",
            "workspace-a",
            "Review",
            session_id="session-a",
        )
        session = control.sessions.put_member(
            "tenant-a",
            session.session_id,
            "router-a/current",
            fixture_id=revision.fixture_id,
            revision_id=revision.revision_id,
            expected_version=session.version,
            make_default=True,
        )
        self.assertEqual(session.version, 1)

        first = control.build_report(scope, session_id=session.session_id)
        second = control.build_report(
            scope,
            revision_ids=(revision.revision_id,),
        )
        self.assertEqual(first.canonical_json, second.canonical_json)
        self.assertEqual(first.markdown, second.markdown)
        summary = first.json_document["summary"]
        self.assertEqual(summary["annotation_count"], 1)
        self.assertEqual(summary["manual_correlation_count"], 1)
        self.assertEqual(summary["event_count"], 2)
        self.assertGreaterEqual(summary["corroboration_fact_count"], 1)
        facts = first.json_document["corroboration_facts"]
        self.assertTrue(
            any(
                item["fact"]["fact_type"] == "shared_resource_ordered" for item in facts
            )
        )
        ordered_fact = next(
            item["fact"]
            for item in facts
            if item["fact"]["fact_type"] == "shared_resource_ordered"
        )
        self.assertEqual(
            ordered_fact["clock_alignment"],
            {
                "left_clock_domain": "utc",
                "right_clock_domain": "utc",
                "comparable": True,
            },
        )
        self.assertTrue(
            all(
                isinstance(event["timestamp_ns"], str)
                for event in first.json_document["observations"]["events"]
            )
        )
        self.assertEqual(
            first.json_document["correlations"]["manual_event_correlations"][0][
                "provenance_class"
            ],
            "user_asserted",
        )

    def test_report_exposes_unresolved_plugin_causal_targets(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        loaded = control._load_revision(scope, revision.revision_id)
        self.assertIsInstance(loaded.dataset, dict)
        dataset = loaded.dataset
        assert isinstance(dataset, dict)
        source_event_id = str(dataset["events"][0]["event_uid"])
        dataset["causal_links"] = [
            {
                "source_event_uid": source_event_id,
                "target_event_uid": "missing-event",
                "target_revision_id": revision.revision_id,
                "link_type": "tests.missing-target",
                "confidence": 1.0,
                "provenance": "correlated",
                "quality": "exact",
            }
        ]
        control.create_annotation(
            scope,
            annotation_id="marker-with-missing-target",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(
                ReviewSubject(
                    revision.revision_id,
                    ReviewSubjectKind.EVENT,
                    source_event_id,
                ),
            ),
            author="alice",
        )

        report = control.build_report(
            scope,
            revision_ids=(revision.revision_id,),
        )

        self.assertEqual(
            report.json_document["summary"]["unresolved_reference_count"],
            1,
        )
        self.assertEqual(
            report.json_document["unresolved_references"][0]["reason"],
            "target_event_missing",
        )

    def test_checksum_tampering_is_rejected_after_restart(self) -> None:
        root = self._root()
        control = self._control_plane(root)
        completed = self._ingest(control)
        scope = control.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        revision = control.resolve_catalog_revision(
            scope,
            fixture_id=completed.fixture_id,
        )
        dataset_path = control.ingestion.dataset_root / str(
            revision.metadata["dataset_ref"]
        )
        control.close()
        dataset_path.write_bytes(b'{"tampered":true}')

        reopened = ControlPlane(
            root,
            registry=PluginRegistry((_EventPlugin(),)),
            pipeline_limits=self._pipeline_limits(),
            limits=ControlPlaneLimits(max_dataset_bytes=1024 * 1024),
        )
        self.addCleanup(reopened.close)
        reopened_scope = reopened.scope(
            "tenant-a",
            "project-a",
            "workspace-a",
        )
        with self.assertRaisesRegex(
            DatasetIntegrityError,
            "checksum",
        ):
            reopened.load_revision_dataset(
                reopened_scope,
                revision.revision_id,
            )

    def test_retention_preview_does_not_wait_for_mutation_fence(self) -> None:
        control = self._control_plane(self._root())
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        fence_entered = threading.Event()
        release_fence = threading.Event()

        def hold_mutation_fence() -> None:
            with control._coordinated_review_catalog():
                fence_entered.set()
                if not release_fence.wait(5):
                    raise TimeoutError("retention fence release timed out")

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(hold_mutation_fence)
            self.assertTrue(fence_entered.wait(2))
            preview = executor.submit(
                control.retention_inventory,
                scope,
                catalog_policy=CatalogRetentionPolicy(),
                review_policy=ReviewRetentionPolicy(),
                now_ns=100,
            )
            try:
                result = preview.result(timeout=1)
            finally:
                release_fence.set()
                holder.result(timeout=2)

        self.assertFalse(result.executed)
        self.assertIs(
            result.observation_mode,
            RetentionObservationMode.BEST_EFFORT_PREVIEW,
        )
        self.assertIs(
            result.ingestion.host_storage_orphan_inventory,
            RetentionHostInventoryCoverage.NOT_OBSERVED,
        )

    def test_catalog_retention_protects_pending_promotion_revisions(self) -> None:
        control = self._control_plane(self._root())
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        pending = ProposalReviewRetentionReferences(
            revision_ids=("pending-promotion-revision",),
            overlay_idempotency_keys=("private-analysis-proposal:pending-decision",),
        )
        with patch.object(
            control.proposal_review_store,
            "pending_retention_references",
            return_value=pending,
        ):
            effective = control._catalog_retention_policy(
                scope,
                CatalogRetentionPolicy(),
            )
        self.assertTrue(effective.external_references_checked)
        self.assertIn(
            "pending-promotion-revision",
            effective.protected_revision_ids,
        )

    def test_retention_replays_and_acknowledges_a_release_after_crash_gap(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        self._age_catalog_for_retention(control)
        direct_policy = replace(
            self._catalog_retention_policy(),
            external_references_checked=True,
        )

        catalog_result = control.sessions.purge_retention(
            "tenant-a",
            "workspace-a",
            direct_policy,
            actor="retention-bot",
            operation_id="catalog-before-crash",
        )
        release = catalog_result.artifact_releases[0]
        self.assertEqual(release.artifact_kind, "dataset")
        pending = control.sessions.pending_artifact_release_audits(
            "tenant-a",
            "workspace-a",
        )
        self.assertEqual(
            tuple(item.operation_id for item in pending),
            ("catalog-before-crash",),
        )

        # Simulate a process death after the idempotent unpin succeeded but
        # before the catalog audit was acknowledged.
        self.assertTrue(
            control.ingestion.release_artifact_pin(
                control.import_scope("tenant-a", "project-a", "workspace-a"),
                artifact_kind=release.artifact_kind,
                artifact_ref=release.artifact_ref,
                owner_operation_id=release.owner_operation_id,
            )
        )
        self.assertEqual(self._artifact_pin_count(control), 1)

        replay = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(enabled=False),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="resume-after-crash",
        )
        self.assertIs(
            replay.observation_mode,
            RetentionObservationMode.COORDINATED_EXECUTION,
        )
        self.assertEqual(replay.replayed_release_actions, 1)
        self.assertEqual(replay.replayed_artifact_releases, 1)
        self.assertEqual(
            control.sessions.pending_artifact_release_audits(
                "tenant-a",
                "workspace-a",
            ),
            (),
        )
        audit = control.sessions.list_retention_audit(
            "tenant-a",
            "workspace-a",
        )[0]
        self.assertIsNotNone(audit.artifact_releases_acknowledged_at_ns)

        # A second maintenance call does not replay an acknowledged action.
        second = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(enabled=False),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="resume-after-crash-again",
        )
        self.assertEqual(second.replayed_release_actions, 0)
        self.assertEqual(second.replayed_artifact_releases, 0)
        self.assertEqual(completed.revision_id, release.catalog_identifier)

    def test_catalog_release_and_ingestion_retention_converge_across_sagas(
        self,
    ) -> None:
        control = self._control_plane(
            self._root(),
            retention_policy=RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            ),
        )
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        self._age_catalog_for_retention(control)
        with control.ingestion._connect() as connection:
            connection.execute(
                "UPDATE ingestion_imports SET updated_at_ns = 0 WHERE import_id = ?",
                (completed.import_id,),
            )
            row = connection.execute(
                "SELECT blob_ref, staged_dataset_ref FROM ingestion_imports "
                "WHERE import_id = ?",
                (completed.import_id,),
            ).fetchone()
        assert row is not None
        blob = control.ingestion.blob_root / Path(str(row["blob_ref"]))
        dataset = control.ingestion.dataset_root / Path(str(row["staged_dataset_ref"]))

        first = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="one-saga-convergence",
        )

        # The catalog first removes the revision. Its fixture still owns the
        # upload blob, so ingestion retains the row as scoped provenance.
        self.assertEqual(first.ingestion.deleted_imports, 0)
        self.assertTrue(blob.exists())
        self.assertTrue(dataset.exists())
        self.assertEqual(self._artifact_pin_count(control), 1)

        second = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="one-saga-convergence-again",
        )
        self.assertEqual(second.ingestion.deleted_imports, 1)
        self.assertEqual(second.ingestion.content_blobs, 1)
        self.assertEqual(second.ingestion.revision_datasets, 1)
        self.assertFalse(blob.exists())
        self.assertFalse(dataset.exists())
        self.assertEqual(self._artifact_pin_count(control), 0)
        self.assertEqual(
            control.ingestion.list_imports(
                control.import_scope(
                    scope.tenant_id,
                    scope.project_id,
                    scope.workspace_id,
                )
            ),
            (),
        )

        third = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="one-saga-convergence-final",
        )
        self.assertEqual(third.ingestion.eligible_imports, 0)
        self.assertEqual(third.ingestion.content_blobs, 0)
        self.assertEqual(third.ingestion.revision_datasets, 0)

    def test_retention_protects_review_references_then_purges_in_order(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        revision = control.sessions.get_revision("tenant-a", completed.revision_id)
        event_id = control.load_revision_dataset(scope, revision.revision_id)["events"][
            0
        ]["event_uid"]
        annotation = control.create_annotation(
            scope,
            annotation_id="protected-revision-marker",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(
                ReviewSubject(
                    revision.revision_id,
                    ReviewSubjectKind.EVENT,
                    event_id,
                ),
            ),
            author="alice",
        )
        self._age_catalog_for_retention(control)

        protected = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="protect-live-review",
        )
        revision_candidate = next(
            item
            for item in protected.catalog.inventory.candidates
            if item.category == "analysis_revision"
        )
        self.assertEqual(revision_candidate.blockers, ("externally_protected",))
        self.assertEqual(
            control.sessions.get_revision("tenant-a", revision.revision_id).revision_id,
            revision.revision_id,
        )

        control.annotations.delete_annotation(
            scope,
            annotation.annotation_id,
            expected_version=annotation.version,
            actor="alice",
        )
        with control.annotations._transaction() as connection:
            connection.execute(
                """
                UPDATE review_annotation
                SET created_at_ns = 1, updated_at_ns = 10, deleted_at_ns = 10
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND annotation_id = ?
                """,
                (
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                    annotation.annotation_id,
                ),
            )
        released = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(
                enabled=True,
                tombstone_before_ns=20,
            ),
            actor="retention-bot",
            operation_id="release-expired-review",
        )
        self.assertEqual(
            tuple(item.identifier for item in released.review.purged),
            (annotation.annotation_id,),
        )
        self.assertIn(
            revision.revision_id,
            {
                item.identifier
                for item in released.catalog.purged
                if item.category == "analysis_revision"
            },
        )
        with self.assertRaises(KeyError):
            control.sessions.get_revision("tenant-a", revision.revision_id)

    def test_retention_evicts_purged_revision_from_dataset_cache(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        control.load_revision_dataset(scope, completed.revision_id)
        cache_key = f"tenant-a\x1f{completed.revision_id}"
        self.assertIn(cache_key, control._cache)
        self._age_catalog_for_retention(control)

        result = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="evict-purged-revision",
        )
        self.assertIn(
            completed.revision_id,
            {
                item.identifier
                for item in result.catalog.purged
                if item.category == "analysis_revision"
            },
        )
        self.assertNotIn(cache_key, control._cache)

    def test_retention_validates_derived_operation_ids_before_mutation(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        event_id = control.load_revision_dataset(scope, completed.revision_id)[
            "events"
        ][0]["event_uid"]
        annotation = control.create_annotation(
            scope,
            annotation_id="operation-boundary-marker",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(
                ReviewSubject(
                    completed.revision_id,
                    ReviewSubjectKind.EVENT,
                    event_id,
                ),
            ),
            author="alice",
        )
        deleted = control.annotations.delete_annotation(
            scope,
            annotation.annotation_id,
            expected_version=annotation.version,
            actor="alice",
        )
        with control.annotations._transaction() as connection:
            connection.execute(
                """
                UPDATE review_annotation
                SET created_at_ns = 1, updated_at_ns = 10, deleted_at_ns = 10
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND annotation_id = ?
                """,
                (
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                    annotation.annotation_id,
                ),
            )

        with self.assertRaises(ValueError):
            control.run_retention(
                scope,
                catalog_policy=self._catalog_retention_policy(),
                review_policy=ReviewRetentionPolicy(
                    enabled=True,
                    tombstone_before_ns=20,
                ),
                actor="retention-bot",
                operation_id="x" * 250,
            )
        self.assertEqual(
            control.annotations.get_annotation(
                scope,
                deleted.annotation_id,
                include_deleted=True,
            ).annotation_id,
            deleted.annotation_id,
        )

    def test_retention_fences_review_creation_across_control_plane_instances(
        self,
    ) -> None:
        root = self._root()
        maintenance = self._control_plane(root)
        completed = self._ingest(maintenance)
        scope = maintenance.scope("tenant-a", "project-a", "workspace-a")
        event_id = maintenance.load_revision_dataset(scope, completed.revision_id)[
            "events"
        ][0]["event_uid"]
        self._age_catalog_for_retention(maintenance)
        writer = ControlPlane(
            root,
            registry=PluginRegistry((_EventPlugin(),)),
            pipeline_limits=self._pipeline_limits(),
            limits=ControlPlaneLimits(
                max_dataset_bytes=1024 * 1024,
                dataset_cache_entries=2,
            ),
        )
        self.addCleanup(writer.close)
        writer_scope = writer.scope("tenant-a", "project-a", "workspace-a")
        references_scanned = threading.Event()
        permit_catalog_purge = threading.Event()
        mutation_started = threading.Event()
        mutation_finished = threading.Event()
        original_references = maintenance.annotations.referenced_revision_ids

        def paused_reference_scan(*args: Any, **kwargs: Any) -> tuple[str, ...]:
            result = original_references(*args, **kwargs)
            references_scanned.set()
            if not permit_catalog_purge.wait(5):
                raise AssertionError("test did not release catalog purge")
            return result

        def create_review_reference() -> object:
            mutation_started.set()
            try:
                return writer.create_annotation(
                    writer_scope,
                    annotation_id="concurrent-reference",
                    kind=ReviewAnnotationKind.MARKER,
                    subjects=(
                        ReviewSubject(
                            completed.revision_id,
                            ReviewSubjectKind.EVENT,
                            event_id,
                        ),
                    ),
                    author="alice",
                )
            finally:
                mutation_finished.set()

        with (
            patch.object(
                maintenance.annotations,
                "referenced_revision_ids",
                side_effect=paused_reference_scan,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            retention = executor.submit(
                maintenance.run_retention,
                scope,
                catalog_policy=self._catalog_retention_policy(),
                review_policy=ReviewRetentionPolicy(),
                actor="retention-bot",
                operation_id="fenced-retention",
            )
            self.assertTrue(references_scanned.wait(5))
            mutation = executor.submit(create_review_reference)
            self.assertTrue(mutation_started.wait(5))
            try:
                self.assertFalse(
                    mutation_finished.wait(0.2),
                    "review write crossed the retention reference-scan fence",
                )
            finally:
                permit_catalog_purge.set()
            retention.result(timeout=5)
            with self.assertRaises((SubjectResolutionError, KeyError)):
                mutation.result(timeout=5)

    def test_retention_saga_replays_lost_response_exactly(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        self._age_catalog_for_retention(control)
        first = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="lost-response",
        )
        audit_counts = (
            len(control.sessions.list_retention_audit("tenant-a", "workspace-a")),
            len(control.annotations.list_retention_audit(scope)),
            len(
                control.ingestion.list_retention_audits(
                    control.import_scope("tenant-a", "project-a", "workspace-a")
                )
            ),
        )

        replayed = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="lost-response",
        )
        self.assertEqual(replayed, first)
        self.assertEqual(
            (
                len(control.sessions.list_retention_audit("tenant-a", "workspace-a")),
                len(control.annotations.list_retention_audit(scope)),
                len(
                    control.ingestion.list_retention_audits(
                        control.import_scope("tenant-a", "project-a", "workspace-a")
                    )
                ),
            ),
            audit_counts,
        )
        self.assertIn(
            completed.revision_id,
            {
                item.identifier
                for item in first.catalog.purged
                if item.category == "analysis_revision"
            },
        )

    def test_retention_saga_conflicting_reuse_fails_before_reconciliation(
        self,
    ) -> None:
        control = self._control_plane(self._root())
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        catalog = self._catalog_retention_policy(enabled=False)
        review = ReviewRetentionPolicy()
        control.run_retention(
            scope,
            catalog_policy=catalog,
            review_policy=review,
            actor="retention-bot",
            operation_id="exact-request",
            now_ns=100,
        )
        with patch.object(
            control,
            "_reconcile_retention_artifact_releases",
            wraps=control._reconcile_retention_artifact_releases,
        ) as reconcile:
            for actor, changed_catalog, changed_now in (
                ("different-actor", catalog, 100),
                (
                    "retention-bot",
                    replace(catalog, snapshot_before_ns=20),
                    100,
                ),
                ("retention-bot", catalog, 101),
            ):
                with self.assertRaises(IdempotencyConflict):
                    control.run_retention(
                        scope,
                        catalog_policy=changed_catalog,
                        review_policy=review,
                        actor=actor,
                        operation_id="exact-request",
                        now_ns=changed_now,
                    )
            reconcile.assert_not_called()

    def test_retention_saga_resumes_after_review_commit(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        event_id = control.load_revision_dataset(scope, completed.revision_id)[
            "events"
        ][0]["event_uid"]
        marker = control.create_annotation(
            scope,
            annotation_id="review-crash-marker",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(
                ReviewSubject(
                    completed.revision_id,
                    ReviewSubjectKind.EVENT,
                    event_id,
                ),
            ),
            author="alice",
        )
        control.annotations.delete_annotation(
            scope,
            marker.annotation_id,
            expected_version=marker.version,
            actor="alice",
        )
        with control.annotations._transaction() as connection:
            connection.execute(
                """
                UPDATE review_annotation
                SET created_at_ns = 1, updated_at_ns = 10, deleted_at_ns = 10
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND annotation_id = ?
                """,
                (
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                    marker.annotation_id,
                ),
            )
        self._age_catalog_for_retention(control)
        original_checkpoint = control.sessions.record_retention_saga_phase
        failed = False

        def fail_after_review(*args: Any, **kwargs: Any):
            nonlocal failed
            phase = args[3]
            if phase == "review" and not failed:
                failed = True
                raise RuntimeError("crash after review commit")
            return original_checkpoint(*args, **kwargs)

        with (
            patch.object(
                control.sessions,
                "record_retention_saga_phase",
                side_effect=fail_after_review,
            ),
            self.assertRaisesRegex(RuntimeError, "review commit"),
        ):
            control.run_retention(
                scope,
                catalog_policy=self._catalog_retention_policy(),
                review_policy=ReviewRetentionPolicy(
                    enabled=True,
                    tombstone_before_ns=20,
                ),
                actor="retention-bot",
                operation_id="review-commit-crash",
                now_ns=100,
            )

        resumed = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(
                enabled=True,
                tombstone_before_ns=20,
            ),
            actor="retention-bot",
            operation_id="review-commit-crash",
            now_ns=100,
        )
        self.assertEqual(
            tuple(item.identifier for item in resumed.review.purged),
            (marker.annotation_id,),
        )
        self.assertIn(
            completed.revision_id,
            {item.identifier for item in resumed.catalog.purged},
        )

    def test_retention_saga_resumes_after_catalog_commit(self) -> None:
        control = self._control_plane(self._root())
        completed = self._ingest(control)
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        self._age_catalog_for_retention(control)
        original_checkpoint = control.sessions.record_retention_saga_phase
        failed = False

        def fail_after_catalog(*args: Any, **kwargs: Any):
            nonlocal failed
            phase = args[3]
            if phase == "catalog" and not failed:
                failed = True
                raise RuntimeError("crash after catalog commit")
            return original_checkpoint(*args, **kwargs)

        with (
            patch.object(
                control.sessions,
                "record_retention_saga_phase",
                side_effect=fail_after_catalog,
            ),
            self.assertRaisesRegex(RuntimeError, "catalog commit"),
        ):
            control.run_retention(
                scope,
                catalog_policy=self._catalog_retention_policy(),
                review_policy=ReviewRetentionPolicy(),
                actor="retention-bot",
                operation_id="catalog-commit-crash",
                now_ns=100,
            )
        self.assertEqual(
            control.sessions.pending_artifact_release_audits("tenant-a", "workspace-a"),
            (),
        )

        resumed = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="catalog-commit-crash",
            now_ns=100,
        )
        self.assertIn(
            completed.revision_id,
            {item.identifier for item in resumed.catalog.purged},
        )

    def test_retention_saga_resumes_after_ingestion_commit(self) -> None:
        control = self._control_plane(
            self._root(),
            retention_policy=RetentionPolicy(
                enabled=True,
                terminal_import_grace_seconds=0,
                idempotency_replay_seconds=0,
                orphan_artifact_grace_seconds=0,
                stale_partial_seconds=0,
            ),
        )
        scope = control.scope("tenant-a", "project-a", "workspace-a")
        original_checkpoint = control.sessions.record_retention_saga_phase
        failed = False

        def fail_after_ingestion(*args: Any, **kwargs: Any):
            nonlocal failed
            phase = args[3]
            if phase == "ingestion" and not failed:
                failed = True
                raise RuntimeError("crash after ingestion commit")
            return original_checkpoint(*args, **kwargs)

        with (
            patch.object(
                control.sessions,
                "record_retention_saga_phase",
                side_effect=fail_after_ingestion,
            ),
            self.assertRaisesRegex(RuntimeError, "ingestion commit"),
        ):
            control.run_retention(
                scope,
                catalog_policy=self._catalog_retention_policy(enabled=False),
                review_policy=ReviewRetentionPolicy(),
                actor="retention-bot",
                operation_id="ingestion-commit-crash",
                now_ns=100,
            )
        audit_before = control.ingestion.list_retention_audits(
            control.import_scope("tenant-a", "project-a", "workspace-a")
        )
        self.assertEqual(len(audit_before), 1)

        resumed = control.run_retention(
            scope,
            catalog_policy=self._catalog_retention_policy(enabled=False),
            review_policy=ReviewRetentionPolicy(),
            actor="retention-bot",
            operation_id="ingestion-commit-crash",
            now_ns=100,
        )
        self.assertEqual(resumed.ingestion.audit_id, audit_before[0].audit_id)
        self.assertEqual(
            len(
                control.ingestion.list_retention_audits(
                    control.import_scope("tenant-a", "project-a", "workspace-a")
                )
            ),
            1,
        )

    def test_close_timeout_keeps_dependencies_open_for_retry(self) -> None:
        control = self._control_plane(self._root())
        real_close = control.ingestion.close
        with (
            patch.object(
                control.ingestion,
                "close",
                side_effect=TimeoutError("worker still running"),
            ),
            self.assertRaisesRegex(TimeoutError, "worker still running"),
        ):
            control.close(timeout=0)

        # A failed worker shutdown must not strand a live worker with closed
        # catalog dependencies.
        self.assertEqual(
            control.sessions.get_project("tenant-a", "project-a").label,
            "Project A",
        )
        real_close(timeout=5)
        control.close(timeout=5)


if __name__ == "__main__":
    unittest.main()
