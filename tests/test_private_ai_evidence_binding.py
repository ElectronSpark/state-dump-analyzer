from __future__ import annotations

import unittest
from dataclasses import replace

from router_dump_analyzer.plugin_execution_plan import (
    PLUGIN_EXECUTION_PLAN_VERSION_V1,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.private_analysis import (
    CoreEvidenceProducer,
    EvidenceAuthority,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceTimeRange,
    PrivateAnalysisEvidenceClass,
    evidence_locator_digest,
    evidence_payload_digest,
)
from router_dump_analyzer.private_analysis_binding import (
    PrivateAnalysisEvidenceBindingError,
    bind_private_analysis_plugin_producer,
    bind_private_analysis_revision,
    verify_private_analysis_evidence_binding,
)
from router_dump_analyzer.session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)


def _pin(
    instance_id: str,
    *,
    plugin_id: str = "vendor.shared",
    roles: tuple[str, ...] = (),
    capabilities: tuple[str, ...] = ("source_record_parser",),
) -> PluginExecutionPin:
    suffix = "a" if instance_id == "parser-a" else "b"
    return PluginExecutionPin(
        instance_id=instance_id,
        plugin_id=plugin_id,
        plugin_version="1.2.3",
        core_api_version="1",
        artifact=PluginArtifactIdentity(
            distribution_name=f"vendor-{suffix}",
            distribution_version="1.2.3",
            package_hash="sha256:" + suffix * 64,
            entry_point_name=instance_id,
            module_target=f"vendor_{suffix}:plugin",
        ),
        configuration_digest="sha256:" + "c" * 64,
        schema_digest="sha256:" + "d" * 64,
        registered_execution_identity="sha256:" + suffix * 64,
        capabilities=capabilities,
        roles=roles,
    )


def _catalog() -> tuple[
    WorkspaceDescriptor,
    FixtureDescriptor,
    AnalysisRevisionDescriptor,
]:
    workspace = WorkspaceDescriptor(
        tenant_id="tenant-a",
        project_id="project-a",
        workspace_id="workspace-a",
        label="Workspace A",
    )
    fixture = FixtureDescriptor(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        fixture_id="fixture-a",
        label="Fixture A",
        content_digest="1" * 64,
    )
    plan = PluginExecutionPlan(
        node_id="node-a",
        basis_revision_id="dump-basis-a",
        plugins=(
            _pin("parser-a", roles=("primary_parser",)),
            _pin(
                "parser-b",
                capabilities=("route_resolver", "source_record_parser"),
            ),
        ),
    )
    revision = AnalysisRevisionDescriptor(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        fixture_id="fixture-a",
        revision_id="catalog-revision-a",
        node_id="node-a",
        identity_digest="2" * 64,
        plugin_ids=("vendor.shared",),
        execution_plan=plan,
    )
    return workspace, fixture, revision


def _reference() -> tuple[
    EvidenceReference,
    WorkspaceDescriptor,
    FixtureDescriptor,
    AnalysisRevisionDescriptor,
]:
    workspace, fixture, revision = _catalog()
    scope, revision_binding = bind_private_analysis_revision(
        workspace,
        fixture,
        revision,
    )
    producer = bind_private_analysis_plugin_producer(
        revision,
        plugin_instance_id="parser-b",
        capability="route_resolver",
    )
    payload = {"route": "203.0.113.0/24", "labels": [16000]}
    reference = EvidenceReference(
        scope=scope,
        revision=revision_binding,
        producer=producer,
        kind=EvidenceKind.RESOURCE_STATE_INTERVAL,
        subject_kind="route_entry",
        locator_digest=evidence_locator_digest(
            "route_entry",
            {"vrf": "blue", "prefix": "203.0.113.0/24", "interval": 3},
        ),
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        payload_schema="vendor.route-entry.v1",
        fact_provenance=EvidenceFactProvenance.SNAPSHOT_OBSERVED,
        time_range=EvidenceTimeRange.not_applicable(),
        content_digest=evidence_payload_digest("vendor.route-entry.v1", payload),
    )
    return reference, workspace, fixture, revision


class PrivateAnalysisEvidenceBindingTests(unittest.TestCase):
    def test_catalog_binding_covers_scope_fixture_dataset_basis_and_plan(self) -> None:
        reference, workspace, fixture, revision = _reference()
        verify_private_analysis_evidence_binding(
            reference,
            workspace,
            fixture,
            revision,
        )
        self.assertEqual(reference.scope.tenant_id, "tenant-a")
        self.assertEqual(reference.scope.project_id, "project-a")
        self.assertEqual(reference.revision.fixture_content_sha256, "1" * 64)
        self.assertEqual(reference.revision.revision_identity_sha256, "2" * 64)
        assert revision.execution_plan is not None
        self.assertEqual(
            reference.revision.execution_plan_digest,
            revision.execution_plan.plan_digest,
        )
        self.assertEqual(
            reference.revision.plan_basis_revision_id,
            "dump-basis-a",
        )

    def test_path_shaped_plan_basis_is_bound_as_an_opaque_digest(self) -> None:
        workspace, fixture, revision = _catalog()
        assert revision.execution_plan is not None
        plan = replace(
            revision.execution_plan,
            basis_revision_id="ingested/router-a/private/source.jsonl",
            plan_digest="",
        )
        revision = replace(revision, execution_plan=plan)

        _scope, first = bind_private_analysis_revision(
            workspace,
            fixture,
            revision,
        )
        _scope, second = bind_private_analysis_revision(
            workspace,
            fixture,
            revision,
        )

        self.assertEqual(first, second)
        self.assertRegex(
            first.plan_basis_revision_id,
            r"^plan-basis-sha256-[0-9a-f]{64}$",
        )
        self.assertNotIn("ingested", first.plan_basis_revision_id)
        self.assertNotIn("/", first.plan_basis_revision_id)

    def test_duplicate_plugin_ids_are_qualified_by_instance_and_capability(
        self,
    ) -> None:
        _workspace, _fixture, revision = _catalog()
        parser = bind_private_analysis_plugin_producer(
            revision,
            plugin_instance_id="parser-a",
            capability="source_record_parser",
        )
        resolver = bind_private_analysis_plugin_producer(
            revision,
            plugin_instance_id="parser-b",
            capability="route_resolver",
        )
        self.assertEqual(parser.producer_id, resolver.producer_id)
        self.assertNotEqual(parser.plugin_instance_id, resolver.plugin_instance_id)
        self.assertNotEqual(parser, resolver)

    def test_primary_parser_role_is_bound_without_guessing_a_capability(self) -> None:
        _workspace, _fixture, revision = _catalog()
        producer = bind_private_analysis_plugin_producer(
            revision,
            plugin_instance_id="parser-a",
            role="primary_parser",
        )
        self.assertEqual(producer.plugin_role, "primary_parser")
        self.assertIsNone(producer.plugin_capability)
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "not assigned",
        ):
            bind_private_analysis_plugin_producer(
                revision,
                plugin_instance_id="parser-b",
                role="primary_parser",
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            bind_private_analysis_plugin_producer(
                revision,
                plugin_instance_id="parser-a",
                capability="source_record_parser",
                role="primary_parser",
            )

    def test_unknown_instance_or_undeclared_capability_fails_closed(self) -> None:
        _workspace, _fixture, revision = _catalog()
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "not present",
        ):
            bind_private_analysis_plugin_producer(
                revision,
                plugin_instance_id="unknown",
                capability="route_resolver",
            )
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "not declared",
        ):
            bind_private_analysis_plugin_producer(
                revision,
                plugin_instance_id="parser-a",
                capability="route_resolver",
            )

    def test_planless_legacy_revision_is_ineligible(self) -> None:
        workspace, fixture, revision = _catalog()
        legacy = replace(revision, plugin_ids=(), execution_plan=None)
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "requires an immutable plug-in execution plan",
        ):
            bind_private_analysis_revision(workspace, fixture, legacy)
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "requires an immutable plug-in execution plan",
        ):
            bind_private_analysis_plugin_producer(
                legacy,
                plugin_instance_id="parser-a",
                capability="source_record_parser",
            )

    def test_retained_v1_revision_remains_catalog_readable_but_not_evidence_bound(
        self,
    ) -> None:
        workspace, fixture, revision = _catalog()
        plan = revision.execution_plan
        assert plan is not None
        legacy_plan = PluginExecutionPlan(
            node_id=plan.node_id,
            basis_revision_id=plan.basis_revision_id,
            plugins=(
                replace(
                    plan.plugins[0],
                    registered_execution_identity="sha256:" + "0" * 64,
                ),
            ),
            decoder=plan.decoder,
            contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
        )
        legacy_revision = replace(revision, execution_plan=legacy_plan)
        self.assertEqual(legacy_revision.execution_plan, legacy_plan)
        self.assertEqual(
            legacy_revision.execution_plan_digest,
            legacy_plan.plan_digest,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "retained v1.*cannot produce",
        ):
            bind_private_analysis_revision(workspace, fixture, legacy_revision)
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "retained v1.*cannot produce",
        ):
            bind_private_analysis_plugin_producer(
                legacy_revision,
                plugin_instance_id="parser-a",
                capability="source_record_parser",
            )

    def test_cross_scope_and_cross_fixture_splicing_fails_closed(self) -> None:
        reference, workspace, fixture, revision = _reference()
        mismatches = (
            (
                replace(workspace, tenant_id="tenant-b"),
                fixture,
                revision,
                "fixture tenant",
            ),
            (
                replace(workspace, workspace_id="workspace-b"),
                fixture,
                revision,
                "fixture workspace",
            ),
            (
                workspace,
                replace(fixture, fixture_id="fixture-b"),
                revision,
                "revision fixture",
            ),
            (
                workspace,
                fixture,
                replace(revision, tenant_id="tenant-b"),
                "revision tenant",
            ),
        )
        for (
            selected_workspace,
            selected_fixture,
            selected_revision,
            message,
        ) in mismatches:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    PrivateAnalysisEvidenceBindingError,
                    message,
                ),
            ):
                verify_private_analysis_evidence_binding(
                    reference,
                    selected_workspace,
                    selected_fixture,
                    selected_revision,
                )

    def test_every_bound_identity_and_plugin_claim_is_revalidated(self) -> None:
        reference, workspace, fixture, revision = _reference()
        mutations = (
            replace(
                reference,
                scope=replace(reference.scope, project_id="other"),
                reference_digest="",
            ),
            replace(
                reference,
                revision=replace(reference.revision, fixture_content_sha256="3" * 64),
                reference_digest="",
            ),
            replace(
                reference,
                revision=replace(reference.revision, revision_identity_sha256="4" * 64),
                reference_digest="",
            ),
            replace(
                reference,
                revision=replace(reference.revision, plan_basis_revision_id="other"),
                reference_digest="",
            ),
            replace(
                reference,
                revision=replace(
                    reference.revision, execution_plan_digest="sha256:" + "5" * 64
                ),
                reference_digest="",
            ),
            replace(
                reference,
                producer=replace(reference.producer, producer_id="impersonator"),
                reference_digest="",
            ),
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(PrivateAnalysisEvidenceBindingError),
            ):
                verify_private_analysis_evidence_binding(
                    mutation,
                    workspace,
                    fixture,
                    revision,
                )

    def test_core_evidence_keeps_revision_binding_without_plugin_impersonation(
        self,
    ) -> None:
        reference, workspace, fixture, revision = _reference()
        core = replace(
            reference,
            producer=EvidenceProducer(
                authority=EvidenceAuthority.CORE_CORROBORATION,
                producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
            ),
            reference_digest="",
        )
        verify_private_analysis_evidence_binding(core, workspace, fixture, revision)


if __name__ == "__main__":
    unittest.main()
