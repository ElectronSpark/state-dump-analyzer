from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.capability_router import CapabilityProviderRegistry
from router_dump_analyzer.control_plane import SessionCatalogPublisher
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import (
    DurableIngestionPipeline,
    ImportScope,
    ImportState,
    IngestionPipelineError,
    PipelineLimits,
    PluginExecutionMode,
    PluginExecutionProcessError,
    PluginRegistry,
    _auxiliary_execution_pin,
    _dataset_with_execution_plan,
    _execution_plan_for_result,
    _frozen_auxiliary_execution_pins,
    _run_plugin_child,
    _StagedChildIngestion,
    executable_plugin_fingerprint,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    PluginCapability,
    PluginManifest,
    ReconstructionSupport,
)
from router_dump_analyzer.plugin_composition import (
    PLUGIN_COMPOSITION_POLICY_VERSION,
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from router_dump_analyzer.plugin_execution_plan import (
    DecoderIdentity,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
    plugin_execution_plan_dict,
    plugin_execution_plan_plugin_ids,
)
from router_dump_analyzer.plugin_identity import PluginExecutableIdentityError
from router_dump_analyzer.private_analysis_binding import (
    bind_private_analysis_revision,
)
from router_dump_analyzer.session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)
from tests.test_ingestion import ParseOnlyPlugin
from tests.test_ingestion_pipeline import _fixture_bytes


class _AuxiliaryPlugin(ParseOnlyPlugin):
    manifest = PluginManifest(
        plugin_id="tests.auxiliary",
        plugin_version="2.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("test-os",),
        supported_software_versions="*",
        capabilities=frozenset({PluginCapability.STATUS_PARSE}),
        reconstruction_default=ReconstructionSupport.EXACT,
    )


class _ManifestAccessFailure(BaseException):
    pass


class _ManifestPropertyAuxiliaryPlugin(_AuxiliaryPlugin):
    def __init__(self) -> None:
        self._manifest_reads = 0
        self._manifest_failure_at: int | None = None

    @property
    def manifest(self) -> PluginManifest:
        self._manifest_reads += 1
        failure_at = self._manifest_failure_at
        if failure_at is not None and self._manifest_reads >= failure_at:
            raise _ManifestAccessFailure("PRIVATE-AUXILIARY-MANIFEST-DETAIL")
        return _AuxiliaryPlugin.manifest

    def arm_manifest_failure(self, *, failure_at: int) -> None:
        self._manifest_reads = 0
        self._manifest_failure_at = failure_at


class _NoopTraceDecoder:
    def iter_ctf(self, *args, **kwargs):
        del args, kwargs
        return ()


class PluginCompositionTests(unittest.TestCase):
    @staticmethod
    def _selection(instance_id: str, digest_character: str):
        return PluginParticipationSelection(
            instance_id=instance_id,
            registered_execution_identity="sha256:" + digest_character * 64,
            roles=("private_analysis_evidence",),
        )

    def _assert_auxiliary_drift_rejected(
        self,
        mode: str,
        *,
        primary,
        result,
        providers,
        policy,
        payload: dict[str, object],
    ) -> None:
        expected_error = (
            IngestionPipelineError if mode == "inline" else PluginExecutionProcessError
        )
        with self.assertRaises(expected_error) as caught:
            if mode == "inline":
                _execution_plan_for_result(
                    primary,
                    result,
                    capability_providers=providers,
                    composition_policy=policy,
                    execution_plan_authority=(PluginExecutionPlanAuthority.PROCESS),
                )
            else:
                DurableIngestionPipeline._child_ingestion_metadata(
                    payload,
                    primary,
                    capability_providers=providers,
                    composition_policy=policy,
                    allow_inline_only=False,
                    expected_execution_plan_authority=(
                        PluginExecutionPlanAuthority.PROCESS
                    ),
                )
        self.assertNotIn(
            "PRIVATE-AUXILIARY-MANIFEST-DETAIL",
            str(caught.exception),
        )

    def test_policy_is_canonical_bounded_and_content_addressed(self) -> None:
        class StringSubclass(str):
            pass

        first = self._selection("aux-a", "a")
        second = self._selection("aux-b", "b")
        rule = PluginCompositionRule(
            primary_instance_id="primary",
            primary_registered_execution_identity="sha256:" + "c" * 64,
            auxiliaries=(first, second),
        )
        policy = PluginCompositionPolicy((rule,))
        self.assertTrue(policy.policy_digest.startswith("sha256:"))
        self.assertEqual(
            policy.auxiliaries_for(
                primary_instance_id="primary",
                primary_registered_execution_identity="sha256:" + "c" * 64,
            ),
            (first, second),
        )
        self.assertEqual(
            policy.auxiliaries_for(
                primary_instance_id="other",
                primary_registered_execution_identity="sha256:" + "d" * 64,
            ),
            (),
        )
        with self.assertRaisesRegex(ValueError, "canonical identity order"):
            PluginCompositionRule(
                primary_instance_id="primary",
                primary_registered_execution_identity="sha256:" + "c" * 64,
                auxiliaries=(second, first),
            )
        with self.assertRaisesRegex(ValueError, "primary_parser"):
            PluginParticipationSelection(
                instance_id="aux-c",
                registered_execution_identity="sha256:" + "d" * 64,
                roles=("primary_parser",),
            )
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            replace(policy, policy_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(TypeError, "contract_version"):
            PluginCompositionPolicy(
                contract_version=StringSubclass(PLUGIN_COMPOSITION_POLICY_VERSION)
            )
        for malformed_digest in (None, False, 0, (), {}):
            with (
                self.subTest(malformed_digest=malformed_digest),
                self.assertRaisesRegex(TypeError, "policy_digest"),
            ):
                PluginCompositionPolicy(  # type: ignore[arg-type]
                    policy_digest=malformed_digest
                )

    def test_execution_plan_includes_exact_auxiliary_without_identity_merging(
        self,
    ) -> None:
        registry = PluginRegistry()
        primary_plugin = ParseOnlyPlugin()
        primary_coordinator = IngestionCoordinator()
        primary = registry.register(
            primary_plugin,
            coordinator=primary_coordinator,
            instance_id="primary",
        )
        auxiliary = registry.register(
            _AuxiliaryPlugin(),
            instance_id="auxiliary",
        )
        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = primary_coordinator.ingest(primary_plugin, path)
        plan = _execution_plan_for_result(
            primary,
            result,
            capability_providers=providers,
            composition_policy=policy,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )

        self.assertEqual(
            tuple(pin.instance_id for pin in plan.plugins),
            ("primary", "auxiliary"),
        )
        self.assertEqual(plan.plugins[0].roles, ("primary_parser",))
        self.assertEqual(plan.plugins[1].roles, ("private_analysis_evidence",))
        self.assertEqual(plan.composition_policy_digest, policy.policy_digest)
        self.assertEqual(
            plugin_execution_plan_dict(plan)["composition_policy_digest"],
            policy.policy_digest,
        )
        self.assertNotEqual(
            plan.plugins[0].schema_digest,
            "",
        )

        stale_policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        replace(
                            policy.rules[0].auxiliaries[0],
                            registered_execution_identity="sha256:" + "f" * 64,
                        ),
                    ),
                ),
            )
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "identity or schema could not be frozen",
        ):
            _execution_plan_for_result(
                primary,
                result,
                capability_providers=providers,
                composition_policy=stale_policy,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )
        with self.assertRaisesRegex(TypeError, "composition_policy"):
            _execution_plan_for_result(  # type: ignore[arg-type]
                primary,
                result,
                composition_policy=False,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )

    def test_unrelated_policy_change_alters_all_durable_revision_identities(
        self,
    ) -> None:
        registry = PluginRegistry()
        primary_plugin = ParseOnlyPlugin()
        coordinator = IngestionCoordinator()
        primary = registry.register(
            primary_plugin,
            coordinator=coordinator,
            instance_id="primary",
        )
        auxiliary = registry.register(
            _AuxiliaryPlugin(),
            instance_id="auxiliary",
        )
        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        selected_rule = PluginCompositionRule(
            primary_instance_id=primary.instance_id,
            primary_registered_execution_identity=(
                primary.registered_execution_identity
            ),
            auxiliaries=(
                PluginParticipationSelection(
                    instance_id=auxiliary.instance_id,
                    registered_execution_identity=(
                        auxiliary.registered_execution_identity
                    ),
                    roles=("private_analysis_evidence",),
                ),
            ),
        )
        original_policy = PluginCompositionPolicy((selected_rule,))
        changed_policy = PluginCompositionPolicy(
            (
                selected_rule,
                PluginCompositionRule(
                    primary_instance_id="zz-unrelated-primary",
                    primary_registered_execution_identity="sha256:" + "f" * 64,
                    auxiliaries=(),
                ),
            )
        )
        self.assertEqual(
            original_policy.auxiliaries_for(
                primary_instance_id=primary.instance_id,
                primary_registered_execution_identity=(
                    primary.registered_execution_identity
                ),
            ),
            changed_policy.auxiliaries_for(
                primary_instance_id=primary.instance_id,
                primary_registered_execution_identity=(
                    primary.registered_execution_identity
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = coordinator.ingest(primary_plugin, path)
        original_dataset, original_plan = _dataset_with_execution_plan(
            primary,
            result,
            capability_providers=providers,
            composition_policy=original_policy,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        changed_dataset, changed_plan = _dataset_with_execution_plan(
            primary,
            result,
            capability_providers=providers,
            composition_policy=changed_policy,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        self.assertEqual(original_plan.plugins, changed_plan.plugins)
        self.assertNotEqual(
            original_plan.composition_policy_digest,
            changed_plan.composition_policy_digest,
        )
        self.assertNotEqual(original_plan.plan_digest, changed_plan.plan_digest)
        original_dataset_digest = hashlib.sha256(original_dataset).hexdigest()
        changed_dataset_digest = hashlib.sha256(changed_dataset).hexdigest()
        self.assertNotEqual(original_dataset_digest, changed_dataset_digest)

        scope = ImportScope("tenant-a", "project-a", "workspace-a")
        original_revision_id = SessionCatalogPublisher.catalog_revision_id(
            scope,
            fixture_id="fixture-a",
            source_revision_id=result.revision_id,
            dataset_sha256=original_dataset_digest,
        )
        changed_revision_id = SessionCatalogPublisher.catalog_revision_id(
            scope,
            fixture_id="fixture-a",
            source_revision_id=result.revision_id,
            dataset_sha256=changed_dataset_digest,
        )
        self.assertNotEqual(original_revision_id, changed_revision_id)
        workspace = WorkspaceDescriptor(
            tenant_id=scope.tenant_id,
            project_id=scope.project_id,
            workspace_id=scope.workspace_id,
            label="Workspace",
        )
        fixture = FixtureDescriptor(
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            fixture_id="fixture-a",
            label="Fixture",
            content_digest="1" * 64,
        )

        def revision(
            revision_id: str,
            identity_digest: str,
            plan: PluginExecutionPlan,
        ) -> AnalysisRevisionDescriptor:
            return AnalysisRevisionDescriptor(
                tenant_id=scope.tenant_id,
                workspace_id=scope.workspace_id,
                fixture_id=fixture.fixture_id,
                revision_id=revision_id,
                node_id=result.node_id,
                identity_digest=identity_digest,
                plugin_ids=plugin_execution_plan_plugin_ids(plan),
                execution_plan=plan,
            )

        _scope, original_binding = bind_private_analysis_revision(
            workspace,
            fixture,
            revision(
                original_revision_id,
                original_dataset_digest,
                original_plan,
            ),
        )
        _scope, changed_binding = bind_private_analysis_revision(
            workspace,
            fixture,
            revision(
                changed_revision_id,
                changed_dataset_digest,
                changed_plan,
            ),
        )
        self.assertNotEqual(original_binding, changed_binding)

    def test_same_plugin_version_with_distinct_configs_compose_deterministically(
        self,
    ) -> None:
        primary_registry = PluginRegistry()
        auxiliary_registry = PluginRegistry()
        primary_plugin = ParseOnlyPlugin()
        auxiliary_plugin = ParseOnlyPlugin()
        primary_coordinator = IngestionCoordinator()
        primary = primary_registry.register(
            primary_plugin,
            coordinator=primary_coordinator,
            instance_id="same.primary.config-a",
            configuration_digest="sha256:" + "a" * 64,
        )
        auxiliary = auxiliary_registry.register(
            auxiliary_plugin,
            instance_id="same.auxiliary.config-b",
            configuration_digest="sha256:" + "b" * 64,
        )
        providers = CapabilityProviderRegistry((auxiliary, primary))
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = primary_coordinator.ingest(primary_plugin, path)
        first = _execution_plan_for_result(
            primary,
            result,
            capability_providers=providers,
            composition_policy=policy,
            allow_inline_only=True,
            execution_plan_authority=(
                PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
            ),
        )
        second = _execution_plan_for_result(
            primary,
            result,
            capability_providers=providers,
            composition_policy=policy,
            allow_inline_only=True,
            execution_plan_authority=(
                PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
            ),
        )
        self.assertEqual(first, second)
        self.assertEqual(
            tuple(pin.plugin_id for pin in first.plugins),
            (primary.plugin_id, auxiliary.plugin_id),
        )
        self.assertEqual(
            tuple(pin.configuration_digest for pin in first.plugins),
            ("sha256:" + "a" * 64, "sha256:" + "b" * 64),
        )
        self.assertNotEqual(
            first.plugins[0].registered_execution_identity,
            first.plugins[1].registered_execution_identity,
        )

    def test_parent_attests_child_timeline_bounds_and_manifest_binding(self) -> None:
        registry = PluginRegistry()
        plugin = ParseOnlyPlugin()
        coordinator = IngestionCoordinator()
        registered = registry.register(
            plugin,
            coordinator=coordinator,
            instance_id="primary",
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "status.jsonl"
            source.write_bytes(_fixture_bytes())
            result = coordinator.ingest(plugin, source)
            plan = _execution_plan_for_result(
                registered,
                result,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )

            def attest(**changes: object) -> None:
                ingestion: dict[str, object] = {
                    "plugin_execution_plan_digest": plan.plan_digest,
                    "timeline_time_basis": "revision_start_relative_ns",
                    "timeline_clock_domain": None,
                    "timeline_start_ns": "0",
                    "timeline_end_ns": "100",
                }
                ingestion.update(changes)
                encoded = json.dumps(
                    {"_ingestion": ingestion},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                path = Path(directory) / "staged.json"
                path.write_bytes(encoded)
                digest = hashlib.sha256(encoded).hexdigest()
                DurableIngestionPipeline._validate_staged_timeline_binding(
                    path,
                    staged=_StagedChildIngestion(
                        revision_id=result.revision_id,
                        node_id=result.node_id,
                        dataset_sha256=digest,
                        dataset_bytes=len(encoded),
                        event_count=0,
                        source_record_count=0,
                        resource_count=0,
                        execution_plan=plan,
                    ),
                    registered=registered,
                )

            attest()
            for forged in (
                {"timeline_time_basis": "absolute_unix_ns"},
                {"timeline_start_ns": "101", "timeline_end_ns": "100"},
                {
                    "timeline_start_ns": str(-(1 << 63)),
                    "timeline_end_ns": str((1 << 63) - 1),
                },
                {"plugin_execution_plan_digest": "sha256:" + "0" * 64},
            ):
                with (
                    self.subTest(forged=forged),
                    self.assertRaises(IngestionPipelineError),
                ):
                    attest(**forged)

    def test_parent_rejects_forged_child_composition_before_staging(self) -> None:
        registry = PluginRegistry()
        primary_plugin = ParseOnlyPlugin()
        coordinator = IngestionCoordinator()
        primary = registry.register(
            primary_plugin,
            coordinator=coordinator,
            instance_id="primary",
        )
        auxiliary = registry.register(
            _AuxiliaryPlugin(),
            instance_id="auxiliary",
        )
        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = coordinator.ingest(primary_plugin, path)
        valid_plan = _execution_plan_for_result(
            primary,
            result,
            capability_providers=providers,
            composition_policy=policy,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )

        def payload(plan: PluginExecutionPlan) -> dict[str, object]:
            return {
                "revision_id": result.revision_id,
                "node_id": result.node_id,
                "dataset_sha256": "a" * 64,
                "dataset_bytes": 1,
                "event_count": 0,
                "source_record_count": 0,
                "resource_count": 0,
                "execution_plan": plugin_execution_plan_dict(plan),
            }

        accepted = DurableIngestionPipeline._child_ingestion_metadata(
            payload(valid_plan),
            primary,
            capability_providers=providers,
            composition_policy=policy,
            allow_inline_only=False,
            expected_execution_plan_authority=(PluginExecutionPlanAuthority.PROCESS),
        )
        self.assertEqual(accepted.execution_plan, valid_plan)

        forged_plans = (
            PluginExecutionPlan(
                node_id=valid_plan.node_id,
                basis_revision_id=valid_plan.basis_revision_id,
                plugins=(valid_plan.plugins[0],),
                decoder=valid_plan.decoder,
            ),
            PluginExecutionPlan(
                node_id=valid_plan.node_id,
                basis_revision_id=valid_plan.basis_revision_id,
                plugins=(
                    valid_plan.plugins[0],
                    replace(
                        valid_plan.plugins[1],
                        roles=("route_resolver",),
                    ),
                ),
                decoder=valid_plan.decoder,
            ),
            PluginExecutionPlan(
                node_id=valid_plan.node_id,
                basis_revision_id=valid_plan.basis_revision_id,
                plugins=(
                    replace(
                        valid_plan.plugins[0],
                        roles=("primary_parser", "route_resolver"),
                    ),
                    valid_plan.plugins[1],
                ),
                decoder=valid_plan.decoder,
            ),
            PluginExecutionPlan(
                node_id=valid_plan.node_id,
                basis_revision_id=valid_plan.basis_revision_id,
                plugins=(
                    valid_plan.plugins[0],
                    replace(
                        valid_plan.plugins[1],
                        schema_digest="sha256:" + "0" * 64,
                    ),
                ),
                decoder=valid_plan.decoder,
            ),
        )
        for forged in forged_plans:
            with (
                self.subTest(roles=tuple(pin.roles for pin in forged.plugins)),
                self.assertRaisesRegex(
                    Exception,
                    "execution plan does not match the staged revision basis",
                ),
            ):
                DurableIngestionPipeline._child_ingestion_metadata(
                    payload(forged),
                    primary,
                    capability_providers=providers,
                    composition_policy=policy,
                    allow_inline_only=False,
                    expected_execution_plan_authority=(
                        PluginExecutionPlanAuthority.PROCESS
                    ),
                )

        with patch.object(
            type(auxiliary.execution_plugin),
            "describe",
            side_effect=KeyboardInterrupt("process control"),
            create=True,
        ) as describe:
            accepted_without_provider_invocation = (
                DurableIngestionPipeline._child_ingestion_metadata(
                    payload(valid_plan),
                    primary,
                    capability_providers=providers,
                    composition_policy=policy,
                    allow_inline_only=False,
                    expected_execution_plan_authority=(
                        PluginExecutionPlanAuthority.PROCESS
                    ),
                )
            )
        self.assertEqual(
            accepted_without_provider_invocation.execution_plan, valid_plan
        )
        describe.assert_not_called()

        with patch.object(
            type(auxiliary.execution_plugin),
            "describe",
            side_effect=BaseException("private schema detail"),
            create=True,
        ) as describe:
            accepted_without_hostile_provider_invocation = (
                DurableIngestionPipeline._child_ingestion_metadata(
                    payload(valid_plan),
                    primary,
                    capability_providers=providers,
                    composition_policy=policy,
                    allow_inline_only=False,
                    expected_execution_plan_authority=(
                        PluginExecutionPlanAuthority.PROCESS
                    ),
                )
            )
        self.assertEqual(
            accepted_without_hostile_provider_invocation.execution_plan,
            valid_plan,
        )
        describe.assert_not_called()

    def test_parent_readmission_revalidates_live_auxiliary_with_inline_parity(
        self,
    ) -> None:
        for drift in ("executable", "manifest", "manifest_property"):
            for mode in ("inline", "process"):
                with self.subTest(drift=drift, mode=mode):
                    primary_registry = PluginRegistry()
                    primary_plugin = ParseOnlyPlugin()
                    primary_coordinator = IngestionCoordinator()
                    primary = primary_registry.register(
                        primary_plugin,
                        coordinator=primary_coordinator,
                        instance_id="primary",
                    )
                    auxiliary_plugin = (
                        _ManifestPropertyAuxiliaryPlugin()
                        if drift == "manifest_property"
                        else _AuxiliaryPlugin()
                    )
                    auxiliary = PluginRegistry().register(
                        auxiliary_plugin,
                        instance_id="auxiliary",
                    )
                    providers = CapabilityProviderRegistry((auxiliary,))
                    policy = PluginCompositionPolicy(
                        (
                            PluginCompositionRule(
                                primary_instance_id=primary.instance_id,
                                primary_registered_execution_identity=(
                                    primary.registered_execution_identity
                                ),
                                auxiliaries=(
                                    PluginParticipationSelection(
                                        instance_id=auxiliary.instance_id,
                                        registered_execution_identity=(
                                            auxiliary.registered_execution_identity
                                        ),
                                        roles=("private_analysis_evidence",),
                                    ),
                                ),
                            ),
                        )
                    )
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "status.jsonl"
                        path.write_bytes(_fixture_bytes())
                        result = primary_coordinator.ingest(primary_plugin, path)
                    valid_plan = _execution_plan_for_result(
                        primary,
                        result,
                        capability_providers=providers,
                        composition_policy=policy,
                        execution_plan_authority=(PluginExecutionPlanAuthority.PROCESS),
                    )
                    payload = {
                        "revision_id": result.revision_id,
                        "node_id": result.node_id,
                        "dataset_sha256": "a" * 64,
                        "dataset_bytes": 1,
                        "event_count": 0,
                        "source_record_count": 0,
                        "resource_count": 0,
                        "execution_plan": plugin_execution_plan_dict(valid_plan),
                    }

                    if drift == "executable":

                        def drifted_fingerprint(
                            value: object,
                            expected: object = auxiliary_plugin,
                        ) -> str:
                            if value is expected:
                                return "package-sha256:" + "0" * 64
                            return executable_plugin_fingerprint(value)

                        with patch(
                            "router_dump_analyzer.plugin_registration."
                            "executable_plugin_fingerprint",
                            side_effect=drifted_fingerprint,
                        ):
                            self._assert_auxiliary_drift_rejected(
                                mode,
                                primary=primary,
                                result=result,
                                providers=providers,
                                policy=policy,
                                payload=payload,
                            )
                    elif drift == "manifest":
                        auxiliary_plugin.manifest = replace(
                            auxiliary_plugin.manifest,
                            supported_platforms=("changed-platform",),
                        )
                        self._assert_auxiliary_drift_rejected(
                            mode,
                            primary=primary,
                            result=result,
                            providers=providers,
                            policy=policy,
                            payload=payload,
                        )
                    else:
                        assert isinstance(
                            auxiliary_plugin,
                            _ManifestPropertyAuxiliaryPlugin,
                        )
                        auxiliary_plugin.arm_manifest_failure(failure_at=2)
                        self._assert_auxiliary_drift_rejected(
                            mode,
                            primary=primary,
                            result=result,
                            providers=providers,
                            policy=policy,
                            payload=payload,
                        )

    def test_process_publication_rejects_auxiliary_drift_after_child_returns(
        self,
    ) -> None:
        primary_registry = PluginRegistry()
        primary = primary_registry.register(
            ParseOnlyPlugin(),
            instance_id="primary",
        )
        auxiliary_plugin = _ManifestPropertyAuxiliaryPlugin()
        auxiliary = PluginRegistry().register(
            auxiliary_plugin,
            instance_id="auxiliary",
        )
        providers = CapabilityProviderRegistry((auxiliary,))
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        scope = ImportScope("tenant", "project", "workspace")
        child_returned = False

        def run_then_drift(
            target,
            args,
            *,
            timeout_seconds: float,
            stage: str,
        ):
            nonlocal child_returned
            payload = _run_plugin_child(
                target,
                args,
                timeout_seconds=timeout_seconds,
                stage=stage,
            )
            if stage == "ingest":
                child_returned = True
                # The first parent read remains valid; the second read fails,
                # proving readmission checks both sides of identity/schema use.
                auxiliary_plugin.arm_manifest_failure(failure_at=2)
            return payload

        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=primary_registry,
                capability_providers=providers,
                composition_policy=policy,
                limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    max_attempts=1,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.PROCESS,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                    plugin_execution_timeout_seconds=30,
                ),
            )
            with (
                patch(
                    "router_dump_analyzer.ingestion_pipeline._run_plugin_child",
                    side_effect=run_then_drift,
                ),
                pipeline,
            ):
                admitted = pipeline.submit_bytes(
                    scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                )
                completed = pipeline.wait(scope, admitted.import_id, timeout=60)
            with pipeline._connect() as connection:
                staged = connection.execute(
                    """
                    SELECT state, staged_dataset_ref, staged_execution_plan_digest
                    FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (admitted.import_id,),
                ).fetchone()

        self.assertTrue(child_returned)
        self.assertEqual(completed.state, ImportState.FAILED)
        self.assertEqual(completed.error_code, "plugin_execution_failed")
        self.assertNotIn(
            "PRIVATE-AUXILIARY-MANIFEST-DETAIL",
            str(completed.error_message),
        )
        assert staged is not None
        self.assertEqual(staged["state"], ImportState.FAILED.value)
        self.assertIsNone(staged["staged_dataset_ref"])
        self.assertIsNone(staged["staged_execution_plan_digest"])

    def test_decoder_bound_auxiliary_is_rejected_before_plan_publication(self) -> None:
        registry = PluginRegistry()
        primary_plugin = ParseOnlyPlugin()
        primary_coordinator = IngestionCoordinator()
        primary = registry.register(
            primary_plugin,
            coordinator=primary_coordinator,
            instance_id="primary",
        )
        decoder = DecoderIdentity(
            "test.decoder",
            "1",
            "sha256:" + "7" * 64,
        )
        auxiliary = registry.register(
            _AuxiliaryPlugin(),
            coordinator=IngestionCoordinator(trace_decoder=_NoopTraceDecoder()),
            instance_id="decoder-auxiliary",
            decoder_identity=decoder,
        )
        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = primary_coordinator.ingest(primary_plugin, path)

        with self.assertRaisesRegex(
            IngestionPipelineError,
            "auxiliary plug-in cannot bind a trace decoder",
        ):
            _execution_plan_for_result(
                primary,
                result,
                capability_providers=providers,
                composition_policy=policy,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )

    def test_non_revalidatable_auxiliary_is_rejected_before_plan_publication(
        self,
    ) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary_plugin = ParseOnlyPlugin()
        primary_coordinator = IngestionCoordinator()
        primary = registry.register(
            primary_plugin,
            coordinator=primary_coordinator,
            instance_id="primary",
        )
        auxiliary = registry.register(
            _AuxiliaryPlugin(),
            instance_id="manifest-only-auxiliary",
            package_hash="manifest-sha256:" + "a" * 64,
        )
        self.assertFalse(auxiliary.verify_package_bytes)
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_fixture_bytes())
            result = primary_coordinator.ingest(primary_plugin, path)

        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        self.assertIn(auxiliary.instance_id, providers.instance_ids())
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "identity or schema could not be frozen",
        ):
            _execution_plan_for_result(
                primary,
                result,
                capability_providers=providers,
                composition_policy=policy,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )
        trusted_plan = _execution_plan_for_result(
            primary,
            result,
            capability_providers=providers,
            composition_policy=policy,
            allow_inline_only=True,
            execution_plan_authority=(
                PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST
            ),
        )
        self.assertIs(
            trusted_plan.execution_plan_authority,
            PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST,
        )

    def test_process_auxiliary_pinning_matches_inline_revalidation(
        self,
    ) -> None:
        auxiliary_plugin = _AuxiliaryPlugin()
        auxiliary = PluginRegistry().register(
            auxiliary_plugin,
            instance_id="process-auxiliary",
        )
        providers = CapabilityProviderRegistry((auxiliary,))
        selections = (
            PluginParticipationSelection(
                instance_id=auxiliary.instance_id,
                registered_execution_identity=(auxiliary.registered_execution_identity),
                roles=("private_analysis_evidence",),
            ),
        )
        freezers = (
            (
                "inline",
                lambda: _auxiliary_execution_pin(
                    providers,
                    selections[0],
                    process_authority=True,
                ),
            ),
            (
                "process",
                lambda: _frozen_auxiliary_execution_pins(providers, selections),
            ),
        )
        for mode, freeze in freezers:
            with (
                self.subTest(mode=mode, drift="executable"),
                patch(
                    "router_dump_analyzer.plugin_registration."
                    "executable_plugin_fingerprint",
                    return_value="package-sha256:" + "0" * 64,
                ),
                self.assertRaisesRegex(
                    IngestionPipelineError,
                    "executable bytes changed after registration",
                ),
            ):
                freeze()

        auxiliary_plugin.manifest = replace(
            auxiliary_plugin.manifest,
            supported_platforms=("changed-platform",),
        )
        for mode, freeze in freezers:
            with (
                self.subTest(mode=mode, drift="manifest"),
                self.assertRaisesRegex(
                    IngestionPipelineError,
                    "manifest changed after registration",
                ),
            ):
                freeze()

    def test_inline_only_auxiliary_is_local_route_only_and_cannot_be_frozen(
        self,
    ) -> None:
        package_identity = "package-sha256:" + "9" * 64
        with (
            patch(
                "router_dump_analyzer.plugin_registration.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.plugin_registration."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
        ):
            auxiliary = PluginRegistry(allow_manifest_identity=True).register(
                _AuxiliaryPlugin(),
                instance_id="inline-only-auxiliary",
            )

        with patch(
            "router_dump_analyzer.plugin_registration.executable_plugin_fingerprint",
            return_value=package_identity,
        ):
            providers = CapabilityProviderRegistry((auxiliary,))
        self.assertEqual(providers.instance_ids(), (auxiliary.instance_id,))

        selection = PluginParticipationSelection(
            instance_id=auxiliary.instance_id,
            registered_execution_identity=auxiliary.registered_execution_identity,
            roles=("private_analysis_evidence",),
        )
        freezers = (
            (
                "inline",
                lambda: _auxiliary_execution_pin(
                    providers,
                    selection,
                    process_authority=False,
                ),
            ),
            (
                "process",
                lambda: _frozen_auxiliary_execution_pins(providers, (selection,)),
            ),
        )
        for mode, freeze in freezers:
            with (
                self.subTest(mode=mode),
                self.assertRaisesRegex(
                    IngestionPipelineError,
                    "identity or schema could not be frozen",
                ),
            ):
                freeze()

        with patch(
            "router_dump_analyzer.plugin_registration.executable_plugin_fingerprint",
            return_value=package_identity,
        ):
            trusted_pin = _auxiliary_execution_pin(
                providers,
                selection,
                process_authority=False,
                allow_inline_only=True,
            )
        self.assertEqual(trusted_pin.instance_id, auxiliary.instance_id)

        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            with self.assertRaisesRegex(ValueError, "PROCESS-capable auxiliary"):
                DurableIngestionPipeline(
                    state_dir,
                    registry=PluginRegistry((ParseOnlyPlugin(),)),
                    capability_providers=providers,
                    limits=PipelineLimits(
                        plugin_execution_mode=PluginExecutionMode.INLINE,
                    ),
                )
            self.assertFalse(state_dir.exists())
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "router_dump_analyzer.plugin_registration.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
        ):
            trusted_pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                capability_providers=providers,
                limits=PipelineLimits(
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                    publisher_execution_mode=PluginExecutionMode.INLINE,
                ),
                allow_inline_only=True,
            )
            self.assertTrue(trusted_pipeline.requires_inline_execution)
            trusted_pipeline.close()

    def test_durable_pipeline_seals_provider_snapshot_against_late_auxiliary(
        self,
    ) -> None:
        primary_registry = PluginRegistry()
        primary = primary_registry.register(
            ParseOnlyPlugin(),
            instance_id="primary",
        )
        providers = CapabilityProviderRegistry((primary,))
        with tempfile.TemporaryDirectory() as directory:
            pipeline = DurableIngestionPipeline(
                Path(directory),
                registry=primary_registry,
                capability_providers=providers,
                limits=PipelineLimits(
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
            )
            self.assertIsNot(pipeline.capability_providers, providers)

            package_identity = "package-sha256:" + "a" * 64
            auxiliary_plugin = _AuxiliaryPlugin()
            with (
                patch(
                    "router_dump_analyzer.plugin_registration."
                    "executable_plugin_fingerprint",
                    return_value=package_identity,
                ),
                patch(
                    "router_dump_analyzer.plugin_registration."
                    "executable_module_target_fingerprint",
                    side_effect=PluginExecutableIdentityError(
                        "target attestation unavailable"
                    ),
                ),
            ):
                auxiliary = PluginRegistry(allow_manifest_identity=True).register(
                    auxiliary_plugin,
                    instance_id="late-inline-only-auxiliary",
                )
            with patch(
                "router_dump_analyzer.plugin_registration.executable_plugin_fingerprint",
                return_value=package_identity,
            ):
                providers.add_registered(auxiliary)

            self.assertIn(auxiliary, providers.records())
            self.assertNotIn(auxiliary, pipeline.capability_providers.records())
            with self.assertRaisesRegex(RuntimeError, "sealed"):
                pipeline.capability_providers.add_registered(auxiliary)
            pipeline.close()

    def test_falsey_non_policy_is_not_treated_as_default(self) -> None:
        registry = PluginRegistry((ParseOnlyPlugin(),))
        limits = PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )
        for malformed in (False, 0, "", (), {}):
            with (
                self.subTest(malformed=malformed),
                tempfile.TemporaryDirectory() as directory,
                self.assertRaisesRegex(TypeError, "composition_policy"),
            ):
                DurableIngestionPipeline(  # type: ignore[arg-type]
                    Path(directory),
                    registry=registry,
                    limits=limits,
                    composition_policy=malformed,
                )

    def test_import_durably_pins_policy_before_worker_execution(self) -> None:
        registry = PluginRegistry((ParseOnlyPlugin(),))
        primary = registry.get("tests.parse-only", "1.0")
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(),
                ),
            )
        )
        limits = PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )
        scope = ImportScope("tenant", "project", "workspace")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admitted_by_default = DurableIngestionPipeline(
                root,
                registry=registry,
                limits=limits,
            )
            descriptor = admitted_by_default.submit_bytes(
                scope,
                _fixture_bytes(),
                original_name="status.jsonl",
            )
            self.assertEqual(
                descriptor.plugin_composition_policy_digest,
                admitted_by_default.composition_policy.policy_digest,
            )

            reopened = DurableIngestionPipeline(
                root,
                registry=registry,
                limits=limits,
                composition_policy=policy,
            )
            with reopened._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM ingestion_imports WHERE import_id = ?",
                    (descriptor.import_id,),
                ).fetchone()
                assert row is not None
                with self.assertRaisesRegex(
                    IngestionPipelineError,
                    "immutable plug-in composition policy",
                ):
                    reopened._require_composition_policy(row)
                with self.assertRaisesRegex(
                    Exception,
                    "plug-in composition policy is immutable",
                ):
                    connection.execute(
                        "UPDATE ingestion_imports "
                        "SET composition_policy_digest = ? WHERE import_id = ?",
                        (policy.policy_digest, descriptor.import_id),
                    )

    def test_restart_policy_drift_blocks_every_catalog_stage(self) -> None:
        registry = PluginRegistry((ParseOnlyPlugin(),))
        primary = registry.get("tests.parse-only", "1.0")
        changed_policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(),
                ),
            )
        )
        limits = PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )
        scope = ImportScope("tenant", "project", "workspace")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admitted = DurableIngestionPipeline(
                root,
                registry=registry,
                limits=limits,
            )
            descriptors = tuple(
                admitted.submit_bytes(
                    scope,
                    _fixture_bytes(),
                    original_name=f"status-{index}.jsonl",
                )
                for index in range(2)
            )
            with admitted._connect() as connection:
                connection.execute(
                    "UPDATE ingestion_imports SET state = ? WHERE import_id = ?",
                    ("admitting", descriptors[0].import_id),
                )
                connection.execute(
                    "UPDATE ingestion_imports SET state = ? WHERE import_id = ?",
                    ("publishing", descriptors[1].import_id),
                )

            restarted = DurableIngestionPipeline(
                root,
                registry=registry,
                limits=limits,
                composition_policy=changed_policy,
            )
            for expected_stage, method_name in (
                ("admitting", "_run_admission"),
                ("publishing", "_run_publication"),
            ):
                with restarted._connect() as connection:
                    row = connection.execute(
                        "SELECT * FROM ingestion_imports WHERE state = ?",
                        (expected_stage,),
                    ).fetchone()
                assert row is not None
                with patch.object(restarted, method_name) as stage:
                    with self.assertRaisesRegex(
                        IngestionPipelineError,
                        "immutable plug-in composition policy",
                    ):
                        restarted._run_claimed_stage(row)
                    stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
