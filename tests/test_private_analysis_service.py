from __future__ import annotations

import tempfile
import unittest
from dataclasses import fields, replace
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.private_analysis import (
    EvidenceReference,
    EvidenceScope,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    default_private_analysis_tool_catalog,
    evidence_snapshot_digest,
    private_analysis_result_json,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisExecutionCoordinator,
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessContext,
    PrivateAnalysisInProcessToolGateway,
)
from router_dump_analyzer.private_analysis_run_store import (
    PrivateAnalysisRunState,
    PrivateAnalysisRunStoreError,
    SqlitePrivateAnalysisRunStore,
)
from router_dump_analyzer.private_analysis_service import (
    PrivateAnalysisDeploymentCeilings,
    PrivateAnalysisRequestSpec,
    PrivateAnalysisRunReport,
    PrivateAnalysisRunView,
    PrivateAnalysisService,
    PrivateAnalysisServiceConflict,
    PrivateAnalysisServiceInvalidRequest,
    PrivateAnalysisServiceNotFound,
    PrivateAnalysisServicePolicyDenied,
    PrivateAnalysisServiceReportNotReady,
    PrivateAnalysisServiceRunnerUnavailable,
    PrivateAnalysisServiceUnavailable,
)
from router_dump_analyzer.session_store import SqliteSessionStore

try:
    from tests.test_private_ai_in_process_runner import (
        _Harness,
        _reference,
        _selection,
        _supported_result,
        _unsupported_result,
    )
except ModuleNotFoundError:
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _Harness,
        _reference,
        _selection,
        _supported_result,
        _unsupported_result,
    )

_PROFILE_DIGEST = "sha256:" + "b" * 64


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _plan(node_id: str, suffix: str) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id=f"basis-{suffix}",
        plugins=(
            PluginExecutionPin(
                instance_id=f"parser-{suffix}",
                plugin_id="test.private-analysis",
                plugin_version="1.0.0",
                core_api_version="1",
                artifact=PluginArtifactIdentity(
                    distribution_name="test-private-analysis",
                    distribution_version="1.0.0",
                    package_hash="sha256:" + suffix * 64,
                    entry_point_name=f"parser-{suffix}",
                    module_target="test_private_analysis:plugin",
                ),
                configuration_digest="sha256:" + "c" * 64,
                schema_digest="sha256:" + "d" * 64,
                registered_execution_identity="sha256:" + suffix * 64,
                capabilities=("source_record_parser",),
                roles=("primary_parser",),
            ),
        ),
    )


class PrivateAnalysisServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.sessions = SqliteSessionStore(root / "sessions.sqlite3")
        self.sessions.create_project(
            "tenant-a",
            "Project A",
            project_id="project-a",
        )
        self.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace A",
            workspace_id="workspace-a",
        )
        self.sessions.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
        )
        self.revision = self.sessions.publish_revision(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            "revision-a",
            node_id="node-a",
            identity_digest=_digest("revision-a"),
            plugin_ids=("test.private-analysis",),
            execution_plan=_plan("node-a", "a"),
        )
        self.policy = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        self.policy_record = self.sessions.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self.policy,
            actor_id="admin",
            expected_version=0,
        )
        self.runs = SqlitePrivateAnalysisRunStore(
            root / "runs.sqlite3",
            admission_validator=lambda _request: None,
        )
        self.runner = ConfiguredPrivateAnalysisInProcessRunner(
            _selection(),
            instruction_profile_digest=_PROFILE_DIGEST,
            model_callback=self._model_callback,
        )
        self.execution = PrivateAnalysisExecutionCoordinator(
            self.runs,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    runner=self.runner,
                    trusted_inline_tool_service_factory=lambda request: _Harness(
                        request,
                        policy=self.policy,
                    ).service(),
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
        )
        self.service = PrivateAnalysisService(
            self.sessions,
            self.runs,
            self.execution,
        )

    def tearDown(self) -> None:
        self.execution.close(timeout=1)
        self.runs.close()
        self.sessions.close()
        self.temporary.cleanup()

    @staticmethod
    def _model_callback(
        context: PrivateAnalysisInProcessContext,
        _gateway: PrivateAnalysisInProcessToolGateway,
    ) -> str:
        return private_analysis_result_json(
            _unsupported_result(context.request)
        )

    @staticmethod
    def _scope(
        *,
        project_id: str = "project-a",
        workspace_id: str = "workspace-a",
    ) -> EvidenceScope:
        return EvidenceScope("tenant-a", project_id, workspace_id)

    def _spec(
        self,
        *,
        scope: EvidenceScope | None = None,
        limits: PrivateAnalysisLimits | None = None,
        runner_id: str | None = None,
        revision_ids: tuple[str, ...] = ("revision-a",),
    ) -> PrivateAnalysisRequestSpec:
        selection = _selection()
        return PrivateAnalysisRequestSpec(
            scope=scope or self._scope(),
            revision_ids=revision_ids,
            runner_id=runner_id or selection.runner_id,
            runner_version=selection.runner_version,
            task_kind=PrivateAnalysisTaskKind.RESOURCE_CORRELATION,
            query="Explain the correlated route transition.",
            clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
            limits=limits or PrivateAnalysisLimits(),
        )

    def _create(self, *, run_id: str = "run-a") -> PrivateAnalysisRunView:
        return self.service.create(
            self._spec(),
            actor_id="analyst",
            idempotency_key=f"create-{run_id}",
            run_id=run_id,
        )

    def test_create_derives_every_authority_binding_before_persistence(self) -> None:
        created = self._create()

        self.assertIs(type(created), PrivateAnalysisRunView)
        self.assertIs(created.state, PrivateAnalysisRunState.QUEUED)
        stored = self.runs.get_run(self._scope(), created.run_id)
        self.assertEqual(stored.request.scope, self._scope())
        self.assertEqual(stored.request.revisions[0].revision_id, "revision-a")
        self.assertEqual(
            stored.request.revisions[0].execution_plan_digest,
            self.revision.execution_plan_digest,
        )
        self.assertEqual(stored.request.runner, self.runner.selection)
        self.assertEqual(
            stored.request.workspace_policy_digest,
            self.policy_record.policy_digest,
        )
        self.assertEqual(
            stored.request.instruction_profile_digest,
            _PROFILE_DIGEST,
        )
        self.assertEqual(
            stored.request.tool_catalog_digest,
            default_private_analysis_tool_catalog().catalog_digest,
        )

    def test_expired_recovery_is_explicit_scoped_and_never_reexecutes(self) -> None:
        queued = self._create(run_id="expired-service-run")
        self.runs.claim_run(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
            execution_id="interrupted-service-attempt",
            lease_duration_ns=1,
            now_ns=queued.created_at_ns,
        )

        recovered = self.service.recover_expired(
            self._scope(),
            actor_id="operator-recovery",
            limit=1,
        )

        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].run_id, queued.run_id)
        self.assertIs(recovered[0].state, PrivateAnalysisRunState.COMPLETED)
        with self.assertRaises(PrivateAnalysisServiceInvalidRequest):
            self.service.recover_expired(
                self._scope(),
                actor_id="operator-recovery",
                limit=0,
            )

    def test_runner_catalog_is_policy_filtered_and_empty_by_default(self) -> None:
        self.assertEqual(
            self.service.list_runners(self._scope())[0].selection,
            self.runner.selection,
        )
        empty_execution = PrivateAnalysisExecutionCoordinator(self.runs)
        empty_service = PrivateAnalysisService(
            self.sessions,
            self.runs,
            empty_execution,
        )
        self.assertEqual(empty_service.list_runners(self._scope()), ())
        empty_execution.close(timeout=1)

    def test_capabilities_are_closed_scoped_and_policy_filtered(self) -> None:
        capabilities = self.service.capabilities(self._scope())

        self.assertEqual(capabilities.scope, self._scope())
        self.assertTrue(capabilities.enabled)
        self.assertEqual(
            tuple(item.value for item in capabilities.task_kinds),
            tuple(sorted(item.value for item in PrivateAnalysisTaskKind)),
        )
        self.assertEqual(
            capabilities.request_limit_ceilings,
            PrivateAnalysisLimits(),
        )
        self.assertEqual(
            capabilities.transports,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        self.assertEqual(
            tuple(item.value for item in capabilities.states),
            ("queued", "running", "cancel_requested", "completed", "cancelled"),
        )
        self.assertEqual(
            tuple(item.value for item in capabilities.actions),
            ("create", "list", "get", "execute", "cancel", "report"),
        )

        disabled = self.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Disabled",
            workspace_id="workspace-capabilities-disabled",
        )
        unavailable = self.service.capabilities(
            self._scope(workspace_id=disabled.workspace_id)
        )
        self.assertFalse(unavailable.enabled)
        self.assertEqual(unavailable.transports, ())

    def test_capabilities_reject_cross_project_and_missing_workspace_scope(self) -> None:
        with self.assertRaises(PrivateAnalysisServiceInvalidRequest):
            self.service.capabilities(self._scope(project_id="project-other"))
        with self.assertRaises(PrivateAnalysisServiceNotFound):
            self.service.capabilities(self._scope(workspace_id="workspace-missing"))

    def test_public_runner_identity_cannot_select_ambiguous_configuration(self) -> None:
        alternate = ConfiguredPrivateAnalysisInProcessRunner(
            replace(
                _selection(),
                configuration_digest="sha256:" + "e" * 64,
            ),
            instruction_profile_digest=_PROFILE_DIGEST,
            model_callback=self._model_callback,
        )
        with self.assertRaisesRegex(ValueError, "ID and version"):
            PrivateAnalysisExecutionCoordinator(
                self.runs,
                registrations=(
                    PrivateAnalysisRunnerRegistration(
                        self.runner,
                        lambda request: _Harness(request, policy=self.policy).service(),
                        custom_evidence_service_digest="sha256:" + "f" * 64,
                    ),
                    PrivateAnalysisRunnerRegistration(
                        alternate,
                        lambda request: _Harness(request, policy=self.policy).service(),
                        custom_evidence_service_digest="sha256:" + "e" * 64,
                    ),
                ),
            )

    def test_disabled_policy_and_unapproved_transport_fail_before_admission(
        self,
    ) -> None:
        disabled_workspace = self.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Disabled",
            workspace_id="workspace-disabled",
        )
        disabled_spec = self._spec(
            scope=EvidenceScope(
                "tenant-a",
                "project-a",
                disabled_workspace.workspace_id,
            )
        )
        with self.assertRaises(PrivateAnalysisServicePolicyDenied):
            self.service.create(
                disabled_spec,
                actor_id="analyst",
                idempotency_key="disabled",
            )
        self.assertEqual(self.runs.list_runs(self._scope()), ())

        subprocess_policy = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.LOCAL_SUBPROCESS,),
        )
        self.sessions.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            subprocess_policy,
            actor_id="admin",
            expected_version=self.policy_record.version,
        )
        with self.assertRaises(PrivateAnalysisServicePolicyDenied):
            self.service.create(
                self._spec(),
                actor_id="analyst",
                idempotency_key="transport-denied",
            )
        self.assertEqual(self.runs.list_runs(self._scope()), ())

    def test_unknown_runner_and_limit_ceiling_fail_before_admission(self) -> None:
        with self.assertRaises(PrivateAnalysisServiceRunnerUnavailable):
            self.service.create(
                self._spec(runner_id="missing.runner"),
                actor_id="analyst",
                idempotency_key="missing-runner",
            )
        ceilings = PrivateAnalysisDeploymentCeilings(
            request_limits=PrivateAnalysisLimits(max_tool_calls=1),
        )
        limited = PrivateAnalysisService(
            self.sessions,
            self.runs,
            self.execution,
            ceilings=ceilings,
        )
        with self.assertRaises(PrivateAnalysisServiceInvalidRequest):
            limited.create(
                self._spec(limits=PrivateAnalysisLimits(max_tool_calls=2)),
                actor_id="analyst",
                idempotency_key="over-limit",
            )
        self.assertEqual(self.runs.list_runs(self._scope()), ())

    def test_execute_rechecks_current_policy_before_claiming_the_run(self) -> None:
        queued = self._create()
        self.sessions.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy(PrivateAnalysisDisclosureMode.DISABLED, ()),
            actor_id="admin",
            expected_version=self.policy_record.version,
        )

        with self.assertRaises(PrivateAnalysisServicePolicyDenied):
            self.service.execute(
                self._scope(),
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker",
            )
        self.assertIs(
            self.runs.get_run(self._scope(), queued.run_id).state,
            PrivateAnalysisRunState.QUEUED,
        )

    def test_planless_and_cross_workspace_revisions_fail_before_admission(self) -> None:
        self.sessions.publish_revision(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            "revision-planless",
            node_id="node-planless",
            identity_digest=_digest("revision-planless"),
            plugin_ids=(),
            execution_plan=None,
        )
        with self.assertRaises(PrivateAnalysisServiceInvalidRequest):
            self.service.create(
                self._spec(revision_ids=("revision-planless",)),
                actor_id="analyst",
                idempotency_key="planless",
            )

        self.sessions.create_workspace(
            "tenant-a",
            "project-a",
            "Other",
            workspace_id="workspace-other",
        )
        self.sessions.attach_fixture(
            "tenant-a",
            "workspace-other",
            "fixture-other",
            label="Other fixture",
            content_digest=_digest("fixture-other"),
        )
        self.sessions.publish_revision(
            "tenant-a",
            "workspace-other",
            "fixture-other",
            "revision-other",
            node_id="node-other",
            identity_digest=_digest("revision-other"),
            plugin_ids=("test.private-analysis",),
            execution_plan=_plan("node-other", "e"),
        )
        with self.assertRaises(PrivateAnalysisServiceNotFound):
            self.service.create(
                self._spec(revision_ids=("revision-other",)),
                actor_id="analyst",
                idempotency_key="cross-workspace",
            )
        self.assertEqual(self.runs.list_runs(self._scope()), ())

    def test_views_exclude_internal_state_and_report_requires_terminal_run(
        self,
    ) -> None:
        queued = self._create()
        forbidden = {
            "transcript_summary",
            "disclosed_references",
            "execution_id",
            "lease_expires_at_ns",
            "cancellation_requested_at_ns",
            "audit_root_digest",
            "audit_tip_digest",
        }
        self.assertTrue(forbidden.isdisjoint({item.name for item in fields(queued)}))
        with self.assertRaises(PrivateAnalysisServiceReportNotReady):
            self.service.get_report(self._scope(), queued.run_id)

        completed = self.service.execute(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
        )
        report = self.service.get_report(self._scope(), queued.run_id)
        self.assertEqual(report.run, completed)
        self.assertEqual(report.query, "Explain the correlated route transition.")
        self.assertIsNotNone(report.outcome)
        self.assertEqual(report.outcome.outcome_digest, completed.outcome_digest)
        self.assertTrue(
            forbidden.isdisjoint({item.name for item in fields(report.run)})
        )

    def test_report_projects_only_exact_cited_disclosed_reference_metadata(
        self,
    ) -> None:
        queued = self._create(run_id="run-cited-evidence")
        self.service.execute(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
        )
        stored = self.runs.get_run(self._scope(), queued.run_id)
        references: tuple[EvidenceReference, ...] = tuple(
            sorted(
                (
                    _reference(
                        ordinal,
                        scope=stored.request.scope,
                        revision=stored.request.revisions[0],
                    )
                    for ordinal in (1, 2)
                ),
                key=lambda item: item.reference_digest,
            )
        )
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=_supported_result(stored.request, references[0]),
        )
        forged = replace(
            stored,
            disclosed_references=references,
            evidence_ledger_digest=evidence_snapshot_digest(references),
            budget_state=replace(
                stored.budget_state,
                evidence_items_disclosed=len(references),
            ),
            outcome=outcome,
        )
        with patch.object(self.runs, "get_run", return_value=forged):
            report = self.service.get_report(self._scope(), queued.run_id)

        self.assertEqual(report.run.disclosed_reference_count, 2)
        self.assertEqual(len(report.evidence_references), 1)
        projected = report.evidence_references[0]
        cited = references[0]
        self.assertEqual(projected.reference_digest, cited.reference_digest)
        self.assertEqual(projected.revision_id, cited.revision.revision_id)
        self.assertEqual(projected.node_id, cited.revision.node_id)
        self.assertEqual(projected.producer, cited.producer)
        self.assertEqual(projected.kind, cited.kind)
        self.assertEqual(projected.time_range, cited.time_range)
        self.assertNotEqual(
            projected.reference_digest,
            references[1].reference_digest,
        )
        self.assertTrue(
            {
                "content_digest",
                "locator_digest",
                "payload",
                "payload_json",
                "fixture_id",
                "execution_plan_digest",
            }.isdisjoint({item.name for item in fields(projected)})
        )

    def test_report_rejects_missing_duplicate_extra_and_mismatched_disclosures(
        self,
    ) -> None:
        queued = self._create(run_id="run-cited-evidence-invalid")
        self.service.execute(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
        )
        stored = self.runs.get_run(self._scope(), queued.run_id)
        references = tuple(
            sorted(
                (
                    _reference(
                        ordinal,
                        scope=stored.request.scope,
                        revision=stored.request.revisions[0],
                    )
                    for ordinal in (1, 2)
                ),
                key=lambda item: item.reference_digest,
            )
        )
        reference = references[0]
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=_supported_result(stored.request, reference),
        )
        forged = replace(
            stored,
            disclosed_references=references,
            evidence_ledger_digest=evidence_snapshot_digest(references),
            budget_state=replace(
                stored.budget_state,
                evidence_items_disclosed=len(references),
            ),
            outcome=outcome,
        )
        with patch.object(self.runs, "get_run", return_value=forged):
            valid = self.service.get_report(self._scope(), queued.run_id)
        arguments = {
            "run": valid.run,
            "query": stored.request.query,
            "outcome": outcome,
        }
        empty_run = replace(
            valid.run,
            evidence_ledger_digest=evidence_snapshot_digest(()),
            disclosed_reference_count=0,
            budget_state=replace(
                valid.run.budget_state,
                evidence_items_disclosed=0,
            ),
        )
        with self.assertRaisesRegex(ValueError, "undisclosed evidence"):
            PrivateAnalysisRunReport(
                **{**arguments, "run": empty_run},
                disclosed_references=(),
            )
        with self.assertRaisesRegex(ValueError, "unique and canonical"):
            PrivateAnalysisRunReport(
                **arguments,
                disclosed_references=(reference, reference),
            )
        with self.assertRaisesRegex(ValueError, "ledger does not match"):
            PrivateAnalysisRunReport(
                **arguments,
                disclosed_references=(reference,),
            )
        extra = _reference(
            3,
            scope=stored.request.scope,
            revision=stored.request.revisions[0],
        )
        with self.assertRaisesRegex(ValueError, "ledger does not match"):
            PrivateAnalysisRunReport(
                **arguments,
                disclosed_references=tuple(
                    sorted(
                        (*references, extra),
                        key=lambda item: item.reference_digest,
                    )
                ),
            )
        mismatched = replace(
            reference,
            scope=EvidenceScope("tenant-a", "project-a", "workspace-other"),
            reference_digest="",
        )
        mismatched_run = replace(
            valid.run,
            evidence_ledger_digest=evidence_snapshot_digest((mismatched,)),
            disclosed_reference_count=1,
            budget_state=replace(
                valid.run.budget_state,
                evidence_items_disclosed=1,
            ),
        )
        with self.assertRaisesRegex(ValueError, "run scope"):
            PrivateAnalysisRunReport(
                **{**arguments, "run": mismatched_run},
                disclosed_references=(mismatched,),
            )

    def test_get_list_cancel_and_error_translation_use_only_service_values(
        self,
    ) -> None:
        queued = self._create()
        self.assertEqual(self.service.get(self._scope(), queued.run_id), queued)
        self.assertEqual(self.service.list(self._scope()), (queued,))
        cancelled = self.service.cancel(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="analyst",
        )
        self.assertIs(type(cancelled), PrivateAnalysisRunView)
        self.assertTrue(cancelled.state.is_terminal)
        with self.assertRaises(PrivateAnalysisServiceConflict):
            self.service.cancel(
                self._scope(),
                queued.run_id,
                expected_version=queued.version,
                actor_id="analyst",
            )
        with self.assertRaises(PrivateAnalysisServiceNotFound):
            self.service.get(self._scope(), "missing-run")

    def test_public_views_revalidate_nested_values_and_state_relationships(
        self,
    ) -> None:
        queued = self._create()
        with self.assertRaises(ValueError):
            replace(
                queued,
                clock_mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                selected_time_ns=None,
            )
        with self.assertRaises(ValueError):
            replace(
                queued,
                state=PrivateAnalysisRunState.COMPLETED,
                outcome_digest=None,
            )
        with self.assertRaises(ValueError):
            replace(queued, disclosed_reference_count=1)
        with self.assertRaises(TypeError):
            replace(queued, limits={})

    def test_service_errors_do_not_inherit_payload_carrying_builtin_types(
        self,
    ) -> None:
        self.assertFalse(issubclass(PrivateAnalysisServiceInvalidRequest, ValueError))
        self.assertFalse(issubclass(PrivateAnalysisServiceNotFound, KeyError))
        self.assertEqual(
            str(PrivateAnalysisServiceInvalidRequest("hostile diagnostic")),
            "Private analysis request is invalid.",
        )
        with (
            patch.object(
                self.runs,
                "get_run",
                side_effect=PrivateAnalysisRunStoreError("hostile diagnostic"),
            ),
            self.assertRaisesRegex(
                PrivateAnalysisServiceUnavailable,
                "^Private analysis service is unavailable\\.$",
            ),
        ):
            self.service.get(self._scope(), "run-a")

    def test_report_binds_exact_outcome_to_the_same_request(self) -> None:
        queued = self._create()
        completed = self.service.execute(
            self._scope(),
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
        )
        stored = self.runs.get_run(self._scope(), queued.run_id)
        other_request = replace(
            stored.request,
            query="A distinct private-analysis request.",
            request_digest="",
        )
        other_outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=_unsupported_result(other_request),
        )
        forged_view = replace(
            completed,
            outcome_digest=other_outcome.outcome_digest,
        )
        with self.assertRaisesRegex(ValueError, "run request"):
            PrivateAnalysisRunReport(
                run=forged_view,
                query=stored.request.query,
                outcome=other_outcome,
            )


if __name__ == "__main__":
    unittest.main()
