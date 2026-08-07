from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.annotation_store import ReviewScope
from router_dump_analyzer.private_analysis import (
    EvidenceScope,
    PrivateAnalysisClockMode,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    evidence_snapshot_digest,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisRegisteredRunner,
)
from router_dump_analyzer.private_analysis_promotion import (
    AnnotationPromotionTarget,
    ProposalReviewDecision,
    ProposalReviewDisposition,
    ProposalReviewState,
)
from router_dump_analyzer.private_analysis_run_store import PrivateAnalysisRunState
from router_dump_analyzer.private_analysis_service import (
    PrivateAnalysisCapabilities,
    PrivateAnalysisLifecycleAction,
    PrivateAnalysisRunReport,
    PrivateAnalysisRunView,
    PrivateAnalysisServiceConflict,
    PrivateAnalysisServiceReportNotReady,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
)
from router_dump_analyzer.web import control_plane_api
from router_dump_analyzer.web.control_plane_api import (
    CONTROL_PLANE_READ_ROLE,
    CONTROL_PLANE_WRITE_ROLE,
    ControlPlaneIdentity,
    control_plane_router,
)


class _Sessions:
    @staticmethod
    def get_workspace(tenant_id: str, workspace_id: str) -> SimpleNamespace:
        if tenant_id != "tenant-a" or workspace_id != "workspace-a":
            raise KeyError(workspace_id)
        return SimpleNamespace(project_id="project-a")


def _identity(request: object) -> ControlPlaneIdentity:
    headers = request.headers  # type: ignore[attr-defined]
    tenant_id = headers.get("X-Tenant-ID", "tenant-a")
    principal_id = headers.get("X-Principal-ID", "reader")
    roles = frozenset(
        value.strip()
        for value in headers.get("X-Test-Roles", CONTROL_PLANE_READ_ROLE).split(",")
        if value.strip()
    )
    return ControlPlaneIdentity(
        tenant_id=tenant_id,
        principal_id=principal_id,
        roles=roles,
        project_ids=frozenset({"project-a"}),
        workspace_ids=frozenset({"workspace-a"}),
    )


def _selection() -> PrivateAnalysisRunnerSelection:
    return PrivateAnalysisRunnerSelection(
        runner_id="local-private-model",
        runner_version="1",
        transport=PrivateAnalysisTransport.IN_PROCESS,
        configuration_digest="sha256:" + "1" * 64,
    )


def _budget(limits: PrivateAnalysisLimits) -> PrivateAnalysisToolBudgetState:
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=limits.max_tool_calls,
        tool_calls_consumed=0,
        max_evidence_items=limits.max_evidence_items,
        evidence_items_disclosed=0,
        max_evidence_bytes=limits.max_evidence_bytes,
        evidence_bytes_disclosed=0,
    )


def _view(
    *,
    state: PrivateAnalysisRunState = PrivateAnalysisRunState.QUEUED,
    version: int = 1,
    outcome_digest: str | None = None,
) -> PrivateAnalysisRunView:
    limits = PrivateAnalysisLimits()
    terminal = state.is_terminal
    return PrivateAnalysisRunView(
        scope=EvidenceScope("tenant-a", "project-a", "workspace-a"),
        run_id="run-a",
        state=state,
        version=version,
        request_digest="sha256:" + "2" * 64,
        task_kind=PrivateAnalysisTaskKind.ROUTE_TRACE_ANALYSIS,
        revision_ids=("revision-a",),
        node_ids=("node-a",),
        runner=_selection(),
        workspace_policy_digest="3" * 64,
        instruction_profile_digest="sha256:" + "4" * 64,
        tool_catalog_digest="sha256:" + "5" * 64,
        evidence_service_digest="sha256:" + "7" * 64,
        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
        selected_time_ns=None,
        limits=limits,
        evidence_ledger_digest=evidence_snapshot_digest(()),
        disclosed_reference_count=0,
        budget_state=_budget(limits),
        outcome_digest=outcome_digest,
        created_at_ns=100,
        updated_at_ns=200 if terminal else 100,
        completed_at_ns=200 if terminal else None,
    )


def _report() -> PrivateAnalysisRunReport:
    request_digest = "sha256:" + "2" * 64
    outcome = PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=PrivateAnalysisError(
            request_digest=request_digest,
            stage=PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            code=PrivateAnalysisErrorCode.INVALID_RESULT,
            retryable=False,
        ),
    )
    return PrivateAnalysisRunReport(
        run=_view(
            state=PrivateAnalysisRunState.COMPLETED,
            version=2,
            outcome_digest=outcome.outcome_digest,
        ),
        query="Why did left\u202eright change?",
        outcome=outcome,
    )


def _capabilities() -> PrivateAnalysisCapabilities:
    return PrivateAnalysisCapabilities(
        scope=EvidenceScope("tenant-a", "project-a", "workspace-a"),
        enabled=True,
        task_kinds=tuple(
            sorted(PrivateAnalysisTaskKind, key=lambda item: item.value)
        ),
        request_limit_ceilings=PrivateAnalysisLimits(),
        max_revisions=128,
        max_list_runs=1_000,
        transports=(PrivateAnalysisTransport.IN_PROCESS,),
        states=tuple(PrivateAnalysisRunState),
        actions=tuple(PrivateAnalysisLifecycleAction),
    )


def _review_decision() -> ProposalReviewDecision:
    return ProposalReviewDecision(
        scope=ReviewScope("tenant-a", "project-a", "workspace-a"),
        decision_id="decision-a",
        run_id="run-a",
        proposal_id="proposal-a",
        proposal_digest="sha256:" + "8" * 64,
        result_digest="sha256:" + "9" * 64,
        run_version=2,
        disposition=ProposalReviewDisposition.REJECT,
        state=ProposalReviewState.COMPLETED,
        actor="analyst",
        rationale="Not supported by the cited evidence.",
        request_digest="sha256:" + "a" * 64,
        target_kind=None,
        target_id=None,
        created_at_ns=300,
        updated_at_ns=300,
        version=1,
    )


class PrivateAnalysisApiTests(unittest.TestCase):
    def setUp(self) -> None:
        application = FastAPI()
        application.include_router(control_plane_router)
        application.state.control_plane = SimpleNamespace(sessions=_Sessions())
        application.state.control_plane_identity_resolver = _identity
        self.service = Mock()
        self.service.list_runners.return_value = (
            PrivateAnalysisRegisteredRunner(
                selection=_selection(),
                instruction_profile_digest="sha256:" + "4" * 64,
                evidence_service_digest="sha256:" + "7" * 64,
            ),
        )
        self.service.capabilities.return_value = _capabilities()
        self.service.create.return_value = _view()
        self.service.list.return_value = (_view(),)
        self.service.get.return_value = _view()
        self.service.execute.return_value = _view()
        self.service.cancel.return_value = _view()
        self.service.get_report.return_value = _report()
        self.service_patch = patch.object(
            control_plane_api,
            "_private_analysis_service",
            return_value=self.service,
        )
        self.service_patch.start()
        self.review_service = Mock()
        self.review_service.decide.return_value = _review_decision()
        self.review_service.list.return_value = (_review_decision(),)
        self.review_service.get.return_value = _review_decision()
        self.review_service.recover.return_value = _review_decision()
        self.review_service_patch = patch.object(
            control_plane_api,
            "_proposal_review_service",
            return_value=self.review_service,
        )
        self.review_service_patch.start()
        self.client_context = TestClient(application)
        self.client = self.client_context.__enter__()
        self.base = "/v1/control-plane/projects/project-a/workspaces/workspace-a"

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.review_service_patch.stop()
        self.service_patch.stop()

    @staticmethod
    def _read_headers() -> dict[str, str]:
        return {
            "X-Tenant-ID": "tenant-a",
            "X-Test-Roles": CONTROL_PLANE_READ_ROLE,
        }

    @staticmethod
    def _write_headers(*, idempotency: bool = False) -> dict[str, str]:
        headers = {
            "X-Tenant-ID": "tenant-a",
            "X-Principal-ID": "analyst",
            "X-Test-Roles": CONTROL_PLANE_WRITE_ROLE,
        }
        if idempotency:
            headers["Idempotency-Key"] = "request-a"
        return headers

    @staticmethod
    def _request_body() -> dict[str, object]:
        return {
            "revision_ids": ["revision-a"],
            "runner": {
                "runner_id": "local-private-model",
                "runner_version": "1",
            },
            "task_kind": "route_trace_analysis",
            "query": "Explain this route.",
            "clock": {"mode": "latest_per_revision"},
            "limits": {"max_tool_calls": "8"},
        }

    def test_runner_catalog_is_scoped_bounded_and_inert(self) -> None:
        response = self.client.get(
            f"{self.base}/private-analysis-runners",
            headers=self._read_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(
            response.json()["items"],
            [
                {
                    "runner_id": "local-private-model",
                    "runner_version": "1",
                    "transport": "in_process",
                    "configuration_digest": "sha256:" + "1" * 64,
                    "instruction_profile_digest": "sha256:" + "4" * 64,
                    "evidence_service_digest": "sha256:" + "7" * 64,
                }
            ],
        )

    def test_capabilities_are_read_scoped_no_store_and_provider_free(self) -> None:
        response = self.client.get(
            f"{self.base}/private-analysis-capabilities",
            headers=self._read_headers(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("etag", response.headers)
        payload = response.json()
        self.assertEqual(
            payload["contract"],
            "router_dump_analyzer.private_analysis.capabilities.v1",
        )
        self.assertEqual(payload["scope"]["workspace_id"], "workspace-a")
        self.assertEqual(
            self.service.capabilities.call_args.args,
            (EvidenceScope("tenant-a", "project-a", "workspace-a"),),
        )
        serialized = response.text.lower()
        for forbidden in (
            '"provider"',
            '"model"',
            '"plugin"',
            '"runner_id"',
            '"configuration_digest"',
        ):
            self.assertNotIn(forbidden, serialized)

        denied = self.client.get(
            f"{self.base}/private-analysis-capabilities",
            headers={
                "X-Tenant-ID": "tenant-a",
                "X-Test-Roles": CONTROL_PLANE_WRITE_ROLE,
            },
        )
        self.assertEqual(denied.status_code, 403)

        concealed = self.client.get(
            "/v1/control-plane/projects/project-b/workspaces/workspace-a/"
            "private-analysis-capabilities",
            headers=self._read_headers(),
        )
        self.assertEqual(concealed.status_code, 404)

    def test_create_derives_scope_and_requires_idempotency_and_write_role(self) -> None:
        missing = self.client.post(
            f"{self.base}/private-analysis-runs",
            headers=self._write_headers(),
            json=self._request_body(),
        )
        self.assertEqual(missing.status_code, 428)

        denied = self.client.post(
            f"{self.base}/private-analysis-runs",
            headers={
                "X-Tenant-ID": "tenant-a",
                "X-Principal-ID": "analyst",
                "X-Test-Roles": CONTROL_PLANE_READ_ROLE,
                "Idempotency-Key": "request-a",
            },
            json=self._request_body(),
        )
        self.assertEqual(denied.status_code, 403)

        response = self.client.post(
            f"{self.base}/private-analysis-runs",
            headers=self._write_headers(idempotency=True),
            json=self._request_body(),
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["etag"], '"1"')
        spec = self.service.create.call_args.args[0]
        self.assertEqual(
            spec.scope,
            EvidenceScope("tenant-a", "project-a", "workspace-a"),
        )
        self.assertEqual(spec.limits.max_tool_calls, 8)
        self.assertNotIn("workspace_policy_digest", self._request_body())

    def test_create_rejects_authority_fields_and_unsafe_time_numbers(self) -> None:
        authority = self._request_body()
        authority["workspace_policy_digest"] = "0" * 64
        response = self.client.post(
            f"{self.base}/private-analysis-runs",
            headers=self._write_headers(idempotency=True),
            json=authority,
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.json(),
            {"detail": "private-analysis request has an invalid field set"},
        )

        unsafe_time = self._request_body()
        unsafe_time["clock"] = {
            "mode": "absolute_unix_ns",
            "selected_time_ns": 9_007_199_254_740_992,
        }
        response = self.client.post(
            f"{self.base}/private-analysis-runs",
            headers=self._write_headers(idempotency=True),
            json=unsafe_time,
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.json(),
            {"detail": "selected_time_ns must be a canonical decimal string"},
        )
        self.assertEqual(self.service.create.call_count, 0)

    def test_lifecycle_routes_use_etags_keyset_cursor_and_no_store(self) -> None:
        listed = self.client.get(
            f"{self.base}/private-analysis-runs",
            headers=self._read_headers(),
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["items"][0]["created_at_ns"], "100")
        self.assertEqual(listed.headers["cache-control"], "no-store")

        incomplete_cursor = self.client.get(
            f"{self.base}/private-analysis-runs?after_created_at_ns=100",
            headers=self._read_headers(),
        )
        self.assertEqual(incomplete_cursor.status_code, 422)

        detail = self.client.get(
            f"{self.base}/private-analysis-runs/run-a",
            headers=self._read_headers(),
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.headers["etag"], '"1"')
        self.assertNotIn("transcript", detail.text)
        self.assertNotIn("execution_id", detail.text)

        missing_match = self.client.post(
            f"{self.base}/private-analysis-runs/run-a/execute",
            headers=self._write_headers(),
        )
        self.assertEqual(missing_match.status_code, 428)
        executed = self.client.post(
            f"{self.base}/private-analysis-runs/run-a/execute",
            headers={**self._write_headers(), "If-Match": '"1"'},
        )
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(
            self.service.execute.call_args.kwargs["expected_version"],
            1,
        )
        cancelled = self.client.post(
            f"{self.base}/private-analysis-runs/run-a/cancel",
            headers={**self._write_headers(), "If-Match": '"1"'},
        )
        self.assertEqual(cancelled.status_code, 200)

    def test_report_is_terminal_only_and_display_safe(self) -> None:
        waiting = PrivateAnalysisServiceReportNotReady()
        self.service.get_report.side_effect = waiting
        response = self.client.get(
            f"{self.base}/private-analysis-runs/run-a/report",
            headers=self._read_headers(),
        )
        self.assertEqual(response.status_code, 409)

        self.service.get_report.side_effect = None
        self.service.get_report.return_value = _report()
        response = self.client.get(
            f"{self.base}/private-analysis-runs/run-a/report",
            headers=self._read_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["display_contract"],
            "router_dump_analyzer.private_analysis.display.v1",
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(
            response.json()["query"],
            "Why did left\\u202eright change?",
        )

        self.assertEqual(response.json()["evidence_references"], [])

    def test_proposal_decision_requires_pins_idempotency_and_write_role(self) -> None:
        path = (
            f"{self.base}/private-analysis-runs/run-a/proposals/"
            "proposal-a/decision"
        )
        body = {
            "proposal_digest": "sha256:" + "8" * 64,
            "result_digest": "sha256:" + "9" * 64,
            "disposition": "reject",
            "rationale": "Not supported by the cited evidence.",
        }
        missing_match = self.client.post(
            path,
            headers={**self._write_headers(idempotency=True)},
            json=body,
        )
        self.assertEqual(missing_match.status_code, 428)
        missing_key = self.client.post(
            path,
            headers={**self._write_headers(), "If-Match": '"2"'},
            json=body,
        )
        self.assertEqual(missing_key.status_code, 428)
        denied = self.client.post(
            path,
            headers={
                "X-Tenant-ID": "tenant-a",
                "X-Principal-ID": "analyst",
                "X-Test-Roles": CONTROL_PLANE_READ_ROLE,
                "If-Match": '"2"',
                "Idempotency-Key": "decision-request-a",
            },
            json=body,
        )
        self.assertEqual(denied.status_code, 403)

        response = self.client.post(
            path,
            headers={
                **self._write_headers(),
                "If-Match": '"2"',
                "Idempotency-Key": "decision-request-a",
            },
            json=body,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers["etag"], '"1"')
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json()["decision_id"], "decision-a")
        call = self.review_service.decide.call_args
        self.assertEqual(
            call.args,
            (EvidenceScope("tenant-a", "project-a", "workspace-a"),),
        )
        self.assertEqual(call.kwargs["run_id"], "run-a")
        self.assertEqual(call.kwargs["proposal_id"], "proposal-a")
        self.assertEqual(call.kwargs["expected_run_version"], 2)
        self.assertEqual(call.kwargs["actor"], "analyst")
        self.assertEqual(call.kwargs["idempotency_key"], "decision-request-a")
        self.assertIsNone(call.kwargs["target"])

    def test_proposal_promotion_target_is_human_authored_not_model_applied(self) -> None:
        response = self.client.post(
            f"{self.base}/private-analysis-runs/run-a/proposals/proposal-a/decision",
            headers={
                **self._write_headers(),
                "If-Match": '"2"',
                "Idempotency-Key": "decision-request-b",
            },
            json={
                "proposal_digest": "sha256:" + "8" * 64,
                "result_digest": "sha256:" + "9" * 64,
                "disposition": "promote",
                "rationale": "Reviewed against event 17.",
                "target": {
                    "kind": "annotation",
                    "annotation_kind": "note",
                    "subjects": [
                        {
                            "revision_id": "revision-a",
                            "kind": "event",
                            "subject_id": "event-17",
                            "node_id": "node-a",
                        }
                    ],
                    "title": "Verified failover",
                    "body": "Human-authored conclusion.",
                    "tags": ["reviewed"],
                },
            },
        )
        self.assertEqual(response.status_code, 201)
        target = self.review_service.decide.call_args.kwargs["target"]
        self.assertIs(type(target), AnnotationPromotionTarget)
        self.assertEqual(target.title, "Verified failover")
        self.assertEqual(target.body, "Human-authored conclusion.")
        self.assertEqual(target.subjects[0].subject_id, "event-17")
        self.assertNotIn("payload", target.body)

    def test_proposal_decisions_are_scoped_to_the_named_run(self) -> None:
        listed = self.client.get(
            f"{self.base}/private-analysis-runs/run-a/proposal-decisions",
            headers=self._read_headers(),
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.headers["cache-control"], "no-store")
        self.assertEqual(listed.json()["items"][0]["proposal_id"], "proposal-a")
        self.assertEqual(
            self.review_service.list.call_args.kwargs,
            {"run_id": "run-a", "limit": 1000, "offset": 0},
        )

        detail = self.client.get(
            f"{self.base}/private-analysis-runs/run-a/"
            "proposal-decisions/decision-a",
            headers=self._read_headers(),
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.headers["etag"], '"1"')
        concealed = self.client.get(
            f"{self.base}/private-analysis-runs/run-b/"
            "proposal-decisions/decision-a",
            headers=self._read_headers(),
        )
        self.assertEqual(concealed.status_code, 404)

        recover_path = (
            f"{self.base}/private-analysis-runs/run-a/"
            "proposal-decisions/decision-a/recover"
        )
        missing_match = self.client.post(
            recover_path,
            headers=self._write_headers(),
        )
        self.assertEqual(missing_match.status_code, 428)
        recovered = self.client.post(
            recover_path,
            headers={**self._write_headers(), "If-Match": '"1"'},
        )
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.headers["etag"], '"1"')
        self.assertEqual(
            self.review_service.recover.call_args.kwargs,
            {"expected_decision_version": 1},
        )

    def test_service_conflicts_are_static_and_scope_denials_are_concealed(self) -> None:
        self.service.get.side_effect = PrivateAnalysisServiceConflict()
        response = self.client.get(
            f"{self.base}/private-analysis-runs/run-a",
            headers=self._read_headers(),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {"detail": "private-analysis run conflicts with durable state"},
        )

        concealed = self.client.get(
            "/v1/control-plane/projects/project-b/workspaces/workspace-a/"
            "private-analysis-runs/run-a",
            headers=self._read_headers(),
        )
        self.assertEqual(concealed.status_code, 404)


if __name__ == "__main__":
    unittest.main()
