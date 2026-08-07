from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
    EvidenceAuthority,
    EvidenceProducer,
    EvidenceScope,
    PrivateAnalysisCitation,
    PrivateAnalysisClaim,
    PrivateAnalysisClaimSupport,
    PrivateAnalysisClockMode,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    evidence_snapshot_digest,
)
from router_dump_analyzer.private_analysis_application_wire import (
    PRIVATE_ANALYSIS_CAPABILITIES_CONTRACT,
    PRIVATE_ANALYSIS_DISPLAY_CONTRACT,
    PrivateAnalysisApplicationWireLimitError,
    PrivateAnalysisApplicationWireRequestError,
    parse_private_analysis_request_spec,
    private_analysis_capabilities_to_wire,
    private_analysis_cited_evidence_to_wire,
    private_analysis_display_value,
    private_analysis_report_to_wire,
    private_analysis_run_to_wire,
    private_analysis_runner_to_wire,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisRegisteredRunner,
)
from router_dump_analyzer.private_analysis_run_store import PrivateAnalysisRunState
from router_dump_analyzer.private_analysis_service import (
    PrivateAnalysisCapabilities,
    PrivateAnalysisLifecycleAction,
    PrivateAnalysisRunReport,
    PrivateAnalysisRunView,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
)

try:
    from tests.test_private_ai_in_process_runner import _reference, _revision
except ModuleNotFoundError:
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _reference,
        _revision,
    )


def _scope() -> EvidenceScope:
    return EvidenceScope("tenant-a", "project-a", "workspace-a")


def _selection() -> PrivateAnalysisRunnerSelection:
    return PrivateAnalysisRunnerSelection(
        runner_id="local-private-model",
        runner_version="1",
        transport=PrivateAnalysisTransport.IN_PROCESS,
        configuration_digest="sha256:" + "1" * 64,
    )


def _run_view() -> PrivateAnalysisRunView:
    limits = PrivateAnalysisLimits()
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
    return PrivateAnalysisRunView(
        scope=_scope(),
        run_id="run-a",
        state=PrivateAnalysisRunState.COMPLETED,
        version=9_007_199_254_740_992,
        request_digest=request_digest,
        task_kind=PrivateAnalysisTaskKind.ROUTE_TRACE_ANALYSIS,
        revision_ids=("revision-a",),
        node_ids=("node-a",),
        runner=_selection(),
        workspace_policy_digest="3" * 64,
        instruction_profile_digest="sha256:" + "4" * 64,
        tool_catalog_digest="sha256:" + "5" * 64,
        evidence_service_digest="sha256:" + "7" * 64,
        clock_mode=PrivateAnalysisClockMode.REVISION_END_RELATIVE_NS,
        selected_time_ns=-9_007_199_254_740_992,
        limits=limits,
        evidence_ledger_digest=evidence_snapshot_digest(()),
        disclosed_reference_count=0,
        budget_state=PrivateAnalysisToolBudgetState(
            max_tool_calls=limits.max_tool_calls,
            tool_calls_consumed=0,
            max_evidence_items=limits.max_evidence_items,
            evidence_items_disclosed=0,
            max_evidence_bytes=limits.max_evidence_bytes,
            evidence_bytes_disclosed=0,
        ),
        outcome_digest=outcome.outcome_digest,
        created_at_ns=9_007_199_254_740_992,
        updated_at_ns=9_007_199_254_740_993,
        completed_at_ns=9_007_199_254_740_993,
    )


def _report() -> PrivateAnalysisRunReport:
    run = _run_view()
    outcome = PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=PrivateAnalysisError(
            request_digest=run.request_digest,
            stage=PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            code=PrivateAnalysisErrorCode.INVALID_RESULT,
            retryable=False,
        ),
    )
    return PrivateAnalysisRunReport(
        run=run,
        query="Why did left\u202eright change?",
        outcome=outcome,
    )


def _capabilities() -> PrivateAnalysisCapabilities:
    return PrivateAnalysisCapabilities(
        scope=_scope(),
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


def _cited_report() -> PrivateAnalysisRunReport:
    core = _reference(
        1,
        scope=_scope(),
        revision=_revision(1, node_id="node-a", revision_id="revision-a"),
    )
    plugin = replace(
        _reference(
            2,
            scope=_scope(),
            revision=_revision(2, node_id="node-b", revision_id="revision-b"),
        ),
        producer=EvidenceProducer(
            authority=EvidenceAuthority.PLUGIN_INFERRED,
            producer_id="plugin.route-evidence",
            plugin_instance_id="route-parser-a",
            plugin_capability="source_record_parser",
        ),
        reference_digest="",
    )
    references = tuple(
        sorted((core, plugin), key=lambda item: item.reference_digest)
    )
    base = _run_view()
    result = PrivateAnalysisResult(
        request_digest=base.request_digest,
        summary=PrivateAnalysisClaim(
            claim_id="summary-1",
            support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
            text="The two disclosed references corroborate the route event.",
            citations=(
                PrivateAnalysisCitation(
                    evidence_reference_digest=references[1].reference_digest
                ),
            ),
        ),
        claims=(
            PrivateAnalysisClaim(
                claim_id="claim-2",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="The producer identities are independently bound.",
                citations=(
                    PrivateAnalysisCitation(
                        evidence_reference_digest=references[0].reference_digest
                    ),
                ),
            ),
        ),
        proposals=(),
    )
    outcome = PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.RESULT,
        result=result,
    )
    run = replace(
        base,
        revision_ids=("revision-a", "revision-b"),
        node_ids=("node-a", "node-b"),
        evidence_ledger_digest=evidence_snapshot_digest(references),
        disclosed_reference_count=len(references),
        budget_state=replace(
            base.budget_state,
            evidence_items_disclosed=len(references),
        ),
        outcome_digest=outcome.outcome_digest,
    )
    return PrivateAnalysisRunReport(
        run=run,
        query="Corroborate the route event.",
        outcome=outcome,
        disclosed_references=references,
    )


class PrivateAnalysisApplicationWireTests(unittest.TestCase):
    @staticmethod
    def _request() -> dict[str, object]:
        return {
            "revision_ids": ["revision-b", "revision-a"],
            "runner": {
                "runner_id": "local-private-model",
                "runner_version": "1",
            },
            "task_kind": "route_trace_analysis",
            "query": "Explain this route.",
            "clock": {
                "mode": "absolute_unix_ns",
                "selected_time_ns": "9007199254740992",
            },
            "limits": {"max_tool_calls": "8"},
        }

    def test_request_parser_is_strict_closed_and_lossless(self) -> None:
        spec = parse_private_analysis_request_spec(_scope(), self._request())
        self.assertEqual(spec.revision_ids, ("revision-a", "revision-b"))
        self.assertEqual(spec.selected_time_ns, 9_007_199_254_740_992)
        self.assertEqual(spec.limits.max_tool_calls, 8)

        for mutate, detail in (
            (
                lambda body: body.__setitem__("workspace_policy_digest", "0" * 64),
                "private-analysis request has an invalid field set",
            ),
            (
                lambda body: body["clock"].__setitem__("unknown", True),  # type: ignore[union-attr]
                "clock has an invalid field set",
            ),
            (
                lambda body: body["clock"].__setitem__("mode", None),  # type: ignore[union-attr]
                "mode must be a non-empty string",
            ),
            (
                lambda body: body["clock"].__setitem__(  # type: ignore[union-attr]
                    "selected_time_ns", 9_007_199_254_740_992
                ),
                "selected_time_ns must be a canonical decimal string",
            ),
            (
                lambda body: body["limits"].__setitem__(  # type: ignore[union-attr]
                    "max_tool_calls", "+1"
                ),
                "max_tool_calls must be a canonical decimal integer",
            ),
        ):
            with self.subTest(detail=detail):
                body = self._request()
                mutate(body)
                with self.assertRaisesRegex(
                    PrivateAnalysisApplicationWireRequestError,
                    f"^{detail.replace('\\', '\\\\')}$",
                ) as caught:
                    parse_private_analysis_request_spec(_scope(), body)
                self.assertEqual(caught.exception.detail, detail)

    def test_runner_and_run_projection_are_payload_free_and_lossless(self) -> None:
        runner = private_analysis_runner_to_wire(
            PrivateAnalysisRegisteredRunner(
                selection=_selection(),
                instruction_profile_digest="sha256:" + "4" * 64,
                evidence_service_digest="sha256:" + "7" * 64,
            )
        )
        self.assertEqual(runner["transport"], "in_process")
        self.assertEqual(runner["evidence_service_digest"], "sha256:" + "7" * 64)
        self.assertNotIn("command", runner)

        run = private_analysis_run_to_wire(_run_view())
        self.assertEqual(run["version"], "9007199254740992")
        self.assertEqual(run["created_at_ns"], "9007199254740992")
        self.assertEqual(run["evidence_service_digest"], "sha256:" + "7" * 64)
        self.assertEqual(
            run["clock"]["selected_time_ns"],  # type: ignore[index]
            "-9007199254740992",
        )
        self.assertNotIn("query", run)
        self.assertNotIn("transcript", run)

    def test_capabilities_projection_is_closed_scoped_and_inert(self) -> None:
        projected = private_analysis_capabilities_to_wire(_capabilities())

        self.assertEqual(
            projected["contract"],
            PRIVATE_ANALYSIS_CAPABILITIES_CONTRACT,
        )
        self.assertEqual(projected["scope"]["workspace_id"], "workspace-a")  # type: ignore[index]
        self.assertEqual(
            [item["id"] for item in projected["capabilities"]],  # type: ignore[index]
            sorted(item.value for item in PrivateAnalysisTaskKind),
        )
        self.assertEqual(
            [item["id"] for item in projected["limits"]],  # type: ignore[index]
            sorted(
                (
                    "deadline_ms",
                    "max_claims",
                    "max_evidence_bytes",
                    "max_evidence_items",
                    "max_list_runs",
                    "max_output_bytes",
                    "max_proposals",
                    "max_revisions",
                    "max_tool_calls",
                )
            ),
        )
        self.assertEqual(
            [item["id"] for item in projected["transports"]],  # type: ignore[index]
            ["in_process"],
        )
        self.assertEqual(
            [item["id"] for item in projected["actions"]],  # type: ignore[index]
            [item.value for item in PrivateAnalysisLifecycleAction],
        )
        self.assertTrue(
            {"provider", "model", "plugin", "runner_id", "configuration_digest"}
            .isdisjoint(projected)
        )

    def test_report_projection_is_display_safe_and_bounded(self) -> None:
        report = private_analysis_report_to_wire(_report())
        self.assertEqual(report["display_contract"], PRIVATE_ANALYSIS_DISPLAY_CONTRACT)
        self.assertEqual(report["query"], "Why did left\\u202eright change?")
        self.assertEqual(report["evidence_references"], [])
        self.assertEqual(
            private_analysis_display_value("literal\\u202e and raw\u202e"),
            "literal\\\\u202e and raw\\u202e",
        )

        with patch(
            "router_dump_analyzer.private_analysis_application_wire."
            "MAX_PRIVATE_ANALYSIS_DISPLAY_BYTES",
            1,
        ), self.assertRaises(PrivateAnalysisApplicationWireLimitError):
            private_analysis_report_to_wire(_report())

    def test_report_projects_exact_citations_without_raw_evidence(self) -> None:
        report = private_analysis_report_to_wire(_cited_report())
        references = report["evidence_references"]
        self.assertEqual(
            [item["reference_digest"] for item in references],  # type: ignore[index]
            sorted(
                item["reference_digest"]  # type: ignore[index]
                for item in references  # type: ignore[union-attr]
            ),
        )
        self.assertEqual(len(references), 2)  # type: ignore[arg-type]
        self.assertEqual(
            {
                item["revision"]["node_id"]  # type: ignore[index]
                for item in references  # type: ignore[union-attr]
            },
            {"node-a", "node-b"},
        )
        self.assertTrue(
            any(
                item["producer"]["plugin_binding"] is not None  # type: ignore[index]
                for item in references  # type: ignore[union-attr]
            )
        )

        forbidden = {
            "content_digest",
            "locator",
            "locator_digest",
            "payload",
            "payload_json",
            "fixture_id",
            "fixture_content_sha256",
            "execution_plan_digest",
        }

        def keys(value: object) -> set[str]:
            if isinstance(value, dict):
                return set(value).union(
                    *(keys(item) for item in value.values())
                )
            if isinstance(value, list):
                return set().union(*(keys(item) for item in value))
            return set()

        self.assertTrue(forbidden.isdisjoint(keys(references)))

    def test_projection_rejects_lookalike_values(self) -> None:
        for projection in (
            private_analysis_capabilities_to_wire,
            private_analysis_cited_evidence_to_wire,
            private_analysis_runner_to_wire,
            private_analysis_run_to_wire,
            private_analysis_report_to_wire,
        ):
            with self.subTest(
                projection=projection.__name__
            ), self.assertRaises(TypeError):
                projection(object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
