from __future__ import annotations

import unittest
from unittest.mock import patch

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
)
from router_dump_analyzer.private_analysis_application_wire import (
    PRIVATE_ANALYSIS_DISPLAY_CONTRACT,
    PrivateAnalysisApplicationWireLimitError,
    PrivateAnalysisApplicationWireRequestError,
    parse_private_analysis_request_spec,
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
    PrivateAnalysisRunReport,
    PrivateAnalysisRunView,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
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
        clock_mode=PrivateAnalysisClockMode.REVISION_END_RELATIVE_NS,
        selected_time_ns=-9_007_199_254_740_992,
        limits=limits,
        evidence_ledger_digest="sha256:" + "6" * 64,
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
            )
        )
        self.assertEqual(runner["transport"], "in_process")
        self.assertNotIn("command", runner)

        run = private_analysis_run_to_wire(_run_view())
        self.assertEqual(run["version"], "9007199254740992")
        self.assertEqual(run["created_at_ns"], "9007199254740992")
        self.assertEqual(
            run["clock"]["selected_time_ns"],  # type: ignore[index]
            "-9007199254740992",
        )
        self.assertNotIn("query", run)
        self.assertNotIn("transcript", run)

    def test_report_projection_is_display_safe_and_bounded(self) -> None:
        report = private_analysis_report_to_wire(_report())
        self.assertEqual(report["display_contract"], PRIVATE_ANALYSIS_DISPLAY_CONTRACT)
        self.assertEqual(report["query"], "Why did left\\u202eright change?")
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

    def test_projection_rejects_lookalike_values(self) -> None:
        for projection in (
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
