from __future__ import annotations

import unittest

try:
    from tests.test_private_ai_in_process_runner import (
        _assert_receipt_error,
        _Harness,
        _query_call,
        _read_call,
        _reference,
        _request,
        _runner,
        _supported_result,
        _unsupported_result,
    )
except ModuleNotFoundError:  # Direct execution from the tests directory.
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _assert_receipt_error,
        _Harness,
        _query_call,
        _read_call,
        _reference,
        _request,
        _runner,
        _supported_result,
        _unsupported_result,
    )

from router_dump_analyzer.private_analysis import (
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcomeKind,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)


class PrivateAnalysisInProcessCancellationTests(unittest.TestCase):
    def test_cancellation_before_lease_discloses_nothing_and_leaves_service_unused(
        self,
    ) -> None:
        request = _request()
        harness = _Harness(request, (_reference(),))
        callback_called = False

        def callback(_context, _gateway):  # type: ignore[no-untyped-def]
            nonlocal callback_called
            callback_called = True
            return "unreachable"

        service = harness.service()
        receipt = _runner(callback).execute(
            service,
            cancellation_probe=lambda: True,
        )

        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.CANCELLED,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertFalse(callback_called)
        self.assertEqual(harness.authorization_calls, 0)
        self.assertEqual(receipt.disclosed_references, ())
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
        self.assertEqual(receipt.transcript.exchange_count, 0)

        lease = service.acquire_run_lease()
        lease.close()

    def test_probe_contract_failure_is_static_and_process_control_propagates(
        self,
    ) -> None:
        request = _request()

        def raise_failure() -> bool:
            raise RuntimeError("C:\\Users\\alice\\secret\\cancel.py")

        for probe in (raise_failure, lambda: 1):
            with self.subTest(probe=probe):
                receipt = _runner(lambda _context, _gateway: "unreachable").execute(
                    _Harness(request).service(),
                    cancellation_probe=probe,  # type: ignore[arg-type]
                )
                _assert_receipt_error(
                    self,
                    receipt,
                    PrivateAnalysisErrorCode.RUNNER_FAILED,
                    PrivateAnalysisErrorStage.RUNNER,
                )
                self.assertNotIn("alice", repr(receipt))
                self.assertNotIn("secret", repr(receipt).casefold())

        def stop_process() -> bool:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            _runner(lambda _context, _gateway: "unreachable").execute(
                _Harness(request).service(),
                cancellation_probe=stop_process,
            )

    def test_post_callback_probe_wins_over_untrusted_result_validation(self) -> None:
        request = _request()
        cancel = False

        def callback(_context, _gateway):  # type: ignore[no-untyped-def]
            nonlocal cancel
            cancel = True
            return "not JSON and must not be validated as the terminal outcome"

        receipt = _runner(callback).execute(
            _Harness(request).service(),
            cancellation_probe=lambda: cancel,
        )

        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.CANCELLED,
            PrivateAnalysisErrorStage.RUNNER,
        )

    def test_tool_boundary_cancellation_preserves_disclosure_accounting(self) -> None:
        request = _request()
        reference = _reference()
        harness = _Harness(request, (reference,))
        cancel = False
        observed = []

        def query_references(_request, _arguments):  # type: ignore[no-untyped-def]
            nonlocal cancel
            cancel = True
            return (reference,)

        def callback(context, gateway):  # type: ignore[no-untyped-def]
            gateway.execute(
                private_analysis_tool_call_json(_query_call(context.request))
            )
            gateway.execute(
                private_analysis_tool_call_json(_read_call(context.request, reference))
            )
            return private_analysis_result_json(
                _supported_result(context.request, reference)
            )

        receipt = _runner(callback).execute(
            harness.service(query_references=query_references),
            accounting_observer=lambda references, budget: observed.append(
                (references, budget)
            ),
            cancellation_probe=lambda: cancel,
        )

        _assert_receipt_error(self, receipt, PrivateAnalysisErrorCode.CANCELLED)
        self.assertEqual(receipt.disclosed_references, (reference,))
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
        self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
        self.assertTrue(observed)
        self.assertEqual(observed[-1][0], (reference,))
        self.assertEqual(observed[-1][1], receipt.budget_state)

    def test_final_sealing_probe_reseals_cancelled_outcome(self) -> None:
        request = _request()
        probe_calls = 0

        def probe() -> bool:
            nonlocal probe_calls
            probe_calls += 1
            return probe_calls == 5

        receipt = _runner(
            lambda context, _gateway: _unsupported_result(context.request)
        ).execute(
            _Harness(request).service(),
            cancellation_probe=probe,
        )

        self.assertGreaterEqual(probe_calls, 5)
        _assert_receipt_error(self, receipt, PrivateAnalysisErrorCode.CANCELLED)
        self.assertEqual(
            receipt.transcript.outcome_digest,
            receipt.outcome.outcome_digest,
        )

    def test_as_cancelled_preserves_ledger_budget_and_exchange_metadata(self) -> None:
        request = _request()
        reference = _reference()
        harness = _Harness(request, (reference,))

        def callback(context, gateway):  # type: ignore[no-untyped-def]
            gateway.execute(
                private_analysis_tool_call_json(_query_call(context.request))
            )
            gateway.execute(
                private_analysis_tool_call_json(_read_call(context.request, reference))
            )
            return private_analysis_result_json(
                _supported_result(context.request, reference)
            )

        completed = _runner(callback).execute(harness.service())
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)

        cancelled = completed.as_cancelled()

        _assert_receipt_error(self, cancelled, PrivateAnalysisErrorCode.CANCELLED)
        self.assertEqual(cancelled.disclosed_references, completed.disclosed_references)
        self.assertEqual(cancelled.budget_state, completed.budget_state)
        self.assertEqual(
            cancelled.transcript.exchange_count,
            completed.transcript.exchange_count,
        )
        self.assertEqual(
            cancelled.transcript.exchange_metadata_bytes,
            completed.transcript.exchange_metadata_bytes,
        )
        self.assertEqual(
            cancelled.transcript.exchange_chain_digest,
            completed.transcript.exchange_chain_digest,
        )
        self.assertNotEqual(
            cancelled.transcript.transcript_digest,
            completed.transcript.transcript_digest,
        )
        self.assertEqual(
            cancelled.transcript.outcome_digest,
            cancelled.outcome.outcome_digest,
        )
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)


if __name__ == "__main__":
    unittest.main()
