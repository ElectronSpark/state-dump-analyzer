from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import router_dump_analyzer.private_analysis_subprocess_runner as runner_module
from router_dump_analyzer.private_analysis import (
    PrivateAnalysisErrorCode,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisToolResult,
    private_analysis_tool_call_dict,
    private_analysis_tool_result_dict,
)
from router_dump_analyzer.private_analysis.local_subprocess_protocol import (
    PrivateAnalysisLocalSubprocessMessageKind,
)

try:
    from tests.test_private_ai_subprocess_runner import (
        _analysis_result,
        _build_case,
        _Harness,
        _hello,
        _message,
        _query_call,
        _read_action,
        _ready,
        _reference,
        _service,
        _start,
        _supported_result,
        _unsupported_result,
        _write_action,
        _write_control,
        _zero_tool_actions,
    )
except ModuleNotFoundError:  # Direct execution from the tests directory.
    from test_private_ai_subprocess_runner import (  # type: ignore[no-redef]
        _analysis_result,
        _build_case,
        _Harness,
        _hello,
        _message,
        _query_call,
        _read_action,
        _ready,
        _reference,
        _service,
        _start,
        _supported_result,
        _unsupported_result,
        _write_action,
        _write_control,
        _zero_tool_actions,
    )


def _assert_cancelled(
    testcase: unittest.TestCase,
    receipt: runner_module.PrivateAnalysisSubprocessExecutionReceipt,
) -> None:
    outcome = receipt.outcome
    testcase.assertIs(outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
    testcase.assertIsNotNone(outcome.error)
    assert outcome.error is not None
    testcase.assertIs(outcome.error.code, PrivateAnalysisErrorCode.CANCELLED)


class PrivateAnalysisSubprocessCancellationTests(unittest.TestCase):
    def test_cancellation_before_spawn_returns_attested_cancelled_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            with patch.object(
                runner_module,
                "_spawn_local_child",
                side_effect=AssertionError("cancelled run must not spawn"),
            ):
                receipt = case.runner.execute(
                    service,
                    cancellation_probe=lambda: True,
                )

            _assert_cancelled(self, receipt)
            self.assertTrue(receipt.cancellation_attested)
            lease = service.acquire_run_lease()
            lease.close()
            resealed = receipt.as_cancelled()
            _assert_cancelled(self, resealed)
            self.assertEqual(resealed.transcript, receipt.transcript)
            self.assertEqual(resealed.disclosed_references, ())
            self.assertEqual(resealed.budget_state, receipt.budget_state)

    def test_cancellation_interrupts_blocked_child_and_attests_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                terminate_grace_ms=50,
                kill_grace_ms=500,
            )
            _write_control(case.control_path, [{"kind": "block"}])
            service, _harness = _service(case)
            probe_calls = 0
            processes: list[subprocess.Popen[bytes]] = []
            real_spawn = runner_module._spawn_local_child

            def cancel_after_child_wait() -> bool:
                nonlocal probe_calls
                probe_calls += 1
                return probe_calls >= 4

            def capture_spawn(
                configuration: runner_module.PrivateAnalysisSubprocessLaunchConfiguration,
            ) -> subprocess.Popen[bytes]:
                process = real_spawn(configuration)
                processes.append(process)
                return process

            started = time.monotonic()
            with patch.object(
                runner_module,
                "_spawn_local_child",
                new=capture_spawn,
            ):
                receipt = case.runner.execute(
                    service,
                    cancellation_probe=cancel_after_child_wait,
                )
            elapsed = time.monotonic() - started

            _assert_cancelled(self, receipt)
            self.assertTrue(receipt.cancellation_attested)
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].poll(), "cancelled child was not reaped")
            self.assertLess(elapsed, 2.0)

    def test_cancellation_while_waiting_for_exit_discards_child_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                terminate_grace_ms=50,
                kill_grace_ms=500,
            )
            _write_control(
                case.control_path,
                [
                    *_zero_tool_actions(case, _unsupported_result(case.request)),
                    {"kind": "block"},
                ],
            )
            service, _harness = _service(case)
            probe_calls = 0

            def cancel_during_finish() -> bool:
                nonlocal probe_calls
                probe_calls += 1
                return probe_calls >= 8

            receipt = case.runner.execute(
                service,
                cancellation_probe=cancel_during_finish,
            )

            _assert_cancelled(self, receipt)
            self.assertTrue(receipt.cancellation_attested)
            self.assertIsNone(receipt.outcome.result)

    def test_cancellation_after_tool_operation_preserves_complete_accounting(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                terminate_grace_ms=50,
                kill_grace_ms=500,
            )
            reference = _reference()
            call = _query_call(case.request)
            _write_control(
                case.control_path,
                [
                    _read_action(_hello(case)),
                    _write_action(_ready(case)),
                    _read_action(_start(case)),
                    _write_action(
                        _message(
                            case,
                            3,
                            PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                            {"tool_call": private_analysis_tool_call_dict(call)},
                        )
                    ),
                    {"kind": "block"},
                ],
            )
            harness = _Harness(case.request, (reference,), policy=case.policy)
            service, _harness = _service(case, harness)

            receipt = case.runner.execute(
                service,
                cancellation_probe=lambda: harness.query_calls == 1,
            )

            _assert_cancelled(self, receipt)
            self.assertTrue(receipt.cancellation_attested)
            self.assertEqual(harness.query_calls, 1)
            self.assertEqual(receipt.disclosed_references, (reference,))
            self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
            self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
            self.assertEqual(receipt.transcript.tool_call_count, 1)
            self.assertEqual(
                receipt.transcript.evidence_ledger_digest,
                runner_module.evidence_snapshot_digest((reference,)),
            )

    def test_cleanup_failure_cannot_be_relabelled_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                terminate_grace_ms=50,
                kill_grace_ms=500,
            )
            _write_control(case.control_path, [{"kind": "block"}])
            service, _harness = _service(case)
            probe_calls = 0
            real_cleanup = runner_module._LocalChildSession.cleanup

            def cancel_after_child_wait() -> bool:
                nonlocal probe_calls
                probe_calls += 1
                return probe_calls >= 4

            def cleanup_but_withhold_attestation(
                session: runner_module._LocalChildSession,
            ) -> bool:
                self.assertTrue(real_cleanup(session))
                return False

            with patch.object(
                runner_module._LocalChildSession,
                "cleanup",
                new=cleanup_but_withhold_attestation,
            ):
                receipt = case.runner.execute(
                    service,
                    cancellation_probe=cancel_after_child_wait,
                )

            outcome = receipt.outcome
            self.assertIs(outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
            assert outcome.error is not None
            self.assertIs(outcome.error.code, PrivateAnalysisErrorCode.RUNNER_FAILED)
            self.assertFalse(receipt.cancellation_attested)
            with self.assertRaisesRegex(RuntimeError, "cleanup attestation"):
                receipt.as_cancelled()

    def test_process_control_from_probe_propagates_after_child_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(
                Path(temporary),
                terminate_grace_ms=50,
                kill_grace_ms=500,
            )
            _write_control(case.control_path, [{"kind": "block"}])
            service, _harness = _service(case)
            probe_calls = 0
            processes: list[subprocess.Popen[bytes]] = []
            real_spawn = runner_module._spawn_local_child

            def interrupt_after_spawn() -> bool:
                nonlocal probe_calls
                probe_calls += 1
                if probe_calls >= 4:
                    raise KeyboardInterrupt("synthetic process control")
                return False

            def capture_spawn(
                configuration: runner_module.PrivateAnalysisSubprocessLaunchConfiguration,
            ) -> subprocess.Popen[bytes]:
                process = real_spawn(configuration)
                processes.append(process)
                return process

            with (
                patch.object(
                    runner_module,
                    "_spawn_local_child",
                    new=capture_spawn,
                ),
                self.assertRaisesRegex(KeyboardInterrupt, "synthetic process control"),
            ):
                case.runner.execute(
                    service,
                    cancellation_probe=interrupt_after_spawn,
                )

            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(
                processes[0].poll(), "interrupted child was not reaped"
            )

    def test_as_cancelled_preserves_disclosure_ledger_and_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            reference = _reference()
            call = _query_call(case.request)
            expected_harness = _Harness(case.request, (reference,), policy=case.policy)
            expected_service, _ = _service(case, expected_harness)
            expected_response = expected_service.execute(call)
            self.assertIs(type(expected_response), PrivateAnalysisToolResult)
            actions = [
                _read_action(_hello(case)),
                _write_action(_ready(case)),
                _read_action(_start(case)),
                _write_action(
                    _message(
                        case,
                        3,
                        PrivateAnalysisLocalSubprocessMessageKind.TOOL_CALL,
                        {"tool_call": private_analysis_tool_call_dict(call)},
                    )
                ),
                _read_action(
                    _message(
                        case,
                        4,
                        PrivateAnalysisLocalSubprocessMessageKind.TOOL_RESULT,
                        {
                            "tool_result": private_analysis_tool_result_dict(
                                expected_response
                            )
                        },
                    )
                ),
                _write_action(
                    _analysis_result(
                        case,
                        _supported_result(case.request, reference),
                        sequence=5,
                    )
                ),
            ]
            _write_control(case.control_path, actions)
            service, _harness = _service(
                case,
                _Harness(case.request, (reference,), policy=case.policy),
            )

            receipt = case.runner.execute(service)
            self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
            self.assertTrue(receipt.cancellation_attested)
            cancelled = receipt.as_cancelled()

            _assert_cancelled(self, cancelled)
            self.assertEqual(cancelled.disclosed_references, (reference,))
            self.assertEqual(cancelled.budget_state, receipt.budget_state)
            self.assertEqual(
                cancelled.transcript.evidence_ledger_digest,
                receipt.transcript.evidence_ledger_digest,
            )
            self.assertEqual(
                cancelled.transcript.message_chain_digest,
                receipt.transcript.message_chain_digest,
            )
            self.assertNotEqual(
                cancelled.transcript.outcome_digest,
                receipt.transcript.outcome_digest,
            )
            self.assertNotEqual(
                cancelled.transcript.transcript_digest,
                receipt.transcript.transcript_digest,
            )

    def test_probe_contract_is_typed_and_input_is_callable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = _build_case(Path(temporary))
            service, _harness = _service(case)
            with self.assertRaisesRegex(TypeError, "must be callable"):
                case.runner.execute(
                    service,
                    cancellation_probe=False,  # type: ignore[arg-type]
                )
            receipt = case.runner.execute(
                service,
                cancellation_probe=lambda: 1,  # type: ignore[return-value]
            )
            outcome = receipt.outcome
            self.assertIs(outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
            assert outcome.error is not None
            self.assertIs(outcome.error.code, PrivateAnalysisErrorCode.RUNNER_FAILED)
            self.assertTrue(receipt.cancellation_attested)


if __name__ == "__main__":
    unittest.main()
