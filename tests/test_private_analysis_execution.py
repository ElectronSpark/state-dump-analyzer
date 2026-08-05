from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
    PrivateAnalysisErrorCode,
    PrivateAnalysisOutcomeKind,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisExecutionClosed,
    PrivateAnalysisExecutionCloseTimeout,
    PrivateAnalysisExecutionCoordinator,
    PrivateAnalysisExecutionLimits,
    PrivateAnalysisExecutionUnavailable,
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessContext,
    PrivateAnalysisInProcessToolGateway,
)
from router_dump_analyzer.private_analysis_run_store import (
    PrivateAnalysisRunConflict,
    PrivateAnalysisRunStaleVersion,
    PrivateAnalysisRunState,
    SqlitePrivateAnalysisRunStore,
)

try:
    from tests.test_private_ai_in_process_runner import (
        _INSTRUCTION_PROFILE_DIGEST,
        _Harness,
        _query_call,
        _reference,
        _request,
        _selection,
        _supported_result,
        _unsupported_result,
    )
    from tests.test_private_ai_in_process_runner import (
        _limits as _request_limits,
    )
except ModuleNotFoundError:
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _INSTRUCTION_PROFILE_DIGEST,
        _Harness,
        _query_call,
        _reference,
        _request,
        _selection,
        _supported_result,
        _unsupported_result,
    )
    from test_private_ai_in_process_runner import (
        _limits as _request_limits,
    )


def _limits() -> PrivateAnalysisExecutionLimits:
    return PrivateAnalysisExecutionLimits(
        max_concurrent_runs=4,
        lease_duration_ns=2_000_000_000,
        heartbeat_interval_ns=100_000_000,
        cancellation_poll_interval_ns=10_000_000,
        monitor_join_timeout_ns=1_000_000_000,
    )


class PrivateAnalysisExecutionCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SqlitePrivateAnalysisRunStore(
            Path(self.temporary.name) / "runs.sqlite3",
            admission_validator=lambda _request: None,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _created(self, request: Any, run_id: str = "run-1") -> Any:
        return self.store.create_run(
            request,
            actor_id="admission",
            idempotency_key=f"key-{run_id}",
            run_id=run_id,
        )

    def _coordinator(
        self,
        request: Any,
        callback: Any,
        *,
        factory: Any | None = None,
        limits: PrivateAnalysisExecutionLimits | None = None,
    ) -> PrivateAnalysisExecutionCoordinator:
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=callback,
        )
        harness = _Harness(request)
        return PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    runner=runner,
                    tool_service_factory=factory
                    or (lambda _request: harness.service()),
                ),
            ),
            limits=limits or _limits(),
        )

    def test_exact_runner_executes_and_persists_transport_neutral_receipt(self) -> None:
        request = _request()
        queued = self._created(request)

        def callback(
            _context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(request, callback)
        completed = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(completed.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(completed.transcript_summary)
        self.assertIsNotNone(completed.outcome)
        assert completed.outcome is not None
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(self.store.get_run(request.scope, queued.run_id), completed)
        self.assertEqual(
            [
                entry.reason.value
                for entry in self.store.list_audit(request.scope, queued.run_id)
            ],
            ["admitted", "claimed", "completed"],
        )
        coordinator.close(timeout=1)

    def test_unconfigured_selection_and_profile_leave_run_queued(self) -> None:
        request = _request()
        queued = self._created(request)
        empty = PrivateAnalysisExecutionCoordinator(self.store, limits=_limits())
        with self.assertRaises(PrivateAnalysisExecutionUnavailable):
            empty.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        self.assertEqual(self.store.get_run(request.scope, queued.run_id), queued)

        wrong_profile_runner = ConfiguredPrivateAnalysisInProcessRunner(
            _selection(),
            instruction_profile_digest="sha256:" + "d" * 64,
            model_callback=lambda _context, _gateway: "{}",
        )
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    wrong_profile_runner,
                    lambda _request: _Harness(request).service(),
                ),
            ),
            limits=_limits(),
        )
        with self.assertRaises(PrivateAnalysisExecutionUnavailable):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        self.assertEqual(self.store.get_run(request.scope, queued.run_id), queued)

    def test_duplicate_exact_registration_is_rejected(self) -> None:
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        first = PrivateAnalysisRunnerRegistration(
            runner,
            lambda _request: _Harness(request).service(),
        )
        second = PrivateAnalysisRunnerRegistration(
            runner,
            lambda _request: _Harness(request).service(),
        )
        with self.assertRaises(ValueError):
            PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(first, second),
            )

    def test_factory_failure_is_terminal_without_fabricated_transcript(self) -> None:
        request = _request()
        queued = self._created(request)
        callback_called = False

        def callback(_context: Any, _gateway: Any) -> str:
            nonlocal callback_called
            callback_called = True
            return "{}"

        def failed_factory(_request: Any) -> Any:
            raise RuntimeError("hostile C:\\private\\provider.txt")

        coordinator = self._coordinator(
            request,
            callback,
            factory=failed_factory,
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertFalse(callback_called)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code, PrivateAnalysisErrorCode.RUNNER_FAILED
        )
        self.assertNotIn("provider", repr(terminal))

    def test_hidden_zero_counter_service_use_is_finalized_before_runner(self) -> None:
        request = _request(limits=_request_limits(max_tool_calls=0))
        queued = self._created(request)
        service = _Harness(request).service()
        service.execute(_query_call(request))
        self.assertFalse(service.runner_lease_eligible)
        self.assertEqual(service.budget_state.tool_calls_consumed, 0)
        callback_called = False

        def callback(_context: Any, _gateway: Any) -> str:
            nonlocal callback_called
            callback_called = True
            return "{}"

        coordinator = self._coordinator(
            request,
            callback,
            factory=lambda _request: service,
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        self.assertFalse(callback_called)

    def test_shared_runner_is_serialized_across_coordinators(self) -> None:
        request = _request()
        first = self._created(request, "run-shared-1")
        second = self._created(request, "run-shared-2")
        entered = threading.Event()
        release = threading.Event()
        results: list[Any] = []

        def callback(_context: Any, _gateway: Any) -> str:
            entered.set()
            if not release.wait(2):
                raise RuntimeError("test release was not signalled")
            return private_analysis_result_json(_unsupported_result(request))

        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=callback,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner,
            lambda selected: _Harness(selected).service(),
        )
        first_coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )
        second_coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )

        def execute_first() -> None:
            try:
                results.append(
                    first_coordinator.execute_run(
                        request.scope,
                        first.run_id,
                        expected_version=first.version,
                        actor_id="worker-1",
                    )
                )
            except BaseException as error:  # noqa: BLE001 - test handoff.
                results.append(error)

        thread = threading.Thread(target=execute_first)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            with self.assertRaises(PrivateAnalysisExecutionUnavailable):
                second_coordinator.execute_run(
                    request.scope,
                    second.run_id,
                    expected_version=second.version,
                    actor_id="worker-2",
                )
            self.assertEqual(
                self.store.get_run(request.scope, second.run_id),
                second,
            )
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertNotIsInstance(results[0], BaseException)

    def test_write_ahead_accounting_is_visible_before_tool_response(self) -> None:
        request = _request()
        reference = _reference()
        harness = _Harness(request, (reference,))
        queued = self._created(request)
        observed_versions: list[int] = []

        def callback(
            _context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            response = gateway.execute(
                private_analysis_tool_call_json(_query_call(request))
            )
            self.assertIsNotNone(response.result)
            durable = self.store.get_run(request.scope, queued.run_id)
            observed_versions.append(durable.version)
            self.assertEqual(durable.disclosed_references, (reference,))
            self.assertEqual(durable.budget_state.tool_calls_consumed, 1)
            return private_analysis_result_json(_supported_result(request, reference))

        coordinator = self._coordinator(
            request,
            callback,
            factory=lambda _request: harness.service(),
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertTrue(observed_versions)
        self.assertEqual(terminal.disclosed_references, (reference,))
        self.assertEqual(terminal.budget_state.tool_calls_consumed, 1)
        reasons = [
            entry.reason.value
            for entry in self.store.list_audit(request.scope, queued.run_id)
        ]
        self.assertEqual(reasons.count("accounting_committed"), 1)

    def test_concurrent_execution_has_one_claim_factory_and_callback(self) -> None:
        request = _request()
        queued = self._created(request)
        entered = threading.Event()
        release = threading.Event()
        counts = {"factory": 0, "callback": 0}
        count_lock = threading.Lock()
        harness = _Harness(request)

        def callback(_context: Any, _gateway: Any) -> str:
            with count_lock:
                counts["callback"] += 1
            entered.set()
            self.assertTrue(release.wait(2))
            return private_analysis_result_json(_unsupported_result(request))

        def factory(_request: Any) -> Any:
            with count_lock:
                counts["factory"] += 1
            return harness.service()

        coordinator = self._coordinator(request, callback, factory=factory)
        outcomes: list[object] = []

        def execute() -> None:
            try:
                outcomes.append(
                    coordinator.execute_run(
                        request.scope,
                        queued.run_id,
                        expected_version=queued.version,
                        actor_id="worker-1",
                    )
                )
            except BaseException as error:  # noqa: BLE001 - thread assertion.
                outcomes.append(error)

        first = threading.Thread(target=execute, daemon=False)
        first.start()
        self.assertTrue(entered.wait(2))
        second = threading.Thread(target=execute, daemon=False)
        second.start()
        second.join(2)
        release.set()
        first.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(counts, {"factory": 1, "callback": 1})
        self.assertEqual(
            sum(
                isinstance(item, PrivateAnalysisRunStaleVersion)
                for item in outcomes
            ),
            1,
        )
        self.assertEqual(
            sum(
                getattr(item, "state", None) is PrivateAnalysisRunState.COMPLETED
                for item in outcomes
            ),
            1,
        )

    def test_close_is_bounded_and_blocks_new_work(self) -> None:
        request = _request()
        queued = self._created(request)
        entered = threading.Event()
        release = threading.Event()

        def callback(_context: Any, _gateway: Any) -> str:
            entered.set()
            self.assertTrue(release.wait(2))
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(request, callback)
        worker = threading.Thread(
            target=lambda: coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            ),
            daemon=False,
        )
        worker.start()
        self.assertTrue(entered.wait(2))
        started = time.monotonic()
        with self.assertRaises(PrivateAnalysisExecutionCloseTimeout):
            coordinator.close(timeout=0.01)
        self.assertLess(time.monotonic() - started, 0.5)
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        coordinator.close(timeout=1)
        with self.assertRaises(PrivateAnalysisExecutionClosed):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

    def test_running_cancellation_is_durable_and_reseals_the_receipt(self) -> None:
        request = _request()
        queued = self._created(request)
        entered = threading.Event()
        results: list[object] = []

        def callback(
            _context: Any, gateway: PrivateAnalysisInProcessToolGateway
        ) -> str:
            entered.set()
            while True:
                gateway.checkpoint()
                time.sleep(0.005)

        coordinator = self._coordinator(request, callback)

        def execute() -> None:
            try:
                results.append(
                    coordinator.execute_run(
                        request.scope,
                        queued.run_id,
                        expected_version=queued.version,
                        actor_id="worker-1",
                    )
                )
            except BaseException as error:  # noqa: BLE001 - thread assertion.
                results.append(error)

        worker = threading.Thread(target=execute, daemon=False)
        worker.start()
        self.assertTrue(entered.wait(2))
        running = self.store.get_run(request.scope, queued.run_id)
        cancelled = coordinator.request_cancellation(
            request.scope,
            queued.run_id,
            expected_version=running.version,
            actor_id="operator-1",
        )
        self.assertIs(cancelled.state, PrivateAnalysisRunState.CANCEL_REQUESTED)
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        terminal = results[0]
        self.assertIs(
            getattr(terminal, "state", None), PrivateAnalysisRunState.CANCELLED
        )
        assert not isinstance(terminal, BaseException)
        self.assertIsNotNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(terminal.outcome.error.code, PrivateAnalysisErrorCode.CANCELLED)

    def test_post_tool_cancellation_preserves_local_and_durable_accounting(
        self,
    ) -> None:
        request = _request()
        reference = _reference()
        queued = self._created(request)
        harness = _Harness(request, (reference,))
        coordinator: PrivateAnalysisExecutionCoordinator

        def cancel_during_query(request_value: Any, arguments: Any) -> Any:
            references = harness.query_references(request_value, arguments)
            active = self.store.get_run(request.scope, queued.run_id)
            coordinator.request_cancellation(
                request.scope,
                queued.run_id,
                expected_version=active.version,
                actor_id="operator-1",
            )
            return references

        service = harness.service(query_references=cancel_during_query)

        def callback(_context: Any, gateway: Any) -> str:
            gateway.execute(private_analysis_tool_call_json(_query_call(request)))
            return private_analysis_result_json(_supported_result(request, reference))

        coordinator = self._coordinator(
            request,
            callback,
            factory=lambda _request: service,
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.CANCELLED)
        self.assertEqual(terminal.disclosed_references, (reference,))
        self.assertEqual(terminal.budget_state.tool_calls_consumed, 1)
        self.assertEqual(terminal.budget_state.evidence_items_disclosed, 1)
        self.assertIsNotNone(terminal.transcript_summary)
        assert terminal.transcript_summary is not None
        self.assertEqual(
            terminal.transcript_summary.evidence_ledger_digest,
            terminal.evidence_ledger_digest,
        )

    def test_queued_cancellation_never_constructs_or_invokes_runner(self) -> None:
        request = _request()
        queued = self._created(request)
        calls = {"factory": 0, "runner": 0}

        def callback(_context: Any, _gateway: Any) -> str:
            calls["runner"] += 1
            return "{}"

        def factory(_request: Any) -> Any:
            calls["factory"] += 1
            return _Harness(request).service()

        coordinator = self._coordinator(request, callback, factory=factory)
        cancelled = coordinator.request_cancellation(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="operator-1",
        )
        replay = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=cancelled.version,
            actor_id="worker-1",
        )
        self.assertEqual(replay, cancelled)
        self.assertEqual(calls, {"factory": 0, "runner": 0})
        with self.assertRaises(PrivateAnalysisRunStaleVersion):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

    def test_cancellation_between_claim_and_registration_uses_no_service(self) -> None:
        request = _request()
        queued = self._created(request)
        service = _Harness(request).service()
        blocked = threading.Event()
        release = threading.Event()
        factory_calls = 0
        results: list[Any] = []

        def callback(_context: Any, _gateway: Any) -> str:
            raise AssertionError("cancelled attempt must not invoke the runner")

        def factory(_request: Any) -> Any:
            nonlocal factory_calls
            factory_calls += 1
            return service

        coordinator = self._coordinator(
            request,
            callback,
            factory=factory,
        )
        original_register = PrivateAnalysisExecutionCoordinator._register_attempt

        def delayed_register(
            selected: Any,
            key: Any,
            attempt: Any,
        ) -> None:
            blocked.set()
            if not release.wait(2):
                raise RuntimeError("test release was not signalled")
            original_register(selected, key, attempt)

        def execute() -> None:
            try:
                results.append(
                    coordinator.execute_run(
                        request.scope,
                        queued.run_id,
                        expected_version=queued.version,
                        actor_id="worker-1",
                    )
                )
            except BaseException as error:  # noqa: BLE001 - test handoff.
                results.append(error)

        with patch.object(
            PrivateAnalysisExecutionCoordinator,
            "_register_attempt",
            delayed_register,
        ):
            thread = threading.Thread(target=execute)
            thread.start()
            self.assertTrue(blocked.wait(1))
            active = self.store.get_run(request.scope, queued.run_id)
            cancelled = coordinator.request_cancellation(
                request.scope,
                queued.run_id,
                expected_version=active.version,
                actor_id="operator-1",
            )
            self.assertIs(cancelled.state, PrivateAnalysisRunState.CANCEL_REQUESTED)
            release.set()
            thread.join(2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertNotIsInstance(results[0], BaseException)
        terminal = results[0]
        self.assertIs(terminal.state, PrivateAnalysisRunState.CANCELLED)
        self.assertIsNone(terminal.transcript_summary)
        self.assertEqual(factory_calls, 0)
        self.assertTrue(service.runner_lease_eligible)

    def test_cancellation_after_runner_receipt_wins_before_completion(self) -> None:
        request = _request()
        queued = self._created(request)

        def callback(_context: Any, _gateway: Any) -> str:
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(request, callback)
        original_execute = ConfiguredPrivateAnalysisInProcessRunner.execute

        def execute_then_cancel(runner: Any, service: Any, **keywords: Any) -> Any:
            receipt = original_execute(runner, service, **keywords)
            running = self.store.get_run(request.scope, queued.run_id)
            self.store.request_cancellation(
                request.scope,
                queued.run_id,
                expected_version=running.version,
                actor_id="operator-1",
            )
            return receipt

        with patch.object(
            ConfiguredPrivateAnalysisInProcessRunner,
            "execute",
            execute_then_cancel,
        ):
            terminal = coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        self.assertIs(terminal.state, PrivateAnalysisRunState.CANCELLED)
        self.assertIsNotNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(terminal.outcome.error.code, PrivateAnalysisErrorCode.CANCELLED)

    def test_conflicting_terminal_writer_is_not_treated_as_idempotent(self) -> None:
        request = _request()
        queued = self._created(request)

        def callback(_context: Any, _gateway: Any) -> str:
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(
            request,
            callback,
            limits=PrivateAnalysisExecutionLimits(
                max_concurrent_runs=4,
                lease_duration_ns=2_000_000_000,
                heartbeat_interval_ns=1_000_000_000,
                cancellation_poll_interval_ns=1_000_000_000,
                monitor_join_timeout_ns=1_000_000_000,
            ),
        )
        original_execute = ConfiguredPrivateAnalysisInProcessRunner.execute

        def execute_then_recover(runner: Any, service: Any, **keywords: Any) -> Any:
            receipt = original_execute(runner, service, **keywords)
            active = self.store.get_run(request.scope, queued.run_id)
            assert active.lease_expires_at_ns is not None
            recovered = self.store.recover_expired_runs(
                actor_id="recovery",
                now_ns=active.lease_expires_at_ns + 1,
            )
            self.assertEqual(len(recovered), 1)
            return receipt

        with (
            patch.object(
                ConfiguredPrivateAnalysisInProcessRunner,
                "execute",
                execute_then_recover,
            ),
            self.assertRaises(PrivateAnalysisRunConflict),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

    def test_heartbeat_renews_without_breaking_terminal_version(self) -> None:
        request = _request()
        queued = self._created(request)

        def callback(_context: Any, _gateway: Any) -> str:
            time.sleep(0.25)
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(request, callback)
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        reasons = [
            entry.reason.value
            for entry in self.store.list_audit(request.scope, queued.run_id)
        ]
        self.assertGreaterEqual(reasons.count("lease_renewed"), 1)

    def test_shell_free_subprocess_receipt_is_persisted_by_same_coordinator(
        self,
    ) -> None:
        try:
            from tests.test_private_ai_subprocess_runner import (
                _build_case,
                _service,
                _write_control,
                _zero_tool_actions,
            )
        except ModuleNotFoundError:
            from test_private_ai_subprocess_runner import (  # type: ignore[no-redef]
                _build_case,
                _service,
                _write_control,
                _zero_tool_actions,
            )

        child_directory = Path(self.temporary.name) / "child"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "subprocess-run")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                ),
            ),
            limits=_limits(),
        )
        terminal = coordinator.execute_run(
            case.request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(terminal.transcript_summary)
        assert terminal.transcript_summary is not None
        self.assertIs(
            terminal.transcript_summary.transport,
            case.request.runner.transport,
        )

    def test_process_control_propagates_and_active_fence_is_not_fabricated(
        self,
    ) -> None:
        request = _request()
        queued = self._created(request)

        def callback(_context: Any, _gateway: Any) -> str:
            raise KeyboardInterrupt("synthetic control")

        coordinator = self._coordinator(request, callback)
        with self.assertRaisesRegex(KeyboardInterrupt, "synthetic control"):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        active = self.store.get_run(request.scope, queued.run_id)
        self.assertIs(active.state, PrivateAnalysisRunState.RUNNING)
        self.assertIsNone(active.outcome)
        self.assertIsNone(active.transcript_summary)
        assert active.lease_expires_at_ns is not None
        recovered = self.store.recover_expired_runs(
            actor_id="recovery",
            now_ns=active.lease_expires_at_ns + 1,
        )
        self.assertEqual(len(recovered), 1)
        self.assertIs(recovered[0].state, PrivateAnalysisRunState.COMPLETED)


class PrivateAnalysisUnstartedFinalizationTests(unittest.TestCase):
    def test_unstarted_finalization_requires_zero_accounting_and_exact_fence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqlitePrivateAnalysisRunStore(
                Path(directory) / "runs.sqlite3",
                admission_validator=lambda _request: None,
            )
            try:
                request = _request()
                queued = store.create_run(
                    request,
                    actor_id="admission",
                    idempotency_key="key-1",
                    run_id="run-1",
                )
                claimed = store.claim_run(
                    request.scope,
                    queued.run_id,
                    expected_version=queued.version,
                    execution_id="attempt-1",
                    actor_id="worker-1",
                    lease_duration_ns=1_000_000_000,
                )
                with self.assertRaises(PrivateAnalysisRunConflict):
                    store.finalize_unstarted_attempt(
                        request.scope,
                        queued.run_id,
                        expected_version=claimed.version,
                        execution_id="wrong-attempt",
                        actor_id="worker-1",
                    )
                terminal = store.finalize_unstarted_attempt(
                    request.scope,
                    queued.run_id,
                    expected_version=claimed.version,
                    execution_id="attempt-1",
                    actor_id="worker-1",
                )
                self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
                self.assertIsNone(terminal.transcript_summary)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
