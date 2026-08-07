from __future__ import annotations

import importlib
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import router_dump_analyzer.private_analysis_factory_process as factory_process_module
import router_dump_analyzer.private_analysis_in_process_runner as in_process_runner_module
import router_dump_analyzer.private_analysis_subprocess_runner as subprocess_runner_module
from router_dump_analyzer.canonical import strict_canonical_json
from router_dump_analyzer.plugin_identity import executable_module_target_fingerprint
from router_dump_analyzer.private_analysis import (
    PrivateAnalysisErrorCode,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)
from router_dump_analyzer.private_analysis.contracts import (
    LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST,
    PRIVATE_ANALYSIS_REQUEST_VERSION_V2,
)
from router_dump_analyzer.private_analysis.evidence import evidence_reference_dict
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisExecutionClosed,
    PrivateAnalysisExecutionCloseTimeout,
    PrivateAnalysisExecutionCoordinator,
    PrivateAnalysisExecutionLimits,
    PrivateAnalysisExecutionUnavailable,
    PrivateAnalysisRunnerRegistration,
    PrivateAnalysisToolServiceProcessFactory,
)
from router_dump_analyzer.private_analysis_factory_process import (
    PrivateAnalysisFactoryExecutableIdentityError,
    PrivateAnalysisFactoryProcessCleanupError,
    PrivateAnalysisRemoteToolService,
    _decode_message,
    _exact_message,
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
        _selection,
        _supported_result,
        _unsupported_result,
    )
    from tests.test_private_ai_in_process_runner import (
        _limits as _request_limits,
    )
    from tests.test_private_ai_in_process_runner import (
        _request as _base_request,
    )
except ModuleNotFoundError:
    from test_private_ai_in_process_runner import (  # type: ignore[no-redef]
        _INSTRUCTION_PROFILE_DIGEST,
        _Harness,
        _query_call,
        _reference,
        _selection,
        _supported_result,
        _unsupported_result,
    )
    from test_private_ai_in_process_runner import (
        _limits as _request_limits,
    )
    from test_private_ai_in_process_runner import (
        _request as _base_request,
    )


def _limits() -> PrivateAnalysisExecutionLimits:
    return PrivateAnalysisExecutionLimits(
        max_concurrent_runs=4,
        lease_duration_ns=2_000_000_000,
        heartbeat_interval_ns=100_000_000,
        cancellation_poll_interval_ns=10_000_000,
        monitor_join_timeout_ns=1_000_000_000,
    )


def _request(*args: Any, **kwargs: Any) -> Any:
    return replace(
        _base_request(*args, **kwargs),
        evidence_service_digest="sha256:" + "f" * 64,
        request_digest="",
    )


class _StubbornFactoryProcess:
    def __init__(self, *, stop_after_kills: int = 2) -> None:
        self.alive = True
        self.stop_after_kills = stop_after_kills
        self.terminate_calls = 0
        self.kill_calls = 0
        self.join_calls: list[float] = []
        self.close_calls = 0

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1
        if self.kill_calls >= self.stop_after_kills:
            self.alive = False

    def join(self, timeout: float) -> None:
        self.join_calls.append(timeout)

    def close(self) -> None:
        self.close_calls += 1


class _PartialStartFactoryProcess(_StubbornFactoryProcess):
    def start(self) -> None:
        raise KeyboardInterrupt("synthetic partial Process.start")


class _FactoryConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.close_calls = 0

    def send_bytes(self, value: bytes) -> None:
        self.sent.append(value)

    def poll(self, _timeout: float) -> bool:
        return False

    def close(self) -> None:
        self.close_calls += 1


class _FactoryCloseControlConnection(_FactoryConnection):
    def __init__(self, control: BaseException | None) -> None:
        super().__init__()
        self.control = control

    def close(self) -> None:
        super().close()
        if self.control is not None:
            raise self.control


class _MutableAnalysisCallback:
    """Source-backed callable used to exercise registration-time attestation."""

    def __init__(self, request: Any, *, mode: str = "registered") -> None:
        self.request = request
        self.mode = mode
        self.calls = 0

    def __call__(
        self,
        _context: PrivateAnalysisInProcessContext,
        _gateway: PrivateAnalysisInProcessToolGateway,
    ) -> str:
        self.calls += 1
        return private_analysis_result_json(_unsupported_result(self.request))


def _replacement_mutable_analysis_call(
    self: _MutableAnalysisCallback,
    _context: PrivateAnalysisInProcessContext,
    _gateway: PrivateAnalysisInProcessToolGateway,
) -> str:
    self.calls += 100
    return private_analysis_result_json(_unsupported_result(self.request))


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
        process_factory: PrivateAnalysisToolServiceProcessFactory | None = None,
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
                    trusted_inline_tool_service_factory=(
                        None
                        if process_factory is not None
                        else factory or (lambda _request: harness.service())
                    ),
                    tool_service_process_factory=process_factory,
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=limits or _limits(),
        )

    def test_partial_factory_process_start_transfers_exact_owner_before_control(
        self,
    ) -> None:
        process = _PartialStartFactoryProcess(stop_after_kills=2)
        parent = _FactoryConnection()
        child = _FactoryConnection()

        class Context:
            @staticmethod
            def Pipe(*, duplex: bool) -> tuple[Any, Any]:
                self.assertTrue(duplex)
                return parent, child

            @staticmethod
            def Process(**_kwargs: Any) -> _PartialStartFactoryProcess:
                return process

        with patch.object(
            factory_process_module,
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        ):
            process_factory = PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory"
            )
            with (
                patch.object(
                    factory_process_module.multiprocessing,
                    "get_context",
                    return_value=Context(),
                ),
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "partial Process.start",
                ) as raised,
            ):
                factory_process_module.start_private_analysis_tool_service_process(
                    process_factory,
                    _request(),
                    cancellation_probe=lambda: False,
                    absolute_deadline_ns=time.monotonic_ns() + 1_000_000_000,
                    poll_interval_ns=1_000_000,
                )

        owner = factory_process_module.private_analysis_factory_process_cleanup_owner(
            raised.exception
        )
        self.assertIsNotNone(owner)
        assert owner is not None
        self.assertFalse(owner.cleanup_confirmed)
        self.assertEqual(process.kill_calls, 1)
        owner.close()
        self.assertTrue(owner.cleanup_confirmed)
        self.assertEqual(process.kill_calls, 2)

    def test_factory_process_construction_control_closes_both_pipe_endpoints(
        self,
    ) -> None:
        parent = _FactoryConnection()
        child = _FactoryConnection()

        class Context:
            @staticmethod
            def Pipe(*, duplex: bool) -> tuple[Any, Any]:
                self.assertTrue(duplex)
                return parent, child

            @staticmethod
            def Process(**_kwargs: Any) -> Any:
                raise KeyboardInterrupt("synthetic Process construction")

        with patch.object(
            factory_process_module,
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        ):
            process_factory = PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory"
            )
            with (
                patch.object(
                    factory_process_module.multiprocessing,
                    "get_context",
                    return_value=Context(),
                ),
                self.assertRaisesRegex(
                    KeyboardInterrupt,
                    "synthetic Process construction",
                ) as raised,
            ):
                factory_process_module.start_private_analysis_tool_service_process(
                    process_factory,
                    _request(),
                    cancellation_probe=lambda: False,
                    absolute_deadline_ns=time.monotonic_ns() + 1_000_000_000,
                    poll_interval_ns=1_000_000,
                )

        self.assertEqual(parent.close_calls, 1)
        self.assertEqual(child.close_calls, 1)
        self.assertIsNone(
            factory_process_module.private_analysis_factory_process_cleanup_owner(
                raised.exception
            )
        )

    def test_factory_process_construction_close_control_has_exact_precedence(
        self,
    ) -> None:
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )

        def context_for(
            parent_endpoint: Any,
            child_endpoint: Any,
            process_failure: BaseException,
        ) -> Any:
            class Context:
                @staticmethod
                def Pipe(*, duplex: bool) -> tuple[Any, Any]:
                    self.assertTrue(duplex)
                    return parent_endpoint, child_endpoint

                @staticmethod
                def Process(**_kwargs: Any) -> Any:
                    raise process_failure

            return Context()

        cases = (
            (
                "generic_child_control",
                RuntimeError("synthetic generic Process construction"),
                KeyboardInterrupt("synthetic child close control"),
                None,
                "child",
            ),
            (
                "generic_parent_control",
                RuntimeError("synthetic generic Process construction"),
                None,
                SystemExit("synthetic parent close control"),
                "parent",
            ),
            (
                "generic_both_controls",
                RuntimeError("synthetic generic Process construction"),
                KeyboardInterrupt("synthetic first child close control"),
                SystemExit("synthetic later parent close control"),
                "child",
            ),
            (
                "process_control_wins",
                KeyboardInterrupt("synthetic Process construction control"),
                SystemExit("synthetic child close control"),
                KeyboardInterrupt("synthetic parent close control"),
                "process",
            ),
        )
        for name, process_error, child_error, parent_error, expected_owner in cases:
            with self.subTest(name=name):
                parent = _FactoryCloseControlConnection(parent_error)
                child = _FactoryCloseControlConnection(child_error)

                expected = {
                    "process": process_error,
                    "child": child_error,
                    "parent": parent_error,
                }[expected_owner]
                assert expected is not None
                with (
                    patch.object(
                        factory_process_module.multiprocessing,
                        "get_context",
                        return_value=context_for(parent, child, process_error),
                    ),
                    self.assertRaises(type(expected)) as raised,
                ):
                    factory_process_module.start_private_analysis_tool_service_process(
                        process_factory,
                        _request(),
                        cancellation_probe=lambda: False,
                        absolute_deadline_ns=time.monotonic_ns() + 1_000_000_000,
                        poll_interval_ns=1_000_000,
                    )

                self.assertIs(raised.exception, expected)
                self.assertEqual(child.close_calls, 1)
                self.assertEqual(parent.close_calls, 1)
                self.assertIsNone(
                    factory_process_module.private_analysis_factory_process_cleanup_owner(
                        raised.exception
                    )
                )

    def test_never_started_factory_process_is_clean_without_join(self) -> None:
        process = multiprocessing.get_context("spawn").Process(target=os.getpid)
        owner = factory_process_module.PrivateAnalysisFactoryProcessCleanupOwner(
            process
        )
        owner.close()
        self.assertTrue(owner.cleanup_confirmed)

        class UninspectableProcess:
            @staticmethod
            def is_alive() -> bool:
                return False

            @property
            def pid(self) -> int:
                raise OSError("synthetic pid inspection failure")

        ambiguous_owner = (
            factory_process_module.PrivateAnalysisFactoryProcessCleanupOwner(
                UninspectableProcess()
            )
        )
        with self.assertRaises(PrivateAnalysisFactoryProcessCleanupError):
            ambiguous_owner.close()
        self.assertFalse(ambiguous_owner.cleanup_confirmed)

        class InterruptedInspection:
            @staticmethod
            def is_alive() -> bool:
                return False

            @property
            def pid(self) -> int:
                raise KeyboardInterrupt("synthetic process inspection control")

        interrupted_owner = (
            factory_process_module.PrivateAnalysisFactoryProcessCleanupOwner(
                InterruptedInspection()
            )
        )
        with self.assertRaisesRegex(
            KeyboardInterrupt,
            "synthetic process inspection control",
        ) as raised:
            interrupted_owner.close()
        self.assertIs(
            factory_process_module.private_analysis_factory_process_cleanup_owner(
                raised.exception
            ),
            interrupted_owner,
        )
        self.assertFalse(interrupted_owner.cleanup_confirmed)

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
        reasons = [
            entry.reason.value
            for entry in self.store.list_audit(request.scope, queued.run_id)
        ]
        self.assertEqual(reasons[:2], ["admitted", "claimed"])
        self.assertEqual(reasons[-1], "completed")
        self.assertTrue(all(reason == "lease_renewed" for reason in reasons[2:-1]))
        coordinator.close(timeout=1)

    def test_registered_callback_state_drift_fails_before_invocation(self) -> None:
        request = _request()
        queued = self._created(request, "run-callback-drift")
        callback = _MutableAnalysisCallback(request)
        coordinator = self._coordinator(request, callback)

        callback.mode = "mutated-after-registration"
        completed = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )

        self.assertEqual(callback.calls, 0)
        self.assertIsNotNone(completed.outcome)
        assert completed.outcome is not None
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
        self.assertIsNotNone(completed.outcome.error)
        assert completed.outcome.error is not None
        self.assertIs(
            completed.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
        )
        coordinator.close(timeout=1)

    def test_registered_callback_class_drift_fails_before_invocation(self) -> None:
        request = _request()
        queued = self._created(request, "run-callback-class-drift")
        callback = _MutableAnalysisCallback(request)
        coordinator = self._coordinator(request, callback)

        original_call = _MutableAnalysisCallback.__call__
        try:
            _MutableAnalysisCallback.__call__ = _replacement_mutable_analysis_call
            completed = coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        finally:
            _MutableAnalysisCallback.__call__ = original_call

        self.assertEqual(callback.calls, 0)
        self.assertIsNotNone(completed.outcome)
        assert completed.outcome is not None
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
        self.assertIsNotNone(completed.outcome.error)
        assert completed.outcome.error is not None
        self.assertIs(
            completed.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
        )
        coordinator.close(timeout=1)

    def test_registered_callback_closure_drift_fails_before_invocation(self) -> None:
        request = _request()
        queued = self._created(request, "run-callback-closure-drift")
        callback_state = {"mode": "registered", "calls": 0}

        def callback(
            _context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            callback_state["calls"] += 1
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(request, callback)
        callback_state["mode"] = "mutated-after-registration"
        completed = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )

        self.assertEqual(callback_state["calls"], 0)
        self.assertIsNotNone(completed.outcome)
        assert completed.outcome is not None
        self.assertIs(completed.outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
        self.assertIsNotNone(completed.outcome.error)
        assert completed.outcome.error is not None
        self.assertIs(
            completed.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
        )
        coordinator.close(timeout=1)

    def test_registration_detaches_runner_callback_slot(self) -> None:
        request = _request()
        queued = self._created(request, "run-detached-callback")
        admitted_callback = _MutableAnalysisCallback(request)
        replacement_callback = _MutableAnalysisCallback(
            request,
            mode="replacement",
        )
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=admitted_callback,
        )
        harness = _Harness(request)
        registration = PrivateAnalysisRunnerRegistration(
            runner=runner,
            trusted_inline_tool_service_factory=lambda _request: harness.service(),
            custom_evidence_service_digest="sha256:" + "f" * 64,
        )
        runner._callback = replacement_callback
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )

        completed = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )

        self.assertIs(completed.state, PrivateAnalysisRunState.COMPLETED)
        self.assertEqual(admitted_callback.calls, 1)
        self.assertEqual(replacement_callback.calls, 0)
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

    def test_evidence_service_drift_is_rejected_before_claim(self) -> None:
        request = _request()
        queued = self._created(request, "run-custom-service-drift")
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        custom_drift = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    runner,
                    lambda selected: _Harness(selected).service(),
                    custom_evidence_service_digest="sha256:" + "e" * 64,
                ),
            ),
            limits=_limits(),
        )
        with self.assertRaises(PrivateAnalysisExecutionUnavailable):
            custom_drift.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        self.assertEqual(
            self.store.get_run(request.scope, queued.run_id),
            queued,
        )

        client_safe = PrivateAnalysisRunnerRegistration(
            runner,
            core_revision_evidence_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=False,
            ),
        )
        full_fidelity = PrivateAnalysisRunnerRegistration(
            runner,
            core_revision_evidence_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=True,
            ),
        )
        self.assertNotEqual(
            client_safe.evidence_service_digest,
            full_fidelity.evidence_service_digest,
        )
        core_request = replace(
            request,
            evidence_service_digest=client_safe.evidence_service_digest,
            request_digest="",
        )
        core_queued = self._created(core_request, "run-core-service-drift")
        core_drift = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(full_fidelity,),
            core_tool_service_factory=(
                lambda selected, _policy, _cancelled: _Harness(selected).service()
            ),
            limits=_limits(),
        )
        with self.assertRaises(PrivateAnalysisExecutionUnavailable):
            core_drift.execute_run(
                core_request.scope,
                core_queued.run_id,
                expected_version=core_queued.version,
                actor_id="worker-1",
            )
        self.assertEqual(
            self.store.get_run(core_request.scope, core_queued.run_id),
            core_queued,
        )

        legacy_request = replace(
            request,
            contract_version=PRIVATE_ANALYSIS_REQUEST_VERSION_V2,
            evidence_service_digest=(
                LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
            ),
            request_digest="",
        )
        legacy_queued = self._created(legacy_request, "run-v2-legacy-service")
        with self.assertRaises(PrivateAnalysisExecutionUnavailable):
            custom_drift.execute_run(
                legacy_request.scope,
                legacy_queued.run_id,
                expected_version=legacy_queued.version,
                actor_id="worker-1",
            )
        self.assertEqual(
            self.store.get_run(legacy_request.scope, legacy_queued.run_id),
            legacy_queued,
        )

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
                    custom_evidence_service_digest="sha256:" + "f" * 64,
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
            custom_evidence_service_digest="sha256:" + "f" * 64,
        )
        second = PrivateAnalysisRunnerRegistration(
            runner,
            lambda _request: _Harness(request).service(),
            custom_evidence_service_digest="sha256:" + "f" * 64,
        )
        with self.assertRaises(ValueError):
            PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(first, second),
            )

    def test_process_factory_identity_binds_target_and_configuration(self) -> None:
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        semantic_digest = "sha256:" + "f" * 64
        factories = (
            PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory"
            ),
            PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory",
                strict_canonical_json({"profile": "second"}),
            ),
            PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "malformed_service_factory"
            ),
        )
        digests = {
            PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=factory,
                custom_evidence_service_digest=semantic_digest,
            ).evidence_service_digest
            for factory in factories
        }
        self.assertEqual(len(digests), 3)

    def test_process_factory_descriptor_is_detached_at_each_owner_boundary(
        self,
    ) -> None:
        secret = "C:\\deployment\\raw-provider-token"
        caller_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory",
            strict_canonical_json({"nested": {"secret": secret}}),
        )
        custom_evidence_service_digest = "sha256:" + "f" * 64
        request = replace(
            _request(),
            evidence_service_digest=caller_factory.evidence_service_digest(
                custom_evidence_service_digest
            ),
            request_digest="",
        )

        def callback(_context: Any, _gateway: Any) -> str:
            return private_analysis_result_json(_unsupported_result(request))

        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=callback,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner,
            tool_service_process_factory=caller_factory,
            custom_evidence_service_digest=custom_evidence_service_digest,
        )
        registered_factory = registration.tool_service_process_factory
        assert registered_factory is not None
        self.assertIsNot(registered_factory, caller_factory)

        configuration_view = registered_factory.configuration
        nested = configuration_view["nested"]
        assert type(nested) is dict
        nested["secret"] = "mutated-decoded-view"
        self.assertEqual(
            registered_factory.configuration,
            {"nested": {"secret": secret}},
        )

        object.__setattr__(
            caller_factory,
            "target",
            "tests.support.private_analysis_factory_fixture:"
            "malformed_service_factory",
        )
        object.__setattr__(
            caller_factory,
            "configuration_json",
            strict_canonical_json({"secret": "mutated-caller"}),
        )
        self.assertEqual(
            registration.evidence_service_digest,
            request.evidence_service_digest,
        )
        queued = self._created(request, "run-process-factory-detached")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )
        internal_registration = next(iter(coordinator._routes.values())).registration
        internal_factory = internal_registration.tool_service_process_factory
        assert internal_factory is not None
        self.assertIsNot(internal_factory, registered_factory)

        object.__setattr__(
            registered_factory,
            "target",
            "tests.support.private_analysis_factory_fixture:"
            "malformed_service_factory",
        )
        object.__setattr__(
            registered_factory,
            "configuration_json",
            strict_canonical_json({"secret": "mutated-registration"}),
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(terminal.transcript_summary)
        self.assertNotIn(secret, repr(registration))
        self.assertNotIn(secret, repr(internal_registration))
        self.assertNotIn(secret, repr(terminal))

    def test_process_factory_launch_revalidates_the_bound_snapshot(self) -> None:
        secret = "C:\\deployment\\raw-mutated-config"
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        custom_evidence_service_digest = "sha256:" + "f" * 64
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                custom_evidence_service_digest
            ),
            request_digest="",
        )
        callback_called = False

        def callback(_context: Any, _gateway: Any) -> str:
            nonlocal callback_called
            callback_called = True
            return private_analysis_result_json(_unsupported_result(request))

        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=callback,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner,
            tool_service_process_factory=process_factory,
            custom_evidence_service_digest=custom_evidence_service_digest,
        )
        self.assertEqual(
            registration.evidence_service_digest,
            request.evidence_service_digest,
        )
        queued = self._created(request, "run-process-factory-revalidate")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )
        internal_registration = next(iter(coordinator._routes.values())).registration
        internal_factory = internal_registration.tool_service_process_factory
        assert internal_factory is not None
        object.__setattr__(
            internal_factory,
            "target",
            "tests.support.private_analysis_factory_fixture:"
            "malformed_service_factory",
        )
        object.__setattr__(
            internal_factory,
            "configuration_json",
            strict_canonical_json({"secret": secret}),
        )

        with patch(
            "router_dump_analyzer.private_analysis_execution."
            "start_private_analysis_tool_service_process"
        ) as launch:
            terminal = coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        launch.assert_not_called()
        self.assertFalse(callback_called)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        self.assertNotIn(secret, repr(internal_registration))
        self.assertNotIn(secret, repr(terminal))

    def test_process_factory_rejects_module_attribute_swap_before_spawn(
        self,
    ) -> None:
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        custom_evidence_service_digest = "sha256:" + "f" * 64
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                custom_evidence_service_digest
            ),
            request_digest="",
        )
        callback_called = False

        def callback(_context: Any, _gateway: Any) -> str:
            nonlocal callback_called
            callback_called = True
            return private_analysis_result_json(_unsupported_result(request))

        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=callback,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner,
            tool_service_process_factory=process_factory,
            custom_evidence_service_digest=custom_evidence_service_digest,
        )
        self.assertEqual(
            registration.evidence_service_digest,
            request.evidence_service_digest,
        )
        queued = self._created(request, "run-process-factory-attribute-swap")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )
        fixture = importlib.import_module(
            "tests.support.private_analysis_factory_fixture"
        )
        original = fixture.configured_service_factory
        try:
            fixture.configured_service_factory = fixture.malformed_service_factory
            with patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch:
                terminal = coordinator.execute_run(
                    request.scope,
                    queued.run_id,
                    expected_version=queued.version,
                    actor_id="worker-1",
                )
        finally:
            fixture.configured_service_factory = original
        launch.assert_not_called()
        self.assertFalse(callback_called)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )

        with self.assertRaisesRegex(RuntimeError, "executable identity"):
            PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=(
                    PrivateAnalysisToolServiceProcessFactory("builtins:dict")
                ),
                custom_evidence_service_digest="sha256:" + "f" * 64,
            )

    def test_process_factory_rejects_actual_module_byte_drift_before_spawn(
        self,
    ) -> None:
        module_name = "_rda_private_factory_parent_drift"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        source = (
            "from tests.support.private_analysis_factory_fixture import "
            "configured_service_factory\n\n"
            "def factory(request, configuration):\n"
            "    return configured_service_factory(request, configuration)\n"
        )
        module_path.write_text(source, encoding="utf-8")
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        callback_called = False
        try:
            process_factory = PrivateAnalysisToolServiceProcessFactory(
                f"{module_name}:factory"
            )
            custom_evidence_service_digest = "sha256:" + "f" * 64
            request = replace(
                _request(),
                evidence_service_digest=process_factory.evidence_service_digest(
                    custom_evidence_service_digest
                ),
                request_digest="",
            )

            def callback(_context: Any, _gateway: Any) -> str:
                nonlocal callback_called
                callback_called = True
                return private_analysis_result_json(_unsupported_result(request))

            runner = ConfiguredPrivateAnalysisInProcessRunner(
                request.runner,
                instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                model_callback=callback,
            )
            registration = PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=process_factory,
                custom_evidence_service_digest=custom_evidence_service_digest,
            )
            self.assertEqual(
                registration.evidence_service_digest,
                request.evidence_service_digest,
            )
            queued = self._created(request, "run-process-factory-parent-drift")
            coordinator = PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(registration,),
                limits=_limits(),
            )
            module_path.write_text(source + "\n# changed bytes\n", encoding="utf-8")
            with patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch:
                terminal = coordinator.execute_run(
                    request.scope,
                    queued.run_id,
                    expected_version=queued.version,
                    actor_id="worker-1",
                )
        finally:
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()
        launch.assert_not_called()
        self.assertFalse(callback_called)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        self.assertNotIn(str(module_path), repr(terminal))

    def test_process_factory_contains_child_module_byte_drift(self) -> None:
        module_name = "_rda_private_factory_child_drift"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        source = (
            "import multiprocessing\n"
            "from pathlib import Path\n"
            "from tests.support.private_analysis_factory_fixture import "
            "configured_service_factory\n\n"
            "if multiprocessing.current_process().name.startswith(\n"
            "    'private-analysis-evidence-factory-'\n"
            "):\n"
            "    _source = Path(__file__)\n"
            "    _source.write_bytes(_source.read_bytes() + "
            "b'\\n# child drift\\n')\n\n"
            "def factory(request, configuration):\n"
            "    return configured_service_factory(request, configuration)\n"
        )
        module_path.write_text(source, encoding="utf-8")
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        callback_called = False
        try:
            process_factory = PrivateAnalysisToolServiceProcessFactory(
                f"{module_name}:factory"
            )
            custom_evidence_service_digest = "sha256:" + "f" * 64
            request = replace(
                _request(),
                evidence_service_digest=process_factory.evidence_service_digest(
                    custom_evidence_service_digest
                ),
                request_digest="",
            )

            def callback(_context: Any, _gateway: Any) -> str:
                nonlocal callback_called
                callback_called = True
                return private_analysis_result_json(_unsupported_result(request))

            runner = ConfiguredPrivateAnalysisInProcessRunner(
                request.runner,
                instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                model_callback=callback,
            )
            registration = PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=process_factory,
                custom_evidence_service_digest=custom_evidence_service_digest,
            )
            self.assertEqual(
                registration.evidence_service_digest,
                request.evidence_service_digest,
            )
            queued = self._created(request, "run-process-factory-child-drift")
            coordinator = PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(registration,),
                limits=_limits(),
            )
            terminal = coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )
        finally:
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()
        self.assertFalse(callback_called)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        self.assertNotIn(str(module_path), repr(terminal))
        self.assertFalse(
            any(
                child.name.startswith("private-analysis-evidence-factory-")
                for child in multiprocessing.active_children()
            )
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

    def test_process_factory_rejects_environment_selected_exec_bytecode(self) -> None:
        module_name = "_rda_private_factory_environment_exec"
        environment_name = "RDA_TEST_FACTORY_EXEC_BRANCH"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        module_path.write_text(
            "import os\n\n"
            "def factory(request, configuration):\n"
            "    return configuration\n\n"
            "_branch = (\n"
            "    'return request'\n"
            f"    if os.environ.get('{environment_name}') == 'request'\n"
            "    else 'return None'\n"
            ")\n"
            "_namespace = {}\n"
            "exec(\n"
            "    compile(\n"
            "        'def alternate(request, configuration):\\n    ' + _branch + "
            "'\\n',\n"
            "        __file__,\n"
            "        'exec',\n"
            "    ),\n"
            "    globals(),\n"
            "    _namespace,\n"
            ")\n"
            "factory.__code__ = _namespace['alternate'].__code__.replace(\n"
            "    co_name='factory',\n"
            "    co_qualname='factory',\n"
            ")\n",
            encoding="utf-8",
        )
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        identities: list[tuple[bytes, tuple[object, ...]]] = []
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        try:
            for branch in ("request", "none"):
                sys.modules.pop(module_name, None)
                with patch.dict(os.environ, {environment_name: branch}):
                    module = importlib.import_module(module_name)
                identities.append((module.factory.__code__.co_code, module.factory.__code__.co_consts))
                with self.assertRaisesRegex(RuntimeError, "executable identity"):
                    PrivateAnalysisRunnerRegistration(
                        runner,
                        tool_service_process_factory=(
                            PrivateAnalysisToolServiceProcessFactory(
                                f"{module_name}:factory"
                            )
                        ),
                        custom_evidence_service_digest="sha256:" + "f" * 64,
                    )
        finally:
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()
        self.assertNotEqual(*identities)

    def test_process_factory_rejects_custom_function_builtins(self) -> None:
        fixture = importlib.import_module(
            "tests.support.private_analysis_factory_fixture"
        )
        original = fixture.malformed_service_factory
        copied_globals = dict(original.__globals__)
        copied_builtins = dict(original.__builtins__)
        copied_builtins["object"] = lambda: None
        copied_globals["__builtins__"] = copied_builtins
        replacement = type(original)(
            original.__code__,
            copied_globals,
            original.__name__,
            original.__defaults__,
            original.__closure__,
        )
        replacement.__module__ = original.__module__
        replacement.__qualname__ = original.__qualname__
        replacement.__annotations__ = dict(original.__annotations__)
        fixture.malformed_service_factory = replacement
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "executable identity"):
                PrivateAnalysisRunnerRegistration(
                    runner,
                    tool_service_process_factory=(
                        PrivateAnalysisToolServiceProcessFactory(
                            "tests.support.private_analysis_factory_fixture:"
                            "malformed_service_factory"
                        )
                    ),
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                )
        finally:
            fixture.malformed_service_factory = original

    def test_process_factory_rejects_live_module_attribute_drift(self) -> None:
        fixture = importlib.import_module(
            "tests.support.private_analysis_factory_fixture"
        )
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "non_returning_service_factory"
        )
        PrivateAnalysisRunnerRegistration(
            runner,
            tool_service_process_factory=factory,
            custom_evidence_service_digest="sha256:" + "f" * 64,
        )

        with (
            patch.object(fixture.time, "sleep", lambda _seconds: None),
            self.assertRaisesRegex(RuntimeError, "executable identity"),
        ):
            PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=factory,
                custom_evidence_service_digest="sha256:" + "f" * 64,
            )

    def test_process_factory_bounds_runtime_default_bytes(self) -> None:
        fixture = importlib.import_module(
            "tests.support.private_analysis_factory_fixture"
        )
        function = fixture.malformed_service_factory
        original_defaults = function.__defaults__
        function.__defaults__ = (b"x" * (1024 * 1024 + 1),)
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        try:
            with (
                patch(
                    "router_dump_analyzer.plugin_identity."
                    "_MAX_TARGET_VALUE_BYTES",
                    1024 * 1024,
                ),
                self.assertRaisesRegex(RuntimeError, "executable identity"),
            ):
                PrivateAnalysisRunnerRegistration(
                    runner,
                    tool_service_process_factory=(
                        PrivateAnalysisToolServiceProcessFactory(
                            "tests.support.private_analysis_factory_fixture:"
                            "malformed_service_factory"
                        )
                    ),
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                )
        finally:
            function.__defaults__ = original_defaults

    def test_process_factory_rejects_live_instance_method_code_drift(self) -> None:
        module_name = "_rda_private_factory_instance_code"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        module_path.write_text(
            "class Factory:\n"
            "    def __call__(self, request, configuration):\n"
            "        return configuration\n\n"
            "def alternate(self, request, configuration):\n"
            "    return request\n\n"
            "factory = Factory()\n",
            encoding="utf-8",
        )
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        request = _request()
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: "{}",
        )
        factory = PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
        try:
            module = importlib.import_module(module_name)
            PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=factory,
                custom_evidence_service_digest="sha256:" + "f" * 64,
            )
            module.Factory.__call__.__code__ = module.alternate.__code__.replace(
                co_name="__call__",
                co_qualname="Factory.__call__",
            )
            with self.assertRaisesRegex(RuntimeError, "executable identity"):
                PrivateAnalysisRunnerRegistration(
                    runner,
                    tool_service_process_factory=factory,
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                )
        finally:
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()

    def test_process_factory_identity_binds_external_helper_global_state(self) -> None:
        module_name = "_rda_private_factory_external_helper_state"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        module_path.write_text(
            "import json\n\n"
            "def factory(request, configuration):\n"
            "    return json.loads(configuration)\n",
            encoding="utf-8",
        )
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        original_decoder = json._default_decoder
        try:
            module = importlib.import_module(module_name)
            executable_module_target_fingerprint(
                module_name,
                "factory",
                module.factory,
            )
            bound = PrivateAnalysisToolServiceProcessFactory.resolved(
                PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
            )
            self.assertIs(type(json.loads("1")), int)
            json._default_decoder = json.JSONDecoder(parse_int=float)
            self.assertIs(type(json.loads("1")), float)
            changed = PrivateAnalysisToolServiceProcessFactory.resolved(
                PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
            )
            self.assertNotEqual(bound.executable_identity, changed.executable_identity)
            with self.assertRaisesRegex(RuntimeError, "executable identity"):
                PrivateAnalysisToolServiceProcessFactory.resolved(bound)
        finally:
            json._default_decoder = original_decoder
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()

    def test_process_factory_identity_binds_instance_and_class_state(self) -> None:
        module_name = "_rda_private_factory_callable_state"
        module_path = Path(self.temporary.name) / f"{module_name}.py"
        module_path.write_text(
            "class Factory:\n"
            "    mode = 'A'\n\n"
            "    def __init__(self):\n"
            "        self.mode = 'A'\n\n"
            "    def __call__(self, request, configuration):\n"
            "        return self.mode, Factory.mode\n\n"
            "factory = Factory()\n",
            encoding="utf-8",
        )
        search_root = str(Path(self.temporary.name))
        sys.path.insert(0, search_root)
        importlib.invalidate_caches()
        try:
            module = importlib.import_module(module_name)
            first = PrivateAnalysisToolServiceProcessFactory.resolved(
                PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
            )
            module.factory.mode = "B"
            instance_changed = PrivateAnalysisToolServiceProcessFactory.resolved(
                PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
            )
            module.factory.mode = "A"
            module.Factory.mode = "B"
            class_changed = PrivateAnalysisToolServiceProcessFactory.resolved(
                PrivateAnalysisToolServiceProcessFactory(f"{module_name}:factory")
            )
        finally:
            sys.modules.pop(module_name, None)
            sys.path.remove(search_root)
            importlib.invalidate_caches()
        self.assertNotEqual(first.executable_identity, instance_changed.executable_identity)
        self.assertNotEqual(first.executable_identity, class_changed.executable_identity)

    def test_remote_service_close_retries_until_stubborn_child_is_reaped(
        self,
    ) -> None:
        request = _request()
        process = _StubbornFactoryProcess()
        connection = _FactoryConnection()
        service = PrivateAnalysisRemoteToolService(
            request,
            process=process,
            connection=connection,
            cancellation_probe=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
            poll_interval_ns=1_000_000,
        )

        with self.assertRaises(PrivateAnalysisFactoryProcessCleanupError):
            service.close()
        self.assertEqual(process.kill_calls, 1)
        self.assertFalse(service.runner_lease_eligible)

        service.close()
        calls_after_reap = (
            process.terminate_calls,
            process.kill_calls,
            tuple(process.join_calls),
            process.close_calls,
            connection.close_calls,
        )
        service.close()
        self.assertEqual(
            (
                process.terminate_calls,
                process.kill_calls,
                tuple(process.join_calls),
                process.close_calls,
                connection.close_calls,
            ),
            calls_after_reap,
        )
        self.assertEqual(process.kill_calls, 2)
        self.assertEqual(process.close_calls, 1)

    def test_preparation_cleanup_failure_does_not_seal_durable_attempt(self) -> None:
        initial_request = _request()
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:configured_service_factory"
        )
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            initial_request.runner,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda _context, _gateway: self.fail(
                "runner must not execute after invalid preparation"
            ),
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner,
            tool_service_process_factory=process_factory,
            custom_evidence_service_digest="sha256:" + "f" * 64,
        )
        request = replace(
            initial_request,
            evidence_service_digest=registration.evidence_service_digest,
            request_digest="",
        )
        queued = self._created(request, "run-process-cleanup-pre-seal")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(registration,),
            limits=_limits(),
        )
        process = _StubbornFactoryProcess()
        connection = _FactoryConnection()
        wrong_request = _request(query="wrong request binding")
        service = PrivateAnalysisRemoteToolService(
            wrong_request,
            process=process,
            connection=connection,
            cancellation_probe=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
            poll_interval_ns=1_000_000,
        )

        with (
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process",
                return_value=service,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisExecutionUnavailable,
                "factory process did not stop",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        current = self.store.get_run(request.scope, queued.run_id)
        self.assertIs(current.state, PrivateAnalysisRunState.RUNNING)
        reasons = [
            entry.reason.value
            for entry in self.store.list_audit(request.scope, queued.run_id)
        ]
        self.assertEqual(reasons[:2], ["admitted", "claimed"])
        self.assertTrue(all(reason == "lease_renewed" for reason in reasons[2:]))
        service.close()
        self.assertEqual(process.kill_calls, 2)
        coordinator.close(timeout=1)

    def test_stubborn_factory_cleanup_fences_recovery_until_retry_reaps(self) -> None:
        initial_request = _request()
        stable_identity = "target-sha256:" + "1" * 64
        with patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value=stable_identity,
        ):
            process_factory = PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory"
            )
            custom_evidence_service_digest = "sha256:" + "f" * 64
            request = replace(
                initial_request,
                evidence_service_digest=process_factory.evidence_service_digest(
                    custom_evidence_service_digest
                ),
                request_digest="",
            )
            runner = ConfiguredPrivateAnalysisInProcessRunner(
                initial_request.runner,
                instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                model_callback=lambda _context, _gateway: (
                    private_analysis_result_json(_unsupported_result(request))
                ),
            )
            registration = PrivateAnalysisRunnerRegistration(
                runner,
                tool_service_process_factory=process_factory,
                custom_evidence_service_digest=custom_evidence_service_digest,
            )
            self.assertEqual(
                registration.evidence_service_digest,
                request.evidence_service_digest,
            )
            queued = self._created(request, "run-stubborn-cleanup")
            coordinator = PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(registration,),
                limits=_limits(),
            )
            process = _StubbornFactoryProcess(stop_after_kills=3)
            service = PrivateAnalysisRemoteToolService(
                request,
                process=process,
                connection=_FactoryConnection(),
                cancellation_probe=lambda: False,
                deadline_ns=time.monotonic_ns() + 1_000_000_000,
                poll_interval_ns=1_000_000,
            )
            with (
                patch(
                    "router_dump_analyzer.private_analysis_execution."
                    "start_private_analysis_tool_service_process",
                    return_value=service,
                ),
                self.assertRaisesRegex(
                    PrivateAnalysisExecutionUnavailable,
                    "cleanup is pending",
                ),
            ):
                coordinator.execute_run(
                    request.scope,
                    queued.run_id,
                    expected_version=queued.version,
                    actor_id="worker-1",
                )

        active = self.store.get_run(request.scope, queued.run_id)
        self.assertIs(active.state, PrivateAnalysisRunState.RUNNING)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        fence = self.store.get_cleanup_fence(request.scope, queued.run_id)
        self.assertIsNotNone(fence)
        assert active.lease_expires_at_ns is not None
        self.assertEqual(
            self.store.recover_expired_runs(
                actor_id="generic-recovery",
                now_ns=active.lease_expires_at_ns + 1,
            ),
            (),
        )

        # A coordinator reconstructed from durable state has neither the live
        # process handle nor its unpersisted deletion capability.  Even after
        # lease expiry it can diagnose the fence but cannot terminalize it.
        with patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value=stable_identity,
        ):
            restarted = PrivateAnalysisExecutionCoordinator(
                self.store,
                registrations=(registration,),
                limits=_limits(),
            )
        self.assertEqual(restarted.locally_owned_cleanup_count, 0)
        with patch(
            "router_dump_analyzer.private_analysis_run_store.time.time_ns",
            return_value=active.lease_expires_at_ns + 1,
        ):
            self.assertEqual(
                restarted.recover_expired_runs(actor_id="restarted-recovery"),
                (),
            )
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        restarted.close(timeout=1)

        # Coordinator recovery performs one bounded retry, then delegates to
        # the same generic expiry recovery.  The still-live child keeps the
        # durable row nonterminal across both operations.
        self.assertEqual(
            coordinator.recover_expired_runs(actor_id="generic-recovery"),
            (),
        )
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertEqual(process.kill_calls, 2)

        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertEqual(process.kill_calls, 3)
        coordinator.close(timeout=1)

    def test_bootstrap_reap_failure_retains_exact_handle_for_retry(self) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-bootstrap-handle-retry")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        process = _StubbornFactoryProcess(stop_after_kills=2)
        owner = factory_process_module.PrivateAnalysisFactoryProcessCleanupOwner(
            process
        )
        with self.assertRaises(PrivateAnalysisFactoryProcessCleanupError) as raised:
            owner.close()
        cleanup_error = raised.exception
        self.assertIs(cleanup_error.cleanup_owner, owner)
        self.assertEqual(process.kill_calls, 1)

        with (
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process",
                side_effect=cleanup_error,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisExecutionUnavailable,
                "factory process did not stop",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertEqual(process.kill_calls, 2)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_factory_fence_begin_post_commit_retains_capability_for_retry(
        self,
    ) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-factory-begin-post-commit")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        real_begin = SqlitePrivateAnalysisRunStore.begin_cleanup_fence

        def commit_then_fail(store: Any, *args: Any, **kwargs: Any) -> Any:
            real_begin(store, *args, **kwargs)
            raise RuntimeError("synthetic begin post-commit failure")

        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "begin_cleanup_fence",
                new=commit_then_fail,
            ),
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch,
            self.assertRaisesRegex(
                PrivateAnalysisExecutionUnavailable,
                "fence commit was ambiguous",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        launch.assert_not_called()
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIsNone(finalized[0].transcript_summary)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_control_after_fence_commit_before_handle_retains_prelaunch_journal(
        self,
    ) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-prelaunch-control-gap")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        real_begin = (
            PrivateAnalysisExecutionCoordinator._begin_prelaunch_cleanup_fence
        )

        def commit_then_interrupt(owner: Any, pending: Any) -> None:
            real_begin(owner, pending)
            raise KeyboardInterrupt("synthetic post-fence prelaunch control")

        with (
            patch.object(
                PrivateAnalysisExecutionCoordinator,
                "_begin_prelaunch_cleanup_fence",
                new=commit_then_interrupt,
            ),
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch,
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic post-fence prelaunch control",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        launch.assert_not_called()
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "finalize_unstarted_attempt",
                side_effect=RuntimeError("synthetic finalization unavailable"),
            ),
            self.assertRaises(PrivateAnalysisExecutionCloseTimeout),
        ):
            coordinator.close(timeout=0)
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(finalized[0].transcript_summary)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        coordinator.close(timeout=1)

    def test_local_fence_begin_post_commit_retains_capability_for_retry(
        self,
    ) -> None:
        try:
            from tests.test_private_ai_subprocess_runner import _build_case, _service
        except ModuleNotFoundError:
            from test_private_ai_subprocess_runner import (  # type: ignore[no-redef]
                _build_case,
                _service,
            )

        child_directory = Path(self.temporary.name) / "local-begin-post-commit"
        child_directory.mkdir()
        case = _build_case(child_directory)
        queued = self._created(case.request, "run-local-begin-post-commit")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        real_begin = SqlitePrivateAnalysisRunStore.begin_cleanup_fence

        def commit_then_fail(store: Any, *args: Any, **kwargs: Any) -> Any:
            real_begin(store, *args, **kwargs)
            raise RuntimeError("synthetic local begin post-commit failure")

        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "begin_cleanup_fence",
                new=commit_then_fail,
            ),
            patch.object(subprocess_runner_module, "_spawn_local_child") as spawn,
            self.assertRaisesRegex(
                PrivateAnalysisExecutionUnavailable,
                "fence commit was ambiguous",
            ),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        spawn.assert_not_called()
        self.assertTrue(
            self.store.get_run(case.request.scope, queued.run_id).cleanup_pending
        )
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIsNone(finalized[0].transcript_summary)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        coordinator.close(timeout=1)

    def test_absent_failed_fence_begin_does_not_invent_cleanup_owner(self) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-absent-begin")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "begin_cleanup_fence",
                side_effect=RuntimeError("synthetic pre-commit begin failure"),
            ),
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch,
            self.assertRaises(PrivateAnalysisExecutionUnavailable),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        launch.assert_not_called()
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_mismatched_fence_begin_discards_uncommitted_prelaunch_journal(
        self,
    ) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-mismatched-begin")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        real_begin = SqlitePrivateAnalysisRunStore.begin_cleanup_fence

        def install_mismatched_fence(
            store: Any,
            scope: Any,
            run_id: str,
            **kwargs: Any,
        ) -> Any:
            real_begin(
                store,
                scope,
                run_id,
                execution_id=kwargs["execution_id"],
                cleanup_capability="cleanup-capability-v1:" + "9" * 64,
            )
            raise PrivateAnalysisRunConflict("synthetic mismatched fence")

        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "begin_cleanup_fence",
                new=install_mismatched_fence,
            ),
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process"
            ) as launch,
            self.assertRaises(PrivateAnalysisExecutionUnavailable),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        launch.assert_not_called()
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_unstarted_atomic_cleanup_control_retains_finalization_intent(
        self,
    ) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-unstarted-fence-clear")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        real_finalize = SqlitePrivateAnalysisRunStore.finalize_unstarted_attempt
        finalize_calls = 0

        def finalize_then_interrupt(store: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal finalize_calls
            finalize_calls += 1
            result = real_finalize(store, *args, **kwargs)
            if finalize_calls == 1:
                raise KeyboardInterrupt("synthetic unstarted terminal commit")
            return result

        preparation_error = (
            factory_process_module.PrivateAnalysisFactoryPreparationFailed(
                "synthetic preparation failure"
            )
        )
        with (
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process",
                side_effect=preparation_error,
            ),
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "finalize_unstarted_attempt",
                new=finalize_then_interrupt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic unstarted terminal commit",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertIs(
            self.store.get_run(request.scope, queued.run_id).state,
            PrivateAnalysisRunState.COMPLETED,
        )
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(finalized[0].transcript_summary)
        self.assertEqual(
            self.store.list_audit(request.scope, queued.run_id)[-1].reason.value,
            "failed_before_runner",
        )
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_factory_failure_after_deadline_is_recorded_as_timeout(self) -> None:
        request = _request(limits=_request_limits(deadline_ms=1))
        queued = self._created(request)
        callback_called = False

        def callback(_context: Any, _gateway: Any) -> str:
            nonlocal callback_called
            callback_called = True
            return "{}"

        def late_failure(_request: Any) -> Any:
            time.sleep(0.1)
            raise RuntimeError("late local evidence preparation")

        coordinator = self._coordinator(
            request,
            callback,
            factory=late_failure,
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
        self.assertIs(terminal.outcome.error.code, PrivateAnalysisErrorCode.TIMEOUT)

    def test_process_factory_success_is_reaped_after_runner_completion(self) -> None:
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-process-factory")
        before = {
            child.pid
            for child in multiprocessing.active_children()
            if child.name.startswith("private-analysis-evidence-factory-")
        }

        def callback(_context: Any, _gateway: Any) -> str:
            return private_analysis_result_json(_unsupported_result(request))

        coordinator = self._coordinator(
            request,
            callback,
            process_factory=process_factory,
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(terminal.transcript_summary)
        self.assertEqual(
            {
                child.pid
                for child in multiprocessing.active_children()
                if child.name.startswith("private-analysis-evidence-factory-")
            },
            before,
        )

    def test_remote_atomic_receipt_control_reconciles_and_retries(self) -> None:
        identity_patch = patch(
            "router_dump_analyzer.private_analysis_factory_process."
            "_resolve_factory_executable_identity",
            return_value="target-sha256:" + "1" * 64,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory"
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-remote-receipt-fence-clear")

        result_json = private_analysis_result_json(_unsupported_result(request))

        def callback(_context: Any, _gateway: Any) -> str:
            return result_json

        coordinator = self._coordinator(
            request,
            callback,
            process_factory=process_factory,
        )
        service = PrivateAnalysisRemoteToolService(
            request,
            process=_StubbornFactoryProcess(stop_after_kills=1),
            connection=_FactoryConnection(),
            cancellation_probe=lambda: False,
            deadline_ns=time.monotonic_ns() + 1_000_000_000,
            poll_interval_ns=1_000_000,
        )
        real_complete = SqlitePrivateAnalysisRunStore.complete_run
        complete_calls = 0

        def complete_then_interrupt(store: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal complete_calls
            complete_calls += 1
            result = real_complete(store, *args, **kwargs)
            if complete_calls == 1:
                raise KeyboardInterrupt("synthetic remote terminal commit")
            return result

        with (
            patch(
                "router_dump_analyzer.private_analysis_execution."
                "start_private_analysis_tool_service_process",
                return_value=service,
            ),
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "complete_run",
                new=complete_then_interrupt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic remote terminal commit",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertIs(
            self.store.get_run(request.scope, queued.run_id).state,
            PrivateAnalysisRunState.COMPLETED,
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(finalized[0].transcript_summary)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_process_factory_proxy_preserves_write_ahead_accounting(self) -> None:
        reference = _reference()
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory",
            strict_canonical_json(
                {"references": [evidence_reference_dict(reference)]}
            ),
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-process-factory-accounting")

        def callback(_context: Any, gateway: Any) -> str:
            response = gateway.execute(
                private_analysis_tool_call_json(_query_call(request))
            )
            self.assertIsNotNone(response.result)
            durable = self.store.get_run(request.scope, queued.run_id)
            self.assertEqual(durable.disclosed_references, (reference,))
            self.assertEqual(durable.budget_state.tool_calls_consumed, 1)
            return private_analysis_result_json(_supported_result(request, reference))

        coordinator = self._coordinator(
            request,
            callback,
            process_factory=process_factory,
        )
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertEqual(terminal.disclosed_references, (reference,))
        self.assertEqual(terminal.budget_state.tool_calls_consumed, 1)

    def test_in_process_receipt_control_preserves_started_remote_accounting(
        self,
    ) -> None:
        reference = _reference()
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "configured_service_factory",
            strict_canonical_json(
                {"references": [evidence_reference_dict(reference)]}
            ),
        )
        request = replace(
            _request(),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-in-process-receipt-control")

        def callback(_context: Any, gateway: Any) -> str:
            response = gateway.execute(
                private_analysis_tool_call_json(_query_call(request))
            )
            self.assertIsNotNone(response.result)
            return private_analysis_result_json(_supported_result(request, reference))

        coordinator = self._coordinator(
            request,
            callback,
            process_factory=process_factory,
        )
        internal_runner = next(iter(coordinator._routes.values())).registration.runner
        self.assertIs(
            type(internal_runner),
            ConfiguredPrivateAnalysisInProcessRunner,
        )
        assert type(internal_runner) is ConfiguredPrivateAnalysisInProcessRunner
        real_receipt = in_process_runner_module._deadline_checked_execution_receipt
        receipt_calls = 0

        def interrupt_first_receipt(*args: Any, **kwargs: Any) -> Any:
            nonlocal receipt_calls
            receipt_calls += 1
            if receipt_calls == 1:
                raise KeyboardInterrupt("synthetic in-process receipt control")
            return real_receipt(*args, **kwargs)

        with (
            patch.object(
                in_process_runner_module,
                "_deadline_checked_execution_receipt",
                new=interrupt_first_receipt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic in-process receipt control",
            ),
        ):
            coordinator.execute_run(
                request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        active = self.store.get_run(request.scope, queued.run_id)
        self.assertIs(active.state, PrivateAnalysisRunState.RUNNING)
        self.assertEqual(active.disclosed_references, (reference,))
        self.assertEqual(active.budget_state.tool_calls_consumed, 1)
        self.assertTrue(internal_runner.receipt_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertNotIn(
            "failed_before_runner",
            tuple(
                item.reason.value
                for item in self.store.list_audit(request.scope, queued.run_id)
            ),
        )

        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        terminal = finalized[0]
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertEqual(terminal.disclosed_references, (reference,))
        self.assertEqual(terminal.budget_state.tool_calls_consumed, 1)
        self.assertIsNotNone(terminal.transcript_summary)
        assert terminal.transcript_summary is not None
        self.assertEqual(terminal.transcript_summary.metadata.exchange_count, 1)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(
            terminal.outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        self.assertFalse(internal_runner.receipt_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNone(
            self.store.get_cleanup_fence(request.scope, queued.run_id)
        )
        self.assertEqual(receipt_calls, 1)
        coordinator.close(timeout=1)

    def test_non_returning_process_factory_is_killed_at_preparation_deadline(
        self,
    ) -> None:
        marker = Path(self.temporary.name) / "factory-timeout-started.txt"
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "non_returning_service_factory",
            strict_canonical_json({"marker": str(marker)}),
        )
        request = replace(
            _request(limits=_request_limits(deadline_ms=50)),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-process-factory-timeout")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        started = time.monotonic()
        terminal = coordinator.execute_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker-1",
        )
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNone(terminal.transcript_summary)
        assert terminal.outcome is not None and terminal.outcome.error is not None
        self.assertIs(terminal.outcome.error.code, PrivateAnalysisErrorCode.TIMEOUT)
        self.assertFalse(
            any(
                child.name.startswith("private-analysis-evidence-factory-")
                for child in multiprocessing.active_children()
            )
        )

    def test_process_factory_observes_durable_cancellation_and_is_reaped(self) -> None:
        marker = Path(self.temporary.name) / "factory-cancel-started.txt"
        process_factory = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "non_returning_service_factory",
            strict_canonical_json({"marker": str(marker)}),
        )
        request = replace(
            _request(limits=_request_limits(deadline_ms=5_000)),
            evidence_service_digest=process_factory.evidence_service_digest(
                "sha256:" + "f" * 64
            ),
            request_digest="",
        )
        queued = self._created(request, "run-process-factory-cancel")
        coordinator = self._coordinator(
            request,
            lambda _context, _gateway: self.fail("runner must not start"),
            process_factory=process_factory,
        )
        results: list[object] = []

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

        worker = threading.Thread(target=execute, daemon=False)
        worker.start()
        deadline = time.monotonic() + 3.0
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists())
        cancellation_deadline = time.monotonic() + 2.0
        while True:
            running = self.store.get_run(request.scope, queued.run_id)
            try:
                coordinator.request_cancellation(
                    request.scope,
                    queued.run_id,
                    expected_version=running.version,
                    actor_id="operator-1",
                )
                break
            except PrivateAnalysisRunStaleVersion:
                if time.monotonic() >= cancellation_deadline:
                    raise
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        self.assertNotIsInstance(results[0], BaseException)
        terminal = results[0]
        self.assertIs(getattr(terminal, "state", None), PrivateAnalysisRunState.CANCELLED)
        self.assertFalse(
            any(
                child.name.startswith("private-analysis-evidence-factory-")
                for child in multiprocessing.active_children()
            )
        )

    def test_process_factory_bootstrap_and_ipc_never_use_pickle_payloads(self) -> None:
        pickle_called = False

        class HostilePickleValue:
            def __reduce__(self) -> object:
                nonlocal pickle_called
                pickle_called = True
                raise AssertionError("pickle hook must not run")

        with self.assertRaises(TypeError):
            PrivateAnalysisToolServiceProcessFactory(
                "tests.support.private_analysis_factory_fixture:"
                "configured_service_factory",
                HostilePickleValue(),  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisToolServiceProcessFactory(
                HostilePickleValue(),  # type: ignore[arg-type]
            )
        self.assertFalse(pickle_called)
        with self.assertRaises(ValueError):
            _decode_message(b'{"kind":"ready", "contract_version":"bad"}')
        with self.assertRaises(ValueError):
            _exact_message(
                {"contract_version": "bad", "kind": "ready"},
                kind="ready",
                fields=frozenset({"contract_version", "kind", "request_digest"}),
            )

    def test_process_factory_contains_child_process_control_and_malformed_service(
        self,
    ) -> None:
        for label, target in (
            ("process-control", "process_control_service_factory"),
            ("malformed-service", "malformed_service_factory"),
        ):
            with self.subTest(label=label):
                process_factory = PrivateAnalysisToolServiceProcessFactory(
                    "tests.support.private_analysis_factory_fixture:" + target
                )
                request = replace(
                    _request(),
                    evidence_service_digest=process_factory.evidence_service_digest(
                        "sha256:" + "f" * 64
                    ),
                    request_digest="",
                )
                queued = self._created(request, "run-contained-" + label)
                coordinator = self._coordinator(
                    request,
                    lambda _context, _gateway: self.fail("runner must not start"),
                    process_factory=process_factory,
                )
                terminal = coordinator.execute_run(
                    request.scope,
                    queued.run_id,
                    expected_version=queued.version,
                    actor_id="worker-1",
                )
                self.assertIs(terminal.state, PrivateAnalysisRunState.COMPLETED)
                self.assertIsNone(terminal.transcript_summary)
                assert (
                    terminal.outcome is not None
                    and terminal.outcome.error is not None
                )
                self.assertIs(
                    terminal.outcome.error.code,
                    PrivateAnalysisErrorCode.RUNNER_FAILED,
                )
                self.assertNotIn("secret-provider", repr(terminal))

        # The former malformed-IPC fixture monkeypatches a locally imported
        # core sender. Runtime-import identity now rejects that executable
        # mutation before child launch, which is the stronger boundary. Wire
        # decoder rejection remains covered by the lower-level framing tests.
        malformed_ipc = PrivateAnalysisToolServiceProcessFactory(
            "tests.support.private_analysis_factory_fixture:"
            "malformed_ipc_service_factory"
        )
        with self.assertRaises(PrivateAnalysisFactoryExecutableIdentityError):
            malformed_ipc.evidence_service_digest("sha256:" + "f" * 64)
        self.assertFalse(
            any(
                child.name.startswith("private-analysis-evidence-factory-")
                for child in multiprocessing.active_children()
            )
        )

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
            custom_evidence_service_digest="sha256:" + "f" * 64,
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
        factory_count = {"value": 0}
        callback_count = {"value": 0}
        count_lock = threading.Lock()
        harness = _Harness(request)

        def callback(_context: Any, _gateway: Any) -> str:
            with count_lock:
                callback_count["value"] += 1
            entered.set()
            self.assertTrue(release.wait(2))
            return private_analysis_result_json(_unsupported_result(request))

        def factory(_request: Any) -> Any:
            with count_lock:
                factory_count["value"] += 1
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
        self.assertEqual(factory_count["value"], 1)
        self.assertEqual(callback_count["value"], 1)
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
                    custom_evidence_service_digest="sha256:" + "f" * 64,
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
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )

    def test_local_atomic_receipt_control_reconciles_and_retries(self) -> None:
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

        child_directory = Path(self.temporary.name) / "local-fence-clear"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "run-local-receipt-fence-clear")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        real_complete = SqlitePrivateAnalysisRunStore.complete_run
        complete_calls = 0

        def complete_then_interrupt(store: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal complete_calls
            complete_calls += 1
            result = real_complete(store, *args, **kwargs)
            if complete_calls == 1:
                raise KeyboardInterrupt("synthetic local terminal commit")
            return result

        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "complete_run",
                new=complete_then_interrupt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic local terminal commit",
            ),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        active = self.store.get_run(case.request.scope, queued.run_id)
        self.assertIs(active.state, PrivateAnalysisRunState.COMPLETED)
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(finalized[0].transcript_summary)
        assert finalized[0].outcome is not None
        self.assertIs(finalized[0].outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_terminal_store_failure_retains_withheld_receipt_for_retry(self) -> None:
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

        child_directory = Path(self.temporary.name) / "terminal-retry"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "run-terminal-retry")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        real_complete = SqlitePrivateAnalysisRunStore.complete_run
        complete_calls = 0

        def fail_once(store: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal complete_calls
            complete_calls += 1
            if complete_calls == 1:
                real_complete(store, *args, **kwargs)
                raise RuntimeError("synthetic terminal store failure")
            return real_complete(store, *args, **kwargs)

        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "complete_run",
                new=fail_once,
            ),
            self.assertRaisesRegex(RuntimeError, "terminal store failure"),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        self.assertIs(
            self.store.get_run(case.request.scope, queued.run_id).state,
            PrivateAnalysisRunState.COMPLETED,
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIsNotNone(finalized[0].transcript_summary)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        coordinator.close(timeout=1)

    def test_withheld_receipt_fence_blocks_recovery_past_lease_expiry(
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

        child_directory = Path(self.temporary.name) / "withheld-expired-retry"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "run-withheld-expired-retry")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        with (
            patch.object(
                SqlitePrivateAnalysisRunStore,
                "complete_run",
                side_effect=RuntimeError("synthetic terminal pre-commit failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "terminal pre-commit failure"),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        active = self.store.get_run(case.request.scope, queued.run_id)
        self.assertTrue(active.cleanup_pending)
        self.assertIsNotNone(active.lease_expires_at_ns)
        assert active.lease_expires_at_ns is not None
        expired_now = active.lease_expires_at_ns + 1
        self.assertEqual(
            self.store.recover_expired_runs(
                actor_id="generic-recovery",
                now_ns=expired_now,
            ),
            (),
        )
        with patch(
            "router_dump_analyzer.private_analysis_run_store.time.time_ns",
            return_value=expired_now,
        ):
            finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(finalized[0].transcript_summary)
        self.assertEqual(
            self.store.list_audit(case.request.scope, queued.run_id)[-1].reason.value,
            "completed",
        )
        self.assertFalse(finalized[0].cleanup_pending)
        coordinator.close(timeout=1)

    def test_local_cleanup_control_keeps_session_and_durable_fence(self) -> None:
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

        child_directory = Path(self.temporary.name) / "local-cleanup-control"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "run-local-cleanup-control")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )

        with (
            patch.object(
                subprocess_runner_module._LocalChildSession,
                "cleanup",
                side_effect=KeyboardInterrupt("synthetic session cleanup"),
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic session cleanup",
            ),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertTrue(case.runner.cleanup_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(finalized[0].transcript_summary)
        self.assertEqual(
            self.store.list_audit(case.request.scope, queued.run_id)[-1].reason.value,
            "completed",
        )
        self.assertFalse(case.runner.cleanup_pending)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

    def test_receipt_sealing_control_retries_with_started_runner_transcript(
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

        child_directory = Path(self.temporary.name) / "receipt-control"
        child_directory.mkdir()
        case = _build_case(child_directory)
        _write_control(
            case.control_path,
            _zero_tool_actions(case, _unsupported_result(case.request)),
        )
        queued = self._created(case.request, "run-receipt-control")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        real_receipt = subprocess_runner_module._deadline_checked_execution_receipt
        receipt_calls = 0

        def interrupt_first_receipt(*args: Any, **kwargs: Any) -> Any:
            nonlocal receipt_calls
            receipt_calls += 1
            if receipt_calls == 1:
                raise KeyboardInterrupt("synthetic coordinator receipt control")
            return real_receipt(*args, **kwargs)

        with (
            patch.object(
                subprocess_runner_module,
                "_deadline_checked_execution_receipt",
                new=interrupt_first_receipt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic coordinator receipt control",
            ),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertTrue(case.runner.cleanup_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertIsNotNone(finalized[0].transcript_summary)
        assert finalized[0].outcome is not None
        assert finalized[0].outcome.error is not None
        self.assertIs(
            finalized[0].outcome.error.code,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        self.assertEqual(
            self.store.list_audit(case.request.scope, queued.run_id)[-1].reason.value,
            "completed",
        )
        self.assertFalse(case.runner.cleanup_pending)
        coordinator.close(timeout=1)

    def test_live_model_child_fences_terminalization_until_handle_retry(
        self,
    ) -> None:
        try:
            from tests.test_private_ai_subprocess_runner import (
                _build_case,
                _service,
            )
        except ModuleNotFoundError:
            from test_private_ai_subprocess_runner import (  # type: ignore[no-redef]
                _build_case,
                _service,
            )

        child_directory = Path(self.temporary.name) / "pending-model-child"
        child_directory.mkdir()
        case = _build_case(child_directory)
        queued = self._created(case.request, "subprocess-cleanup-pending")
        coordinator = PrivateAnalysisExecutionCoordinator(
            self.store,
            registrations=(
                PrivateAnalysisRunnerRegistration(
                    case.runner,
                    lambda _request: _service(case)[0],
                    custom_evidence_service_digest="sha256:" + "f" * 64,
                ),
            ),
            limits=_limits(),
        )
        processes: list[subprocess.Popen[bytes]] = []
        real_popen = subprocess.Popen

        def capture_spawn(*args: object, **kwargs: object) -> Any:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        runner_failure = subprocess_runner_module._static_runner_error(
            case.request,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
        with (
            patch(
                "router_dump_analyzer.private_analysis_subprocess_runner."
                "subprocess.Popen",
                new=capture_spawn,
            ),
            patch.object(
                subprocess_runner_module.ConfiguredPrivateAnalysisSubprocessRunner,
                "_drive_protocol",
                return_value=(runner_failure, None),
            ),
            patch.object(
                subprocess_runner_module._LocalChildSession,
                "cleanup",
                return_value=False,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisExecutionUnavailable,
                "subprocess cleanup is pending",
            ),
        ):
            coordinator.execute_run(
                case.request.scope,
                queued.run_id,
                expected_version=queued.version,
                actor_id="worker-1",
            )

        self.assertEqual(len(processes), 1)
        self.assertIsNone(processes[0].poll())
        active = self.store.get_run(case.request.scope, queued.run_id)
        self.assertIs(active.state, PrivateAnalysisRunState.RUNNING)
        self.assertIsNone(active.outcome)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        assert active.lease_expires_at_ns is not None
        self.assertEqual(
            self.store.recover_expired_runs(
                actor_id="generic-recovery",
                now_ns=active.lease_expires_at_ns + 1,
            ),
            (),
        )
        cancellation = coordinator.request_cancellation(
            case.request.scope,
            queued.run_id,
            expected_version=active.version,
            actor_id="operator-1",
        )
        self.assertIs(cancellation.state, PrivateAnalysisRunState.CANCEL_REQUESTED)

        real_reseal = (
            subprocess_runner_module.PrivateAnalysisSubprocessExecutionReceipt
            ._with_cleanup_attested
        )
        reseal_calls = 0

        def interrupt_reseal_once(receipt: Any) -> Any:
            nonlocal reseal_calls
            reseal_calls += 1
            if reseal_calls == 1:
                raise KeyboardInterrupt("synthetic receipt reseal interruption")
            return real_reseal(receipt)

        with (
            patch.object(
                subprocess_runner_module.PrivateAnalysisSubprocessExecutionReceipt,
                "_with_cleanup_attested",
                new=interrupt_reseal_once,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "receipt reseal interruption",
            ),
        ):
            coordinator.retry_pending_cleanup()

        self.assertTrue(case.runner.cleanup_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNotNone(processes[0].poll())
        real_acknowledge = (
            subprocess_runner_module.ConfiguredPrivateAnalysisSubprocessRunner
            .acknowledge_pending_cleanup
        )

        def acknowledge_then_interrupt(runner: Any) -> None:
            real_acknowledge(runner)
            raise KeyboardInterrupt("synthetic coordinator handoff interruption")

        with (
            patch.object(
                subprocess_runner_module.ConfiguredPrivateAnalysisSubprocessRunner,
                "acknowledge_pending_cleanup",
                new=acknowledge_then_interrupt,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "coordinator handoff interruption",
            ),
        ):
            coordinator.retry_pending_cleanup()

        self.assertFalse(case.runner.cleanup_pending)
        self.assertEqual(coordinator.locally_owned_cleanup_count, 1)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        finalized = coordinator.retry_pending_cleanup()
        self.assertEqual(len(finalized), 1)
        self.assertIs(finalized[0].state, PrivateAnalysisRunState.CANCELLED)
        assert finalized[0].outcome is not None
        assert finalized[0].outcome.error is not None
        self.assertIs(
            finalized[0].outcome.error.code,
            PrivateAnalysisErrorCode.CANCELLED,
        )
        self.assertIsNotNone(processes[0].poll())
        self.assertEqual(coordinator.locally_owned_cleanup_count, 0)
        self.assertIsNone(
            self.store.get_cleanup_fence(case.request.scope, queued.run_id)
        )
        coordinator.close(timeout=1)

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
