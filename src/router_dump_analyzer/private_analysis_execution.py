"""Core-owned execution of already-admitted private-analysis runs.

The coordinator is intentionally a synchronous local-library boundary.  It
does not discover plug-ins, configure providers, schedule retries, expose an
HTTP endpoint, or create model credentials.  It binds one durable request to
one exact, operator-configured runner and keeps disclosure accounting ahead of
every tool response.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final
from uuid import uuid4

from .private_analysis import (
    EvidenceReference,
    EvidenceScope,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
)
from .private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessExecutionReceipt,
)
from .private_analysis_run_store import (
    PrivateAnalysisRunRecord,
    PrivateAnalysisRunStaleVersion,
    PrivateAnalysisRunState,
    SqlitePrivateAnalysisRunStore,
)
from .private_analysis_subprocess_runner import (
    ConfiguredPrivateAnalysisSubprocessRunner,
    PrivateAnalysisSubprocessExecutionReceipt,
)
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolService,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

type CorePrivateAnalysisRunner = (
    ConfiguredPrivateAnalysisInProcessRunner | ConfiguredPrivateAnalysisSubprocessRunner
)
type PrivateAnalysisExecutionReceipt = (
    PrivateAnalysisInProcessExecutionReceipt | PrivateAnalysisSubprocessExecutionReceipt
)
type PrivateAnalysisToolServiceFactory = Callable[
    [PrivateAnalysisRequest], PrivateAnalysisToolService
]

_RUNNER_TYPES: Final = (
    ConfiguredPrivateAnalysisInProcessRunner,
    ConfiguredPrivateAnalysisSubprocessRunner,
)
_MAX_CONCURRENT_RUNS: Final = 256
_MAX_LEASE_DURATION_NS: Final = 24 * 60 * 60 * 1_000_000_000
_MAX_INTERVAL_NS: Final = 60 * 1_000_000_000
_MAX_ACTOR_CHARACTERS: Final = 256


class PrivateAnalysisExecutionError(RuntimeError):
    """Base class for payload-free local coordinator failures."""


class PrivateAnalysisExecutionUnavailable(PrivateAnalysisExecutionError):
    """The exact runner or durable execution attempt is unavailable."""


class PrivateAnalysisExecutionClosed(PrivateAnalysisExecutionError):
    """The local coordinator is closing or closed."""


class PrivateAnalysisExecutionCloseTimeout(PrivateAnalysisExecutionError):
    """Active cooperative executions did not finish within the close bound."""


class _AttemptLost(PrivateAnalysisExecutionUnavailable):
    pass


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _actor_id(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_ACTOR_CHARACTERS
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("actor_id must be bounded visible text")
    return value


def _runner_key(
    value: PrivateAnalysisRunnerSelection,
) -> tuple[str, str, object, str]:
    if type(value) is not PrivateAnalysisRunnerSelection:
        raise TypeError("runner selection must be PrivateAnalysisRunnerSelection")
    return (
        value.runner_id,
        value.runner_version,
        value.transport,
        value.configuration_digest,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunnerRegistration:
    """One exact runner and its trusted request-bound service factory."""

    runner: CorePrivateAnalysisRunner
    tool_service_factory: PrivateAnalysisToolServiceFactory

    def __post_init__(self) -> None:
        if type(self.runner) not in _RUNNER_TYPES:
            raise TypeError(
                "runner must be an exact configured private-analysis runner"
            )
        if not callable(self.tool_service_factory):
            raise TypeError("tool_service_factory must be callable")


@dataclass(frozen=True, slots=True)
class PrivateAnalysisExecutionLimits:
    """Bounded local concurrency, lease, and cancellation polling controls."""

    max_concurrent_runs: int = 8
    lease_duration_ns: int = 30_000_000_000
    heartbeat_interval_ns: int = 10_000_000_000
    cancellation_poll_interval_ns: int = 250_000_000
    monitor_join_timeout_ns: int = 10_000_000_000

    def __post_init__(self) -> None:
        _bounded_integer(
            self.max_concurrent_runs,
            "max_concurrent_runs",
            minimum=1,
            maximum=_MAX_CONCURRENT_RUNS,
        )
        lease = _bounded_integer(
            self.lease_duration_ns,
            "lease_duration_ns",
            minimum=1_000_000,
            maximum=_MAX_LEASE_DURATION_NS,
        )
        heartbeat = _bounded_integer(
            self.heartbeat_interval_ns,
            "heartbeat_interval_ns",
            minimum=1_000_000,
            maximum=_MAX_INTERVAL_NS,
        )
        poll = _bounded_integer(
            self.cancellation_poll_interval_ns,
            "cancellation_poll_interval_ns",
            minimum=1_000_000,
            maximum=_MAX_INTERVAL_NS,
        )
        _bounded_integer(
            self.monitor_join_timeout_ns,
            "monitor_join_timeout_ns",
            minimum=1_000_000,
            maximum=_MAX_INTERVAL_NS,
        )
        if heartbeat >= lease:
            raise ValueError("heartbeat_interval_ns must be shorter than the lease")
        if poll > heartbeat:
            raise ValueError(
                "cancellation_poll_interval_ns must not exceed the heartbeat interval"
            )


@dataclass(slots=True)
class _RegisteredRunner:
    registration: PrivateAnalysisRunnerRegistration


class _DurableExecutionAttempt:
    """Single owner of one execution fence and its optimistic run version."""

    __slots__ = (
        "_actor_id",
        "_cancellation",
        "_failure",
        "_limits",
        "_lock",
        "_monitor",
        "_monitor_exit",
        "_record",
        "_scope",
        "_stop",
        "_store",
    )

    def __init__(
        self,
        store: SqlitePrivateAnalysisRunStore,
        record: PrivateAnalysisRunRecord,
        *,
        actor_id: str,
        limits: PrivateAnalysisExecutionLimits,
        monitor_exit: Callable[[_DurableExecutionAttempt], None],
    ) -> None:
        if record.execution_id is None:
            raise ValueError("claimed run must have an execution fence")
        self._store = store
        self._record = record
        self._scope = record.scope
        self._actor_id = actor_id
        self._limits = limits
        self._monitor_exit = monitor_exit
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._cancellation = threading.Event()
        self._failure = threading.Event()
        self._monitor: threading.Thread | None = None

    @property
    def record(self) -> PrivateAnalysisRunRecord:
        with self._lock:
            return self._record

    @property
    def execution_id(self) -> str:
        value = self._record.execution_id
        if value is None:
            raise _AttemptLost("private-analysis execution fence was lost")
        return value

    def start_monitor(self) -> None:
        with self._lock:
            if self._monitor is not None:
                raise RuntimeError("private-analysis monitor already started")
            monitor = threading.Thread(
                target=self._monitor_main,
                name="private-analysis-run-monitor",
                daemon=False,
            )
            self._monitor = monitor
            try:
                monitor.start()
            except BaseException:
                self._monitor_exit(self)
                raise

    def stop_monitor(self) -> None:
        self._stop.set()
        monitor = self._monitor
        if monitor is None:
            return
        monitor.join(self._limits.monitor_join_timeout_ns / 1_000_000_000)
        if monitor.is_alive():
            self._failure.set()
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis execution monitor did not stop"
            )

    def signal_cancellation(
        self, record: PrivateAnalysisRunRecord | None = None
    ) -> None:
        with self._lock:
            if record is not None and record.execution_id == self._record.execution_id:
                self._record = record
            self._cancellation.set()

    def cancellation_probe(self) -> bool:
        if self._failure.is_set():
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis durable execution state is unavailable"
            )
        return self._cancellation.is_set()

    def accounting_observer(
        self,
        references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
    ) -> None:
        with self._lock:
            self._refresh_locked()
            if (
                references != self._record.disclosed_references
                or budget_state != self._record.budget_state
            ):
                self._record = self._mutate_once_locked(
                    lambda version: self._store.commit_accounting(
                        self._scope,
                        self._record.run_id,
                        expected_version=version,
                        execution_id=self.execution_id,
                        references=references,
                        budget_state=budget_state,
                        actor_id=self._actor_id,
                    )
                )
            if self._record.state is PrivateAnalysisRunState.CANCEL_REQUESTED:
                self._cancellation.set()
                # The accounting snapshot publishes its local copy only after
                # this observer returns.  Returning here keeps that snapshot
                # identical to the already-durable ledger; the runner's next
                # cancellation probe performs the cooperative unwind.

    def refresh(self) -> PrivateAnalysisRunRecord:
        with self._lock:
            self._refresh_locked()
            return self._record

    def complete(
        self, receipt: PrivateAnalysisExecutionReceipt
    ) -> PrivateAnalysisRunRecord:
        with self._lock:
            if self._failure.is_set():
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis durable execution state is unavailable"
                )
            execution_id = self.execution_id
            for attempt in range(2):
                self._refresh_locked(allow_terminal=True)
                selected = receipt
                if self._record.state in {
                    PrivateAnalysisRunState.CANCEL_REQUESTED,
                    PrivateAnalysisRunState.CANCELLED,
                }:
                    self._cancellation.set()
                    selected = receipt.as_cancelled()
                try:
                    completed = self._store.complete_run(
                        self._scope,
                        self._record.run_id,
                        expected_version=self._record.version,
                        execution_id=execution_id,
                        outcome=selected.outcome,
                        transcript_summary=selected.transcript_summary,
                        references=selected.disclosed_references,
                        budget_state=selected.budget_state,
                        actor_id=self._actor_id,
                    )
                except PrivateAnalysisRunStaleVersion:
                    if attempt == 0:
                        continue
                    raise
                self._record = completed
                return completed
            raise AssertionError("unreachable completion retry state")

    def finalize_unstarted(self) -> PrivateAnalysisRunRecord:
        with self._lock:
            return self._mutate_once_locked(
                lambda version: self._store.finalize_unstarted_attempt(
                    self._scope,
                    self._record.run_id,
                    expected_version=version,
                    execution_id=self.execution_id,
                    actor_id=self._actor_id,
                )
            )

    def _mutate_once_locked(
        self,
        operation: Callable[[int], PrivateAnalysisRunRecord],
    ) -> PrivateAnalysisRunRecord:
        for attempt in range(2):
            try:
                return operation(self._record.version)
            except PrivateAnalysisRunStaleVersion:
                if attempt != 0:
                    raise
                self._refresh_locked()
        raise AssertionError("unreachable mutation retry state")

    def _refresh_locked(self, *, allow_terminal: bool = False) -> None:
        current = self._store.get_run(self._scope, self._record.run_id)
        if current.state.is_terminal:
            self._record = current
            if allow_terminal:
                return
            raise _AttemptLost("private-analysis run is already terminal")
        if current.execution_id != self._record.execution_id:
            raise _AttemptLost("private-analysis execution fence was lost")
        if current.state not in {
            PrivateAnalysisRunState.RUNNING,
            PrivateAnalysisRunState.CANCEL_REQUESTED,
        }:
            raise _AttemptLost("private-analysis run is not active")
        if (
            current.lease_expires_at_ns is None
            or current.lease_expires_at_ns < time.time_ns()
        ):
            raise _AttemptLost("private-analysis execution lease expired")
        self._record = current
        if current.state is PrivateAnalysisRunState.CANCEL_REQUESTED:
            self._cancellation.set()

    def _monitor_main(self) -> None:
        next_renewal = time.monotonic_ns() + self._limits.heartbeat_interval_ns
        poll_seconds = self._limits.cancellation_poll_interval_ns / 1_000_000_000
        try:
            while not self._stop.wait(poll_seconds):
                with self._lock:
                    self._refresh_locked()
                    now = time.monotonic_ns()
                    if now < next_renewal:
                        continue
                    self._record = self._mutate_once_locked(
                        lambda version: self._store.renew_lease(
                            self._scope,
                            self._record.run_id,
                            expected_version=version,
                            execution_id=self.execution_id,
                            actor_id=self._actor_id,
                            lease_duration_ns=self._limits.lease_duration_ns,
                        )
                    )
                    next_renewal = now + self._limits.heartbeat_interval_ns
        except BaseException:  # noqa: BLE001 - cross-thread failure latch.
            self._failure.set()
        finally:
            self._monitor_exit(self)


class PrivateAnalysisExecutionCoordinator:
    """Route one durable request to one exact local private-analysis runner."""

    def __init__(
        self,
        store: SqlitePrivateAnalysisRunStore,
        *,
        registrations: tuple[PrivateAnalysisRunnerRegistration, ...] = (),
        limits: PrivateAnalysisExecutionLimits | None = None,
    ) -> None:
        if type(store) is not SqlitePrivateAnalysisRunStore:
            raise TypeError("store must be an exact SqlitePrivateAnalysisRunStore")
        if type(registrations) is not tuple:
            raise TypeError("registrations must be a tuple")
        selected_limits = limits or PrivateAnalysisExecutionLimits()
        if type(selected_limits) is not PrivateAnalysisExecutionLimits:
            raise TypeError("limits must be PrivateAnalysisExecutionLimits or None")
        routes: dict[tuple[str, str, object, str], _RegisteredRunner] = {}
        for registration in registrations:
            if type(registration) is not PrivateAnalysisRunnerRegistration:
                raise TypeError(
                    "registrations must contain PrivateAnalysisRunnerRegistration"
                )
            key = _runner_key(registration.runner.selection)
            if key in routes:
                raise ValueError("private-analysis runner selection is duplicated")
            routes[key] = _RegisteredRunner(registration)
        self._store = store
        self._routes = routes
        self._limits = selected_limits
        self._condition = threading.Condition(threading.RLock())
        self._active: dict[tuple[EvidenceScope, str], _DurableExecutionAttempt] = {}
        self._active_count = 0
        self._active_monitor_count = 0
        self._closing = False
        self._closed = False

    def execute_run(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
        execution_id: str | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Claim and execute one exact already-admitted durable run."""

        _bounded_integer(
            expected_version,
            "expected_version",
            minimum=0,
            maximum=(1 << 63) - 1,
        )
        actor = _actor_id(actor_id)
        self._enter_execution()
        durable_attempt: _DurableExecutionAttempt | None = None
        registered: _RegisteredRunner | None = None
        runner_lock_acquired = False
        try:
            record = self._store.get_run(scope, run_id)
            if record.state.is_terminal:
                return record
            if record.state is not PrivateAnalysisRunState.QUEUED:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis run is already active"
                )
            registered = self._routes.get(_runner_key(record.request.runner))
            if registered is None:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis runner is not configured"
                )
            runner = registered.registration.runner
            if (
                runner.instruction_profile_digest
                != record.request.instruction_profile_digest
            ):
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis instruction profile is not configured"
                )
            if not runner.execution_lock.acquire(blocking=False):
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis runner is already executing"
                )
            runner_lock_acquired = True
            claimed = self._store.claim_run(
                scope,
                run_id,
                expected_version=expected_version,
                actor_id=actor,
                lease_duration_ns=self._limits.lease_duration_ns,
                execution_id=execution_id or uuid4().hex,
            )
            durable_attempt = _DurableExecutionAttempt(
                self._store,
                claimed,
                actor_id=actor,
                limits=self._limits,
                monitor_exit=lambda attempt: self._monitor_exited(
                    (claimed.scope, claimed.run_id), attempt
                ),
            )
            self._register_attempt((claimed.scope, claimed.run_id), durable_attempt)
            durable_attempt.start_monitor()
            # Cancellation may commit after the durable claim but before this
            # attempt becomes visible in the local registry.  Reconcile that
            # exact window before constructing or permanently claiming a tool
            # service; subsequent cancellations also signal the registered
            # attempt directly.
            current = durable_attempt.refresh()
            if current.state is PrivateAnalysisRunState.CANCEL_REQUESTED:
                durable_attempt.stop_monitor()
                return durable_attempt.finalize_unstarted()
            try:
                service = registered.registration.tool_service_factory(claimed.request)
                if (
                    type(service) is not PrivateAnalysisToolService
                    or service.request != claimed.request
                    or not service.runner_lease_eligible
                    or service.disclosed_references
                    or any(
                        (
                            service.budget_state.tool_calls_consumed,
                            service.budget_state.evidence_items_disclosed,
                            service.budget_state.evidence_bytes_disclosed,
                        )
                    )
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis tool service does not match the durable request"
                    )
            except PROCESS_CONTROL_EXCEPTIONS:
                try:
                    durable_attempt.stop_monitor()
                except BaseException:  # noqa: BLE001, S110 - preserve control.
                    pass
                raise
            except BaseException:  # noqa: BLE001 - trusted composition boundary.
                durable_attempt.stop_monitor()
                return durable_attempt.finalize_unstarted()

            try:
                receipt = runner.execute(
                    service,
                    accounting_observer=durable_attempt.accounting_observer,
                    cancellation_probe=durable_attempt.cancellation_probe,
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                try:
                    durable_attempt.stop_monitor()
                except BaseException:  # noqa: BLE001, S110 - preserve control.
                    pass
                raise
            except BaseException:  # noqa: BLE001 - exact runner boundary.
                durable_attempt.stop_monitor()
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis runner did not return a valid receipt"
                ) from None
            durable_attempt.stop_monitor()
            return durable_attempt.complete(receipt)
        finally:
            if registered is not None and runner_lock_acquired:
                registered.registration.runner.execution_lock.release()
            self._leave_execution()

    def request_cancellation(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
    ) -> PrivateAnalysisRunRecord:
        """Durably request cancellation, then notify a matching local attempt."""

        actor = _actor_id(actor_id)
        record = self._store.request_cancellation(
            scope,
            run_id,
            expected_version=expected_version,
            actor_id=actor,
        )
        with self._condition:
            attempt = self._active.get((record.scope, record.run_id))
        if attempt is not None:
            attempt.signal_cancellation(record)
        return record

    def recover_expired_runs(
        self,
        *,
        actor_id: str,
        limit: int = 100,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        """Run the store's no-retry recovery under this coordinator identity."""

        return self._store.recover_expired_runs(
            actor_id=_actor_id(actor_id),
            limit=limit,
        )

    def close(self, *, timeout: float = 30.0) -> None:
        """Stop accepting work and wait a bounded time for cooperative runs."""

        if (
            type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("timeout must be a finite non-negative number")
        deadline = time.monotonic() + float(timeout)
        with self._condition:
            if self._closed:
                return
            self._closing = True
            while self._active_count or self._active_monitor_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PrivateAnalysisExecutionCloseTimeout(
                        "private-analysis executions did not stop before timeout"
                    )
                self._condition.wait(remaining)
            self._closed = True

    def _enter_execution(self) -> None:
        with self._condition:
            if self._closing or self._closed:
                raise PrivateAnalysisExecutionClosed(
                    "private-analysis execution coordinator is closed"
                )
            if self._active_count >= self._limits.max_concurrent_runs:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis execution capacity is exhausted"
                )
            self._active_count += 1

    def _leave_execution(self) -> None:
        with self._condition:
            self._active_count -= 1
            self._condition.notify_all()

    def _register_attempt(
        self,
        key: tuple[EvidenceScope, str],
        attempt: _DurableExecutionAttempt,
    ) -> None:
        with self._condition:
            if key in self._active:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis run already has a local execution"
                )
            self._active[key] = attempt
            self._active_monitor_count += 1

    def _monitor_exited(
        self,
        key: tuple[EvidenceScope, str],
        attempt: _DurableExecutionAttempt,
    ) -> None:
        with self._condition:
            if self._active.get(key) is attempt:
                del self._active[key]
                self._active_monitor_count -= 1
                self._condition.notify_all()
