"""Core-owned execution of already-admitted private-analysis runs.

The coordinator is intentionally a synchronous local-library boundary.  It
does not discover plug-ins, configure providers, schedule retries, expose an
HTTP endpoint, or create model credentials.  It binds one durable request to
one exact, operator-configured runner and keeps disclosure accounting ahead of
every tool response.
"""

from __future__ import annotations

import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final, cast
from uuid import uuid4

from .canonical import strict_canonical_json_sha256
from .value_core import require_bounded_integer as _bounded_integer
from .private_analysis import (
    EvidenceReference,
    EvidenceScope,
    PrivateAnalysisPolicy,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
)
from .private_analysis.contracts import (
    LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST,
)
from .private_analysis_factory_process import (
    PrivateAnalysisFactoryPreparationTimedOut,
    PrivateAnalysisFactoryProcessCleanupError,
    PrivateAnalysisFactoryProcessCleanupOwner,
    PrivateAnalysisFactoryProcessError,
    PrivateAnalysisRemoteToolService,
    PrivateAnalysisToolServiceProcessFactory,
    private_analysis_factory_process_cleanup_owner,
    start_private_analysis_tool_service_process,
)
from .private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessExecutionReceipt,
)
from .private_analysis_run_store import (
    PrivateAnalysisRunConflict,
    PrivateAnalysisRunRecord,
    PrivateAnalysisRunStaleVersion,
    PrivateAnalysisRunState,
    SqlitePrivateAnalysisRunStore,
)
from .private_analysis_subprocess_runner import (
    ConfiguredPrivateAnalysisSubprocessRunner,
    PrivateAnalysisSubprocessCleanupPending,
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
type PrivateAnalysisRuntimeToolService = (
    PrivateAnalysisToolService | PrivateAnalysisRemoteToolService
)
type CorePrivateAnalysisToolServiceFactory = Callable[
    [PrivateAnalysisRequest, PrivateAnalysisPolicy, Callable[[], bool]],
    PrivateAnalysisToolService,
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


class _CleanupFenceEstablishedAfterError(RuntimeError):
    """A failed begin call whose exact durable insert was reconciled."""

    __slots__ = ("original",)

    def __init__(self, original: BaseException) -> None:
        super().__init__("cleanup fence was committed before the store error")
        self.original: BaseException = original


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
    """One exact runner and one evidence-service composition mode.

    A deployment may retain a fully custom trusted factory, or provide only a
    runner policy and ask the owning :class:`ControlPlane` to bind the runner
    to its verified immutable revision evidence.  The two modes are mutually
    exclusive so a local runner cannot silently switch evidence authorities.
    """

    runner: CorePrivateAnalysisRunner
    trusted_inline_tool_service_factory: PrivateAnalysisToolServiceFactory | None = None
    tool_service_process_factory: PrivateAnalysisToolServiceProcessFactory | None = None
    core_revision_evidence_policy: PrivateAnalysisPolicy | None = None
    custom_evidence_service_digest: str | None = None
    evidence_service_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.runner) not in _RUNNER_TYPES:
            raise TypeError(
                "runner must be an exact configured private-analysis runner"
            )
        # Registrations own a fresh runner seal. Replacing fields on the
        # caller's runner after registration therefore cannot replace the
        # authority that core invokes, while mutable callback/artifact state is
        # re-attested immediately before execution by the detached runner.
        detached_runner = self.runner.detached()
        object.__setattr__(self, "runner", detached_runner)
        inline = self.trusted_inline_tool_service_factory is not None
        process = self.tool_service_process_factory is not None
        core = self.core_revision_evidence_policy is not None
        if sum((inline, process, core)) != 1:
            raise ValueError(
                "runner registration requires exactly one trusted inline factory, "
                "process factory, or core revision-evidence policy"
            )
        if inline and not callable(self.trusted_inline_tool_service_factory):
            raise TypeError("trusted_inline_tool_service_factory must be callable")
        if process and type(self.tool_service_process_factory) is not (
            PrivateAnalysisToolServiceProcessFactory
        ):
            raise TypeError(
                "tool_service_process_factory must be "
                "PrivateAnalysisToolServiceProcessFactory"
            )
        process_factory = (
            PrivateAnalysisToolServiceProcessFactory.resolved(
                self.tool_service_process_factory
            )
            if process
            else None
        )
        if process_factory is not None:
            object.__setattr__(
                self,
                "tool_service_process_factory",
                process_factory,
            )
        evidence_service_digest = LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
        if inline or process:
            supplied_digest = self.custom_evidence_service_digest
            if (
                type(supplied_digest) is not str
                or len(supplied_digest) != 71
                or not supplied_digest.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in supplied_digest[7:]
                )
                or supplied_digest == LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
            ):
                raise ValueError(
                    "custom evidence services require a non-legacy stable "
                    "custom_evidence_service_digest"
                )
            evidence_service_digest = (
                process_factory.evidence_service_digest(supplied_digest)
                if process_factory is not None
                else supplied_digest
            )
        if core:
            if self.custom_evidence_service_digest is not None:
                raise ValueError(
                    "core revision evidence cannot carry a custom evidence-service "
                    "digest"
                )
            policy = self.core_revision_evidence_policy
            if type(policy) is not PrivateAnalysisPolicy:
                raise TypeError(
                    "core_revision_evidence_policy must be PrivateAnalysisPolicy"
                )
            selection = self.runner.selection
            if policy.transport is not selection.transport:
                raise ValueError(
                    "core revision-evidence policy transport must match the runner"
                )
            object.__setattr__(
                self,
                "core_revision_evidence_policy",
                PrivateAnalysisPolicy(
                    transport=policy.transport,
                    full_fidelity_workspace_data=(policy.full_fidelity_workspace_data),
                ),
            )
            evidence_service_digest = "sha256:" + strict_canonical_json_sha256(
                {
                    "contract_version": (
                        "router_dump_analyzer.private_analysis."
                        "evidence_service_binding.v1"
                    ),
                    "mode": "core_revision_evidence",
                    "transport": policy.transport.value,
                    "full_fidelity_workspace_data": (
                        policy.full_fidelity_workspace_data
                    ),
                }
            )
        object.__setattr__(
            self,
            "evidence_service_digest",
            evidence_service_digest,
        )

    def detached(self) -> PrivateAnalysisRunnerRegistration:
        """Reconstruct a validated registration for a new owning boundary."""

        if type(self) is not PrivateAnalysisRunnerRegistration:
            raise TypeError("registration must be PrivateAnalysisRunnerRegistration")
        return PrivateAnalysisRunnerRegistration(
            runner=self.runner,
            trusted_inline_tool_service_factory=(
                self.trusted_inline_tool_service_factory
            ),
            tool_service_process_factory=self.tool_service_process_factory,
            core_revision_evidence_policy=self.core_revision_evidence_policy,
            custom_evidence_service_digest=self.custom_evidence_service_digest,
        )


def _validated_process_factory_snapshot(
    registration: PrivateAnalysisRunnerRegistration,
) -> PrivateAnalysisToolServiceProcessFactory | None:
    """Return the exact descriptor bound by the admitted service digest."""

    value = registration.tool_service_process_factory
    if value is None:
        return None
    snapshot = PrivateAnalysisToolServiceProcessFactory.resolved(value)
    semantic_digest = registration.custom_evidence_service_digest
    if (
        type(semantic_digest) is not str
        or snapshot.evidence_service_digest(semantic_digest)
        != registration.evidence_service_digest
    ):
        raise PrivateAnalysisExecutionUnavailable(
            "private-analysis evidence factory identity changed"
        )
    return snapshot


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRegisteredRunner:
    """Detached public identity of one exact configured local runner."""

    selection: PrivateAnalysisRunnerSelection
    instruction_profile_digest: str
    evidence_service_digest: str = LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST

    def __post_init__(self) -> None:
        if type(self.selection) is not PrivateAnalysisRunnerSelection:
            raise TypeError("selection must be PrivateAnalysisRunnerSelection")
        selection = PrivateAnalysisRunnerSelection(
            runner_id=self.selection.runner_id,
            runner_version=self.selection.runner_version,
            transport=self.selection.transport,
            configuration_digest=self.selection.configuration_digest,
        )
        if (
            type(self.instruction_profile_digest) is not str
            or len(self.instruction_profile_digest) != 71
            or not self.instruction_profile_digest.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in self.instruction_profile_digest[7:]
            )
        ):
            raise ValueError(
                "instruction_profile_digest must be a sha256-prefixed digest"
            )
        object.__setattr__(self, "selection", selection)
        if (
            type(self.evidence_service_digest) is not str
            or len(self.evidence_service_digest) != 71
            or not self.evidence_service_digest.startswith("sha256:")
            or any(
                character not in "0123456789abcdef"
                for character in self.evidence_service_digest[7:]
            )
        ):
            raise ValueError("evidence_service_digest must be a sha256-prefixed digest")


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


@dataclass(slots=True)
class _ConfirmedFactoryCleanupOwner:
    """Idempotent release state for a bootstrap that launched no live child."""

    cleanup_confirmed: bool = True

    def close(self) -> None:
        return


type _FactoryCleanupOwner = (
    PrivateAnalysisRemoteToolService
    | PrivateAnalysisFactoryProcessCleanupOwner
    | _ConfirmedFactoryCleanupOwner
)


@dataclass(slots=True)
class _PrelaunchCleanupJournal:
    """Local capability ownership registered before its durable fence call."""

    attempt: _DurableExecutionAttempt
    cleanup_capability: str = field(repr=False)
    receipt: PrivateAnalysisExecutionReceipt | None = None
    finalize_unstarted: bool = True
    timed_out: bool = False
    retry_ready: bool = False
    retry_lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(slots=True)
class _PendingFactoryCleanup:
    """Live, retryable ownership paired with one durable cleanup fence."""

    owner: _FactoryCleanupOwner
    attempt: _DurableExecutionAttempt
    cleanup_capability: str = field(repr=False)
    receipt: PrivateAnalysisExecutionReceipt | None = None
    receipt_runner: ConfiguredPrivateAnalysisInProcessRunner | None = None
    finalize_unstarted: bool = False
    timed_out: bool = False
    retry_ready: bool = False
    retry_lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(slots=True)
class _PendingSubprocessCleanup:
    """One retained local-runner handle and its durable cleanup capability."""

    runner: ConfiguredPrivateAnalysisSubprocessRunner
    attempt: _DurableExecutionAttempt
    cleanup_capability: str = field(repr=False)
    service: PrivateAnalysisRemoteToolService | None = None
    receipt: PrivateAnalysisExecutionReceipt | None = None
    finalize_unstarted: bool = False
    timed_out: bool = False
    retry_ready: bool = False
    retry_lock: threading.Lock = field(default_factory=threading.Lock)


class _DurableExecutionAttempt:
    """Single owner of one execution fence and its optimistic run version."""

    __slots__ = (
        "_actor_id",
        "_cancellation",
        "_execution_id",
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
        self._execution_id = record.execution_id
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
        return self._execution_id

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

    def complete_cleanup(
        self,
        receipt: PrivateAnalysisExecutionReceipt,
        cleanup_capability: str,
    ) -> PrivateAnalysisRunRecord:
        """Atomically consume cleanup authority and persist its exact receipt."""

        with self._lock:
            execution_id = self.execution_id
            for attempt in range(2):
                current = self._store.get_run(self._scope, self._record.run_id)
                self._record = current
                if not current.state.is_terminal and (
                    current.state
                    not in {
                        PrivateAnalysisRunState.RUNNING,
                        PrivateAnalysisRunState.CANCEL_REQUESTED,
                    }
                    or current.execution_id != execution_id
                ):
                    raise _AttemptLost(
                        "private-analysis cleanup execution fence was lost"
                    )
                selected = receipt
                if current.state in {
                    PrivateAnalysisRunState.CANCEL_REQUESTED,
                    PrivateAnalysisRunState.CANCELLED,
                }:
                    self._cancellation.set()
                    selected = receipt.as_cancelled()
                try:
                    completed = self._store.complete_run(
                        self._scope,
                        current.run_id,
                        expected_version=current.version,
                        execution_id=execution_id,
                        outcome=selected.outcome,
                        transcript_summary=selected.transcript_summary,
                        references=selected.disclosed_references,
                        budget_state=selected.budget_state,
                        actor_id=self._actor_id,
                        cleanup_capability=cleanup_capability,
                    )
                except PrivateAnalysisRunStaleVersion:
                    if attempt == 0:
                        continue
                    raise
                self._record = completed
                return completed
            raise AssertionError("unreachable cleanup completion retry state")

    def finalize_unstarted(
        self,
        *,
        timed_out: bool = False,
    ) -> PrivateAnalysisRunRecord:
        if type(timed_out) is not bool:
            raise TypeError("timed_out must be a boolean")
        with self._lock:
            return self._mutate_once_locked(
                lambda version: self._store.finalize_unstarted_attempt(
                    self._scope,
                    self._record.run_id,
                    expected_version=version,
                    execution_id=self.execution_id,
                    actor_id=self._actor_id,
                    timed_out=timed_out,
                )
            )

    def finalize_cleanup_unstarted(
        self,
        cleanup_capability: str,
        *,
        timed_out: bool = False,
    ) -> PrivateAnalysisRunRecord:
        """Atomically consume cleanup authority and seal an unstarted attempt."""

        if type(timed_out) is not bool:
            raise TypeError("timed_out must be a boolean")
        with self._lock:
            execution_id = self.execution_id
            for attempt in range(2):
                current = self._store.get_run(self._scope, self._record.run_id)
                self._record = current
                if not current.state.is_terminal and (
                    current.state
                    not in {
                        PrivateAnalysisRunState.RUNNING,
                        PrivateAnalysisRunState.CANCEL_REQUESTED,
                    }
                    or current.execution_id != execution_id
                ):
                    raise _AttemptLost(
                        "private-analysis cleanup execution fence was lost"
                    )
                try:
                    completed = self._store.finalize_unstarted_attempt(
                        self._scope,
                        current.run_id,
                        expected_version=current.version,
                        execution_id=execution_id,
                        actor_id=self._actor_id,
                        cleanup_capability=cleanup_capability,
                        timed_out=timed_out,
                    )
                except PrivateAnalysisRunStaleVersion:
                    if attempt == 0:
                        continue
                    raise
                self._record = completed
                return completed
            raise AssertionError("unreachable cleanup finalization retry state")

    def begin_cleanup_fence(self, cleanup_capability: str) -> None:
        """Persist cleanup ownership before a factory child may be launched."""

        with self._lock:
            self._refresh_locked()
            try:
                self._store.begin_cleanup_fence(
                    self._scope,
                    self._record.run_id,
                    execution_id=self.execution_id,
                    cleanup_capability=cleanup_capability,
                )
            except BaseException as error:
                try:
                    matches = self._store.cleanup_fence_matches(
                        self._scope,
                        self._record.run_id,
                        execution_id=self.execution_id,
                        cleanup_capability=cleanup_capability,
                    )
                except BaseException as reconciliation_error:  # noqa: BLE001
                    selected = (
                        reconciliation_error
                        if isinstance(reconciliation_error, PROCESS_CONTROL_EXCEPTIONS)
                        else error
                    )
                    raise _CleanupFenceEstablishedAfterError(selected) from error
                if matches is True:
                    raise _CleanupFenceEstablishedAfterError(error) from error
                if matches is None:
                    raise
                raise PrivateAnalysisRunConflict(
                    "private-analysis cleanup ownership changed during begin"
                ) from error

    def note_cleanup_attempt(self, cleanup_capability: str) -> None:
        """Persist bounded retry diagnostics while retaining ownership."""

        with self._lock:
            self._store.note_cleanup_attempt(
                self._scope,
                self._record.run_id,
                execution_id=self.execution_id,
                cleanup_capability=cleanup_capability,
            )

    def cleanup_fence_matches(self, cleanup_capability: str) -> bool | None:
        """Return the exact three-way reconciliation state for this attempt."""

        with self._lock:
            return self._store.cleanup_fence_matches(
                self._scope,
                self._record.run_id,
                execution_id=self.execution_id,
                cleanup_capability=cleanup_capability,
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
        core_tool_service_factory: (
            CorePrivateAnalysisToolServiceFactory | None
        ) = None,
    ) -> None:
        if type(store) is not SqlitePrivateAnalysisRunStore:
            raise TypeError("store must be an exact SqlitePrivateAnalysisRunStore")
        if type(registrations) is not tuple:
            raise TypeError("registrations must be a tuple")
        selected_limits = limits or PrivateAnalysisExecutionLimits()
        if type(selected_limits) is not PrivateAnalysisExecutionLimits:
            raise TypeError("limits must be PrivateAnalysisExecutionLimits or None")
        if core_tool_service_factory is not None and not callable(
            core_tool_service_factory
        ):
            raise TypeError("core_tool_service_factory must be callable or None")
        routes: dict[tuple[str, str, object, str], _RegisteredRunner] = {}
        public_routes: dict[tuple[str, str], _RegisteredRunner] = {}
        for registration in registrations:
            if type(registration) is not PrivateAnalysisRunnerRegistration:
                raise TypeError(
                    "registrations must contain PrivateAnalysisRunnerRegistration"
                )
            registration_snapshot = registration.detached()
            if (
                registration_snapshot.core_revision_evidence_policy is not None
                and core_tool_service_factory is None
            ):
                raise ValueError(
                    "core revision-evidence registrations require a core tool-service "
                    "factory"
                )
            key = _runner_key(registration_snapshot.runner.selection)
            if key in routes:
                raise ValueError("private-analysis runner selection is duplicated")
            public_key = (
                registration_snapshot.runner.selection.runner_id,
                registration_snapshot.runner.selection.runner_version,
            )
            if public_key in public_routes:
                raise ValueError(
                    "private-analysis runner ID and version are duplicated"
                )
            selected = _RegisteredRunner(registration_snapshot)
            routes[key] = selected
            public_routes[public_key] = selected
        self._store = store
        self._routes = routes
        self._public_routes = public_routes
        self._limits = selected_limits
        self._core_tool_service_factory = core_tool_service_factory
        self._condition = threading.Condition(threading.RLock())
        self._active: dict[tuple[EvidenceScope, str], _DurableExecutionAttempt] = {}
        self._pending_cleanup: dict[
            tuple[EvidenceScope, str],
            _PrelaunchCleanupJournal
            | _PendingFactoryCleanup
            | _PendingSubprocessCleanup,
        ] = {}
        self._active_count = 0
        self._active_monitor_count = 0
        self._closing = False
        self._closed = False
        self._close_cleanup_active = False
        self._close_cleanup_error: BaseException | None = None

    def resolve_runner(
        self,
        runner_id: str,
        runner_version: str,
    ) -> PrivateAnalysisRegisteredRunner:
        """Resolve one unambiguous registration without exposing its callback."""

        if type(runner_id) is not str or type(runner_version) is not str:
            raise TypeError("runner identity fields must be strings")
        registered = self._public_routes.get((runner_id, runner_version))
        if registered is None:
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis runner is not configured"
            )
        runner = registered.registration.runner
        return PrivateAnalysisRegisteredRunner(
            selection=runner.selection,
            instruction_profile_digest=runner.instruction_profile_digest,
            evidence_service_digest=registered.registration.evidence_service_digest,
        )

    def list_runners(self) -> tuple[PrivateAnalysisRegisteredRunner, ...]:
        """Return detached registrations in canonical public identity order."""

        runners = tuple(
            PrivateAnalysisRegisteredRunner(
                selection=route.registration.runner.selection,
                instruction_profile_digest=(
                    route.registration.runner.instruction_profile_digest
                ),
                evidence_service_digest=(route.registration.evidence_service_digest),
            )
            for route in self._routes.values()
        )
        return tuple(
            sorted(
                runners,
                key=lambda item: (
                    item.selection.runner_id,
                    item.selection.runner_version,
                    item.selection.transport.value,
                    item.selection.configuration_digest,
                ),
            )
        )

    def is_bound_to_store(self, store: object) -> bool:
        """Check composition identity without exposing the durable store."""

        return store is self._store

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
            minimum=1,
            maximum=(1 << 63) - 1,
        )
        actor = _actor_id(actor_id)
        self._enter_execution()
        durable_attempt: _DurableExecutionAttempt | None = None
        registered: _RegisteredRunner | None = None
        runner_lock_acquired = False
        cleanup_capability: str | None = None
        cleanup_fence_established = False
        service: PrivateAnalysisRuntimeToolService | None = None
        bootstrap_cleanup_owner: _FactoryCleanupOwner | None = None
        try:
            record = self._store.get_run(scope, run_id)
            if record.version != expected_version:
                raise PrivateAnalysisRunStaleVersion(
                    "private-analysis run version is stale"
                )
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
            if (
                registered.registration.evidence_service_digest
                != record.request.evidence_service_digest
            ):
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis evidence service is not configured"
                )
            if not runner.execution_lock.acquire(blocking=False):
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis runner is already executing"
                )
            runner_lock_acquired = True
            if (
                type(runner) is ConfiguredPrivateAnalysisSubprocessRunner
                and runner.cleanup_pending
            ):
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis subprocess cleanup is pending"
                )
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
            preparation_deadline_ns = (
                time.monotonic_ns() + claimed.request.limits.deadline_ms * 1_000_000
            )
            preparation_timed_out = False

            def preparation_cancelled() -> bool:
                nonlocal preparation_timed_out
                if durable_attempt.cancellation_probe():
                    return True
                if time.monotonic_ns() >= preparation_deadline_ns:
                    preparation_timed_out = True
                    return True
                return False

            try:
                factory = registered.registration.trusted_inline_tool_service_factory
                process_factory = _validated_process_factory_snapshot(
                    registered.registration
                )
                if process_factory is not None:
                    # The deletion capability exists only in this coordinator
                    # lifetime and is created before spawning.  Durable state
                    # receives only its one-way verifier.
                    cleanup_capability = "cleanup-capability-v1:" + secrets.token_hex(
                        32
                    )
                    prelaunch_cleanup = self._register_prelaunch_cleanup(
                        durable_attempt,
                        cleanup_capability,
                    )
                    self._begin_prelaunch_cleanup_fence(prelaunch_cleanup)
                    cleanup_fence_established = True
                    try:
                        service = start_private_analysis_tool_service_process(
                            process_factory,
                            claimed.request,
                            cancellation_probe=preparation_cancelled,
                            absolute_deadline_ns=preparation_deadline_ns,
                            poll_interval_ns=(
                                self._limits.cancellation_poll_interval_ns
                            ),
                        )
                    except BaseException as error:
                        bootstrap_cleanup_owner = (
                            private_analysis_factory_process_cleanup_owner(error)
                        )
                        if bootstrap_cleanup_owner is None:
                            if type(error) is PrivateAnalysisFactoryProcessCleanupError:
                                raise PrivateAnalysisExecutionUnavailable(
                                    "private-analysis factory cleanup ownership is invalid"
                                ) from None
                            if isinstance(error, PrivateAnalysisFactoryProcessError):
                                # The launcher omits an owner from this closed
                                # error family only before a Process exists.
                                bootstrap_cleanup_owner = (
                                    _ConfirmedFactoryCleanupOwner()
                                )
                        raise
                elif factory is not None:
                    service = factory(claimed.request)
                else:
                    policy = registered.registration.core_revision_evidence_policy
                    core_factory = self._core_tool_service_factory
                    if policy is None or core_factory is None:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis evidence service is not configured"
                        )
                    service = core_factory(
                        claimed.request,
                        policy,
                        preparation_cancelled,
                    )
                if preparation_cancelled():
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis evidence preparation did not complete"
                    )
                if (
                    type(service)
                    not in {
                        PrivateAnalysisToolService,
                        PrivateAnalysisRemoteToolService,
                    }
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
                if (
                    type(service) is PrivateAnalysisRemoteToolService
                    and cleanup_capability is not None
                ):
                    if type(runner) is ConfiguredPrivateAnalysisSubprocessRunner:
                        self._retain_pending_subprocess_cleanup(
                            durable_attempt,
                            runner,
                            cleanup_capability,
                            service=service,
                            finalize_unstarted=True,
                        )
                    else:
                        self._retain_pending_cleanup(
                            durable_attempt,
                            service,
                            cleanup_capability,
                            finalize_unstarted=True,
                        )
            except PROCESS_CONTROL_EXCEPTIONS:
                try:
                    if (
                        type(service) is PrivateAnalysisRemoteToolService
                        and cleanup_capability is not None
                    ):
                        self._cleanup_factory_owner_or_retain(
                            service,
                            durable_attempt,
                            cleanup_capability,
                            finalize_unstarted=True,
                        )
                    elif (
                        bootstrap_cleanup_owner is not None
                        and cleanup_capability is not None
                    ):
                        if (
                            type(bootstrap_cleanup_owner)
                            is PrivateAnalysisFactoryProcessCleanupOwner
                            and not bootstrap_cleanup_owner.cleanup_confirmed
                        ):
                            self._retain_pending_cleanup(
                                durable_attempt,
                                bootstrap_cleanup_owner,
                                cleanup_capability,
                                finalize_unstarted=True,
                            )
                        else:
                            self._cleanup_factory_owner_or_retain(
                                bootstrap_cleanup_owner,
                                durable_attempt,
                                cleanup_capability,
                                finalize_unstarted=True,
                            )
                except PROCESS_CONTROL_EXCEPTIONS:
                    try:
                        durable_attempt.stop_monitor()
                    except BaseException:  # noqa: BLE001, S110 - preserve control.
                        pass
                    raise
                try:
                    durable_attempt.stop_monitor()
                except BaseException:  # noqa: BLE001, S110 - preserve control.
                    pass
                raise
            except BaseException as error:  # noqa: BLE001 - trusted composition boundary.
                if type(error) is _CleanupFenceEstablishedAfterError:
                    if cleanup_capability is None:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis cleanup fence capability was lost"
                        ) from None
                    try:
                        durable_attempt.stop_monitor()
                    except BaseException:  # noqa: BLE001, S110 - preserve cause.
                        pass
                    original = error.original
                    if isinstance(original, PROCESS_CONTROL_EXCEPTIONS):
                        raise original.with_traceback(original.__traceback__)
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup fence commit was ambiguous"
                    ) from None
                preparation_timed_out = (
                    preparation_timed_out
                    or type(error) is PrivateAnalysisFactoryPreparationTimedOut
                    or time.monotonic_ns() >= preparation_deadline_ns
                )
                cleanup_failed = False
                if type(service) is PrivateAnalysisRemoteToolService and (
                    cleanup_capability is not None
                ):
                    try:
                        cleanup_failed = not self._cleanup_factory_owner_or_retain(
                            service,
                            durable_attempt,
                            cleanup_capability,
                            finalize_unstarted=True,
                            timed_out=preparation_timed_out,
                        )
                    except PROCESS_CONTROL_EXCEPTIONS:
                        try:
                            durable_attempt.stop_monitor()
                        except BaseException:  # noqa: BLE001, S110 - preserve control.
                            pass
                        raise
                    except BaseException:  # noqa: BLE001 - cleanup is authoritative.
                        cleanup_failed = True
                elif (
                    bootstrap_cleanup_owner is not None
                    and cleanup_capability is not None
                ):
                    if (
                        type(bootstrap_cleanup_owner)
                        is PrivateAnalysisFactoryProcessCleanupOwner
                        and not bootstrap_cleanup_owner.cleanup_confirmed
                    ):
                        self._retain_pending_cleanup(
                            durable_attempt,
                            bootstrap_cleanup_owner,
                            cleanup_capability,
                            finalize_unstarted=True,
                            timed_out=preparation_timed_out,
                        )
                        cleanup_failed = True
                    else:
                        try:
                            cleanup_failed = not (
                                self._cleanup_factory_owner_or_retain(
                                    bootstrap_cleanup_owner,
                                    durable_attempt,
                                    cleanup_capability,
                                    finalize_unstarted=True,
                                    timed_out=preparation_timed_out,
                                )
                            )
                        except PROCESS_CONTROL_EXCEPTIONS:
                            try:
                                durable_attempt.stop_monitor()
                            except BaseException:  # noqa: BLE001, S110
                                pass
                            raise
                elif cleanup_capability is not None:
                    cleanup_failed = True
                if cleanup_failed:
                    try:
                        durable_attempt.stop_monitor()
                    except PROCESS_CONTROL_EXCEPTIONS:
                        raise
                    except BaseException:  # noqa: BLE001, S110 - preserve cleanup fault.
                        pass
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis evidence factory process did not stop"
                    ) from None
                durable_attempt.stop_monitor()
                terminal = (
                    durable_attempt.finalize_cleanup_unstarted(
                        cleanup_capability,
                        timed_out=preparation_timed_out,
                    )
                    if cleanup_capability is not None
                    else durable_attempt.finalize_unstarted(
                        timed_out=preparation_timed_out,
                    )
                )
                self._release_pending_after_terminal(durable_attempt, terminal)
                return terminal

            subprocess_runner = (
                cast(ConfiguredPrivateAnalysisSubprocessRunner, runner)
                if type(runner) is ConfiguredPrivateAnalysisSubprocessRunner
                else None
            )
            in_process_runner = (
                cast(ConfiguredPrivateAnalysisInProcessRunner, runner)
                if type(runner) is ConfiguredPrivateAnalysisInProcessRunner
                else None
            )
            try:
                if subprocess_runner is not None and cleanup_capability is None:
                    cleanup_capability = "cleanup-capability-v1:" + secrets.token_hex(
                        32
                    )
                    prelaunch_cleanup = self._register_prelaunch_cleanup(
                        durable_attempt,
                        cleanup_capability,
                    )
                    self._begin_prelaunch_cleanup_fence(prelaunch_cleanup)
                    cleanup_fence_established = True
                if subprocess_runner is not None and cleanup_capability is not None:
                    self._retain_pending_subprocess_cleanup(
                        durable_attempt,
                        subprocess_runner,
                        cleanup_capability,
                        service=(
                            service
                            if type(service) is PrivateAnalysisRemoteToolService
                            else None
                        ),
                        finalize_unstarted=True,
                    )
                receipt = runner.execute(
                    service,
                    accounting_observer=durable_attempt.accounting_observer,
                    cancellation_probe=durable_attempt.cancellation_probe,
                    absolute_deadline_ns=preparation_deadline_ns,
                )
            except _CleanupFenceEstablishedAfterError as error:
                if subprocess_runner is None or cleanup_capability is None:
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis subprocess cleanup ownership is invalid"
                    ) from None
                try:
                    durable_attempt.stop_monitor()
                except BaseException:  # noqa: BLE001, S110 - preserve cause.
                    pass
                original = error.original
                if isinstance(original, PROCESS_CONTROL_EXCEPTIONS):
                    raise original.with_traceback(original.__traceback__)
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis cleanup fence commit was ambiguous"
                ) from None
            except PrivateAnalysisSubprocessCleanupPending:
                if (
                    subprocess_runner is None
                    or cleanup_capability is None
                    or not cleanup_fence_established
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis subprocess cleanup ownership is invalid"
                    ) from None
                self._retain_pending_subprocess_cleanup(
                    durable_attempt,
                    subprocess_runner,
                    cleanup_capability,
                    service=(
                        service
                        if type(service) is PrivateAnalysisRemoteToolService
                        else None
                    ),
                )
                durable_attempt.stop_monitor()
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis subprocess cleanup is pending"
                ) from None
            except PROCESS_CONTROL_EXCEPTIONS:
                try:
                    if (
                        subprocess_runner is not None
                        and subprocess_runner.cleanup_pending
                    ):
                        if cleanup_capability is None or not cleanup_fence_established:
                            raise PrivateAnalysisExecutionUnavailable(
                                "private-analysis subprocess cleanup ownership is invalid"
                            ) from None
                        self._retain_pending_subprocess_cleanup(
                            durable_attempt,
                            subprocess_runner,
                            cleanup_capability,
                            service=(
                                service
                                if type(service) is PrivateAnalysisRemoteToolService
                                else None
                            ),
                        )
                    elif (
                        type(service) is PrivateAnalysisRemoteToolService
                        and cleanup_capability is not None
                    ):
                        receipt_runner = (
                            in_process_runner
                            if in_process_runner is not None
                            and in_process_runner.receipt_pending
                            else None
                        )
                        self._cleanup_factory_owner_or_retain(
                            service,
                            durable_attempt,
                            cleanup_capability,
                            receipt_runner=receipt_runner,
                            finalize_unstarted=receipt_runner is None,
                        )
                    elif (
                        subprocess_runner is not None
                        and cleanup_capability is not None
                        and cleanup_fence_established
                    ):
                        self._confirm_subprocess_cleanup_or_retain(
                            durable_attempt,
                            subprocess_runner,
                            cleanup_capability,
                            finalize_unstarted=True,
                        )
                except PROCESS_CONTROL_EXCEPTIONS:
                    try:
                        durable_attempt.stop_monitor()
                    except BaseException:  # noqa: BLE001, S110 - preserve control.
                        pass
                    raise
                try:
                    durable_attempt.stop_monitor()
                except BaseException:  # noqa: BLE001, S110 - preserve control.
                    pass
                raise
            except BaseException:  # noqa: BLE001 - exact runner boundary.
                if subprocess_runner is not None and subprocess_runner.cleanup_pending:
                    if cleanup_capability is None or not cleanup_fence_established:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis subprocess cleanup ownership is invalid"
                        ) from None
                    self._retain_pending_subprocess_cleanup(
                        durable_attempt,
                        subprocess_runner,
                        cleanup_capability,
                        service=(
                            service
                            if type(service) is PrivateAnalysisRemoteToolService
                            else None
                        ),
                        finalize_unstarted=True,
                    )
                elif type(service) is PrivateAnalysisRemoteToolService and (
                    cleanup_capability is not None
                ):
                    try:
                        self._cleanup_factory_owner_or_retain(
                            service,
                            durable_attempt,
                            cleanup_capability,
                            finalize_unstarted=True,
                        )
                    except PROCESS_CONTROL_EXCEPTIONS:
                        try:
                            durable_attempt.stop_monitor()
                        except BaseException:  # noqa: BLE001, S110
                            pass
                        raise
                elif (
                    subprocess_runner is not None
                    and cleanup_capability is not None
                    and cleanup_fence_established
                ):
                    try:
                        self._confirm_subprocess_cleanup_or_retain(
                            durable_attempt,
                            subprocess_runner,
                            cleanup_capability,
                            finalize_unstarted=True,
                        )
                    except PROCESS_CONTROL_EXCEPTIONS:
                        try:
                            durable_attempt.stop_monitor()
                        except BaseException:  # noqa: BLE001, S110
                            pass
                        raise
                durable_attempt.stop_monitor()
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis runner did not return a valid receipt"
                ) from None
            if (
                type(service) is PrivateAnalysisRemoteToolService
                and cleanup_capability is not None
            ):
                try:
                    cleanup_confirmed = self._cleanup_factory_owner_or_retain(
                        service,
                        durable_attempt,
                        cleanup_capability,
                        receipt=receipt,
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    try:
                        durable_attempt.stop_monitor()
                    except BaseException:  # noqa: BLE001, S110 - preserve control.
                        pass
                    raise
                except BaseException:  # noqa: BLE001 - cleanup is part of receipt trust.
                    durable_attempt.stop_monitor()
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis evidence factory process did not stop"
                    ) from None
                if not cleanup_confirmed:
                    durable_attempt.stop_monitor()
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis evidence factory cleanup is pending"
                    )
            elif (
                subprocess_runner is not None
                and cleanup_capability is not None
                and cleanup_fence_established
            ):
                try:
                    cleanup_confirmed = self._confirm_subprocess_cleanup_or_retain(
                        durable_attempt,
                        subprocess_runner,
                        cleanup_capability,
                        receipt=receipt,
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    try:
                        durable_attempt.stop_monitor()
                    except BaseException:  # noqa: BLE001, S110 - preserve control.
                        pass
                    raise
                if not cleanup_confirmed:
                    durable_attempt.stop_monitor()
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis subprocess cleanup fence is pending"
                    )
            durable_attempt.stop_monitor()
            terminal = (
                durable_attempt.complete_cleanup(receipt, cleanup_capability)
                if cleanup_capability is not None
                else durable_attempt.complete(receipt)
            )
            self._release_pending_after_terminal(durable_attempt, terminal)
            return terminal
        finally:
            if registered is not None and runner_lock_acquired:
                registered.registration.runner.execution_lock.release()
            if durable_attempt is not None:
                self._activate_pending_cleanup_retry(durable_attempt)
            self._leave_execution()

    def _register_prelaunch_cleanup(
        self,
        attempt: _DurableExecutionAttempt,
        cleanup_capability: str,
    ) -> _PrelaunchCleanupJournal:
        """Own a fresh capability locally before its durable commit can occur."""

        pending = _PrelaunchCleanupJournal(
            attempt=attempt,
            cleanup_capability=cleanup_capability,
        )
        key = (attempt.record.scope, attempt.record.run_id)
        with self._condition:
            if key in self._pending_cleanup:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis cleanup ownership already exists"
                )
            self._pending_cleanup[key] = pending
            self._condition.notify_all()
        return pending

    def _discard_prelaunch_cleanup(
        self,
        pending: _PrelaunchCleanupJournal,
    ) -> None:
        """Release a journal only after durable reconciliation proves no ownership."""

        key = (pending.attempt.record.scope, pending.attempt.record.run_id)
        with self._condition:
            current = self._pending_cleanup.get(key)
            if current is not pending:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis prelaunch cleanup ownership changed"
                )
            del self._pending_cleanup[key]
            self._condition.notify_all()

    def _begin_prelaunch_cleanup_fence(
        self,
        pending: _PrelaunchCleanupJournal,
    ) -> None:
        """Begin and exactly reconcile the fence while retaining local authority."""

        try:
            pending.attempt.begin_cleanup_fence(pending.cleanup_capability)
            return
        except _CleanupFenceEstablishedAfterError:
            raise
        except BaseException as error:
            try:
                matches = pending.attempt.cleanup_fence_matches(
                    pending.cleanup_capability
                )
            except BaseException as reconciliation_error:  # noqa: BLE001
                selected = (
                    reconciliation_error
                    if isinstance(reconciliation_error, PROCESS_CONTROL_EXCEPTIONS)
                    else error
                )
                raise _CleanupFenceEstablishedAfterError(selected) from error
            if matches is True:
                raise _CleanupFenceEstablishedAfterError(error) from error
            self._discard_prelaunch_cleanup(pending)
            if matches is False:
                raise PrivateAnalysisRunConflict(
                    "private-analysis cleanup ownership changed during begin"
                ) from error
            raise

    def _activate_pending_cleanup_retry(
        self,
        attempt: _DurableExecutionAttempt,
    ) -> None:
        """Publish retryability only after the creating execution has unwound."""

        key = (attempt.record.scope, attempt.record.run_id)
        with self._condition:
            pending = self._pending_cleanup.get(key)
            if pending is not None and pending.attempt is attempt:
                pending.retry_ready = True
                self._condition.notify_all()

    def _cleanup_remote_service(
        self,
        owner: _FactoryCleanupOwner,
        attempt: _DurableExecutionAttempt,
        cleanup_capability: str,
    ) -> bool:
        """Try one bounded reap while retaining its fence for terminal commit."""

        try:
            attempt.note_cleanup_attempt(cleanup_capability)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - reconcile prior terminal commit.
            try:
                matches = attempt.cleanup_fence_matches(cleanup_capability)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001 - retry owns the capability.
                return False
            if matches is False:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis cleanup ownership no longer matches"
                ) from None
        try:
            owner.close()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisFactoryProcessCleanupError:
            return False
        except BaseException:  # noqa: BLE001 - unknown cleanup is unconfirmed.
            return False
        return True

    def _cleanup_factory_owner_or_retain(
        self,
        owner: _FactoryCleanupOwner,
        attempt: _DurableExecutionAttempt,
        cleanup_capability: str,
        *,
        receipt: PrivateAnalysisExecutionReceipt | None = None,
        receipt_runner: ConfiguredPrivateAnalysisInProcessRunner | None = None,
        finalize_unstarted: bool = False,
        timed_out: bool = False,
    ) -> bool:
        """Try cleanup, retaining exact ownership before any control escape."""

        self._retain_pending_cleanup(
            attempt,
            owner,
            cleanup_capability,
            receipt=receipt,
            receipt_runner=receipt_runner,
            finalize_unstarted=finalize_unstarted,
            timed_out=timed_out,
        )
        cleanup_confirmed = self._cleanup_remote_service(
            owner,
            attempt,
            cleanup_capability,
        )
        return cleanup_confirmed

    @staticmethod
    def _confirm_subprocess_cleanup_fence(
        attempt: _DurableExecutionAttempt,
        cleanup_capability: str,
    ) -> bool:
        """Confirm exact durable authority without clearing it before terminality."""

        try:
            attempt.note_cleanup_attempt(cleanup_capability)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - reconcile prior terminal commit.
            try:
                matches = attempt.cleanup_fence_matches(cleanup_capability)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:  # noqa: BLE001 - retry owns the capability.
                return False
            if matches is None:
                return True
            if matches is False:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis cleanup ownership no longer matches"
                ) from None
        return True

    def _confirm_subprocess_cleanup_or_retain(
        self,
        attempt: _DurableExecutionAttempt,
        runner: ConfiguredPrivateAnalysisSubprocessRunner,
        cleanup_capability: str,
        *,
        service: PrivateAnalysisRemoteToolService | None = None,
        receipt: PrivateAnalysisExecutionReceipt | None = None,
        finalize_unstarted: bool = False,
        timed_out: bool = False,
    ) -> bool:
        """Retain a reaped-child receipt while its fence awaits terminal commit."""

        self._retain_pending_subprocess_cleanup(
            attempt,
            runner,
            cleanup_capability,
            service=service,
            receipt=receipt,
            finalize_unstarted=finalize_unstarted,
            timed_out=timed_out,
        )
        cleanup_confirmed = self._confirm_subprocess_cleanup_fence(
            attempt,
            cleanup_capability,
        )
        return cleanup_confirmed

    def _retain_pending_cleanup(
        self,
        attempt: _DurableExecutionAttempt,
        owner: _FactoryCleanupOwner,
        cleanup_capability: str,
        *,
        receipt: PrivateAnalysisExecutionReceipt | None = None,
        receipt_runner: ConfiguredPrivateAnalysisInProcessRunner | None = None,
        finalize_unstarted: bool = False,
        timed_out: bool = False,
    ) -> _PendingFactoryCleanup | _PendingSubprocessCleanup:
        if receipt_runner is not None and (
            type(receipt_runner) is not ConfiguredPrivateAnalysisInProcessRunner
            or receipt is not None
            or finalize_unstarted
        ):
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis deferred receipt ownership is invalid"
            )
        key = (attempt.record.scope, attempt.record.run_id)
        with self._condition:
            existing = self._pending_cleanup.get(key)
            if type(existing) is _PrelaunchCleanupJournal:
                if (
                    existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                pending = _PendingFactoryCleanup(
                    owner=owner,
                    attempt=attempt,
                    cleanup_capability=cleanup_capability,
                    receipt=receipt,
                    receipt_runner=receipt_runner,
                    finalize_unstarted=(
                        False
                        if receipt_runner is not None
                        else existing.finalize_unstarted or finalize_unstarted
                    ),
                    timed_out=existing.timed_out or timed_out,
                    retry_ready=existing.retry_ready,
                    retry_lock=existing.retry_lock,
                )
                self._pending_cleanup[key] = pending
                self._condition.notify_all()
                return pending
            if type(existing) is _PendingSubprocessCleanup:
                if (
                    existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                    or existing.service is not owner
                    or receipt_runner is not None
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                if receipt is not None:
                    if existing.receipt is not None and existing.receipt != receipt:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis cleanup receipt changed"
                        )
                    existing.receipt = receipt
                existing.finalize_unstarted = (
                    existing.finalize_unstarted or finalize_unstarted
                )
                existing.timed_out = existing.timed_out or timed_out
                return existing
            if existing is not None:
                if (
                    type(existing) is not _PendingFactoryCleanup
                    or existing.owner is not owner
                    or existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                if receipt is not None:
                    if existing.receipt is not None and existing.receipt != receipt:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis cleanup receipt changed"
                        )
                    existing.receipt = receipt
                if receipt_runner is not None:
                    if (
                        existing.receipt_runner is not None
                        and existing.receipt_runner is not receipt_runner
                    ):
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis deferred receipt owner changed"
                        )
                    existing.receipt_runner = receipt_runner
                existing.finalize_unstarted = (
                    False
                    if receipt_runner is not None
                    else existing.finalize_unstarted or finalize_unstarted
                )
                existing.timed_out = existing.timed_out or timed_out
                return existing
            pending = _PendingFactoryCleanup(
                owner=owner,
                attempt=attempt,
                cleanup_capability=cleanup_capability,
                receipt=receipt,
                receipt_runner=receipt_runner,
                finalize_unstarted=finalize_unstarted,
                timed_out=timed_out,
            )
            self._pending_cleanup[key] = pending
            self._condition.notify_all()
            return pending

    def _retain_pending_subprocess_cleanup(
        self,
        attempt: _DurableExecutionAttempt,
        runner: ConfiguredPrivateAnalysisSubprocessRunner,
        cleanup_capability: str,
        *,
        service: PrivateAnalysisRemoteToolService | None = None,
        receipt: PrivateAnalysisExecutionReceipt | None = None,
        finalize_unstarted: bool = False,
        timed_out: bool = False,
    ) -> _PendingSubprocessCleanup:
        """Retain the only local child handle beside its durable fence."""

        key = (attempt.record.scope, attempt.record.run_id)
        with self._condition:
            existing = self._pending_cleanup.get(key)
            if type(existing) is _PrelaunchCleanupJournal:
                if (
                    existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                pending = _PendingSubprocessCleanup(
                    runner=runner,
                    attempt=attempt,
                    cleanup_capability=cleanup_capability,
                    service=service,
                    receipt=receipt,
                    finalize_unstarted=(
                        existing.finalize_unstarted or finalize_unstarted
                    ),
                    timed_out=existing.timed_out or timed_out,
                    retry_ready=existing.retry_ready,
                    retry_lock=existing.retry_lock,
                )
                self._pending_cleanup[key] = pending
                self._condition.notify_all()
                return pending
            if type(existing) is _PendingFactoryCleanup:
                if (
                    service is None
                    or existing.owner is not service
                    or existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                if (
                    receipt is not None
                    and existing.receipt is not None
                    and existing.receipt != receipt
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup receipt changed"
                    )
                pending = _PendingSubprocessCleanup(
                    runner=runner,
                    attempt=attempt,
                    cleanup_capability=cleanup_capability,
                    service=service,
                    receipt=receipt if receipt is not None else existing.receipt,
                    finalize_unstarted=(
                        existing.finalize_unstarted or finalize_unstarted
                    ),
                    timed_out=existing.timed_out or timed_out,
                    retry_ready=existing.retry_ready,
                    retry_lock=existing.retry_lock,
                )
                self._pending_cleanup[key] = pending
                self._condition.notify_all()
                return pending
            if existing is not None:
                if (
                    type(existing) is not _PendingSubprocessCleanup
                    or existing.runner is not runner
                    or existing.attempt is not attempt
                    or existing.cleanup_capability != cleanup_capability
                    or (
                        existing.service is not None
                        and service is not None
                        and existing.service is not service
                    )
                ):
                    raise PrivateAnalysisExecutionUnavailable(
                        "private-analysis cleanup ownership already exists"
                    )
                if existing.service is None:
                    existing.service = service
                if receipt is not None:
                    if existing.receipt is not None and existing.receipt != receipt:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis cleanup receipt changed"
                        )
                    existing.receipt = receipt
                existing.finalize_unstarted = (
                    existing.finalize_unstarted or finalize_unstarted
                )
                existing.timed_out = existing.timed_out or timed_out
                return existing
            pending = _PendingSubprocessCleanup(
                runner=runner,
                attempt=attempt,
                cleanup_capability=cleanup_capability,
                service=service,
                receipt=receipt,
                finalize_unstarted=finalize_unstarted,
                timed_out=timed_out,
            )
            self._pending_cleanup[key] = pending
            self._condition.notify_all()
            return pending

    def _release_pending_after_terminal(
        self,
        attempt: _DurableExecutionAttempt,
        terminal: PrivateAnalysisRunRecord,
    ) -> None:
        """Acknowledge handoff, then release the exact outer retry journal."""

        if not terminal.state.is_terminal:
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis cleanup finalization is not terminal"
            )
        key = (attempt.record.scope, attempt.record.run_id)
        with self._condition:
            pending = self._pending_cleanup.get(key)
        if pending is None:
            return
        if pending.attempt is not attempt:
            raise PrivateAnalysisExecutionUnavailable(
                "private-analysis cleanup attempt changed before release"
            )
        if type(pending) is _PendingSubprocessCleanup:
            pending.runner.acknowledge_pending_cleanup()
        elif (
            type(pending) is _PendingFactoryCleanup
            and pending.receipt_runner is not None
        ):
            pending.receipt_runner.acknowledge_pending_receipt()
        with self._condition:
            if self._pending_cleanup.get(key) is not pending:
                raise PrivateAnalysisExecutionUnavailable(
                    "private-analysis cleanup ownership changed before release"
                )
            del self._pending_cleanup[key]
            self._condition.notify_all()

    def retry_pending_cleanup(
        self,
        *,
        limit: int = 100,
        scope: EvidenceScope | None = None,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        """Retry locally-owned cleanup with one bounded operation per run.

        Durable fences without a matching live entry belong to an earlier
        coordinator lifetime.  They remain fenced and visible through the run
        store; this method never reconstructs or kills from a persisted PID.
        """

        return self._retry_pending_cleanup(limit=limit, scope=scope)

    def _retry_pending_cleanup(
        self,
        *,
        limit: int,
        scope: EvidenceScope | None = None,
        deadline: float | None = None,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        selected_limit = _bounded_integer(limit, "limit", minimum=1, maximum=1_000)
        if scope is None:
            selected_scope = None
        elif type(scope) is EvidenceScope:
            selected_scope = EvidenceScope(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
            )
        else:
            raise TypeError("scope must be an exact EvidenceScope or None")
        with self._condition:
            selected = tuple(
                sorted(
                    (
                        item
                        for item in self._pending_cleanup.items()
                        if selected_scope is None or item[0][0] == selected_scope
                    ),
                    key=lambda item: (
                        item[0][0].tenant_id,
                        item[0][0].project_id,
                        item[0][0].workspace_id,
                        item[0][1],
                    ),
                )[:selected_limit]
            )
        finalized: list[PrivateAnalysisRunRecord] = []
        for key, pending in selected:
            if deadline is not None and time.monotonic() >= deadline:
                break
            if not pending.retry_ready:
                continue
            if not pending.retry_lock.acquire(blocking=False):
                continue
            locked_runner: CorePrivateAnalysisRunner | None = None
            cleanup_fenced = True
            try:
                if type(pending) is _PrelaunchCleanupJournal:
                    try:
                        matches = pending.attempt.cleanup_fence_matches(
                            pending.cleanup_capability
                        )
                    except PROCESS_CONTROL_EXCEPTIONS:
                        raise
                    except BaseException:  # noqa: BLE001, S112 - retry later.
                        continue
                    if matches is False:
                        self._discard_prelaunch_cleanup(pending)
                        continue
                    cleanup_fenced = matches is True
                elif type(pending) is _PendingFactoryCleanup:
                    if not self._cleanup_remote_service(
                        pending.owner,
                        pending.attempt,
                        pending.cleanup_capability,
                    ):
                        continue
                    if pending.receipt_runner is not None:
                        if not pending.receipt_runner.execution_lock.acquire(
                            blocking=False
                        ):
                            continue
                        locked_runner = pending.receipt_runner
                        if pending.receipt is None:
                            recovered_in_process_receipt = (
                                pending.receipt_runner.retry_pending_receipt()
                            )
                            if recovered_in_process_receipt is None:
                                raise PrivateAnalysisExecutionUnavailable(
                                    "private-analysis deferred receipt was lost"
                                )
                            pending.receipt = recovered_in_process_receipt
                else:
                    if type(pending) is not _PendingSubprocessCleanup:
                        raise PrivateAnalysisExecutionUnavailable(
                            "private-analysis cleanup ownership is invalid"
                        )
                    if not pending.runner.execution_lock.acquire(blocking=False):
                        continue
                    locked_runner = pending.runner
                    if pending.runner.cleanup_pending:
                        cleaned, recovered_subprocess_receipt = (
                            pending.runner.retry_pending_cleanup()
                        )
                        if not cleaned:
                            continue
                        if recovered_subprocess_receipt is not None:
                            pending.receipt = recovered_subprocess_receipt
                    if pending.service is not None:
                        try:
                            pending.service.close()
                        except PROCESS_CONTROL_EXCEPTIONS:
                            raise
                        except PrivateAnalysisFactoryProcessCleanupError:
                            continue
                        except BaseException:  # noqa: BLE001, S112 - retain handle.
                            continue
                    if not self._confirm_subprocess_cleanup_fence(
                        pending.attempt,
                        pending.cleanup_capability,
                    ):
                        continue
                try:
                    receipt = pending.receipt
                    if receipt is not None:
                        terminal = pending.attempt.complete_cleanup(
                            receipt,
                            pending.cleanup_capability,
                        )
                    elif pending.finalize_unstarted:
                        terminal = (
                            pending.attempt.finalize_cleanup_unstarted(
                                pending.cleanup_capability,
                                timed_out=pending.timed_out,
                            )
                            if cleanup_fenced
                            else pending.attempt.finalize_unstarted(
                                timed_out=pending.timed_out,
                            )
                        )
                    else:
                        continue
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException:  # noqa: BLE001, S112 - keep terminal intent.
                    continue
                try:
                    self._release_pending_after_terminal(pending.attempt, terminal)
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException:  # noqa: BLE001, S112 - retry acknowledgment.
                    continue
                finalized.append(terminal)
            finally:
                if locked_runner is not None:
                    locked_runner.execution_lock.release()
                pending.retry_lock.release()
        return tuple(finalized)

    @property
    def locally_owned_cleanup_count(self) -> int:
        """Return a payload-free diagnostic count for this coordinator lifetime."""

        with self._condition:
            return len(self._pending_cleanup)

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
        scope: EvidenceScope | None = None,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        """Run the store's no-retry recovery under this coordinator identity."""

        selected_limit = _bounded_integer(limit, "limit", minimum=1, maximum=1_000)
        actor = _actor_id(actor_id)
        retried = self.retry_pending_cleanup(
            limit=selected_limit,
            scope=scope,
        )
        if len(retried) >= selected_limit:
            return retried[:selected_limit]
        recovered = self._store.recover_expired_runs(
            actor_id=actor,
            limit=selected_limit - len(retried),
            scope=scope,
        )
        return retried + recovered

    def close(self, *, timeout: float = 30.0) -> None:
        """Stop admission, then wait within one deadline for runs and cleanup.

        An in-flight reaper retains its handles and durable fences after a
        timeout. A later close can wait for it; no duplicate reaper is started.
        """

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
            if (
                self._pending_cleanup
                and not self._close_cleanup_active
                and self._close_cleanup_error is None
                and time.monotonic() < deadline
            ):
                self._close_cleanup_active = True
                self._close_cleanup_error = None
                worker = threading.Thread(
                    target=self._close_cleanup,
                    args=(deadline,),
                    name="private-analysis-close-cleanup",
                    daemon=False,
                )
                try:
                    worker.start()
                except BaseException:
                    self._close_cleanup_active = False
                    raise
            while (
                self._active_count
                or self._active_monitor_count
                or self._close_cleanup_active
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PrivateAnalysisExecutionCloseTimeout(
                        "private-analysis executions did not stop before timeout"
                    )
                self._condition.wait(remaining)
            if self._close_cleanup_error is not None:
                error = self._close_cleanup_error
                self._close_cleanup_error = None
                raise error
            if self._pending_cleanup:
                raise PrivateAnalysisExecutionCloseTimeout(
                    "private-analysis child cleanup is still pending"
                )
            self._closed = True

    def _close_cleanup(self, deadline: float) -> None:
        error: BaseException | None = None
        try:
            self._retry_pending_cleanup(limit=1_000, deadline=deadline)
        except BaseException as caught:
            # Transfer failures, including process-control exceptions, to the
            # closing caller. Cleanup ownership remains in this coordinator.
            error = caught
        finally:
            with self._condition:
                self._close_cleanup_error = error
                self._close_cleanup_active = False
                self._condition.notify_all()

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
