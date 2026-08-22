"""Trusted in-process execution boundary for private analysis.

This adapter deliberately is not a Python sandbox.  The deployment-owned
callback is process-trusted, while every value it produces is treated as
untrusted protocol input.  Core grants the callback only detached request and
catalog values plus a closed, request-local evidence-tool gateway.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock, get_ident
from time import monotonic_ns
from typing import Final, TypeAlias

from .canonical import strict_canonical_json, strict_canonical_json_sha256
from .plugin_identity import (
    PluginExecutableIdentityError,
    executable_callable_fingerprint,
)
from .private_analysis import (
    EvidenceReference,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisToolCatalog,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolResult,
    PrivateAnalysisTransport,
    default_private_analysis_tool_catalog,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_from_json,
    private_analysis_request_from_json,
    private_analysis_request_json,
    private_analysis_tool_call_from_json,
    private_analysis_tool_catalog_from_json,
    private_analysis_tool_catalog_json,
    private_analysis_tool_error_from_json,
    private_analysis_tool_error_json,
    private_analysis_tool_result_from_json,
    private_analysis_tool_result_json,
)
from .private_analysis_factory_process import (
    PrivateAnalysisRemoteToolRunLease,
    PrivateAnalysisRemoteToolService,
)
from .private_analysis_runner_support import (
    MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES,
    PrivateAnalysisAccountingObserver,
    PrivateAnalysisCancellationProbe,
    PrivateAnalysisRunnerExecutionOwner,
    PrivateAnalysisTranscriptSummary,
    private_analysis_run_access_error,
)
from .private_analysis_runner_support import (
    PrivateAnalysisInProcessTranscriptSummaryMetadata as _TranscriptSummaryMetadata,
)
from .private_analysis_runner_support import (
    PrivateAnalysisRunAccountingSnapshot as _RunAccountingSnapshot,
)
from .private_analysis_runner_support import (
    detached_private_analysis_budget_state as _detached_budget_state,
)
from .private_analysis_runner_support import (
    detached_private_analysis_error as _detached_error,
)
from .private_analysis_runner_support import (
    detached_private_analysis_transcript_summary as _detached_transcript_summary,
)
from .private_analysis_runner_support import (
    empty_private_analysis_budget_state as _empty_budget_state,
)
from .private_analysis_runner_support import (
    private_analysis_budget_payload as _budget_payload,
)
from .private_analysis_runner_support import (
    private_analysis_error as _analysis_error,
)
from .private_analysis_runner_support import (
    private_analysis_error_outcome as _error_outcome,
)
from .private_analysis_runner_support import (
    private_analysis_execution_receipt_values as _execution_receipt_values,
)
from .private_analysis_runner_support import (
    private_analysis_prefixed_sha256 as _prefixed_sha256,
)
from .private_analysis_runner_support import (
    validate_private_analysis_result_json as _validated_callback_result,
)
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolRunLease,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION: Final = (
    "router_dump_analyzer.private_analysis_in_process_context.v1"
)
PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION: Final = (
    "router_dump_analyzer.private_analysis_in_process_transcript.v1"
)


class PrivateAnalysisInProcessToolResponseKind(StrEnum):
    RESULT = "result"
    ERROR = "error"


class PrivateAnalysisInProcessGatewayAbort(RuntimeError):
    """Static local unwind signal after a terminal gateway failure."""

    def __init__(self) -> None:
        super().__init__("Private analysis tool gateway stopped.")


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessContext:
    """Detached values supplied once to a trusted local callback."""

    request: PrivateAnalysisRequest
    catalog: PrivateAnalysisToolCatalog
    contract_version: str = PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION:
            raise ValueError("unsupported in-process context version")
        request = private_analysis_request_from_json(
            private_analysis_request_json(self.request)
        )
        catalog = private_analysis_tool_catalog_from_json(
            private_analysis_tool_catalog_json(self.catalog)
        )
        if request.tool_catalog_digest != catalog.catalog_digest:
            raise ValueError("request and tool catalog do not match")
        object.__setattr__(self, "request", request)
        object.__setattr__(self, "catalog", catalog)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisInProcessContext("
            f"request_digest={self.request.request_digest!r}, "
            f"catalog_digest={self.catalog.catalog_digest!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessToolResponse:
    """One detached tool result or error returned to the callback."""

    kind: PrivateAnalysisInProcessToolResponseKind
    result: PrivateAnalysisToolResult | None = None
    error: PrivateAnalysisToolError | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not PrivateAnalysisInProcessToolResponseKind:
            raise TypeError("kind must be PrivateAnalysisInProcessToolResponseKind")
        if self.kind is PrivateAnalysisInProcessToolResponseKind.RESULT:
            if (
                type(self.result) is not PrivateAnalysisToolResult
                or self.error is not None
            ):
                raise ValueError("result response requires only a tool result")
            detached = private_analysis_tool_result_from_json(
                private_analysis_tool_result_json(self.result)
            )
            object.__setattr__(self, "result", detached)
        else:
            if (
                type(self.error) is not PrivateAnalysisToolError
                or self.result is not None
            ):
                raise ValueError("error response requires only a tool error")
            detached_error = private_analysis_tool_error_from_json(
                private_analysis_tool_error_json(self.error)
            )
            object.__setattr__(self, "error", detached_error)

    @property
    def response_digest(self) -> str:
        if self.result is not None:
            return self.result.result_digest
        if self.error is None:  # constructor makes this unreachable
            raise RuntimeError("tool response is incomplete")
        return self.error.error_digest

    @property
    def canonical_json(self) -> str:
        if self.result is not None:
            return private_analysis_tool_result_json(self.result)
        if self.error is None:  # constructor makes this unreachable
            raise RuntimeError("tool response is incomplete")
        return private_analysis_tool_error_json(self.error)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisInProcessToolResponse("
            f"kind={self.kind.value!r}, response_digest={self.response_digest!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _PrivateAnalysisInProcessGatewayState:
    terminal_error: PrivateAnalysisError | None
    exchange_count: int
    exchange_metadata_bytes: int
    chain_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessTranscript:
    """Payload-free digest seal for one ephemeral execution."""

    request_digest: str
    catalog_digest: str
    instruction_profile_digest: str
    runner_configuration_digest: str
    exchange_count: int
    unattributed_tool_call_count: int
    exchange_metadata_bytes: int
    exchange_chain_digest: str
    evidence_ledger_digest: str
    budget_state: PrivateAnalysisToolBudgetState
    outcome_digest: str
    contract_version: str = PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION
    transcript_digest: str = ""

    def __post_init__(self) -> None:
        if self.contract_version != PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION:
            raise ValueError("unsupported in-process transcript version")
        for value, label in (
            (self.request_digest, "request_digest"),
            (self.catalog_digest, "catalog_digest"),
            (self.instruction_profile_digest, "instruction_profile_digest"),
            (self.runner_configuration_digest, "runner_configuration_digest"),
            (self.exchange_chain_digest, "exchange_chain_digest"),
            (self.evidence_ledger_digest, "evidence_ledger_digest"),
            (self.outcome_digest, "outcome_digest"),
        ):
            _prefixed_sha256(value, label)
        if type(self.exchange_count) is not int or self.exchange_count < 0:
            raise ValueError("exchange_count must be a non-negative integer")
        if (
            type(self.unattributed_tool_call_count) is not int
            or self.unattributed_tool_call_count < 0
        ):
            raise ValueError(
                "unattributed_tool_call_count must be a non-negative integer"
            )
        if (
            type(self.exchange_metadata_bytes) is not int
            or not 0
            <= self.exchange_metadata_bytes
            <= MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES
        ):
            raise ValueError("exchange metadata exceeds its bounded domain")
        budget = _detached_budget_state(self.budget_state)
        object.__setattr__(self, "budget_state", budget)
        attributed_call_count = self.exchange_count + self.unattributed_tool_call_count
        if not (
            budget.tool_calls_consumed
            <= attributed_call_count
            <= budget.tool_calls_consumed + 1
        ):
            raise ValueError("transcript exchange count disagrees with tool budget")
        expected = "sha256:" + strict_canonical_json_sha256(_transcript_payload(self))
        if self.transcript_digest:
            _prefixed_sha256(self.transcript_digest, "transcript_digest")
            if self.transcript_digest != expected:
                raise ValueError("transcript digest does not match")
        else:
            object.__setattr__(self, "transcript_digest", expected)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisInProcessTranscript("
            f"request_digest={self.request_digest!r}, "
            f"exchange_count={self.exchange_count}, "
            f"transcript_digest={self.transcript_digest!r})"
        )


def _detached_in_process_transcript(
    value: PrivateAnalysisInProcessTranscript,
) -> PrivateAnalysisInProcessTranscript:
    return PrivateAnalysisInProcessTranscript(
        request_digest=value.request_digest,
        catalog_digest=value.catalog_digest,
        instruction_profile_digest=value.instruction_profile_digest,
        runner_configuration_digest=value.runner_configuration_digest,
        exchange_count=value.exchange_count,
        unattributed_tool_call_count=value.unattributed_tool_call_count,
        exchange_metadata_bytes=value.exchange_metadata_bytes,
        exchange_chain_digest=value.exchange_chain_digest,
        evidence_ledger_digest=value.evidence_ledger_digest,
        budget_state=value.budget_state,
        outcome_digest=value.outcome_digest,
        contract_version=value.contract_version,
        transcript_digest=value.transcript_digest,
    )


def _in_process_transcript_summary(
    value: PrivateAnalysisInProcessTranscript,
) -> PrivateAnalysisTranscriptSummary:
    """Project one sealed transcript into the shared payload-free contract."""

    transcript = _detached_in_process_transcript(value)
    return PrivateAnalysisTranscriptSummary(
        transport=PrivateAnalysisTransport.IN_PROCESS,
        request_digest=transcript.request_digest,
        catalog_digest=transcript.catalog_digest,
        instruction_profile_digest=transcript.instruction_profile_digest,
        runner_configuration_digest=transcript.runner_configuration_digest,
        outcome_digest=transcript.outcome_digest,
        evidence_ledger_digest=transcript.evidence_ledger_digest,
        budget_state=transcript.budget_state,
        metadata=_TranscriptSummaryMetadata(
            transcript_digest=transcript.transcript_digest,
            exchange_count=transcript.exchange_count,
            unattributed_tool_call_count=transcript.unattributed_tool_call_count,
            exchange_metadata_bytes=transcript.exchange_metadata_bytes,
            exchange_chain_digest=transcript.exchange_chain_digest,
        ),
    )


class PrivateAnalysisInProcessExecutionReceipt:
    """Trusted internal, detached result of one in-process execution."""

    __slots__ = (
        "_budget",
        "_outcome_json",
        "_references",
        "_transcript",
        "_transcript_summary",
    )

    def __init__(
        self,
        *,
        outcome: PrivateAnalysisOutcome,
        transcript: PrivateAnalysisInProcessTranscript,
        disclosed_references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
    ) -> None:
        if type(transcript) is not PrivateAnalysisInProcessTranscript:
            raise TypeError("transcript must be PrivateAnalysisInProcessTranscript")
        detached_transcript = _detached_in_process_transcript(transcript)
        outcome_json, detached_references, budget = _execution_receipt_values(
            outcome=outcome,
            disclosed_references=disclosed_references,
            budget_state=budget_state,
            transcript_request_digest=detached_transcript.request_digest,
            transcript_evidence_ledger_digest=(
                detached_transcript.evidence_ledger_digest
            ),
            transcript_budget_state=detached_transcript.budget_state,
            transcript_outcome_digest=detached_transcript.outcome_digest,
        )
        self._outcome_json = outcome_json
        self._transcript = detached_transcript
        self._references = detached_references
        self._budget = budget
        self._transcript_summary = _in_process_transcript_summary(detached_transcript)

    @property
    def outcome(self) -> PrivateAnalysisOutcome:
        return private_analysis_outcome_from_json(self._outcome_json)

    @property
    def transcript(self) -> PrivateAnalysisInProcessTranscript:
        value = self._transcript
        return PrivateAnalysisInProcessTranscript(
            request_digest=value.request_digest,
            catalog_digest=value.catalog_digest,
            instruction_profile_digest=value.instruction_profile_digest,
            runner_configuration_digest=value.runner_configuration_digest,
            exchange_count=value.exchange_count,
            unattributed_tool_call_count=value.unattributed_tool_call_count,
            exchange_metadata_bytes=value.exchange_metadata_bytes,
            exchange_chain_digest=value.exchange_chain_digest,
            evidence_ledger_digest=value.evidence_ledger_digest,
            budget_state=value.budget_state,
            outcome_digest=value.outcome_digest,
            contract_version=value.contract_version,
            transcript_digest=value.transcript_digest,
        )

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]:
        return tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in self._references
        )

    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState:
        return _detached_budget_state(self._budget)

    @property
    def transcript_summary(self) -> PrivateAnalysisTranscriptSummary:
        """Return a detached transport-neutral transcript summary."""

        return _detached_transcript_summary(self._transcript_summary)

    def as_cancelled(self) -> PrivateAnalysisInProcessExecutionReceipt:
        """Return a cancelled receipt preserving the truthful execution ledger.

        Cancellation changes only the terminal outcome.  The already-observed
        tool exchange metadata, disclosed-reference ledger, and budget remain
        byte-for-byte bound into a newly sealed transcript.
        """

        transcript = self._transcript
        cancelled_outcome = _error_outcome(
            _analysis_error(
                transcript.request_digest,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.CANCELLED,
            )
        )
        cancelled_transcript = PrivateAnalysisInProcessTranscript(
            request_digest=transcript.request_digest,
            catalog_digest=transcript.catalog_digest,
            instruction_profile_digest=transcript.instruction_profile_digest,
            runner_configuration_digest=transcript.runner_configuration_digest,
            exchange_count=transcript.exchange_count,
            unattributed_tool_call_count=transcript.unattributed_tool_call_count,
            exchange_metadata_bytes=transcript.exchange_metadata_bytes,
            exchange_chain_digest=transcript.exchange_chain_digest,
            evidence_ledger_digest=transcript.evidence_ledger_digest,
            budget_state=self._budget,
            outcome_digest=cancelled_outcome.outcome_digest,
        )
        return PrivateAnalysisInProcessExecutionReceipt(
            outcome=cancelled_outcome,
            transcript=cancelled_transcript,
            disclosed_references=self._references,
            budget_state=self._budget,
        )

    def __repr__(self) -> str:
        outcome = self.outcome
        return (
            "PrivateAnalysisInProcessExecutionReceipt("
            f"outcome={outcome.kind.value!r}, "
            f"outcome_digest={outcome.outcome_digest!r}, "
            f"transcript_digest={self._transcript.transcript_digest!r})"
        )


PrivateAnalysisInProcessModelCallback: TypeAlias = Callable[
    [PrivateAnalysisInProcessContext, "PrivateAnalysisInProcessToolGateway"],
    str,
]


class PrivateAnalysisInProcessToolGateway:
    """Thread-affine closed-tool gateway visible to one trusted callback."""

    __slots__ = (
        "_accounting",
        "_budget_exhausted",
        "_cancellation_probe",
        "_catalog_digest",
        "_chain_digest",
        "_closed",
        "_deadline_ns",
        "_exchange_count",
        "_exchange_metadata_bytes",
        "_in_flight",
        "_instruction_profile_digest",
        "_lease",
        "_lock",
        "_max_exchanges",
        "_owner_thread_id",
        "_request_digest",
        "_runner_configuration_digest",
        "_terminal_error",
    )

    def __init__(
        self,
        lease: PrivateAnalysisToolRunLease | PrivateAnalysisRemoteToolRunLease,
        *,
        accounting: _RunAccountingSnapshot,
        instruction_profile_digest: str,
        runner_configuration_digest: str,
        deadline_ns: int,
        cancellation_probe: PrivateAnalysisCancellationProbe | None = None,
    ) -> None:
        if type(lease) not in {
            PrivateAnalysisToolRunLease,
            PrivateAnalysisRemoteToolRunLease,
        }:
            raise TypeError("lease must be a core private-analysis tool lease")
        if type(accounting) is not _RunAccountingSnapshot:
            raise TypeError("accounting must be PrivateAnalysisRunAccountingSnapshot")
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")
        request = lease.request
        self._lease = lease
        self._accounting = accounting
        self._cancellation_probe = cancellation_probe
        self._request_digest = request.request_digest
        self._catalog_digest = request.tool_catalog_digest
        self._instruction_profile_digest = _prefixed_sha256(
            instruction_profile_digest, "instruction_profile_digest"
        )
        self._runner_configuration_digest = _prefixed_sha256(
            runner_configuration_digest, "runner_configuration_digest"
        )
        if type(deadline_ns) is not int or deadline_ns <= 0:
            raise ValueError("deadline_ns must be a positive integer")
        self._deadline_ns = deadline_ns
        self._owner_thread_id = get_ident()
        self._max_exchanges = request.limits.max_tool_calls + 1
        self._exchange_count = 0
        self._exchange_metadata_bytes = 0
        self._budget_exhausted = False
        self._closed = False
        self._in_flight = False
        self._terminal_error: PrivateAnalysisError | None = None
        self._lock = Lock()
        self._chain_digest = _transcript_seed(
            request_digest=self._request_digest,
            catalog_digest=self._catalog_digest,
            instruction_profile_digest=self._instruction_profile_digest,
            runner_configuration_digest=self._runner_configuration_digest,
        )

    def execute(self, call_json: str) -> PrivateAnalysisInProcessToolResponse:
        """Execute one canonical call; terminal misuse cannot be caught away."""

        self._begin_exchange()
        response: PrivateAnalysisInProcessToolResponse | None = None
        call_digest: str | None = None
        service_error: PrivateAnalysisError | None = None
        protocol_error: PrivateAnalysisError | None = None
        unexpected_failure = False
        try:
            self._probe_cancellation()
            call = private_analysis_tool_call_from_json(call_json)
            call_digest = call.call_digest
            self._probe_cancellation()
            raw_response = self._lease.execute(call)
            self._accounting.refresh(self._lease)
            # A completed tool call may already have disclosed evidence.  The
            # detached accounting snapshot is therefore published before a
            # newly requested cancellation can suppress its response.
            self._probe_cancellation()
            if type(raw_response) is PrivateAnalysisToolResult:
                result = private_analysis_tool_result_from_json(
                    private_analysis_tool_result_json(raw_response)
                )
                response = PrivateAnalysisInProcessToolResponse(
                    kind=PrivateAnalysisInProcessToolResponseKind.RESULT,
                    result=result,
                )
            elif type(raw_response) is PrivateAnalysisToolError:
                error = private_analysis_tool_error_from_json(
                    private_analysis_tool_error_json(raw_response)
                )
                response = PrivateAnalysisInProcessToolResponse(
                    kind=PrivateAnalysisInProcessToolResponseKind.ERROR,
                    error=error,
                )
            else:
                unexpected_failure = True
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisToolServiceError as error:
            service_error = _detached_error(error.error)
        except BaseException:  # noqa: BLE001 - executable trust boundary.
            if call_digest is None:
                protocol_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            else:
                unexpected_failure = True
        finally:
            self._finish_in_flight()

        expired = _deadline_expired(self._deadline_ns)
        if expired:
            self._latch_error(
                _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )
        if service_error is not None:
            if call_digest is not None:
                self._record_exchange(
                    call_digest,
                    "analysis_error",
                    service_error.error_digest,
                )
            if not expired:
                self._latch_error(service_error)
        elif protocol_error is not None:
            if not expired:
                self._latch_error(protocol_error)
        elif unexpected_failure:
            if not expired:
                self._latch_error(
                    _analysis_error(
                        self._request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                    )
                )
        elif response is not None and call_digest is not None:
            self._record_exchange(
                call_digest,
                response.kind.value,
                response.response_digest,
            )
            if (
                response.error is not None
                and response.error.code is PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED
            ):
                self._budget_exhausted = True
        self._probe_cancellation()
        self._raise_if_terminal()
        if response is None:
            self._latch_error(
                _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_FAILED,
                )
            )
            self._raise_if_terminal()
            raise RuntimeError("terminal gateway state was not raised")
        return response

    def checkpoint(self) -> None:
        """Cooperatively observe terminal state and the monotonic deadline."""

        self._require_owner_and_open()
        self._probe_cancellation()
        if _deadline_expired(self._deadline_ns):
            self._latch_error(
                _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )
        self._raise_if_terminal()

    @property
    def remaining_deadline_ms(self) -> int:
        self._require_owner_and_open()
        remaining_ns = max(0, self._deadline_ns - monotonic_ns())
        return remaining_ns // 1_000_000

    def close(self) -> None:
        wrong_thread = get_ident() != self._owner_thread_id
        with self._lock:
            if self._closed:
                if wrong_thread and self._terminal_error is None:
                    self._terminal_error = _analysis_error(
                        self._request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    )
                if wrong_thread:
                    raise PrivateAnalysisInProcessGatewayAbort()
                return
            if wrong_thread and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            if self._in_flight and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            self._closed = True
        if wrong_thread:
            raise PrivateAnalysisInProcessGatewayAbort()

    def _final_state(self) -> _PrivateAnalysisInProcessGatewayState:
        """Return one atomic runner-only snapshot after owner-thread close."""

        if get_ident() != self._owner_thread_id:
            self._latch_error(
                _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            )
            raise PrivateAnalysisInProcessGatewayAbort()
        with self._lock:
            if not self._closed:
                if self._terminal_error is None:
                    self._terminal_error = _analysis_error(
                        self._request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    )
                raise PrivateAnalysisInProcessGatewayAbort()
            terminal = self._terminal_error
            return _PrivateAnalysisInProcessGatewayState(
                terminal_error=None if terminal is None else _detached_error(terminal),
                exchange_count=self._exchange_count,
                exchange_metadata_bytes=self._exchange_metadata_bytes,
                chain_digest=self._chain_digest,
            )

    def _begin_exchange(self) -> None:
        self._require_owner_and_open()
        self._probe_cancellation()
        with self._lock:
            terminal = self._terminal_error is not None
            if self._in_flight and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
                terminal = True
            if self._budget_exhausted and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                )
                terminal = True
            if (
                self._exchange_count >= self._max_exchanges
                and self._terminal_error is None
            ):
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                )
                terminal = True
            if not terminal:
                self._in_flight = True
        self._raise_if_terminal()
        if _deadline_expired(self._deadline_ns):
            self._finish_in_flight()
            self._latch_error(
                _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )
            self._raise_if_terminal()

    def _probe_cancellation(self) -> None:
        error = _cancellation_error(self._request_digest, self._cancellation_probe)
        if error is not None:
            self._latch_error(error)
            self._raise_if_terminal()

    def _require_owner_and_open(self) -> None:
        wrong_thread = get_ident() != self._owner_thread_id
        with self._lock:
            closed = self._closed
            if closed and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            if wrong_thread and not closed and self._terminal_error is None:
                self._terminal_error = _analysis_error(
                    self._request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
        if closed:
            raise PrivateAnalysisInProcessGatewayAbort()
        if wrong_thread:
            self._raise_if_terminal()

    def _finish_in_flight(self) -> None:
        with self._lock:
            self._in_flight = False

    def _record_exchange(
        self,
        call_digest: str,
        response_kind: str,
        response_digest: str,
    ) -> None:
        _prefixed_sha256(call_digest, "call_digest")
        _prefixed_sha256(response_digest, "response_digest")
        with self._lock:
            if self._exchange_count >= self._max_exchanges:
                if self._terminal_error is None:
                    self._terminal_error = _analysis_error(
                        self._request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                    )
                return
            payload = {
                "contract_version": PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION,
                "domain": "tool_exchange",
                "index": self._exchange_count,
                "previous_digest": self._chain_digest,
                "call_digest": call_digest,
                "response_kind": response_kind,
                "response_digest": response_digest,
            }
            encoded_bytes = len(strict_canonical_json(payload).encode("utf-8"))
            if (
                self._exchange_metadata_bytes + encoded_bytes
                > MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES
            ):
                if self._terminal_error is None:
                    self._terminal_error = _analysis_error(
                        self._request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
                    )
                return
            self._chain_digest = "sha256:" + strict_canonical_json_sha256(payload)
            self._exchange_count += 1
            self._exchange_metadata_bytes += encoded_bytes

    def _latch_error(self, error: PrivateAnalysisError) -> None:
        detached = _detached_error(error)
        with self._lock:
            if self._terminal_error is None:
                self._terminal_error = detached

    def _raise_if_terminal(self) -> None:
        with self._lock:
            terminal = self._terminal_error is not None
        if terminal:
            raise PrivateAnalysisInProcessGatewayAbort()

    def __repr__(self) -> str:
        with self._lock:
            state = "closed" if self._closed else "open"
            count = self._exchange_count
        return (
            "PrivateAnalysisInProcessToolGateway("
            f"request_digest={self._request_digest!r}, state={state!r}, "
            f"exchange_count={count})"
        )


@dataclass(frozen=True, slots=True)
class _DeferredInProcessReceipt:
    """Receipt-capable state retained when process control interrupts sealing."""

    request: PrivateAnalysisRequest
    catalog: PrivateAnalysisToolCatalog
    instruction_profile_digest: str
    runner_configuration_digest: str
    gateway_state: _PrivateAnalysisInProcessGatewayState
    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState

    def seal(self) -> PrivateAnalysisInProcessExecutionReceipt:
        outcome = _error_outcome(
            _analysis_error(
                self.request.request_digest,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        )
        try:
            return _execution_receipt(
                request=self.request,
                catalog=self.catalog,
                instruction_profile_digest=self.instruction_profile_digest,
                runner_configuration_digest=self.runner_configuration_digest,
                gateway_state=self.gateway_state,
                references=self.references,
                budget_state=self.budget_state,
                outcome=outcome,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - corrupted runner-only metadata.
            safe_gateway_state = _PrivateAnalysisInProcessGatewayState(
                terminal_error=None,
                exchange_count=0,
                exchange_metadata_bytes=0,
                chain_digest=_transcript_seed(
                    request_digest=self.request.request_digest,
                    catalog_digest=self.catalog.catalog_digest,
                    instruction_profile_digest=self.instruction_profile_digest,
                    runner_configuration_digest=self.runner_configuration_digest,
                ),
            )
            return _execution_receipt(
                request=self.request,
                catalog=self.catalog,
                instruction_profile_digest=self.instruction_profile_digest,
                runner_configuration_digest=self.runner_configuration_digest,
                gateway_state=safe_gateway_state,
                references=self.references,
                budget_state=self.budget_state,
                outcome=outcome,
            )


@dataclass(slots=True)
class _PendingInProcessReceipt:
    deferred: _DeferredInProcessReceipt
    receipt: PrivateAnalysisInProcessExecutionReceipt | None = None


class _InProcessReceiptOwner:
    """Receipt state shared by every detached view of one configured runner."""

    __slots__ = ("lock", "pending")

    def __init__(self) -> None:
        self.lock: Lock = Lock()
        self.pending: _PendingInProcessReceipt | None = None


class ConfiguredPrivateAnalysisInProcessRunner(PrivateAnalysisRunnerExecutionOwner):
    """Execute one request with a process-trusted local callback."""

    __slots__ = (
        "_callback",
        "_callback_attestation_digest",
        "_receipt_owner",
    )

    def __init__(
        self,
        selection: PrivateAnalysisRunnerSelection,
        *,
        instruction_profile_digest: str,
        model_callback: PrivateAnalysisInProcessModelCallback,
    ) -> None:
        super().__init__(
            selection,
            instruction_profile_digest=instruction_profile_digest,
        )
        if self._selection.transport is not PrivateAnalysisTransport.IN_PROCESS:
            raise ValueError("in-process runner requires in_process transport")
        if not callable(model_callback):
            raise TypeError("model_callback must be callable")
        self._callback = model_callback
        self._callback_attestation_digest: str | None = None
        self._receipt_owner = _InProcessReceiptOwner()

    def detached(self) -> ConfiguredPrivateAnalysisInProcessRunner:
        """Return a registration-owned runner sealed to this exact callback."""

        try:
            current = executable_callable_fingerprint(self._callback)
        except PluginExecutableIdentityError as error:
            raise ValueError(
                "model_callback has no bounded executable identity"
            ) from error
        expected = self._callback_attestation_digest
        if expected is not None and current != expected:
            raise ValueError("model_callback executable identity changed")
        detached = ConfiguredPrivateAnalysisInProcessRunner(
            self.selection,
            instruction_profile_digest=self.instruction_profile_digest,
            model_callback=self._callback,
        )
        detached._callback_attestation_digest = current
        # Ownership is detached, but every clone of one admitted runner must
        # retain the same execution gate. Otherwise two coordinators can turn
        # registration detachment into parallel access to a runner that was
        # deliberately configured as a single execution authority.
        detached._private_analysis_execution_lock = self.execution_lock
        detached._receipt_owner = self._receipt_owner
        return detached

    @property
    def receipt_pending(self) -> bool:
        """Return whether a started execution still needs receipt handoff."""

        with self._receipt_owner.lock:
            return self._receipt_owner.pending is not None

    def _retain_pending_receipt(self, receipt: _DeferredInProcessReceipt) -> None:
        pending = _PendingInProcessReceipt(deferred=receipt)
        with self._receipt_owner.lock:
            if self._receipt_owner.pending is not None:
                raise RuntimeError("in-process receipt ownership already exists")
            self._receipt_owner.pending = pending

    def retry_pending_receipt(
        self,
    ) -> PrivateAnalysisInProcessExecutionReceipt | None:
        """Seal or return the exact receipt withheld by process control."""

        with self._receipt_owner.lock:
            pending = self._receipt_owner.pending
            if pending is None:
                return None
            if pending.receipt is None:
                pending.receipt = pending.deferred.seal()
            return pending.receipt

    def acknowledge_pending_receipt(self) -> None:
        """Release retained state only after durable terminal handoff."""

        with self._receipt_owner.lock:
            pending = self._receipt_owner.pending
            if pending is None:
                return
            if pending.receipt is None:
                raise RuntimeError("in-process receipt has not been sealed")
            self._receipt_owner.pending = None

    def _callback_identity_is_current(self) -> bool:
        expected = self._callback_attestation_digest
        if expected is None:
            # Standalone, explicitly trusted use remains source compatible;
            # core registrations always replace the runner with detached().
            return True
        try:
            current = executable_callable_fingerprint(self._callback)
        except PluginExecutableIdentityError:
            return False
        return current == expected

    def execute(
        self,
        tool_service: PrivateAnalysisToolService | PrivateAnalysisRemoteToolService,
        *,
        accounting_observer: PrivateAnalysisAccountingObserver | None = None,
        cancellation_probe: PrivateAnalysisCancellationProbe | None = None,
        absolute_deadline_ns: int | None = None,
    ) -> PrivateAnalysisInProcessExecutionReceipt:
        """Execute once with cooperative cancellation at trusted boundaries.

        In-process callbacks are trusted code and cannot be forcibly
        preempted.  A callback that neither returns nor calls its gateway will
        not observe cancellation until it next reaches one of those points.
        """

        if self.receipt_pending:
            raise RuntimeError("in-process receipt handoff is pending")
        if type(tool_service) not in {
            PrivateAnalysisToolService,
            PrivateAnalysisRemoteToolService,
        }:
            raise TypeError("tool_service must be a core private-analysis service")
        if accounting_observer is not None and not callable(accounting_observer):
            raise TypeError("accounting_observer must be callable or None")
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")
        request = tool_service.request
        start_ns = monotonic_ns()
        if absolute_deadline_ns is not None and (
            type(absolute_deadline_ns) is not int or absolute_deadline_ns < 0
        ):
            raise ValueError(
                "absolute_deadline_ns must be a non-negative integer or None"
            )
        deadline_ns = (
            start_ns + request.limits.deadline_ms * 1_000_000
            if absolute_deadline_ns is None
            else absolute_deadline_ns
        )
        catalog = default_private_analysis_tool_catalog()

        def early_receipt(
            error: PrivateAnalysisError,
        ) -> PrivateAnalysisInProcessExecutionReceipt:
            # The coordinator propagates one absolute deadline that includes
            # evidence preparation. An already-expired deadline must retain
            # timeout precedence over binding or lease-acquisition failures.
            if _deadline_expired(deadline_ns):
                error = _analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            return _standalone_receipt(
                request=request,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                catalog=catalog,
                outcome=_error_outcome(error),
                references=(),
                budget_state=_empty_budget_state(request),
            )

        if _deadline_expired(deadline_ns):
            return early_receipt(
                _analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )
        binding_error = self._binding_error(request, catalog)
        if binding_error is not None:
            return early_receipt(binding_error)

        cancellation_error = _cancellation_error(
            request.request_digest,
            cancellation_probe,
        )
        if cancellation_error is not None:
            return early_receipt(cancellation_error)

        try:
            lease = tool_service.acquire_run_lease()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisToolServiceError as error:
            return early_receipt(error.error)

        budget_state = _empty_budget_state(request)
        accounting = _RunAccountingSnapshot(
            (),
            budget_state,
            observer=accounting_observer,
        )
        gateway: PrivateAnalysisInProcessToolGateway | None = None
        gateway_state = _PrivateAnalysisInProcessGatewayState(
            terminal_error=None,
            exchange_count=0,
            exchange_metadata_bytes=0,
            chain_digest=_transcript_seed(
                request_digest=request.request_digest,
                catalog_digest=catalog.catalog_digest,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
            ),
        )
        raw_result: object = None
        outcome_error: PrivateAnalysisError | None = None
        outcome = _error_outcome(
            _analysis_error(
                request.request_digest,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_FAILED,
            )
        )
        pending_process_control: BaseException | None = None
        execution_failed = False
        finalizer_failed = False
        try:
            try:
                accounting.refresh(lease)
                cancellation_error = _cancellation_error(
                    request.request_digest,
                    cancellation_probe,
                )
                if cancellation_error is not None:
                    outcome_error = cancellation_error
                gateway = PrivateAnalysisInProcessToolGateway(
                    lease,
                    accounting=accounting,
                    instruction_profile_digest=self._instruction_profile_digest,
                    runner_configuration_digest=self._selection.configuration_digest,
                    deadline_ns=deadline_ns,
                    cancellation_probe=cancellation_probe,
                )
                try:
                    if outcome_error is None:
                        outcome_error = _access_or_deadline_error(
                            lease,
                            request,
                            deadline_ns,
                        )
                    if outcome_error is None:
                        context = PrivateAnalysisInProcessContext(
                            request=request,
                            catalog=catalog,
                        )
                        if not self._callback_identity_is_current():
                            outcome_error = _analysis_error(
                                request.request_digest,
                                PrivateAnalysisErrorStage.RUNNER,
                                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                            )
                        else:
                            # Fingerprinting is bounded but may still consume
                            # the remainder of a near-expired deadline. Recheck
                            # cancellation and access after attestation so no
                            # callback begins on authority that expired while
                            # its executable identity was being verified.
                            outcome_error = _cancellation_error(
                                request.request_digest,
                                cancellation_probe,
                            ) or _access_or_deadline_error(
                                lease,
                                request,
                                deadline_ns,
                            )
                            if outcome_error is None:
                                try:
                                    raw_result = self._callback(context, gateway)
                                except PROCESS_CONTROL_EXCEPTIONS:
                                    raise
                                except BaseException:  # noqa: BLE001 - runner boundary.
                                    outcome_error = _analysis_error(
                                        request.request_digest,
                                        PrivateAnalysisErrorStage.RUNNER,
                                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                                    )
                        cancellation_error = _cancellation_error(
                            request.request_digest,
                            cancellation_probe,
                        )
                        if cancellation_error is not None:
                            outcome_error = cancellation_error
                finally:
                    gateway.close()

                gateway_state = gateway._final_state()
                terminal = gateway_state.terminal_error
                if terminal is not None:
                    outcome_error = terminal
                elif outcome_error is None and _deadline_expired(deadline_ns):
                    outcome_error = _analysis_error(
                        request.request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.TIMEOUT,
                    )
                elif outcome_error is None:
                    outcome_error = _access_or_deadline_error(
                        lease,
                        request,
                        deadline_ns,
                    )

                try:
                    accounting.refresh(lease)
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException:  # noqa: BLE001 - snapshot boundary.
                    outcome_error = _analysis_error(
                        request.request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_FAILED,
                    )
                if (
                    accounting.budget_state.tool_calls_consumed
                    > gateway_state.exchange_count
                ):
                    outcome_error = _analysis_error(
                        request.request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    )
                references = accounting.references
                if outcome_error is None:
                    outcome_error = _cancellation_error(
                        request.request_digest,
                        cancellation_probe,
                    )
                if outcome_error is None:
                    result, result_error = _validated_callback_result(
                        raw_result,
                        request,
                        references,
                    )
                    if _deadline_expired(deadline_ns):
                        outcome_error = _analysis_error(
                            request.request_digest,
                            PrivateAnalysisErrorStage.RUNNER,
                            PrivateAnalysisErrorCode.TIMEOUT,
                        )
                    elif result_error is not None:
                        outcome_error = result_error
                    elif result is not None:
                        outcome = PrivateAnalysisOutcome(
                            kind=PrivateAnalysisOutcomeKind.RESULT,
                            result=result,
                        )
                    else:  # helper makes this unreachable
                        outcome_error = _analysis_error(
                            request.request_digest,
                            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                            PrivateAnalysisErrorCode.INVALID_RESULT,
                        )
                if outcome_error is not None:
                    outcome = _error_outcome(outcome_error)
            except PROCESS_CONTROL_EXCEPTIONS as error:
                pending_process_control = error
            except BaseException:  # noqa: BLE001 - runner boundary.
                execution_failed = True
        finally:
            if gateway is not None:
                try:
                    gateway.close()
                except PROCESS_CONTROL_EXCEPTIONS as error:
                    if pending_process_control is None:
                        pending_process_control = error
                except BaseException:  # noqa: BLE001 - finalizer boundary.
                    finalizer_failed = True
            try:
                accounting.refresh(lease)
            except PROCESS_CONTROL_EXCEPTIONS as error:
                if pending_process_control is None:
                    pending_process_control = error
            except BaseException:  # noqa: BLE001 - finalizer boundary.
                finalizer_failed = True
            try:
                lease.close()
            except PROCESS_CONTROL_EXCEPTIONS as error:
                if pending_process_control is None:
                    pending_process_control = error
            except BaseException:  # noqa: BLE001 - finalizer boundary.
                finalizer_failed = True

        if pending_process_control is not None:
            raise pending_process_control.with_traceback(
                pending_process_control.__traceback__
            )
        if execution_failed or finalizer_failed:
            outcome = _error_outcome(
                _analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT
                    if _deadline_expired(deadline_ns)
                    else PrivateAnalysisErrorCode.RUNNER_FAILED,
                )
            )
        elif _deadline_expired(deadline_ns):
            outcome = _error_outcome(
                _analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.TIMEOUT,
                )
            )

        references = accounting.references
        budget_state = accounting.budget_state

        final_cancellation_error = _cancellation_error(
            request.request_digest,
            cancellation_probe,
        )
        if final_cancellation_error is not None:
            outcome = _error_outcome(final_cancellation_error)

        deferred_receipt = _DeferredInProcessReceipt(
            request=request,
            catalog=catalog,
            instruction_profile_digest=self._instruction_profile_digest,
            runner_configuration_digest=self._selection.configuration_digest,
            gateway_state=gateway_state,
            references=references,
            budget_state=budget_state,
        )
        try:
            return _deadline_checked_execution_receipt(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                gateway_state=gateway_state,
                references=references,
                budget_state=budget_state,
                outcome=outcome,
                deadline_ns=deadline_ns,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            self._retain_pending_receipt(deferred_receipt)
            raise
        except BaseException:  # noqa: BLE001 - trusted callback integrity boundary.
            fallback_outcome = _error_outcome(
                _analysis_error(
                    request.request_digest,
                    PrivateAnalysisErrorStage.RUNNER,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )
            )
            try:
                return _deadline_checked_execution_receipt(
                    request=request,
                    instruction_profile_digest=self._instruction_profile_digest,
                    runner_configuration_digest=(self._selection.configuration_digest),
                    catalog=catalog,
                    gateway_state=gateway_state,
                    outcome=fallback_outcome,
                    references=references,
                    budget_state=budget_state,
                    deadline_ns=deadline_ns,
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                self._retain_pending_receipt(deferred_receipt)
                raise
            except BaseException:  # noqa: BLE001 - corrupted private state.
                safe_gateway_state = _PrivateAnalysisInProcessGatewayState(
                    terminal_error=None,
                    exchange_count=0,
                    exchange_metadata_bytes=0,
                    chain_digest=_transcript_seed(
                        request_digest=request.request_digest,
                        catalog_digest=catalog.catalog_digest,
                        instruction_profile_digest=self._instruction_profile_digest,
                        runner_configuration_digest=(
                            self._selection.configuration_digest
                        ),
                    ),
                )
                try:
                    return _deadline_checked_execution_receipt(
                        request=request,
                        instruction_profile_digest=self._instruction_profile_digest,
                        runner_configuration_digest=(
                            self._selection.configuration_digest
                        ),
                        catalog=catalog,
                        gateway_state=safe_gateway_state,
                        outcome=fallback_outcome,
                        references=references,
                        budget_state=budget_state,
                        deadline_ns=deadline_ns,
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    self._retain_pending_receipt(deferred_receipt)
                    raise

    def _binding_error(
        self,
        request: PrivateAnalysisRequest,
        catalog: PrivateAnalysisToolCatalog,
    ) -> PrivateAnalysisError | None:
        selected = request.runner
        if selected != self._selection:
            return _analysis_error(
                request.request_digest,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            )
        if (
            request.instruction_profile_digest != self._instruction_profile_digest
            or request.tool_catalog_digest != catalog.catalog_digest
        ):
            return _analysis_error(
                request.request_digest,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        return None

    def __repr__(self) -> str:
        return (
            "ConfiguredPrivateAnalysisInProcessRunner("
            f"runner_id={self._selection.runner_id!r}, "
            f"runner_version={self._selection.runner_version!r}, "
            f"configuration_digest={self._selection.configuration_digest!r})"
        )


def _access_or_deadline_error(
    lease: PrivateAnalysisToolRunLease | PrivateAnalysisRemoteToolRunLease,
    request: PrivateAnalysisRequest,
    deadline_ns: int,
) -> PrivateAnalysisError | None:
    return private_analysis_run_access_error(
        lease,
        request,
        deadline_ns,
        deadline_expired=_deadline_expired,
    )


def _cancellation_error(
    request_digest: str,
    cancellation_probe: PrivateAnalysisCancellationProbe | None,
) -> PrivateAnalysisError | None:
    """Project one cooperative cancellation observation into a static error."""

    if cancellation_probe is None:
        return None
    try:
        cancelled = cancellation_probe()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - deployment-owned probe boundary.
        return _analysis_error(
            request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
    if type(cancelled) is not bool:
        return _analysis_error(
            request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
    if cancelled:
        return _analysis_error(
            request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.CANCELLED,
        )
    return None


def _deadline_expired(deadline_ns: int) -> bool:
    return monotonic_ns() >= deadline_ns


def _standalone_receipt(
    *,
    request: PrivateAnalysisRequest,
    instruction_profile_digest: str,
    runner_configuration_digest: str,
    catalog: PrivateAnalysisToolCatalog,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
) -> PrivateAnalysisInProcessExecutionReceipt:
    chain = _transcript_seed(
        request_digest=request.request_digest,
        catalog_digest=catalog.catalog_digest,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
    )
    transcript = _sealed_transcript(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
        exchange_count=0,
        exchange_metadata_bytes=0,
        exchange_chain_digest=chain,
        references=references,
        budget_state=budget_state,
        outcome=outcome,
    )
    return PrivateAnalysisInProcessExecutionReceipt(
        outcome=outcome,
        transcript=transcript,
        disclosed_references=references,
        budget_state=budget_state,
    )


def _deadline_checked_execution_receipt(
    *,
    request: PrivateAnalysisRequest,
    instruction_profile_digest: str,
    runner_configuration_digest: str,
    catalog: PrivateAnalysisToolCatalog,
    gateway_state: _PrivateAnalysisInProcessGatewayState,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    deadline_ns: int,
) -> PrivateAnalysisInProcessExecutionReceipt:
    receipt = _execution_receipt(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
        gateway_state=gateway_state,
        outcome=outcome,
        references=references,
        budget_state=budget_state,
    )
    if (
        outcome.error is not None
        and outcome.error.code is PrivateAnalysisErrorCode.TIMEOUT
    ) or not _deadline_expired(deadline_ns):
        return receipt
    timeout_outcome = _error_outcome(
        _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    )
    return _execution_receipt(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
        gateway_state=gateway_state,
        outcome=timeout_outcome,
        references=references,
        budget_state=budget_state,
    )


def _execution_receipt(
    *,
    request: PrivateAnalysisRequest,
    instruction_profile_digest: str,
    runner_configuration_digest: str,
    catalog: PrivateAnalysisToolCatalog,
    gateway_state: _PrivateAnalysisInProcessGatewayState,
    outcome: PrivateAnalysisOutcome,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
) -> PrivateAnalysisInProcessExecutionReceipt:
    transcript = _sealed_transcript(
        request=request,
        catalog=catalog,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
        exchange_count=gateway_state.exchange_count,
        exchange_metadata_bytes=gateway_state.exchange_metadata_bytes,
        exchange_chain_digest=gateway_state.chain_digest,
        references=references,
        budget_state=budget_state,
        outcome=outcome,
    )
    receipt = PrivateAnalysisInProcessExecutionReceipt(
        outcome=outcome,
        transcript=transcript,
        disclosed_references=references,
        budget_state=budget_state,
    )
    return receipt


def _sealed_transcript(
    *,
    request: PrivateAnalysisRequest,
    catalog: PrivateAnalysisToolCatalog,
    instruction_profile_digest: str,
    runner_configuration_digest: str,
    exchange_count: int,
    exchange_metadata_bytes: int,
    exchange_chain_digest: str,
    references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    outcome: PrivateAnalysisOutcome,
) -> PrivateAnalysisInProcessTranscript:
    ledger_digest = evidence_snapshot_digest(references)
    seal_payload = {
        "contract_version": PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION,
        "domain": "execution_seal",
        "request_digest": request.request_digest,
        "catalog_digest": catalog.catalog_digest,
        "instruction_profile_digest": instruction_profile_digest,
        "runner_configuration_digest": runner_configuration_digest,
        "exchange_count": exchange_count,
        "exchange_metadata_bytes": exchange_metadata_bytes,
        "exchange_chain_digest": exchange_chain_digest,
        "evidence_ledger_digest": ledger_digest,
        "budget_state": _budget_payload(budget_state),
        "outcome_digest": outcome.outcome_digest,
    }
    sealed_chain = "sha256:" + strict_canonical_json_sha256(seal_payload)
    return PrivateAnalysisInProcessTranscript(
        request_digest=request.request_digest,
        catalog_digest=catalog.catalog_digest,
        instruction_profile_digest=instruction_profile_digest,
        runner_configuration_digest=runner_configuration_digest,
        exchange_count=exchange_count,
        unattributed_tool_call_count=max(
            0,
            budget_state.tool_calls_consumed - exchange_count,
        ),
        exchange_metadata_bytes=exchange_metadata_bytes,
        exchange_chain_digest=sealed_chain,
        evidence_ledger_digest=ledger_digest,
        budget_state=budget_state,
        outcome_digest=outcome.outcome_digest,
    )


def _transcript_seed(
    *,
    request_digest: str,
    catalog_digest: str,
    instruction_profile_digest: str,
    runner_configuration_digest: str,
) -> str:
    return "sha256:" + strict_canonical_json_sha256(
        {
            "contract_version": PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION,
            "domain": "execution_seed",
            "request_digest": request_digest,
            "catalog_digest": catalog_digest,
            "instruction_profile_digest": instruction_profile_digest,
            "runner_configuration_digest": runner_configuration_digest,
        }
    )


def _transcript_payload(
    value: PrivateAnalysisInProcessTranscript,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "catalog_digest": value.catalog_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
        "runner_configuration_digest": value.runner_configuration_digest,
        "exchange_count": value.exchange_count,
        "unattributed_tool_call_count": value.unattributed_tool_call_count,
        "exchange_metadata_bytes": value.exchange_metadata_bytes,
        "exchange_chain_digest": value.exchange_chain_digest,
        "evidence_ledger_digest": value.evidence_ledger_digest,
        "budget_state": _budget_payload(value.budget_state),
        "outcome_digest": value.outcome_digest,
    }


__all__ = [
    "MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES",
    "PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION",
    "PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION",
    "ConfiguredPrivateAnalysisInProcessRunner",
    "PrivateAnalysisInProcessContext",
    "PrivateAnalysisInProcessExecutionReceipt",
    "PrivateAnalysisInProcessGatewayAbort",
    "PrivateAnalysisInProcessModelCallback",
    "PrivateAnalysisInProcessToolGateway",
    "PrivateAnalysisInProcessToolResponse",
    "PrivateAnalysisInProcessToolResponseKind",
    "PrivateAnalysisInProcessTranscript",
]
