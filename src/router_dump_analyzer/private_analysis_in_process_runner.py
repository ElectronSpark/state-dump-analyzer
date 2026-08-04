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
from typing import Final

from .canonical import strict_canonical_json, strict_canonical_json_sha256
from .private_analysis import (
    EvidenceReference,
    PrivateAnalysisContractError,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    PrivateAnalysisResult,
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
    private_analysis_outcome_json,
    private_analysis_request_from_json,
    private_analysis_request_json,
    private_analysis_result_from_json,
    private_analysis_result_json,
    private_analysis_tool_call_from_json,
    private_analysis_tool_catalog_from_json,
    private_analysis_tool_catalog_json,
    private_analysis_tool_error_from_json,
    private_analysis_tool_error_json,
    private_analysis_tool_result_from_json,
    private_analysis_tool_result_json,
    validate_private_analysis_result,
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
MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES: Final = 4 * 1024 * 1024


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
            type(self.exchange_metadata_bytes) is not int
            or not 0
            <= self.exchange_metadata_bytes
            <= MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES
        ):
            raise ValueError("exchange metadata exceeds its bounded domain")
        budget = _detached_budget_state(self.budget_state)
        object.__setattr__(self, "budget_state", budget)
        if not (
            budget.tool_calls_consumed
            <= self.exchange_count
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


class PrivateAnalysisInProcessExecutionReceipt:
    """Trusted internal, detached result of one in-process execution."""

    __slots__ = ("_budget", "_outcome_json", "_references", "_transcript")

    def __init__(
        self,
        *,
        outcome: PrivateAnalysisOutcome,
        transcript: PrivateAnalysisInProcessTranscript,
        disclosed_references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
    ) -> None:
        if type(outcome) is not PrivateAnalysisOutcome:
            raise TypeError("outcome must be PrivateAnalysisOutcome")
        if type(transcript) is not PrivateAnalysisInProcessTranscript:
            raise TypeError("transcript must be PrivateAnalysisInProcessTranscript")
        if type(disclosed_references) is not tuple:
            raise TypeError("disclosed_references must be a tuple")
        detached_references = tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in disclosed_references
        )
        digests = tuple(item.reference_digest for item in detached_references)
        if digests != tuple(sorted(digests)) or len(digests) != len(set(digests)):
            raise ValueError("disclosed references must be unique and canonical")
        budget = _detached_budget_state(budget_state)
        if transcript.evidence_ledger_digest != evidence_snapshot_digest(
            detached_references
        ):
            raise ValueError("transcript does not bind the disclosed ledger")
        if budget.evidence_items_disclosed != len(detached_references):
            raise ValueError("budget snapshot disagrees with disclosed ledger")
        if transcript.outcome_digest != outcome.outcome_digest:
            raise ValueError("transcript does not bind the outcome")
        if transcript.budget_state != budget:
            raise ValueError("transcript does not bind the budget snapshot")
        outcome_request_digest = (
            outcome.result.request_digest
            if outcome.result is not None
            else outcome.error.request_digest
            if outcome.error is not None
            else None
        )
        if outcome_request_digest != transcript.request_digest:
            raise ValueError("transcript does not bind the outcome request")
        self._outcome_json = private_analysis_outcome_json(outcome)
        self._transcript = transcript
        self._references = detached_references
        self._budget = budget

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

    def __repr__(self) -> str:
        outcome = self.outcome
        return (
            "PrivateAnalysisInProcessExecutionReceipt("
            f"outcome={outcome.kind.value!r}, "
            f"outcome_digest={outcome.outcome_digest!r}, "
            f"transcript_digest={self._transcript.transcript_digest!r})"
        )


PrivateAnalysisInProcessModelCallback = Callable[
    [PrivateAnalysisInProcessContext, "PrivateAnalysisInProcessToolGateway"],
    str,
]


class PrivateAnalysisInProcessToolGateway:
    """Thread-affine closed-tool gateway visible to one trusted callback."""

    __slots__ = (
        "_budget_exhausted",
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
        lease: PrivateAnalysisToolRunLease,
        *,
        instruction_profile_digest: str,
        runner_configuration_digest: str,
        deadline_ns: int,
    ) -> None:
        if type(lease) is not PrivateAnalysisToolRunLease:
            raise TypeError("lease must be PrivateAnalysisToolRunLease")
        request = lease.request
        self._lease = lease
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
            call = private_analysis_tool_call_from_json(call_json)
            call_digest = call.call_digest
            raw_response = self._lease.execute(call)
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


class ConfiguredPrivateAnalysisInProcessRunner:
    """Execute one request with a process-trusted local callback."""

    __slots__ = ("_callback", "_instruction_profile_digest", "_selection")

    def __init__(
        self,
        selection: PrivateAnalysisRunnerSelection,
        *,
        instruction_profile_digest: str,
        model_callback: PrivateAnalysisInProcessModelCallback,
    ) -> None:
        if type(selection) is not PrivateAnalysisRunnerSelection:
            raise TypeError("selection must be PrivateAnalysisRunnerSelection")
        detached = PrivateAnalysisRunnerSelection(
            runner_id=selection.runner_id,
            runner_version=selection.runner_version,
            transport=selection.transport,
            configuration_digest=selection.configuration_digest,
        )
        if detached.transport is not PrivateAnalysisTransport.IN_PROCESS:
            raise ValueError("in-process runner requires in_process transport")
        if not callable(model_callback):
            raise TypeError("model_callback must be callable")
        self._selection = detached
        self._instruction_profile_digest = _prefixed_sha256(
            instruction_profile_digest, "instruction_profile_digest"
        )
        self._callback = model_callback

    @property
    def selection(self) -> PrivateAnalysisRunnerSelection:
        value = self._selection
        return PrivateAnalysisRunnerSelection(
            runner_id=value.runner_id,
            runner_version=value.runner_version,
            transport=value.transport,
            configuration_digest=value.configuration_digest,
        )

    def execute(
        self,
        tool_service: PrivateAnalysisToolService,
    ) -> PrivateAnalysisInProcessExecutionReceipt:
        if type(tool_service) is not PrivateAnalysisToolService:
            raise TypeError("tool_service must be PrivateAnalysisToolService")
        request = tool_service.request
        start_ns = monotonic_ns()
        deadline_ns = start_ns + request.limits.deadline_ms * 1_000_000
        catalog = default_private_analysis_tool_catalog()
        binding_error = self._binding_error(request, catalog)
        if binding_error is not None:
            return _standalone_receipt(
                request=request,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                catalog=catalog,
                outcome=_error_outcome(binding_error),
                references=(),
                budget_state=_empty_budget_state(request),
            )

        try:
            lease = tool_service.acquire_run_lease()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisToolServiceError as error:
            return _standalone_receipt(
                request=request,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                catalog=catalog,
                outcome=_error_outcome(error.error),
                references=(),
                budget_state=_empty_budget_state(request),
            )

        gateway = PrivateAnalysisInProcessToolGateway(
            lease,
            instruction_profile_digest=self._instruction_profile_digest,
            runner_configuration_digest=self._selection.configuration_digest,
            deadline_ns=deadline_ns,
        )
        raw_result: object = None
        outcome_error: PrivateAnalysisError | None = None
        references: tuple[EvidenceReference, ...] = ()
        budget_state = lease.budget_state
        try:
            try:
                outcome_error = _access_or_deadline_error(lease, request, deadline_ns)
                if outcome_error is None:
                    context = PrivateAnalysisInProcessContext(
                        request=request,
                        catalog=catalog,
                    )
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
                outcome_error = _access_or_deadline_error(lease, request, deadline_ns)

            references = lease.disclosed_references
            budget_state = lease.budget_state
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
        finally:
            lease.close()

        try:
            transcript = _sealed_transcript(
                request=request,
                catalog=catalog,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                exchange_count=gateway_state.exchange_count,
                exchange_metadata_bytes=gateway_state.exchange_metadata_bytes,
                exchange_chain_digest=gateway_state.chain_digest,
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
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - trusted callback integrity boundary.
            # Deliberate Python reflection is outside this transport's trust
            # contract, but an accidental use of unsupported private gateway
            # state must still fail closed instead of leaking a constructor
            # diagnostic.  Do not attest the untrusted counters or ledger in
            # the fallback receipt.
            return _standalone_receipt(
                request=request,
                instruction_profile_digest=self._instruction_profile_digest,
                runner_configuration_digest=self._selection.configuration_digest,
                catalog=catalog,
                outcome=_error_outcome(
                    _analysis_error(
                        request.request_digest,
                        PrivateAnalysisErrorStage.RUNNER,
                        PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    )
                ),
                references=(),
                budget_state=_empty_budget_state(request),
            )

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
    lease: PrivateAnalysisToolRunLease,
    request: PrivateAnalysisRequest,
    deadline_ns: int,
) -> PrivateAnalysisError | None:
    if _deadline_expired(deadline_ns):
        return _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    access_error: PrivateAnalysisError | None = None
    try:
        lease.require_run_access()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisToolServiceError as error:
        access_error = _detached_error(error.error)
    except BaseException:  # noqa: BLE001 - executable trust boundary.
        access_error = _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
    if _deadline_expired(deadline_ns):
        return _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    return access_error


def _validated_callback_result(
    raw_result: object,
    request: PrivateAnalysisRequest,
    references: tuple[EvidenceReference, ...],
) -> tuple[PrivateAnalysisResult | None, PrivateAnalysisError | None]:
    if type(raw_result) is not str:
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    if len(raw_result) > request.limits.max_output_bytes:
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        encoded_size = len(raw_result.encode("utf-8"))
    except UnicodeEncodeError:
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    if encoded_size > request.limits.max_output_bytes:
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        result = private_analysis_result_from_json(raw_result)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - untrusted model output boundary.
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    canonical_size = len(private_analysis_result_json(result).encode("utf-8"))
    if (
        canonical_size > request.limits.max_output_bytes
        or 1 + len(result.claims) > request.limits.max_claims
        or len(result.proposals) > request.limits.max_proposals
    ):
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        validate_private_analysis_result(result, request, references)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisContractError:
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    except BaseException:  # noqa: BLE001 - untrusted model output boundary.
        return None, _analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    return private_analysis_result_from_json(private_analysis_result_json(result)), None


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
        "exchange_metadata_bytes": value.exchange_metadata_bytes,
        "exchange_chain_digest": value.exchange_chain_digest,
        "evidence_ledger_digest": value.evidence_ledger_digest,
        "budget_state": _budget_payload(value.budget_state),
        "outcome_digest": value.outcome_digest,
    }


def _budget_payload(value: PrivateAnalysisToolBudgetState) -> dict[str, int]:
    value = _detached_budget_state(value)
    return {
        "max_tool_calls": value.max_tool_calls,
        "tool_calls_consumed": value.tool_calls_consumed,
        "max_evidence_items": value.max_evidence_items,
        "evidence_items_disclosed": value.evidence_items_disclosed,
        "max_evidence_bytes": value.max_evidence_bytes,
        "evidence_bytes_disclosed": value.evidence_bytes_disclosed,
    }


def _detached_budget_state(
    value: PrivateAnalysisToolBudgetState,
) -> PrivateAnalysisToolBudgetState:
    if type(value) is not PrivateAnalysisToolBudgetState:
        raise TypeError("budget_state must be PrivateAnalysisToolBudgetState")
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=value.max_tool_calls,
        tool_calls_consumed=value.tool_calls_consumed,
        max_evidence_items=value.max_evidence_items,
        evidence_items_disclosed=value.evidence_items_disclosed,
        max_evidence_bytes=value.max_evidence_bytes,
        evidence_bytes_disclosed=value.evidence_bytes_disclosed,
    )


def _empty_budget_state(
    request: PrivateAnalysisRequest,
) -> PrivateAnalysisToolBudgetState:
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=request.limits.max_tool_calls,
        tool_calls_consumed=0,
        max_evidence_items=request.limits.max_evidence_items,
        evidence_items_disclosed=0,
        max_evidence_bytes=request.limits.max_evidence_bytes,
        evidence_bytes_disclosed=0,
    )


def _analysis_error(
    request_digest: str,
    stage: PrivateAnalysisErrorStage,
    code: PrivateAnalysisErrorCode,
) -> PrivateAnalysisError:
    return PrivateAnalysisError(
        request_digest=request_digest,
        stage=stage,
        code=code,
        retryable=code
        in {
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorCode.TIMEOUT,
        },
    )


def _error_outcome(error: PrivateAnalysisError) -> PrivateAnalysisOutcome:
    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=_detached_error(error),
    )


def _detached_error(value: PrivateAnalysisError) -> PrivateAnalysisError:
    if type(value) is not PrivateAnalysisError:
        raise TypeError("error must be PrivateAnalysisError")
    return PrivateAnalysisError(
        request_digest=value.request_digest,
        stage=value.stage,
        code=value.code,
        retryable=value.retryable,
        contract_version=value.contract_version,
        error_digest=value.error_digest,
    )


def _prefixed_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be a prefixed lowercase SHA-256 digest")
    return value


def _deadline_expired(deadline_ns: int) -> bool:
    return monotonic_ns() >= deadline_ns


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
