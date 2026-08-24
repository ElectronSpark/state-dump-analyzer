from collections.abc import Callable
from .private_analysis import EvidenceReference, PrivateAnalysisError, PrivateAnalysisOutcome, PrivateAnalysisRequest, PrivateAnalysisRunnerSelection, PrivateAnalysisToolCatalog, PrivateAnalysisToolError, PrivateAnalysisToolResult
from .private_analysis_factory_process import PrivateAnalysisRemoteToolRunLease, PrivateAnalysisRemoteToolService
from .private_analysis_runner_support import MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES as MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES, PrivateAnalysisAccountingObserver, PrivateAnalysisCancellationProbe, PrivateAnalysisRunAccountingSnapshot as _RunAccountingSnapshot, PrivateAnalysisRunnerExecutionOwner, PrivateAnalysisTranscriptSummary
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState, PrivateAnalysisToolRunLease, PrivateAnalysisToolService
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Final

__all__ = ['MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES', 'PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION', 'PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION', 'PrivateAnalysisInProcessToolResponseKind', 'PrivateAnalysisInProcessGatewayAbort', 'PrivateAnalysisInProcessContext', 'PrivateAnalysisInProcessToolResponse', 'PrivateAnalysisInProcessTranscript', 'PrivateAnalysisInProcessExecutionReceipt', 'PrivateAnalysisInProcessModelCallback', 'PrivateAnalysisInProcessToolGateway', 'ConfiguredPrivateAnalysisInProcessRunner']

PRIVATE_ANALYSIS_IN_PROCESS_CONTEXT_VERSION: Final[str]
PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_VERSION: Final[str]

class PrivateAnalysisInProcessToolResponseKind(StrEnum):
    RESULT = 'result'
    ERROR = 'error'

class PrivateAnalysisInProcessGatewayAbort(RuntimeError):
    def __init__(self) -> None: ...

@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessContext:
    request: PrivateAnalysisRequest
    catalog: PrivateAnalysisToolCatalog
    contract_version: str = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessToolResponse:
    kind: PrivateAnalysisInProcessToolResponseKind
    result: PrivateAnalysisToolResult | None = ...
    error: PrivateAnalysisToolError | None = ...
    def __post_init__(self) -> None: ...
    @property
    def response_digest(self) -> str: ...
    @property
    def canonical_json(self) -> str: ...

@dataclass(frozen=True, slots=True, repr=False)
class _PrivateAnalysisInProcessGatewayState:
    terminal_error: PrivateAnalysisError | None
    exchange_count: int
    exchange_metadata_bytes: int
    chain_digest: str

@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessTranscript:
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
    contract_version: str = ...
    transcript_digest: str = ...
    def __post_init__(self) -> None: ...

class PrivateAnalysisInProcessExecutionReceipt:
    def __init__(self, *, outcome: PrivateAnalysisOutcome, transcript: PrivateAnalysisInProcessTranscript, disclosed_references: tuple[EvidenceReference, ...], budget_state: PrivateAnalysisToolBudgetState) -> None: ...
    @property
    def outcome(self) -> PrivateAnalysisOutcome: ...
    @property
    def transcript(self) -> PrivateAnalysisInProcessTranscript: ...
    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]: ...
    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState: ...
    @property
    def transcript_summary(self) -> PrivateAnalysisTranscriptSummary: ...
    def as_cancelled(self) -> PrivateAnalysisInProcessExecutionReceipt: ...

type PrivateAnalysisInProcessModelCallback = Callable[[PrivateAnalysisInProcessContext, 'PrivateAnalysisInProcessToolGateway'], str]

class PrivateAnalysisInProcessToolGateway:
    def __init__(self, lease: PrivateAnalysisToolRunLease | PrivateAnalysisRemoteToolRunLease, *, accounting: _RunAccountingSnapshot, instruction_profile_digest: str, runner_configuration_digest: str, deadline_ns: int, cancellation_probe: PrivateAnalysisCancellationProbe | None = None) -> None: ...
    def execute(self, call_json: str) -> PrivateAnalysisInProcessToolResponse: ...
    def checkpoint(self) -> None: ...
    @property
    def remaining_deadline_ms(self) -> int: ...
    def close(self) -> None: ...

@dataclass(frozen=True, slots=True)
class _DeferredInProcessReceipt:
    request: PrivateAnalysisRequest
    catalog: PrivateAnalysisToolCatalog
    instruction_profile_digest: str
    runner_configuration_digest: str
    gateway_state: _PrivateAnalysisInProcessGatewayState
    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState
    def seal(self) -> PrivateAnalysisInProcessExecutionReceipt: ...

@dataclass(slots=True)
class _PendingInProcessReceipt:
    deferred: _DeferredInProcessReceipt
    receipt: PrivateAnalysisInProcessExecutionReceipt | None = ...

class _InProcessReceiptOwner:
    lock: Lock
    pending: _PendingInProcessReceipt | None
    def __init__(self) -> None: ...

class ConfiguredPrivateAnalysisInProcessRunner(PrivateAnalysisRunnerExecutionOwner):
    def __init__(self, selection: PrivateAnalysisRunnerSelection, *, instruction_profile_digest: str, model_callback: PrivateAnalysisInProcessModelCallback) -> None: ...
    def detached(self) -> ConfiguredPrivateAnalysisInProcessRunner: ...
    @property
    def receipt_pending(self) -> bool: ...
    def retry_pending_receipt(self) -> PrivateAnalysisInProcessExecutionReceipt | None: ...
    def acknowledge_pending_receipt(self) -> None: ...
    def execute(self, tool_service: PrivateAnalysisToolService | PrivateAnalysisRemoteToolService, *, accounting_observer: PrivateAnalysisAccountingObserver | None = None, cancellation_probe: PrivateAnalysisCancellationProbe | None = None, absolute_deadline_ns: int | None = None) -> PrivateAnalysisInProcessExecutionReceipt: ...
