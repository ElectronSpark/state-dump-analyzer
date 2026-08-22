from typing import final
from .canonical import validate_prefixed_lowercase_sha256 as private_analysis_prefixed_sha256
from .private_analysis import EvidenceReference, PrivateAnalysisError, PrivateAnalysisErrorCode, PrivateAnalysisErrorStage, PrivateAnalysisOutcome, PrivateAnalysisRequest, PrivateAnalysisResult, PrivateAnalysisRunnerSelection, PrivateAnalysisTransport
from .private_analysis._wire import SealedContractValue
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Final, Protocol

__all__ = ['private_analysis_prefixed_sha256', 'PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION', 'MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES', 'MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES', 'MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES', 'MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES', 'PrivateAnalysisAccountingObserver', 'PrivateAnalysisCancellationProbe', 'PrivateAnalysisRunnerExecutionOwner', 'PrivateAnalysisRunAccountingSnapshot', 'private_analysis_deadline_expired', 'private_analysis_error', 'detached_private_analysis_error', 'private_analysis_error_outcome', 'detached_private_analysis_budget_state', 'empty_private_analysis_budget_state', 'private_analysis_budget_payload', 'PrivateAnalysisInProcessTranscriptSummaryMetadata', 'PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata', 'PrivateAnalysisTranscriptSummaryMetadata', 'PrivateAnalysisTranscriptSummary', 'private_analysis_transcript_summary_dict', 'private_analysis_transcript_summary_from_dict', 'private_analysis_transcript_summary_json', 'private_analysis_transcript_summary_from_json', 'detached_private_analysis_transcript_summary', 'private_analysis_execution_receipt_values', 'private_analysis_run_access_error', 'validate_private_analysis_result_json']

PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION: Final[str]
MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES: Final[int]
PrivateAnalysisAccountingObserver = Callable[[tuple[EvidenceReference, ...], PrivateAnalysisToolBudgetState], None]
PrivateAnalysisCancellationProbe = Callable[[], bool]

class _PrivateAnalysisRunLeaseAccountingView(Protocol):
    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState: ...
    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]: ...
    def require_run_access(self) -> None: ...

class PrivateAnalysisRunnerExecutionOwner:
    def __init__(self, selection: PrivateAnalysisRunnerSelection, *, instruction_profile_digest: str) -> None: ...
    @property
    def selection(self) -> PrivateAnalysisRunnerSelection: ...
    @property
    def instruction_profile_digest(self) -> str: ...
    @property
    def execution_lock(self) -> Lock: ...

@dataclass(slots=True)
class PrivateAnalysisRunAccountingSnapshot:
    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState
    observer: PrivateAnalysisAccountingObserver | None = ...
    def __post_init__(self) -> None: ...
    def refresh(self, lease: _PrivateAnalysisRunLeaseAccountingView) -> None: ...

def private_analysis_deadline_expired(deadline_ns: int) -> bool: ...
def private_analysis_error(request_digest: str, stage: PrivateAnalysisErrorStage, code: PrivateAnalysisErrorCode) -> PrivateAnalysisError: ...
def detached_private_analysis_error(value: PrivateAnalysisError) -> PrivateAnalysisError: ...
def private_analysis_error_outcome(error: PrivateAnalysisError) -> PrivateAnalysisOutcome: ...
def detached_private_analysis_budget_state(value: PrivateAnalysisToolBudgetState) -> PrivateAnalysisToolBudgetState: ...
def empty_private_analysis_budget_state(request: PrivateAnalysisRequest) -> PrivateAnalysisToolBudgetState: ...
def private_analysis_budget_payload(value: PrivateAnalysisToolBudgetState) -> dict[str, int]: ...

@final
@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessTranscriptSummaryMetadata(SealedContractValue):
    transcript_digest: str
    exchange_count: int
    unattributed_tool_call_count: int
    exchange_metadata_bytes: int
    exchange_chain_digest: str
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(SealedContractValue):
    transcript_digest: str
    launch_configuration_digest: str
    run_digest: str
    message_count: int
    tool_call_count: int
    message_metadata_bytes: int
    message_chain_digest: str
    stderr_bytes: int
    def __post_init__(self) -> None: ...
PrivateAnalysisTranscriptSummaryMetadata = PrivateAnalysisInProcessTranscriptSummaryMetadata | PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata

@final
@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisTranscriptSummary(SealedContractValue):
    transport: PrivateAnalysisTransport
    request_digest: str
    catalog_digest: str
    instruction_profile_digest: str
    runner_configuration_digest: str
    outcome_digest: str
    evidence_ledger_digest: str
    budget_state: PrivateAnalysisToolBudgetState
    metadata: PrivateAnalysisTranscriptSummaryMetadata
    contract_version: str = ...
    summary_digest: str = ...
    def __post_init__(self) -> None: ...

def private_analysis_transcript_summary_dict(value: PrivateAnalysisTranscriptSummary) -> dict[str, object]: ...
def private_analysis_transcript_summary_from_dict(value: object) -> PrivateAnalysisTranscriptSummary: ...
def private_analysis_transcript_summary_json(value: PrivateAnalysisTranscriptSummary) -> str: ...
def private_analysis_transcript_summary_from_json(value: object) -> PrivateAnalysisTranscriptSummary: ...
def detached_private_analysis_transcript_summary(value: PrivateAnalysisTranscriptSummary) -> PrivateAnalysisTranscriptSummary: ...
def private_analysis_execution_receipt_values(*, outcome: PrivateAnalysisOutcome, disclosed_references: tuple[EvidenceReference, ...], budget_state: PrivateAnalysisToolBudgetState, transcript_request_digest: str, transcript_evidence_ledger_digest: str, transcript_budget_state: PrivateAnalysisToolBudgetState, transcript_outcome_digest: str) -> tuple[str, tuple[EvidenceReference, ...], PrivateAnalysisToolBudgetState]: ...
def private_analysis_run_access_error(lease: _PrivateAnalysisRunLeaseAccountingView, request: PrivateAnalysisRequest, deadline_ns: int, *, deadline_expired: Callable[[int], bool] = ...) -> PrivateAnalysisError | None: ...
def validate_private_analysis_result_json(raw_result: object, request: PrivateAnalysisRequest, references: tuple[EvidenceReference, ...]) -> tuple[PrivateAnalysisResult | None, PrivateAnalysisError | None]: ...
