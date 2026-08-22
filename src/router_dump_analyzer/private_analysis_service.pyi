from .private_analysis import EvidenceFactProvenance, EvidenceKind, EvidenceProducer, EvidenceReference, EvidenceScope, EvidenceTimeRange, PrivateAnalysisClockMode, PrivateAnalysisEvidenceClass, PrivateAnalysisLimits, PrivateAnalysisOutcome, PrivateAnalysisRunnerSelection, PrivateAnalysisTaskKind, PrivateAnalysisTransport
from .private_analysis_execution import PrivateAnalysisExecutionCoordinator, PrivateAnalysisRegisteredRunner
from .private_analysis_run_store import PrivateAnalysisRunState, SqlitePrivateAnalysisRunStore
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState
from .session_store import SqliteSessionStore
from dataclasses import InitVar, dataclass, field
from enum import StrEnum

__all__ = ['PrivateAnalysisLifecycleAction', 'PrivateAnalysisServiceErrorCode', 'PrivateAnalysisServiceError', 'PrivateAnalysisServiceInvalidRequest', 'PrivateAnalysisServicePolicyDenied', 'PrivateAnalysisServiceRunnerUnavailable', 'PrivateAnalysisServiceNotFound', 'PrivateAnalysisServiceConflict', 'PrivateAnalysisServiceReportNotReady', 'PrivateAnalysisServiceUnavailable', 'PrivateAnalysisRequestSpec', 'PrivateAnalysisDeploymentCeilings', 'PrivateAnalysisCapabilities', 'PrivateAnalysisRunView', 'PrivateAnalysisCitedEvidenceReference', 'PrivateAnalysisRunReport', 'PrivateAnalysisService']

class PrivateAnalysisLifecycleAction(StrEnum):
    CREATE = 'create'
    LIST = 'list'
    GET = 'get'
    EXECUTE = 'execute'
    CANCEL = 'cancel'
    REPORT = 'report'

class PrivateAnalysisServiceErrorCode(StrEnum):
    INVALID_REQUEST = 'invalid_request'
    POLICY_DENIED = 'policy_denied'
    RUNNER_UNAVAILABLE = 'runner_unavailable'
    NOT_FOUND = 'not_found'
    CONFLICT = 'conflict'
    UNAVAILABLE = 'unavailable'

class PrivateAnalysisServiceError(RuntimeError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str
    def __init__(self, *_ignored: object, **_ignored_keywords: object) -> None: ...

class PrivateAnalysisServiceInvalidRequest(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

class PrivateAnalysisServicePolicyDenied(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

class PrivateAnalysisServiceRunnerUnavailable(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

class PrivateAnalysisServiceNotFound(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

class PrivateAnalysisServiceConflict(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

class PrivateAnalysisServiceReportNotReady(PrivateAnalysisServiceConflict):
    safe_message: str

class PrivateAnalysisServiceUnavailable(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode
    safe_message: str

@dataclass(frozen=True, slots=True)
class PrivateAnalysisRequestSpec:
    scope: EvidenceScope
    revision_ids: tuple[str, ...]
    runner_id: str
    runner_version: str
    task_kind: PrivateAnalysisTaskKind
    query: str
    clock_mode: PrivateAnalysisClockMode
    selected_time_ns: int | None
    limits: PrivateAnalysisLimits
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeploymentCeilings:
    request_limits: PrivateAnalysisLimits = field(default_factory=PrivateAnalysisLimits)
    max_revisions: int = ...
    max_list_runs: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisCapabilities:
    scope: EvidenceScope
    enabled: bool
    task_kinds: tuple[PrivateAnalysisTaskKind, ...]
    request_limit_ceilings: PrivateAnalysisLimits
    max_revisions: int
    max_list_runs: int
    transports: tuple[PrivateAnalysisTransport, ...]
    states: tuple[PrivateAnalysisRunState, ...]
    actions: tuple[PrivateAnalysisLifecycleAction, ...]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunView:
    scope: EvidenceScope
    run_id: str
    state: PrivateAnalysisRunState
    version: int
    request_digest: str
    task_kind: PrivateAnalysisTaskKind
    revision_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    runner: PrivateAnalysisRunnerSelection
    workspace_policy_digest: str
    instruction_profile_digest: str
    tool_catalog_digest: str
    evidence_service_digest: str
    clock_mode: PrivateAnalysisClockMode
    selected_time_ns: int | None
    limits: PrivateAnalysisLimits
    evidence_ledger_digest: str
    disclosed_reference_count: int
    budget_state: PrivateAnalysisToolBudgetState
    outcome_digest: str | None
    created_at_ns: int
    updated_at_ns: int
    completed_at_ns: int | None
    cleanup_pending: bool = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisCitedEvidenceReference:
    reference_digest: str
    revision_id: str
    node_id: str
    producer: EvidenceProducer
    kind: EvidenceKind
    subject_kind: str
    evidence_class: PrivateAnalysisEvidenceClass
    payload_schema: str
    fact_provenance: EvidenceFactProvenance
    time_range: EvidenceTimeRange
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunReport:
    run: PrivateAnalysisRunView
    query: str
    outcome: PrivateAnalysisOutcome
    disclosed_references: InitVar[tuple[EvidenceReference, ...]] = ...
    evidence_references: tuple[PrivateAnalysisCitedEvidenceReference, ...] = field(init=False)
    def __post_init__(self, disclosed_references: tuple[EvidenceReference, ...]) -> None: ...

class PrivateAnalysisService:
    def __init__(self, sessions: SqliteSessionStore, runs: SqlitePrivateAnalysisRunStore, execution: PrivateAnalysisExecutionCoordinator, *, ceilings: PrivateAnalysisDeploymentCeilings | None = None) -> None: ...
    def capabilities(self, scope: EvidenceScope) -> PrivateAnalysisCapabilities: ...
    def list_runners(self, scope: EvidenceScope) -> tuple[PrivateAnalysisRegisteredRunner, ...]: ...
    def create(self, spec: PrivateAnalysisRequestSpec, *, actor_id: str, idempotency_key: str, run_id: str | None = None) -> PrivateAnalysisRunView: ...
    def get(self, scope: EvidenceScope, run_id: str) -> PrivateAnalysisRunView: ...
    def list(self, scope: EvidenceScope, *, limit: int = 100, after_created_at_ns: int | None = None, after_run_id: str | None = None) -> tuple[PrivateAnalysisRunView, ...]: ...
    def execute(self, scope: EvidenceScope, run_id: str, *, expected_version: int, actor_id: str, execution_id: str | None = None) -> PrivateAnalysisRunView: ...
    def cancel(self, scope: EvidenceScope, run_id: str, *, expected_version: int, actor_id: str) -> PrivateAnalysisRunView: ...
    def recover_expired(self, scope: EvidenceScope, *, actor_id: str, limit: int = 100) -> tuple[PrivateAnalysisRunView, ...]: ...
    def get_report(self, scope: EvidenceScope, run_id: str) -> PrivateAnalysisRunReport: ...
