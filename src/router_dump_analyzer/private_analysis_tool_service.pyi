from .private_analysis.contracts import PrivateAnalysisError, PrivateAnalysisRequest
from .private_analysis.disclosure import PrivateAnalysisEvidenceClass, WorkspaceDisclosurePolicy
from .private_analysis.evidence import EvidenceEnvelope, EvidenceReference, EvidenceScope
from .private_analysis.policy import PrivateAnalysisPolicy
from .private_analysis.tool_catalog import PrivateAnalysisCapabilityArguments, PrivateAnalysisEvidenceQueryPage, PrivateAnalysisQueryArguments, PrivateAnalysisToolCall, PrivateAnalysisToolError, PrivateAnalysisToolResult
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = ['PrivateAnalysisAuthorizationReason', 'PrivateAnalysisAuthorizationDecision', 'PrivateAnalysisToolBudgetState', 'PrivateAnalysisWorkspacePolicySnapshot', 'PrivateAnalysisToolServiceError', 'PrivateAnalysisAuthorizer', 'PrivateAnalysisPolicyResolver', 'PrivateAnalysisReferenceQuery', 'PrivateAnalysisReferencePageQuery', 'PrivateAnalysisReferenceResolver', 'PrivateAnalysisPayloadMaterializer', 'PrivateAnalysisReferenceValidator', 'PrivateAnalysisReferenceBatchValidator', 'PrivateAnalysisCapabilityAnalyzer', 'PrivateAnalysisToolService', 'PrivateAnalysisToolRunLease']

class PrivateAnalysisAuthorizationReason(StrEnum):
    ALLOWED = 'allowed'
    TENANT_DENIED = 'tenant_denied'
    PROJECT_DENIED = 'project_denied'
    WORKSPACE_DENIED = 'workspace_denied'
    PERMISSION_DENIED = 'permission_denied'

@dataclass(frozen=True, slots=True)
class PrivateAnalysisAuthorizationDecision:
    request_digest: str
    scope_digest: str
    allowed: bool
    reason: PrivateAnalysisAuthorizationReason
    def __post_init__(self) -> None: ...
    @classmethod
    def allow(cls, request: PrivateAnalysisRequest) -> PrivateAnalysisAuthorizationDecision: ...
    @classmethod
    def deny(cls, request: PrivateAnalysisRequest, reason: PrivateAnalysisAuthorizationReason) -> PrivateAnalysisAuthorizationDecision: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolBudgetState:
    max_tool_calls: int
    tool_calls_consumed: int
    max_evidence_items: int
    evidence_items_disclosed: int
    max_evidence_bytes: int
    evidence_bytes_disclosed: int
    def __post_init__(self) -> None: ...
    @property
    def remaining_tool_calls(self) -> int: ...
    @property
    def remaining_evidence_items(self) -> int: ...
    @property
    def remaining_evidence_bytes(self) -> int: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisWorkspacePolicySnapshot:
    scope: EvidenceScope
    policy_version: int
    policy: WorkspaceDisclosurePolicy
    policy_digest: str
    def __post_init__(self) -> None: ...

class PrivateAnalysisToolServiceError(RuntimeError):
    def __init__(self, error: PrivateAnalysisError) -> None: ...
    @property
    def error(self) -> PrivateAnalysisError: ...
PrivateAnalysisAuthorizer = Callable[[PrivateAnalysisRequest], PrivateAnalysisAuthorizationDecision]
PrivateAnalysisPolicyResolver = Callable[[EvidenceScope], PrivateAnalysisWorkspacePolicySnapshot]
PrivateAnalysisReferenceQuery = Callable[[PrivateAnalysisRequest, PrivateAnalysisQueryArguments], tuple[EvidenceReference, ...]]
PrivateAnalysisReferencePageQuery = Callable[[PrivateAnalysisRequest, PrivateAnalysisQueryArguments, tuple[PrivateAnalysisEvidenceClass, ...], Callable[[], bool] | None], PrivateAnalysisEvidenceQueryPage]
PrivateAnalysisReferenceResolver = Callable[[PrivateAnalysisRequest, str], EvidenceReference | None]
PrivateAnalysisPayloadMaterializer = Callable[[EvidenceReference], dict[str, Any]]
PrivateAnalysisReferenceValidator = Callable[[EvidenceReference], bool]
PrivateAnalysisReferenceBatchValidator = Callable[[tuple[EvidenceReference, ...]], bool]
PrivateAnalysisCapabilityAnalyzer = Callable[[PrivateAnalysisRequest, PrivateAnalysisCapabilityArguments, tuple[EvidenceEnvelope, ...], Callable[[], bool] | None], tuple[EvidenceReference, dict[str, Any]]]

class PrivateAnalysisToolService:
    def __init__(self, request: PrivateAnalysisRequest, *, runner_policy: PrivateAnalysisPolicy, authorize: PrivateAnalysisAuthorizer, resolve_policy: PrivateAnalysisPolicyResolver, query_references: PrivateAnalysisReferenceQuery | None, resolve_reference: PrivateAnalysisReferenceResolver, validate_reference: PrivateAnalysisReferenceValidator, materialize_payload: PrivateAnalysisPayloadMaterializer, query_reference_pages: PrivateAnalysisReferencePageQuery | None = None, validate_references: PrivateAnalysisReferenceBatchValidator | None = None, analyze_evidence: PrivateAnalysisCapabilityAnalyzer | None = None, cancellation_probe: Callable[[], bool] | None = None) -> None: ...
    @property
    def request(self) -> PrivateAnalysisRequest: ...
    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState: ...
    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]: ...
    @property
    def runner_lease_eligible(self) -> bool: ...
    def execute(self, call: PrivateAnalysisToolCall) -> PrivateAnalysisToolResult | PrivateAnalysisToolError: ...
    def acquire_run_lease(self) -> PrivateAnalysisToolRunLease: ...

class _PrivateAnalysisToolRunLeaseFacade:
    def __init__(self, service: Any) -> None: ...
    @property
    def request(self) -> PrivateAnalysisRequest: ...
    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState: ...
    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]: ...
    def require_run_access(self) -> None: ...
    def execute(self, call: PrivateAnalysisToolCall) -> PrivateAnalysisToolResult | PrivateAnalysisToolError: ...
    def close(self) -> None: ...

class PrivateAnalysisToolRunLease(_PrivateAnalysisToolRunLeaseFacade):
    def __init__(self, service: PrivateAnalysisToolService, token: object) -> None: ...
