from typing import final
from ._wire import SealedContractValue
from .evidence import EvidenceReference, EvidenceRevisionBinding, EvidenceScope
from .policy import PrivateAnalysisContributionKind, PrivateAnalysisTransport
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = ['PRIVATE_ANALYSIS_REQUEST_VERSION_V2', 'PRIVATE_ANALYSIS_REQUEST_VERSION', 'PRIVATE_ANALYSIS_CITATION_VERSION', 'PRIVATE_ANALYSIS_CLAIM_VERSION', 'PRIVATE_ANALYSIS_PROPOSAL_VERSION', 'PRIVATE_ANALYSIS_RESULT_VERSION', 'PRIVATE_ANALYSIS_ERROR_VERSION', 'PRIVATE_ANALYSIS_OUTCOME_VERSION', 'MAX_PRIVATE_ANALYSIS_REVISIONS', 'MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS', 'MAX_PRIVATE_ANALYSIS_QUERY_BYTES', 'MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS', 'MAX_PRIVATE_ANALYSIS_SUMMARY_CHARACTERS', 'MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS', 'MAX_PRIVATE_ANALYSIS_CLAIMS', 'MAX_PRIVATE_ANALYSIS_PROPOSALS', 'MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM', 'MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES', 'MAX_PRIVATE_ANALYSIS_WIRE_BYTES', 'PrivateAnalysisTaskKind', 'PrivateAnalysisClockMode', 'PrivateAnalysisClaimSupport', 'PrivateAnalysisProposalKind', 'PrivateAnalysisErrorStage', 'PrivateAnalysisErrorCode', 'PrivateAnalysisOutcomeKind', 'PrivateAnalysisContractError', 'PrivateAnalysisRunnerSelection', 'PrivateAnalysisLimits', 'PrivateAnalysisRequest', 'PrivateAnalysisCitation', 'PrivateAnalysisClaim', 'PrivateAnalysisProposal', 'make_private_analysis_proposal', 'PrivateAnalysisResult', 'PrivateAnalysisError', 'PrivateAnalysisOutcome', 'private_analysis_request_dict', 'private_analysis_citation_dict', 'private_analysis_claim_dict', 'private_analysis_proposal_dict', 'private_analysis_result_dict', 'private_analysis_error_dict', 'private_analysis_outcome_dict', 'private_analysis_request_from_dict', 'private_analysis_citation_from_dict', 'private_analysis_claim_from_dict', 'private_analysis_proposal_from_dict', 'private_analysis_result_from_dict', 'private_analysis_error_from_dict', 'private_analysis_outcome_from_dict', 'private_analysis_request_json', 'private_analysis_result_json', 'private_analysis_error_json', 'private_analysis_outcome_json', 'private_analysis_request_from_json', 'private_analysis_result_from_json', 'private_analysis_error_from_json', 'private_analysis_outcome_from_json', 'validate_private_analysis_result']

PRIVATE_ANALYSIS_REQUEST_VERSION_V2: Final[str]
PRIVATE_ANALYSIS_REQUEST_VERSION: Final[str]
PRIVATE_ANALYSIS_CITATION_VERSION: Final[str]
PRIVATE_ANALYSIS_CLAIM_VERSION: Final[str]
PRIVATE_ANALYSIS_PROPOSAL_VERSION: Final[str]
PRIVATE_ANALYSIS_RESULT_VERSION: Final[str]
PRIVATE_ANALYSIS_ERROR_VERSION: Final[str]
PRIVATE_ANALYSIS_OUTCOME_VERSION: Final[str]
MAX_PRIVATE_ANALYSIS_REVISIONS: Final[int]
MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS: Final[int]
MAX_PRIVATE_ANALYSIS_QUERY_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS: Final[int]
MAX_PRIVATE_ANALYSIS_SUMMARY_CHARACTERS: Final[int]
MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS: Final[int]
MAX_PRIVATE_ANALYSIS_CLAIMS: Final[int]
MAX_PRIVATE_ANALYSIS_PROPOSALS: Final[int]
MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM: Final[int]
MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_WIRE_BYTES: Final[int]

class PrivateAnalysisTaskKind(StrEnum):
    LTTNG_ANALYSIS = 'lttng_analysis'
    RESOURCE_CORRELATION = 'resource_correlation'
    CROSS_NODE_CORROBORATION = 'cross_node_corroboration'
    ROUTE_TRACE_ANALYSIS = 'route_trace_analysis'
    GENERAL_EVIDENCE_REVIEW = 'general_evidence_review'

class PrivateAnalysisClockMode(StrEnum):
    LATEST_PER_REVISION = 'latest_per_revision'
    ABSOLUTE_UNIX_NS = 'absolute_unix_ns'
    REVISION_END_RELATIVE_NS = 'revision_end_relative_ns'

class PrivateAnalysisClaimSupport(StrEnum):
    EVIDENCE_SUPPORTED = 'evidence_supported'
    UNSUPPORTED_HYPOTHESIS = 'unsupported_hypothesis'

class PrivateAnalysisProposalKind(StrEnum):
    EVENT_INTERPRETATION = 'event_interpretation'
    EVENT_CORRELATION = 'event_correlation'
    RESOURCE_CORRELATION = 'resource_correlation'
    IDENTITY_MAPPING = 'identity_mapping'
    ROUTE_HYPOTHESIS = 'route_hypothesis'
    TRACE_STEERING_RULE = 'trace_steering_rule'
    REPORT_ANNOTATION = 'report_annotation'

class PrivateAnalysisErrorStage(StrEnum):
    REQUEST_VALIDATION = 'request_validation'
    AUTHORIZATION = 'authorization'
    DISCLOSURE = 'disclosure'
    EVIDENCE = 'evidence'
    RUNNER = 'runner'
    OUTPUT_VALIDATION = 'output_validation'

class PrivateAnalysisErrorCode(StrEnum):
    INVALID_REQUEST = 'invalid_request'
    POLICY_DENIED = 'policy_denied'
    EVIDENCE_UNAVAILABLE = 'evidence_unavailable'
    BUDGET_EXCEEDED = 'budget_exceeded'
    RUNNER_UNAVAILABLE = 'runner_unavailable'
    RUNNER_PROTOCOL_ERROR = 'runner_protocol_error'
    RUNNER_FAILED = 'runner_failed'
    TIMEOUT = 'timeout'
    CANCELLED = 'cancelled'
    INVALID_RESULT = 'invalid_result'

class PrivateAnalysisOutcomeKind(StrEnum):
    RESULT = 'result'
    ERROR = 'error'

class PrivateAnalysisContractError(ValueError): ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunnerSelection(SealedContractValue):
    runner_id: str
    runner_version: str
    transport: PrivateAnalysisTransport
    configuration_digest: str
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisLimits(SealedContractValue):
    max_evidence_items: int = ...
    max_evidence_bytes: int = ...
    max_tool_calls: int = ...
    max_output_bytes: int = ...
    max_claims: int = ...
    max_proposals: int = ...
    deadline_ms: int = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisRequest(SealedContractValue):
    scope: EvidenceScope
    revisions: tuple[EvidenceRevisionBinding, ...]
    runner: PrivateAnalysisRunnerSelection
    workspace_policy_digest: str
    instruction_profile_digest: str
    tool_catalog_digest: str
    task_kind: PrivateAnalysisTaskKind
    query: str
    clock_mode: PrivateAnalysisClockMode
    selected_time_ns: int | None
    limits: PrivateAnalysisLimits
    evidence_service_digest: str = ...
    contract_version: str = ...
    request_digest: str = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisCitation(SealedContractValue):
    evidence_reference_digest: str
    contract_version: str = ...
    citation_digest: str = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisClaim(SealedContractValue):
    claim_id: str
    support: PrivateAnalysisClaimSupport
    text: str
    citations: tuple[PrivateAnalysisCitation, ...]
    contract_version: str = ...
    claim_digest: str = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisProposal(SealedContractValue):
    proposal_id: str
    kind: PrivateAnalysisProposalKind
    title: str
    rationale: str
    confidence_basis_points: int
    citations: tuple[PrivateAnalysisCitation, ...]
    payload_schema: str
    payload_json: str
    provenance: PrivateAnalysisContributionKind = ...
    contract_version: str = ...
    proposal_digest: str = ...
    def __post_init__(self) -> None: ...
    @property
    def payload(self) -> dict[str, Any]: ...

def make_private_analysis_proposal(*, proposal_id: str, kind: PrivateAnalysisProposalKind, title: str, rationale: str, confidence_basis_points: int, citations: tuple[PrivateAnalysisCitation, ...], payload_schema: str, payload: dict[str, Any]) -> PrivateAnalysisProposal: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisResult(SealedContractValue):
    request_digest: str
    summary: PrivateAnalysisClaim
    claims: tuple[PrivateAnalysisClaim, ...]
    proposals: tuple[PrivateAnalysisProposal, ...]
    contract_version: str = ...
    result_digest: str = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisError(SealedContractValue):
    request_digest: str | None
    stage: PrivateAnalysisErrorStage
    code: PrivateAnalysisErrorCode
    retryable: bool
    contract_version: str = ...
    error_digest: str = ...
    def __post_init__(self) -> None: ...
    @property
    def safe_message(self) -> str: ...

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisOutcome(SealedContractValue):
    kind: PrivateAnalysisOutcomeKind
    result: PrivateAnalysisResult | None = ...
    error: PrivateAnalysisError | None = ...
    contract_version: str = ...
    outcome_digest: str = ...
    def __post_init__(self) -> None: ...

def private_analysis_request_dict(value: PrivateAnalysisRequest) -> dict[str, object]: ...
def private_analysis_citation_dict(value: PrivateAnalysisCitation) -> dict[str, object]: ...
def private_analysis_claim_dict(value: PrivateAnalysisClaim) -> dict[str, object]: ...
def private_analysis_proposal_dict(value: PrivateAnalysisProposal) -> dict[str, object]: ...
def private_analysis_result_dict(value: PrivateAnalysisResult) -> dict[str, object]: ...
def private_analysis_error_dict(value: PrivateAnalysisError) -> dict[str, object]: ...
def private_analysis_outcome_dict(value: PrivateAnalysisOutcome) -> dict[str, object]: ...
def private_analysis_request_from_dict(value: object) -> PrivateAnalysisRequest: ...
def private_analysis_citation_from_dict(value: object) -> PrivateAnalysisCitation: ...
def private_analysis_claim_from_dict(value: object) -> PrivateAnalysisClaim: ...
def private_analysis_proposal_from_dict(value: object) -> PrivateAnalysisProposal: ...
def private_analysis_result_from_dict(value: object) -> PrivateAnalysisResult: ...
def private_analysis_error_from_dict(value: object) -> PrivateAnalysisError: ...
def private_analysis_outcome_from_dict(value: object) -> PrivateAnalysisOutcome: ...
def private_analysis_request_json(value: PrivateAnalysisRequest) -> str: ...
def private_analysis_result_json(value: PrivateAnalysisResult) -> str: ...
def private_analysis_error_json(value: PrivateAnalysisError) -> str: ...
def private_analysis_outcome_json(value: PrivateAnalysisOutcome) -> str: ...
def private_analysis_request_from_json(value: str) -> PrivateAnalysisRequest: ...
def private_analysis_result_from_json(value: str) -> PrivateAnalysisResult: ...
def private_analysis_error_from_json(value: str) -> PrivateAnalysisError: ...
def private_analysis_outcome_from_json(value: str) -> PrivateAnalysisOutcome: ...
def validate_private_analysis_result(result: PrivateAnalysisResult, request: PrivateAnalysisRequest, disclosed_references: tuple[EvidenceReference, ...]) -> None: ...

# Importable compatibility value used by another typed core module.
LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST: Final[str]
