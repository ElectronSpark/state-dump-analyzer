from typing import final
from ._wire import SealedContractValue
from .policy import PrivateAnalysisPolicy, PrivateAnalysisTransport
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = ['WORKSPACE_DISCLOSURE_POLICY_VERSION', 'DISCLOSURE_SCOPE_VERSION', 'PrivateAnalysisDisclosureMode', 'PrivateAnalysisEvidenceClass', 'DisclosureDecisionReason', 'WorkspaceDisclosurePolicy', 'DisclosureDecision', 'workspace_disclosure_policy_dict', 'workspace_disclosure_policy_from_dict', 'workspace_disclosure_policy_digest', 'disclosure_scope_digest', 'evaluate_workspace_disclosure', 'disclosure_decision_dict', 'disclosure_decision_from_dict']

WORKSPACE_DISCLOSURE_POLICY_VERSION: Final[str]
DISCLOSURE_SCOPE_VERSION: Final[str]

class PrivateAnalysisDisclosureMode(StrEnum):
    DISABLED = 'disabled'
    CLIENT_SAFE = 'client_safe'
    FULL_FIDELITY = 'full_fidelity'

class PrivateAnalysisEvidenceClass(StrEnum):
    PUBLIC_METADATA = 'public_metadata'
    CLIENT_SAFE = 'client_safe'
    PROPRIETARY = 'proprietary'
    NEVER_ASSISTANT = 'never_assistant'

class DisclosureDecisionReason(StrEnum):
    ALLOWED = 'allowed'
    WORKSPACE_DISABLED = 'workspace_disabled'
    TRANSPORT_NOT_APPROVED = 'transport_not_approved'
    RUNNER_FULL_FIDELITY_NOT_APPROVED = 'runner_full_fidelity_not_approved'
    EVIDENCE_CLASS_NOT_APPROVED = 'evidence_class_not_approved'
    NEVER_ASSISTANT = 'never_assistant'

@final
@dataclass(frozen=True, slots=True)
class WorkspaceDisclosurePolicy(SealedContractValue):
    mode: PrivateAnalysisDisclosureMode
    transports: tuple[PrivateAnalysisTransport, ...] = ...
    def __post_init__(self) -> None: ...
    @classmethod
    def disabled(cls) -> WorkspaceDisclosurePolicy: ...
    @property
    def digest(self) -> str: ...

@final
@dataclass(frozen=True, slots=True)
class DisclosureDecision(SealedContractValue):
    policy_digest: str
    scope_digest: str
    transport: PrivateAnalysisTransport
    evidence_class: PrivateAnalysisEvidenceClass
    allowed: bool
    reason: DisclosureDecisionReason
    def __post_init__(self) -> None: ...
    @property
    def digest(self) -> str: ...

def workspace_disclosure_policy_dict(policy: WorkspaceDisclosurePolicy) -> dict[str, object]: ...
def workspace_disclosure_policy_from_dict(value: dict[str, Any]) -> WorkspaceDisclosurePolicy: ...
def workspace_disclosure_policy_digest(policy: WorkspaceDisclosurePolicy) -> str: ...
def disclosure_scope_digest(*, tenant_id: str, project_id: str, workspace_id: str) -> str: ...
def evaluate_workspace_disclosure(policy: WorkspaceDisclosurePolicy, *, tenant_id: str, project_id: str, workspace_id: str, runner_policy: PrivateAnalysisPolicy, evidence_class: PrivateAnalysisEvidenceClass) -> DisclosureDecision: ...
def disclosure_decision_dict(decision: DisclosureDecision) -> dict[str, object]: ...
def disclosure_decision_from_dict(value: dict[str, Any]) -> DisclosureDecision: ...
