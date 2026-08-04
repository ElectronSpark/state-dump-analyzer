"""Private, advisory AI-analysis boundary owned by the core.

The package deliberately contains no public-model client.  Deployments may
eventually provide an in-process runner or a local subprocess runner, but all
model interaction remains behind the closed policy declared in :mod:`policy`.
"""

from .disclosure import (
    WORKSPACE_DISCLOSURE_POLICY_VERSION,
    DisclosureDecision,
    DisclosureDecisionReason,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    WorkspaceDisclosurePolicy,
    disclosure_decision_dict,
    evaluate_workspace_disclosure,
    workspace_disclosure_policy_dict,
    workspace_disclosure_policy_digest,
    workspace_disclosure_policy_from_dict,
)
from .policy import (
    ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED,
    ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED,
    PRIVATE_ANALYSIS_POLICY_VERSION,
    PUBLIC_MODEL_API_INTEGRATION_ALLOWED,
    PrivateAnalysisContributionKind,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
)

__all__ = [
    "ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED",
    "ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED",
    "PRIVATE_ANALYSIS_POLICY_VERSION",
    "PUBLIC_MODEL_API_INTEGRATION_ALLOWED",
    "WORKSPACE_DISCLOSURE_POLICY_VERSION",
    "DisclosureDecision",
    "DisclosureDecisionReason",
    "PrivateAnalysisContributionKind",
    "PrivateAnalysisDisclosureMode",
    "PrivateAnalysisEvidenceClass",
    "PrivateAnalysisPolicy",
    "PrivateAnalysisTransport",
    "WorkspaceDisclosurePolicy",
    "disclosure_decision_dict",
    "evaluate_workspace_disclosure",
    "workspace_disclosure_policy_dict",
    "workspace_disclosure_policy_digest",
    "workspace_disclosure_policy_from_dict",
]
