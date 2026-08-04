"""Non-negotiable trust and authority rules for private AI analysis.

This module is intentionally small.  It freezes the security decisions that
later runner, tool, storage, API, and UI implementations must consume:

* model execution is either in-process or through a local child process;
* the core never contains a public-model API integration;
* an authorized private model may receive full-fidelity workspace evidence;
* model output is advisory and cannot directly mutate immutable ground truth;
* model output cannot directly invoke plug-ins or arbitrary host capabilities.

The concrete task, evidence, runner, and proposal contracts are added in later
implementation stages.  Keeping these policy values separate makes widening a
trust boundary a deliberate contract change instead of a hidden adapter option.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

PRIVATE_ANALYSIS_POLICY_VERSION: Final = (
    "router_dump_analyzer.private_analysis_policy.v1"
)

# These values are intentionally not constructor arguments.  A deployment
# cannot turn them on through configuration; doing so requires changing the
# core contract and its structural tests.
PUBLIC_MODEL_API_INTEGRATION_ALLOWED: Final = False
ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED: Final = False
ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED: Final = False


class PrivateAnalysisTransport(StrEnum):
    """The complete set of model transports supplied by the core."""

    IN_PROCESS = "in_process"
    LOCAL_SUBPROCESS = "local_subprocess"


class PrivateAnalysisContributionKind(StrEnum):
    """Assistant-related origins kept outside deterministic fact provenance."""

    ASSISTANT_SUGGESTED = "assistant_suggested"
    USER_APPROVED_DERIVATION = "user_approved_derivation"
    COUNTERFACTUAL = "counterfactual"


@dataclass(frozen=True, slots=True)
class PrivateAnalysisPolicy:
    """One immutable workspace policy for an approved private model.

    ``full_fidelity_workspace_data`` controls whether an authorized run may
    retrieve proprietary dump content.  It does not override future
    ``never_assistant`` declarations for credentials or other secrets.
    Operational pagination and byte budgets likewise remain mandatory even
    when the model is approved for full-fidelity evidence.
    """

    transport: PrivateAnalysisTransport
    full_fidelity_workspace_data: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.transport, PrivateAnalysisTransport):
            raise TypeError(
                "private analysis transport must be PrivateAnalysisTransport"
            )
        if type(self.full_fidelity_workspace_data) is not bool:
            raise TypeError(
                "full_fidelity_workspace_data must be a boolean"
            )

    @property
    def public_model_api_integration_allowed(self) -> bool:
        return PUBLIC_MODEL_API_INTEGRATION_ALLOWED

    @property
    def direct_ground_truth_mutation_allowed(self) -> bool:
        return ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED

    @property
    def direct_plugin_authority_allowed(self) -> bool:
        return ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED
