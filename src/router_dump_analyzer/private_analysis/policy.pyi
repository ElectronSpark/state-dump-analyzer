from typing import final
from ._wire import SealedContractValue as SealedContractValue
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

PRIVATE_ANALYSIS_POLICY_VERSION: Final[str]
PUBLIC_MODEL_API_INTEGRATION_ALLOWED: Final[bool]
ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED: Final[bool]
ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED: Final[bool]

class PrivateAnalysisTransport(StrEnum):
    IN_PROCESS = 'in_process'
    LOCAL_SUBPROCESS = 'local_subprocess'

class PrivateAnalysisContributionKind(StrEnum):
    ASSISTANT_SUGGESTED = 'assistant_suggested'
    USER_APPROVED_DERIVATION = 'user_approved_derivation'
    COUNTERFACTUAL = 'counterfactual'

@final
@dataclass(frozen=True, slots=True)
class PrivateAnalysisPolicy(SealedContractValue):
    transport: PrivateAnalysisTransport
    full_fidelity_workspace_data: bool = ...
    def __post_init__(self) -> None: ...
    @property
    def public_model_api_integration_allowed(self) -> bool: ...
    @property
    def direct_ground_truth_mutation_allowed(self) -> bool: ...
    @property
    def direct_plugin_authority_allowed(self) -> bool: ...
