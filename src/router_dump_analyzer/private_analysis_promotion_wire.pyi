from .private_analysis_promotion import PromotionTarget, ProposalReviewDecision, ProposalReviewDisposition
from dataclasses import dataclass
from typing import Any, Final

__all__ = ['PROPOSAL_REVIEW_WIRE_CONTRACT', 'ProposalReviewWireError', 'ProposalReviewRequest', 'parse_proposal_review_request', 'proposal_review_decision_to_wire']

PROPOSAL_REVIEW_WIRE_CONTRACT: Final[str]

class ProposalReviewWireError(ValueError): ...

@dataclass(frozen=True, slots=True)
class ProposalReviewRequest:
    proposal_digest: str
    result_digest: str
    disposition: ProposalReviewDisposition
    rationale: str
    target: PromotionTarget | None

def parse_proposal_review_request(value: object) -> ProposalReviewRequest: ...
def proposal_review_decision_to_wire(value: ProposalReviewDecision) -> dict[str, Any]: ...
