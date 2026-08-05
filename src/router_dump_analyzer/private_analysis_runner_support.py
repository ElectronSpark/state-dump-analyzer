"""Transport-neutral helpers for executable private-analysis runners.

This module centralizes static error projection, detached budget snapshots,
live run-access checks, and final model-result validation.  It owns no model,
process, network, filesystem, plug-in, persistence, or user interface
authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic_ns

from .canonical import (
    validate_prefixed_lowercase_sha256 as private_analysis_prefixed_sha256,
)
from .private_analysis import (
    EvidenceReference,
    PrivateAnalysisContractError,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    PrivateAnalysisResult,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_json,
    private_analysis_result_from_json,
    private_analysis_result_json,
    validate_private_analysis_result,
)
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolRunLease,
    PrivateAnalysisToolServiceError,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS


@dataclass(slots=True)
class PrivateAnalysisRunAccountingSnapshot:
    """Last complete detached ledger and budget read from one active lease."""

    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState

    def __post_init__(self) -> None:
        self.references = tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in self.references
        )
        self.budget_state = detached_private_analysis_budget_state(self.budget_state)

    def refresh(self, lease: PrivateAnalysisToolRunLease) -> None:
        """Atomically publish one complete detached snapshot from ``lease``."""

        references = lease.disclosed_references
        budget_state = lease.budget_state
        detached_references = tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in references
        )
        detached_budget = detached_private_analysis_budget_state(budget_state)
        self.references = detached_references
        self.budget_state = detached_budget


def private_analysis_deadline_expired(deadline_ns: int) -> bool:
    """Return whether one monotonic deadline has expired."""

    return monotonic_ns() >= deadline_ns


def private_analysis_error(
    request_digest: str,
    stage: PrivateAnalysisErrorStage,
    code: PrivateAnalysisErrorCode,
) -> PrivateAnalysisError:
    """Construct one closed payload-free runner error."""

    return PrivateAnalysisError(
        request_digest=request_digest,
        stage=stage,
        code=code,
        retryable=code
        in {
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorCode.TIMEOUT,
        },
    )


def detached_private_analysis_error(
    value: PrivateAnalysisError,
) -> PrivateAnalysisError:
    """Return one revalidated detached error value."""

    if type(value) is not PrivateAnalysisError:
        raise TypeError("error must be PrivateAnalysisError")
    return PrivateAnalysisError(
        request_digest=value.request_digest,
        stage=value.stage,
        code=value.code,
        retryable=value.retryable,
        contract_version=value.contract_version,
        error_digest=value.error_digest,
    )


def private_analysis_error_outcome(
    error: PrivateAnalysisError,
) -> PrivateAnalysisOutcome:
    """Wrap one detached error in the closed outcome contract."""

    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=detached_private_analysis_error(error),
    )


def detached_private_analysis_budget_state(
    value: PrivateAnalysisToolBudgetState,
) -> PrivateAnalysisToolBudgetState:
    """Return a detached immutable tool-budget snapshot."""

    if type(value) is not PrivateAnalysisToolBudgetState:
        raise TypeError("budget_state must be PrivateAnalysisToolBudgetState")
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=value.max_tool_calls,
        tool_calls_consumed=value.tool_calls_consumed,
        max_evidence_items=value.max_evidence_items,
        evidence_items_disclosed=value.evidence_items_disclosed,
        max_evidence_bytes=value.max_evidence_bytes,
        evidence_bytes_disclosed=value.evidence_bytes_disclosed,
    )


def empty_private_analysis_budget_state(
    request: PrivateAnalysisRequest,
) -> PrivateAnalysisToolBudgetState:
    """Return the zero-consumption budget bound to one request."""

    return PrivateAnalysisToolBudgetState(
        max_tool_calls=request.limits.max_tool_calls,
        tool_calls_consumed=0,
        max_evidence_items=request.limits.max_evidence_items,
        evidence_items_disclosed=0,
        max_evidence_bytes=request.limits.max_evidence_bytes,
        evidence_bytes_disclosed=0,
    )


def private_analysis_budget_payload(
    value: PrivateAnalysisToolBudgetState,
) -> dict[str, int]:
    """Project a detached budget into a canonical digest payload."""

    value = detached_private_analysis_budget_state(value)
    return {
        "max_tool_calls": value.max_tool_calls,
        "tool_calls_consumed": value.tool_calls_consumed,
        "max_evidence_items": value.max_evidence_items,
        "evidence_items_disclosed": value.evidence_items_disclosed,
        "max_evidence_bytes": value.max_evidence_bytes,
        "evidence_bytes_disclosed": value.evidence_bytes_disclosed,
    }


def private_analysis_execution_receipt_values(
    *,
    outcome: PrivateAnalysisOutcome,
    disclosed_references: tuple[EvidenceReference, ...],
    budget_state: PrivateAnalysisToolBudgetState,
    transcript_request_digest: str,
    transcript_evidence_ledger_digest: str,
    transcript_budget_state: PrivateAnalysisToolBudgetState,
    transcript_outcome_digest: str,
) -> tuple[str, tuple[EvidenceReference, ...], PrivateAnalysisToolBudgetState]:
    """Validate and detach the transport-neutral receipt bindings."""

    if type(outcome) is not PrivateAnalysisOutcome:
        raise TypeError("outcome must be PrivateAnalysisOutcome")
    if type(disclosed_references) is not tuple:
        raise TypeError("disclosed_references must be a tuple")
    references = tuple(
        evidence_reference_from_dict(evidence_reference_dict(item))
        for item in disclosed_references
    )
    reference_digests = tuple(item.reference_digest for item in references)
    if reference_digests != tuple(sorted(reference_digests)) or len(
        reference_digests
    ) != len(set(reference_digests)):
        raise ValueError("disclosed references must be unique and canonical")
    budget = detached_private_analysis_budget_state(budget_state)
    if transcript_evidence_ledger_digest != evidence_snapshot_digest(references):
        raise ValueError("transcript does not bind the disclosed ledger")
    if budget.evidence_items_disclosed != len(references):
        raise ValueError("budget snapshot disagrees with disclosed ledger")
    if transcript_outcome_digest != outcome.outcome_digest:
        raise ValueError("transcript does not bind the outcome")
    if detached_private_analysis_budget_state(transcript_budget_state) != budget:
        raise ValueError("transcript does not bind the budget snapshot")
    outcome_request_digest = (
        outcome.result.request_digest
        if outcome.result is not None
        else outcome.error.request_digest
        if outcome.error is not None
        else None
    )
    if outcome_request_digest != transcript_request_digest:
        raise ValueError("transcript does not bind the outcome request")
    return private_analysis_outcome_json(outcome), references, budget


def private_analysis_run_access_error(
    lease: PrivateAnalysisToolRunLease,
    request: PrivateAnalysisRequest,
    deadline_ns: int,
    *,
    deadline_expired: Callable[[int], bool] = private_analysis_deadline_expired,
) -> PrivateAnalysisError | None:
    """Recheck run access with systematic post-operation timeout precedence."""

    if deadline_expired(deadline_ns):
        return private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    access_error: PrivateAnalysisError | None = None
    try:
        lease.require_run_access()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisToolServiceError as error:
        access_error = detached_private_analysis_error(error.error)
    except BaseException:  # noqa: BLE001 - executable trust boundary.
        access_error = private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )
    if deadline_expired(deadline_ns):
        return private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.TIMEOUT,
        )
    return access_error


def validate_private_analysis_result_json(
    raw_result: object,
    request: PrivateAnalysisRequest,
    references: tuple[EvidenceReference, ...],
) -> tuple[PrivateAnalysisResult | None, PrivateAnalysisError | None]:
    """Parse, bound, cite-check, and detach one untrusted model result."""

    if type(raw_result) is not str:
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    if len(raw_result) > request.limits.max_output_bytes:
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        encoded_size = len(raw_result.encode("utf-8"))
    except UnicodeEncodeError:
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    if encoded_size > request.limits.max_output_bytes:
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        result = private_analysis_result_from_json(raw_result)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - untrusted model output boundary.
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    canonical_size = len(private_analysis_result_json(result).encode("utf-8"))
    if (
        canonical_size > request.limits.max_output_bytes
        or 1 + len(result.claims) > request.limits.max_claims
        or len(result.proposals) > request.limits.max_proposals
    ):
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
        )
    try:
        validate_private_analysis_result(result, request, references)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except PrivateAnalysisContractError:
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    except BaseException:  # noqa: BLE001 - untrusted model output boundary.
        return None, private_analysis_error(
            request.request_digest,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
            PrivateAnalysisErrorCode.INVALID_RESULT,
        )
    return private_analysis_result_from_json(private_analysis_result_json(result)), None


__all__ = [
    "PrivateAnalysisRunAccountingSnapshot",
    "detached_private_analysis_budget_state",
    "detached_private_analysis_error",
    "empty_private_analysis_budget_state",
    "private_analysis_budget_payload",
    "private_analysis_deadline_expired",
    "private_analysis_error",
    "private_analysis_error_outcome",
    "private_analysis_execution_receipt_values",
    "private_analysis_prefixed_sha256",
    "private_analysis_run_access_error",
    "validate_private_analysis_result_json",
]
