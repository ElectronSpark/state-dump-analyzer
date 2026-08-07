"""Transport-neutral helpers for executable private-analysis runners.

This module centralizes static error projection, detached budget snapshots,
live run-access checks, and final model-result validation.  It owns no model,
process, network, filesystem, plug-in, persistence, or user interface
authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from json import JSONDecodeError, loads
from threading import Lock
from time import monotonic_ns
from typing import Final, Protocol

from .canonical import (
    strict_canonical_json,
    strict_canonical_json_sha256,
)
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
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTransport,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_json,
    private_analysis_result_from_json,
    private_analysis_result_json,
    validate_private_analysis_result,
)
from .private_analysis._wire import (
    SealedContractValue,
    exact_contract_version,
    exact_json_object,
    reject_duplicate_json_object_pairs,
    strict_string_enum,
)
from .private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
    PrivateAnalysisToolServiceError,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .value_core import MAX_JSON_SAFE_INTEGER

PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION: Final = (
    "router_dump_analyzer.private_analysis.transcript_summary.v1"
)
MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES: Final = 16 * 1024
MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES: Final = 4 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES: Final = 256 * 1024
MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES: Final = 8 * 1024 * 1024


PrivateAnalysisAccountingObserver = Callable[
    [tuple[EvidenceReference, ...], PrivateAnalysisToolBudgetState],
    None,
]
PrivateAnalysisCancellationProbe = Callable[[], bool]


class _PrivateAnalysisRunLeaseAccountingView(Protocol):
    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState: ...

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]: ...

    def require_run_access(self) -> None: ...


class PrivateAnalysisRunnerExecutionOwner:
    """Own immutable runner identity and its cross-coordinator execution gate."""

    __slots__ = (
        "_instruction_profile_digest",
        "_private_analysis_execution_lock",
        "_selection",
    )

    def __init__(
        self,
        selection: PrivateAnalysisRunnerSelection,
        *,
        instruction_profile_digest: str,
    ) -> None:
        if type(selection) is not PrivateAnalysisRunnerSelection:
            raise TypeError("selection must be PrivateAnalysisRunnerSelection")
        self._selection = PrivateAnalysisRunnerSelection(
            runner_id=selection.runner_id,
            runner_version=selection.runner_version,
            transport=selection.transport,
            configuration_digest=selection.configuration_digest,
        )
        self._instruction_profile_digest = private_analysis_prefixed_sha256(
            instruction_profile_digest,
            "instruction_profile_digest",
        )
        self._private_analysis_execution_lock = Lock()

    @property
    def selection(self) -> PrivateAnalysisRunnerSelection:
        value = self._selection
        return PrivateAnalysisRunnerSelection(
            runner_id=value.runner_id,
            runner_version=value.runner_version,
            transport=value.transport,
            configuration_digest=value.configuration_digest,
        )

    @property
    def instruction_profile_digest(self) -> str:
        """Return the sealed instruction profile used by this runner."""

        return self._instruction_profile_digest

    @property
    def execution_lock(self) -> Lock:
        """Return the runner-instance gate used by core composition."""

        return self._private_analysis_execution_lock


@dataclass(slots=True)
class PrivateAnalysisRunAccountingSnapshot:
    """Last complete detached ledger and budget read from one active lease."""

    references: tuple[EvidenceReference, ...]
    budget_state: PrivateAnalysisToolBudgetState
    observer: PrivateAnalysisAccountingObserver | None = None

    def __post_init__(self) -> None:
        self.references = tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in self.references
        )
        self.budget_state = detached_private_analysis_budget_state(self.budget_state)
        if self.observer is not None and not callable(self.observer):
            raise TypeError("observer must be callable or None")

    def refresh(self, lease: _PrivateAnalysisRunLeaseAccountingView) -> None:
        """Atomically publish one complete detached snapshot from ``lease``."""

        references = lease.disclosed_references
        budget_state = lease.budget_state
        detached_references = tuple(
            evidence_reference_from_dict(evidence_reference_dict(item))
            for item in references
        )
        detached_budget = detached_private_analysis_budget_state(budget_state)
        if self.observer is not None:
            # The observer must durably commit this complete snapshot before
            # the corresponding tool response can return to a model.  Its
            # failure propagates and the last published local snapshot stays
            # unchanged, making the disclosure fail closed.
            self.observer(detached_references, detached_budget)
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


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisInProcessTranscriptSummaryMetadata(SealedContractValue):
    """Bounded, payload-free metadata for one in-process transcript."""

    transcript_digest: str
    exchange_count: int
    unattributed_tool_call_count: int
    exchange_metadata_bytes: int
    exchange_chain_digest: str

    def __post_init__(self) -> None:
        private_analysis_prefixed_sha256(
            self.transcript_digest,
            "transcript_digest",
        )
        _summary_counter(self.exchange_count, "exchange_count")
        _summary_counter(
            self.unattributed_tool_call_count,
            "unattributed_tool_call_count",
        )
        _summary_counter(
            self.exchange_metadata_bytes,
            "exchange_metadata_bytes",
            maximum=MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES,
        )
        private_analysis_prefixed_sha256(
            self.exchange_chain_digest,
            "exchange_chain_digest",
        )

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisInProcessTranscriptSummaryMetadata("
            f"exchange_count={self.exchange_count}, "
            "unattributed_tool_call_count="
            f"{self.unattributed_tool_call_count}, "
            f"transcript_digest={self.transcript_digest!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(SealedContractValue):
    """Bounded, payload-free metadata for one local-subprocess transcript."""

    transcript_digest: str
    launch_configuration_digest: str
    run_digest: str
    message_count: int
    tool_call_count: int
    message_metadata_bytes: int
    message_chain_digest: str
    stderr_bytes: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.transcript_digest, "transcript_digest"),
            (self.launch_configuration_digest, "launch_configuration_digest"),
            (self.run_digest, "run_digest"),
            (self.message_chain_digest, "message_chain_digest"),
        ):
            private_analysis_prefixed_sha256(value, label)
        _summary_counter(self.message_count, "message_count")
        _summary_counter(self.tool_call_count, "tool_call_count")
        _summary_counter(
            self.message_metadata_bytes,
            "message_metadata_bytes",
            maximum=MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES,
        )
        _summary_counter(
            self.stderr_bytes,
            "stderr_bytes",
            maximum=MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES,
        )

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata("
            f"message_count={self.message_count}, "
            f"tool_call_count={self.tool_call_count}, "
            f"stderr_bytes={self.stderr_bytes}, "
            f"transcript_digest={self.transcript_digest!r})"
        )


PrivateAnalysisTranscriptSummaryMetadata = (
    PrivateAnalysisInProcessTranscriptSummaryMetadata
    | PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata
)


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAnalysisTranscriptSummary(SealedContractValue):
    """Transport-neutral, payload-free seal suitable for durable binding."""

    transport: PrivateAnalysisTransport
    request_digest: str
    catalog_digest: str
    instruction_profile_digest: str
    runner_configuration_digest: str
    outcome_digest: str
    evidence_ledger_digest: str
    budget_state: PrivateAnalysisToolBudgetState
    metadata: PrivateAnalysisTranscriptSummaryMetadata
    contract_version: str = PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION
    summary_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION,
            "private-analysis transcript summary",
        )
        if type(self.transport) is not PrivateAnalysisTransport:
            raise TypeError("transport must be PrivateAnalysisTransport")
        for value, label in (
            (self.request_digest, "request_digest"),
            (self.catalog_digest, "catalog_digest"),
            (self.instruction_profile_digest, "instruction_profile_digest"),
            (self.runner_configuration_digest, "runner_configuration_digest"),
            (self.outcome_digest, "outcome_digest"),
            (self.evidence_ledger_digest, "evidence_ledger_digest"),
        ):
            private_analysis_prefixed_sha256(value, label)
        budget = _private_analysis_budget_state_from_payload(
            private_analysis_budget_payload(self.budget_state)
        )
        object.__setattr__(self, "budget_state", budget)
        metadata = _detached_transcript_summary_metadata(self.metadata)
        if self.transport is PrivateAnalysisTransport.IN_PROCESS:
            if type(metadata) is not PrivateAnalysisInProcessTranscriptSummaryMetadata:
                raise ValueError("in-process summary requires in-process metadata")
            attributed_calls = (
                metadata.exchange_count + metadata.unattributed_tool_call_count
            )
            if not (
                budget.tool_calls_consumed
                <= attributed_calls
                <= budget.tool_calls_consumed + 1
            ):
                raise ValueError("in-process metadata disagrees with tool budget")
        elif self.transport is PrivateAnalysisTransport.LOCAL_SUBPROCESS:
            if (
                type(metadata)
                is not PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata
            ):
                raise ValueError(
                    "local-subprocess summary requires local-subprocess metadata"
                )
            if not (
                budget.tool_calls_consumed
                <= metadata.tool_call_count
                <= budget.tool_calls_consumed + 1
            ):
                raise ValueError("local-subprocess metadata disagrees with tool budget")
        else:  # closed enum makes this unreachable
            raise ValueError("unsupported private-analysis summary transport")
        object.__setattr__(self, "metadata", metadata)
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_transcript_summary_payload(self)
        )
        if type(self.summary_digest) is not str:
            raise TypeError("summary_digest must be a string")
        if self.summary_digest:
            private_analysis_prefixed_sha256(
                self.summary_digest,
                "summary_digest",
            )
            if self.summary_digest != expected:
                raise ValueError("transcript summary digest does not match")
        else:
            object.__setattr__(self, "summary_digest", expected)

    def __repr__(self) -> str:
        return (
            "PrivateAnalysisTranscriptSummary("
            f"transport={self.transport.value!r}, "
            f"request_digest={self.request_digest!r}, "
            f"summary_digest={self.summary_digest!r})"
        )


def private_analysis_transcript_summary_dict(
    value: PrivateAnalysisTranscriptSummary,
) -> dict[str, object]:
    """Return the exact discriminated wire object for one summary."""

    detached = detached_private_analysis_transcript_summary(value)
    payload = _private_analysis_transcript_summary_payload(detached)
    payload["summary_digest"] = detached.summary_digest
    return payload


def private_analysis_transcript_summary_from_dict(
    value: object,
) -> PrivateAnalysisTranscriptSummary:
    """Parse one exact discriminated transcript-summary object."""

    if type(value) is not dict:
        raise TypeError("private-analysis transcript summary must be a dictionary")
    raw_transport = value.get("transport")
    transport = strict_string_enum(
        PrivateAnalysisTransport,
        raw_transport,
        "private-analysis transcript summary transport",
    )
    branch_name = transport.value
    item = exact_json_object(
        value,
        "private-analysis transcript summary",
        _TRANSCRIPT_SUMMARY_COMMON_FIELDS | {branch_name},
    )
    metadata: PrivateAnalysisTranscriptSummaryMetadata
    if transport is PrivateAnalysisTransport.IN_PROCESS:
        metadata = _in_process_transcript_summary_metadata_from_dict(item[branch_name])
    else:
        metadata = _local_subprocess_transcript_summary_metadata_from_dict(
            item[branch_name]
        )
    return PrivateAnalysisTranscriptSummary(
        transport=transport,
        request_digest=item["request_digest"],
        catalog_digest=item["catalog_digest"],
        instruction_profile_digest=item["instruction_profile_digest"],
        runner_configuration_digest=item["runner_configuration_digest"],
        outcome_digest=item["outcome_digest"],
        evidence_ledger_digest=item["evidence_ledger_digest"],
        budget_state=_private_analysis_budget_state_from_payload(item["budget_state"]),
        metadata=metadata,
        contract_version=item["contract_version"],
        summary_digest=item["summary_digest"],
    )


def private_analysis_transcript_summary_json(
    value: PrivateAnalysisTranscriptSummary,
) -> str:
    """Serialize one summary as bounded strict canonical JSON."""

    encoded = strict_canonical_json(private_analysis_transcript_summary_dict(value))
    if len(encoded.encode("utf-8")) > MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES:
        raise ValueError("private-analysis transcript summary exceeds its byte limit")
    return encoded


def private_analysis_transcript_summary_from_json(
    value: object,
) -> PrivateAnalysisTranscriptSummary:
    """Parse one bounded exact-canonical transcript-summary JSON value."""

    if type(value) is not str:
        raise TypeError("private-analysis transcript summary JSON must be a string")
    if len(value) > MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES:
        raise ValueError("private-analysis transcript summary JSON is too large")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(
            "private-analysis transcript summary JSON must contain Unicode scalars"
        ) from error
    if len(encoded) > MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES:
        raise ValueError("private-analysis transcript summary JSON is too large")

    def reject_constant(constant: str) -> None:
        raise ValueError(f"unsupported JSON constant {constant}")

    try:
        parsed = loads(
            value,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError(
            "private-analysis transcript summary is not strict JSON"
        ) from error
    if type(parsed) is not dict:
        raise ValueError("private-analysis transcript summary must be a JSON object")
    if strict_canonical_json(parsed) != value:
        raise ValueError(
            "private-analysis transcript summary JSON must be exact canonical JSON"
        )
    return private_analysis_transcript_summary_from_dict(parsed)


def detached_private_analysis_transcript_summary(
    value: PrivateAnalysisTranscriptSummary,
) -> PrivateAnalysisTranscriptSummary:
    """Return a fully revalidated detached summary value."""

    if type(value) is not PrivateAnalysisTranscriptSummary:
        raise TypeError("summary must be PrivateAnalysisTranscriptSummary")
    return PrivateAnalysisTranscriptSummary(
        transport=value.transport,
        request_digest=value.request_digest,
        catalog_digest=value.catalog_digest,
        instruction_profile_digest=value.instruction_profile_digest,
        runner_configuration_digest=value.runner_configuration_digest,
        outcome_digest=value.outcome_digest,
        evidence_ledger_digest=value.evidence_ledger_digest,
        budget_state=value.budget_state,
        metadata=value.metadata,
        contract_version=value.contract_version,
        summary_digest=value.summary_digest,
    )


_TRANSCRIPT_SUMMARY_COMMON_FIELDS: Final = {
    "contract_version",
    "transport",
    "request_digest",
    "catalog_digest",
    "instruction_profile_digest",
    "runner_configuration_digest",
    "outcome_digest",
    "evidence_ledger_digest",
    "budget_state",
    "summary_digest",
}
_BUDGET_STATE_FIELDS: Final = {
    "max_tool_calls",
    "tool_calls_consumed",
    "max_evidence_items",
    "evidence_items_disclosed",
    "max_evidence_bytes",
    "evidence_bytes_disclosed",
}
_IN_PROCESS_SUMMARY_METADATA_FIELDS: Final = {
    "transcript_digest",
    "exchange_count",
    "unattributed_tool_call_count",
    "exchange_metadata_bytes",
    "exchange_chain_digest",
}
_LOCAL_SUBPROCESS_SUMMARY_METADATA_FIELDS: Final = {
    "transcript_digest",
    "launch_configuration_digest",
    "run_digest",
    "message_count",
    "tool_call_count",
    "message_metadata_bytes",
    "message_chain_digest",
    "stderr_bytes",
}


def _summary_counter(
    value: object,
    label: str,
    *,
    maximum: int = MAX_JSON_SAFE_INTEGER,
) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be an integer from 0 through {maximum}")
    return value


def _detached_transcript_summary_metadata(
    value: PrivateAnalysisTranscriptSummaryMetadata,
) -> PrivateAnalysisTranscriptSummaryMetadata:
    if type(value) is PrivateAnalysisInProcessTranscriptSummaryMetadata:
        return PrivateAnalysisInProcessTranscriptSummaryMetadata(
            transcript_digest=value.transcript_digest,
            exchange_count=value.exchange_count,
            unattributed_tool_call_count=value.unattributed_tool_call_count,
            exchange_metadata_bytes=value.exchange_metadata_bytes,
            exchange_chain_digest=value.exchange_chain_digest,
        )
    if type(value) is PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata:
        return PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
            transcript_digest=value.transcript_digest,
            launch_configuration_digest=value.launch_configuration_digest,
            run_digest=value.run_digest,
            message_count=value.message_count,
            tool_call_count=value.tool_call_count,
            message_metadata_bytes=value.message_metadata_bytes,
            message_chain_digest=value.message_chain_digest,
            stderr_bytes=value.stderr_bytes,
        )
    raise TypeError("metadata must be private-analysis transcript summary metadata")


def _in_process_transcript_summary_metadata_payload(
    value: PrivateAnalysisInProcessTranscriptSummaryMetadata,
) -> dict[str, object]:
    return {
        "transcript_digest": value.transcript_digest,
        "exchange_count": value.exchange_count,
        "unattributed_tool_call_count": value.unattributed_tool_call_count,
        "exchange_metadata_bytes": value.exchange_metadata_bytes,
        "exchange_chain_digest": value.exchange_chain_digest,
    }


def _local_subprocess_transcript_summary_metadata_payload(
    value: PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
) -> dict[str, object]:
    return {
        "transcript_digest": value.transcript_digest,
        "launch_configuration_digest": value.launch_configuration_digest,
        "run_digest": value.run_digest,
        "message_count": value.message_count,
        "tool_call_count": value.tool_call_count,
        "message_metadata_bytes": value.message_metadata_bytes,
        "message_chain_digest": value.message_chain_digest,
        "stderr_bytes": value.stderr_bytes,
    }


def _private_analysis_transcript_summary_payload(
    value: PrivateAnalysisTranscriptSummary,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": value.contract_version,
        "transport": value.transport.value,
        "request_digest": value.request_digest,
        "catalog_digest": value.catalog_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
        "runner_configuration_digest": value.runner_configuration_digest,
        "outcome_digest": value.outcome_digest,
        "evidence_ledger_digest": value.evidence_ledger_digest,
        "budget_state": private_analysis_budget_payload(value.budget_state),
    }
    if type(value.metadata) is PrivateAnalysisInProcessTranscriptSummaryMetadata:
        payload[PrivateAnalysisTransport.IN_PROCESS.value] = (
            _in_process_transcript_summary_metadata_payload(value.metadata)
        )
    elif (
        type(value.metadata) is PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata
    ):
        payload[PrivateAnalysisTransport.LOCAL_SUBPROCESS.value] = (
            _local_subprocess_transcript_summary_metadata_payload(value.metadata)
        )
    else:  # constructor makes this unreachable unless a frozen value was tampered with
        raise TypeError("summary metadata has an unsupported type")
    return payload


def _private_analysis_budget_state_from_payload(
    value: object,
) -> PrivateAnalysisToolBudgetState:
    item = exact_json_object(
        value,
        "private-analysis transcript summary budget state",
        _BUDGET_STATE_FIELDS,
    )
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=_summary_counter(
            item["max_tool_calls"],
            "max_tool_calls",
        ),
        tool_calls_consumed=_summary_counter(
            item["tool_calls_consumed"],
            "tool_calls_consumed",
        ),
        max_evidence_items=_summary_counter(
            item["max_evidence_items"],
            "max_evidence_items",
        ),
        evidence_items_disclosed=_summary_counter(
            item["evidence_items_disclosed"],
            "evidence_items_disclosed",
        ),
        max_evidence_bytes=_summary_counter(
            item["max_evidence_bytes"],
            "max_evidence_bytes",
        ),
        evidence_bytes_disclosed=_summary_counter(
            item["evidence_bytes_disclosed"],
            "evidence_bytes_disclosed",
        ),
    )


def _in_process_transcript_summary_metadata_from_dict(
    value: object,
) -> PrivateAnalysisInProcessTranscriptSummaryMetadata:
    item = exact_json_object(
        value,
        "in-process transcript summary metadata",
        _IN_PROCESS_SUMMARY_METADATA_FIELDS,
    )
    return PrivateAnalysisInProcessTranscriptSummaryMetadata(
        transcript_digest=item["transcript_digest"],
        exchange_count=item["exchange_count"],
        unattributed_tool_call_count=item["unattributed_tool_call_count"],
        exchange_metadata_bytes=item["exchange_metadata_bytes"],
        exchange_chain_digest=item["exchange_chain_digest"],
    )


def _local_subprocess_transcript_summary_metadata_from_dict(
    value: object,
) -> PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata:
    item = exact_json_object(
        value,
        "local-subprocess transcript summary metadata",
        _LOCAL_SUBPROCESS_SUMMARY_METADATA_FIELDS,
    )
    return PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
        transcript_digest=item["transcript_digest"],
        launch_configuration_digest=item["launch_configuration_digest"],
        run_digest=item["run_digest"],
        message_count=item["message_count"],
        tool_call_count=item["tool_call_count"],
        message_metadata_bytes=item["message_metadata_bytes"],
        message_chain_digest=item["message_chain_digest"],
        stderr_bytes=item["stderr_bytes"],
    )


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
    lease: _PrivateAnalysisRunLeaseAccountingView,
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
    "MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES",
    "MAX_PRIVATE_ANALYSIS_SUBPROCESS_TRANSCRIPT_BYTES",
    "MAX_PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_BYTES",
    "PRIVATE_ANALYSIS_TRANSCRIPT_SUMMARY_VERSION",
    "PrivateAnalysisAccountingObserver",
    "PrivateAnalysisCancellationProbe",
    "PrivateAnalysisInProcessTranscriptSummaryMetadata",
    "PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata",
    "PrivateAnalysisRunAccountingSnapshot",
    "PrivateAnalysisRunnerExecutionOwner",
    "PrivateAnalysisTranscriptSummary",
    "PrivateAnalysisTranscriptSummaryMetadata",
    "detached_private_analysis_budget_state",
    "detached_private_analysis_error",
    "detached_private_analysis_transcript_summary",
    "empty_private_analysis_budget_state",
    "private_analysis_budget_payload",
    "private_analysis_deadline_expired",
    "private_analysis_error",
    "private_analysis_error_outcome",
    "private_analysis_execution_receipt_values",
    "private_analysis_prefixed_sha256",
    "private_analysis_run_access_error",
    "private_analysis_transcript_summary_dict",
    "private_analysis_transcript_summary_from_dict",
    "private_analysis_transcript_summary_from_json",
    "private_analysis_transcript_summary_json",
    "validate_private_analysis_result_json",
]
