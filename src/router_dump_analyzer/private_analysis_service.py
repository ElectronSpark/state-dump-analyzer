"""Application facade for durable, local-only private-analysis runs.

The facade accepts only caller-owned intent.  It resolves every authority-
bearing value from the durable catalog, current workspace policy, the exact
configured runner registry, and the core-owned tool catalog before admitting
a run.  It intentionally contains no HTTP, model-provider, plug-in, shell, or
network integration.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, replace
from enum import StrEnum
from typing import Final, cast

from .canonical import validate_prefixed_lowercase_sha256
from .private_analysis import (
    MAX_PRIVATE_ANALYSIS_QUERY_BYTES,
    MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS,
    MAX_PRIVATE_ANALYSIS_REVISIONS,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeRange,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    default_private_analysis_tool_catalog,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_from_json,
    private_analysis_outcome_json,
)
from .private_analysis.evidence import (
    MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
    validate_evidence_identifier,
    validate_evidence_token,
)
from .private_analysis_binding import (
    PrivateAnalysisEvidenceBindingError,
    bind_private_analysis_revision,
)
from .private_analysis_execution import (
    PrivateAnalysisExecutionCoordinator,
    PrivateAnalysisExecutionError,
    PrivateAnalysisExecutionUnavailable,
    PrivateAnalysisRegisteredRunner,
)
from .private_analysis_run_store import (
    PrivateAnalysisRunConflict,
    PrivateAnalysisRunNotFound,
    PrivateAnalysisRunRecord,
    PrivateAnalysisRunState,
    PrivateAnalysisRunStoreError,
    SqlitePrivateAnalysisRunStore,
)
from .private_analysis_runner_support import (
    detached_private_analysis_budget_state,
)
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .session_store import SessionStoreError, SqliteSessionStore

_MAX_LIST_RUNS: Final = 1_000
_MAX_SIGNED_64: Final = (1 << 63) - 1


class PrivateAnalysisLifecycleAction(StrEnum):
    """Closed browser-visible operations implemented by the core API."""

    CREATE = "create"
    LIST = "list"
    GET = "get"
    EXECUTE = "execute"
    CANCEL = "cancel"
    REPORT = "report"


_PRIVATE_ANALYSIS_TASK_KINDS: Final = tuple(
    sorted(PrivateAnalysisTaskKind, key=lambda item: item.value)
)
_PRIVATE_ANALYSIS_RUN_STATES: Final = tuple(PrivateAnalysisRunState)
_PRIVATE_ANALYSIS_LIFECYCLE_ACTIONS: Final = tuple(PrivateAnalysisLifecycleAction)


class PrivateAnalysisServiceErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    POLICY_DENIED = "policy_denied"
    RUNNER_UNAVAILABLE = "runner_unavailable"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"


class PrivateAnalysisServiceError(RuntimeError):
    """Closed, payload-free application error base."""

    code: PrivateAnalysisServiceErrorCode = PrivateAnalysisServiceErrorCode.UNAVAILABLE
    safe_message: str = "Private analysis service is unavailable."

    def __init__(self, *_ignored: object, **_ignored_keywords: object) -> None:
        super().__init__(self.safe_message)


class PrivateAnalysisServiceInvalidRequest(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = (
        PrivateAnalysisServiceErrorCode.INVALID_REQUEST
    )
    safe_message = "Private analysis request is invalid."


class PrivateAnalysisServicePolicyDenied(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = (
        PrivateAnalysisServiceErrorCode.POLICY_DENIED
    )
    safe_message = "Private analysis is not allowed."


class PrivateAnalysisServiceRunnerUnavailable(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = (
        PrivateAnalysisServiceErrorCode.RUNNER_UNAVAILABLE
    )
    safe_message = "Private analysis runner is unavailable."


class PrivateAnalysisServiceNotFound(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = PrivateAnalysisServiceErrorCode.NOT_FOUND
    safe_message = "Private analysis run was not found."


class PrivateAnalysisServiceConflict(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = PrivateAnalysisServiceErrorCode.CONFLICT
    safe_message = "Private analysis run conflicts with durable state."


class PrivateAnalysisServiceReportNotReady(PrivateAnalysisServiceConflict):
    safe_message = "Private analysis report is not ready."


class PrivateAnalysisServiceUnavailable(PrivateAnalysisServiceError):
    code: PrivateAnalysisServiceErrorCode = PrivateAnalysisServiceErrorCode.UNAVAILABLE
    safe_message = "Private analysis service is unavailable."


def _detached_scope(value: object) -> EvidenceScope:
    if type(value) is not EvidenceScope:
        raise TypeError("scope must be EvidenceScope")
    selected = cast(EvidenceScope, value)
    return replace(selected)


def _detached_limits(value: object) -> PrivateAnalysisLimits:
    if type(value) is not PrivateAnalysisLimits:
        raise TypeError("limits must be PrivateAnalysisLimits")
    return replace(cast(PrivateAnalysisLimits, value))


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _bare_digest(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    validate_prefixed_lowercase_sha256(f"sha256:{value}", label)
    return value


def _bounded_query(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS
    ):
        raise ValueError("query must be bounded non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("query must contain Unicode scalar values") from error
    if len(encoded) > MAX_PRIVATE_ANALYSIS_QUERY_BYTES:
        raise ValueError("query exceeds its encoded UTF-8 byte limit")
    return value


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRequestSpec:
    """Caller-owned intent; authority-bearing bindings are deliberately absent."""

    scope: EvidenceScope
    revision_ids: tuple[str, ...]
    runner_id: str
    runner_version: str
    task_kind: PrivateAnalysisTaskKind
    query: str
    clock_mode: PrivateAnalysisClockMode
    selected_time_ns: int | None
    limits: PrivateAnalysisLimits

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", _detached_scope(self.scope))
        if type(self.revision_ids) is not tuple:
            raise TypeError("revision_ids must be a tuple")
        if not 1 <= len(self.revision_ids) <= MAX_PRIVATE_ANALYSIS_REVISIONS:
            raise ValueError("revision_ids must contain 1 to 128 values")
        revisions = tuple(
            validate_evidence_identifier(value, "revision_id")
            for value in self.revision_ids
        )
        if revisions != tuple(sorted(set(revisions))):
            raise ValueError("revision_ids must be unique and in canonical order")
        object.__setattr__(self, "revision_ids", revisions)
        validate_evidence_identifier(self.runner_id, "runner_id")
        validate_evidence_identifier(self.runner_version, "runner_version")
        if any(character.isspace() for character in self.runner_id):
            raise ValueError("runner_id must be an opaque token")
        if any(character.isspace() for character in self.runner_version):
            raise ValueError("runner_version must be an opaque token")
        if type(self.task_kind) is not PrivateAnalysisTaskKind:
            raise TypeError("task_kind must be PrivateAnalysisTaskKind")
        _bounded_query(self.query)
        if type(self.clock_mode) is not PrivateAnalysisClockMode:
            raise TypeError("clock_mode must be PrivateAnalysisClockMode")
        if self.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION:
            if self.selected_time_ns is not None:
                raise ValueError("latest-per-revision clock cannot carry a time")
        else:
            minimum = (
                0
                if self.clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS
                else -(1 << 63)
            )
            _bounded_integer(
                self.selected_time_ns,
                "selected_time_ns",
                minimum=minimum,
                maximum=_MAX_SIGNED_64,
            )
        object.__setattr__(self, "limits", _detached_limits(self.limits))


def _detached_spec(value: object) -> PrivateAnalysisRequestSpec:
    if type(value) is not PrivateAnalysisRequestSpec:
        raise TypeError("spec must be PrivateAnalysisRequestSpec")
    return PrivateAnalysisRequestSpec(
        scope=value.scope,
        revision_ids=value.revision_ids,
        runner_id=value.runner_id,
        runner_version=value.runner_version,
        task_kind=value.task_kind,
        query=value.query,
        clock_mode=value.clock_mode,
        selected_time_ns=value.selected_time_ns,
        limits=value.limits,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeploymentCeilings:
    """Deployment-owned admission ceilings, never caller-overridable."""

    request_limits: PrivateAnalysisLimits = field(default_factory=PrivateAnalysisLimits)
    max_revisions: int = MAX_PRIVATE_ANALYSIS_REVISIONS
    max_list_runs: int = _MAX_LIST_RUNS

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "request_limits",
            _detached_limits(self.request_limits),
        )
        _bounded_integer(
            self.max_revisions,
            "max_revisions",
            minimum=1,
            maximum=MAX_PRIVATE_ANALYSIS_REVISIONS,
        )
        _bounded_integer(
            self.max_list_runs,
            "max_list_runs",
            minimum=1,
            maximum=_MAX_LIST_RUNS,
        )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCapabilities:
    """Scoped, core-owned browser workflow vocabulary and deployment ceilings."""

    scope: EvidenceScope
    enabled: bool
    task_kinds: tuple[PrivateAnalysisTaskKind, ...]
    request_limit_ceilings: PrivateAnalysisLimits
    max_revisions: int
    max_list_runs: int
    transports: tuple[PrivateAnalysisTransport, ...]
    states: tuple[PrivateAnalysisRunState, ...]
    actions: tuple[PrivateAnalysisLifecycleAction, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", _detached_scope(self.scope))
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be a boolean")
        if self.task_kinds != _PRIVATE_ANALYSIS_TASK_KINDS:
            raise ValueError("private-analysis task inventory is not canonical")
        limits = _detached_limits(self.request_limit_ceilings)
        object.__setattr__(self, "request_limit_ceilings", limits)
        _bounded_integer(
            self.max_revisions,
            "max_revisions",
            minimum=1,
            maximum=MAX_PRIVATE_ANALYSIS_REVISIONS,
        )
        _bounded_integer(
            self.max_list_runs,
            "max_list_runs",
            minimum=1,
            maximum=_MAX_LIST_RUNS,
        )
        if type(self.transports) is not tuple or any(
            type(item) is not PrivateAnalysisTransport for item in self.transports
        ):
            raise TypeError("transports must contain PrivateAnalysisTransport values")
        canonical_transports = tuple(
            sorted(set(self.transports), key=lambda item: item.value)
        )
        if self.transports != canonical_transports:
            raise ValueError("private-analysis transport inventory is not canonical")
        if self.enabled is (not self.transports):
            raise ValueError("private-analysis availability and transports disagree")
        if self.states != _PRIVATE_ANALYSIS_RUN_STATES:
            raise ValueError("private-analysis state inventory is not canonical")
        if self.actions != _PRIVATE_ANALYSIS_LIFECYCLE_ACTIONS:
            raise ValueError("private-analysis action inventory is not canonical")


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunView:
    """Payload-free lifecycle and request identity safe for API projection."""

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
    cleanup_pending: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", _detached_scope(self.scope))
        validate_evidence_identifier(self.run_id, "run_id")
        if type(self.state) is not PrivateAnalysisRunState:
            raise TypeError("state must be PrivateAnalysisRunState")
        if type(self.cleanup_pending) is not bool:
            raise TypeError("cleanup_pending must be a boolean")
        if self.cleanup_pending and self.state.is_terminal:
            raise ValueError("terminal run view cannot have pending cleanup")
        _bounded_integer(self.version, "version", minimum=1, maximum=_MAX_SIGNED_64)
        validate_prefixed_lowercase_sha256(self.request_digest, "request_digest")
        if type(self.task_kind) is not PrivateAnalysisTaskKind:
            raise TypeError("task_kind must be PrivateAnalysisTaskKind")
        if type(self.revision_ids) is not tuple or type(self.node_ids) is not tuple:
            raise TypeError("revision_ids and node_ids must be tuples")
        if not 1 <= len(self.revision_ids) <= MAX_PRIVATE_ANALYSIS_REVISIONS:
            raise ValueError("run view must bind 1 to 128 revisions")
        if len(self.revision_ids) != len(self.node_ids):
            raise ValueError("revision_ids and node_ids must have equal lengths")
        revision_pairs = tuple(
            (
                validate_evidence_identifier(node_id, "node_id"),
                validate_evidence_identifier(revision_id, "revision_id"),
            )
            for node_id, revision_id in zip(
                self.node_ids,
                self.revision_ids,
                strict=True,
            )
        )
        if revision_pairs != tuple(sorted(set(revision_pairs))):
            raise ValueError("run view revisions must be unique and canonical")
        if type(self.runner) is not PrivateAnalysisRunnerSelection:
            raise TypeError("runner must be PrivateAnalysisRunnerSelection")
        object.__setattr__(
            self,
            "runner",
            PrivateAnalysisRunnerSelection(
                runner_id=self.runner.runner_id,
                runner_version=self.runner.runner_version,
                transport=self.runner.transport,
                configuration_digest=self.runner.configuration_digest,
            ),
        )
        _bare_digest(self.workspace_policy_digest, "workspace_policy_digest")
        validate_prefixed_lowercase_sha256(
            self.instruction_profile_digest,
            "instruction_profile_digest",
        )
        validate_prefixed_lowercase_sha256(
            self.tool_catalog_digest,
            "tool_catalog_digest",
        )
        validate_prefixed_lowercase_sha256(
            self.evidence_service_digest,
            "evidence_service_digest",
        )
        if type(self.clock_mode) is not PrivateAnalysisClockMode:
            raise TypeError("clock_mode must be PrivateAnalysisClockMode")
        if self.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION:
            if self.selected_time_ns is not None:
                raise ValueError("latest-per-revision clock cannot carry a time")
        else:
            minimum = (
                0
                if self.clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS
                else -(1 << 63)
            )
            _bounded_integer(
                self.selected_time_ns,
                "selected_time_ns",
                minimum=minimum,
                maximum=_MAX_SIGNED_64,
            )
        limits = _detached_limits(self.limits)
        object.__setattr__(self, "limits", limits)
        validate_prefixed_lowercase_sha256(
            self.evidence_ledger_digest,
            "evidence_ledger_digest",
        )
        _bounded_integer(
            self.disclosed_reference_count,
            "disclosed_reference_count",
            minimum=0,
            maximum=limits.max_evidence_items,
        )
        budget = detached_private_analysis_budget_state(self.budget_state)
        if (
            budget.max_tool_calls != limits.max_tool_calls
            or budget.max_evidence_items != limits.max_evidence_items
            or budget.max_evidence_bytes != limits.max_evidence_bytes
            or budget.evidence_items_disclosed != self.disclosed_reference_count
        ):
            raise ValueError("run view budget does not match request limits")
        object.__setattr__(self, "budget_state", budget)
        if self.outcome_digest is not None:
            validate_prefixed_lowercase_sha256(
                self.outcome_digest,
                "outcome_digest",
            )
        if self.state.is_terminal is (self.outcome_digest is None):
            raise ValueError("run view terminal state and outcome digest disagree")
        created = _bounded_integer(
            self.created_at_ns,
            "created_at_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        updated = _bounded_integer(
            self.updated_at_ns,
            "updated_at_ns",
            minimum=created,
            maximum=_MAX_SIGNED_64,
        )
        if self.state.is_terminal:
            completed = _bounded_integer(
                self.completed_at_ns,
                "completed_at_ns",
                minimum=created,
                maximum=_MAX_SIGNED_64,
            )
            if completed != updated:
                raise ValueError("terminal completion and update timestamps disagree")
        elif self.completed_at_ns is not None:
            raise ValueError("nonterminal run view cannot have a completion time")


def _detached_run_view(value: object) -> PrivateAnalysisRunView:
    if type(value) is not PrivateAnalysisRunView:
        raise TypeError("run must be PrivateAnalysisRunView")
    return PrivateAnalysisRunView(
        scope=value.scope,
        run_id=value.run_id,
        state=value.state,
        version=value.version,
        request_digest=value.request_digest,
        task_kind=value.task_kind,
        revision_ids=value.revision_ids,
        node_ids=value.node_ids,
        runner=value.runner,
        workspace_policy_digest=value.workspace_policy_digest,
        instruction_profile_digest=value.instruction_profile_digest,
        tool_catalog_digest=value.tool_catalog_digest,
        evidence_service_digest=value.evidence_service_digest,
        clock_mode=value.clock_mode,
        selected_time_ns=value.selected_time_ns,
        limits=value.limits,
        evidence_ledger_digest=value.evidence_ledger_digest,
        disclosed_reference_count=value.disclosed_reference_count,
        budget_state=value.budget_state,
        outcome_digest=value.outcome_digest,
        created_at_ns=value.created_at_ns,
        updated_at_ns=value.updated_at_ns,
        completed_at_ns=value.completed_at_ns,
        cleanup_pending=value.cleanup_pending,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCitedEvidenceReference:
    """Display-safe metadata for one exact cited disclosed reference."""

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

    def __post_init__(self) -> None:
        validate_prefixed_lowercase_sha256(
            self.reference_digest,
            "reference_digest",
        )
        validate_evidence_identifier(self.revision_id, "revision_id")
        validate_evidence_identifier(self.node_id, "node_id")
        if type(self.producer) is not EvidenceProducer:
            raise TypeError("producer must be EvidenceProducer")
        producer = EvidenceProducer(
            authority=self.producer.authority,
            producer_id=self.producer.producer_id,
            plugin_instance_id=self.producer.plugin_instance_id,
            plugin_capability=self.producer.plugin_capability,
            plugin_role=self.producer.plugin_role,
        )
        object.__setattr__(self, "producer", producer)
        if type(self.kind) is not EvidenceKind:
            raise TypeError("kind must be EvidenceKind")
        validate_evidence_token(
            self.subject_kind,
            "subject_kind",
            maximum=MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
        )
        if type(self.evidence_class) is not PrivateAnalysisEvidenceClass:
            raise TypeError("evidence_class must be PrivateAnalysisEvidenceClass")
        validate_evidence_token(self.payload_schema, "payload_schema")
        if type(self.fact_provenance) is not EvidenceFactProvenance:
            raise TypeError("fact_provenance must be EvidenceFactProvenance")
        if type(self.time_range) is not EvidenceTimeRange:
            raise TypeError("time_range must be EvidenceTimeRange")
        object.__setattr__(
            self,
            "time_range",
            EvidenceTimeRange(
                basis=self.time_range.basis,
                start_ns=self.time_range.start_ns,
                end_ns=self.time_range.end_ns,
                uncertainty_ns=self.time_range.uncertainty_ns,
                clock_domain=self.time_range.clock_domain,
            ),
        )


def _outcome_citation_digests(
    outcome: PrivateAnalysisOutcome,
) -> tuple[str, ...]:
    result = outcome.result
    if result is None:
        return ()
    digests = {
        citation.evidence_reference_digest
        for citation in result.summary.citations
    }
    digests.update(
        citation.evidence_reference_digest
        for claim in result.claims
        for citation in claim.citations
    )
    digests.update(
        citation.evidence_reference_digest
        for proposal in result.proposals
        for citation in proposal.citations
    )
    return tuple(sorted(digests))


def _cited_evidence_references(
    run: PrivateAnalysisRunView,
    outcome: PrivateAnalysisOutcome,
    disclosed_references: object,
) -> tuple[PrivateAnalysisCitedEvidenceReference, ...]:
    if type(disclosed_references) is not tuple:
        raise TypeError("disclosed_references must be a tuple")
    references = tuple(
        evidence_reference_from_dict(evidence_reference_dict(item))
        for item in disclosed_references
    )
    if len(references) > run.limits.max_evidence_items:
        raise ValueError("report evidence exceeds the run limit")
    reference_digests = tuple(item.reference_digest for item in references)
    if reference_digests != tuple(sorted(reference_digests)) or len(
        reference_digests
    ) != len(set(reference_digests)):
        raise ValueError("report evidence ledger must be unique and canonical")
    if (
        len(references) != run.disclosed_reference_count
        or evidence_snapshot_digest(references) != run.evidence_ledger_digest
    ):
        raise ValueError("report evidence ledger does not match its run view")
    revision_pairs = set(zip(run.node_ids, run.revision_ids, strict=True))
    for reference in references:
        if (
            reference.scope != run.scope
            or (reference.revision.node_id, reference.revision.revision_id)
            not in revision_pairs
        ):
            raise ValueError("report evidence does not match the run scope")
    reference_by_digest = {
        reference.reference_digest: reference for reference in references
    }
    cited_digests = _outcome_citation_digests(outcome)
    try:
        selected = tuple(reference_by_digest[digest] for digest in cited_digests)
    except KeyError as error:
        raise ValueError("report outcome cites undisclosed evidence") from error
    projected = tuple(
        PrivateAnalysisCitedEvidenceReference(
            reference_digest=reference.reference_digest,
            revision_id=reference.revision.revision_id,
            node_id=reference.revision.node_id,
            producer=reference.producer,
            kind=reference.kind,
            subject_kind=reference.subject_kind,
            evidence_class=reference.evidence_class,
            payload_schema=reference.payload_schema,
            fact_provenance=reference.fact_provenance,
            time_range=reference.time_range,
        )
        for reference in selected
    )
    if tuple(item.reference_digest for item in projected) != cited_digests:
        raise ValueError("report evidence does not match outcome citations")
    return projected


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunReport:
    """Terminal view plus its exact advisory outcome, without internal state."""

    run: PrivateAnalysisRunView
    query: str
    outcome: PrivateAnalysisOutcome
    disclosed_references: InitVar[tuple[EvidenceReference, ...]] = ()
    evidence_references: tuple[PrivateAnalysisCitedEvidenceReference, ...] = field(
        init=False
    )

    def __post_init__(
        self,
        disclosed_references: tuple[EvidenceReference, ...],
    ) -> None:
        run = _detached_run_view(self.run)
        query = _bounded_query(self.query)
        if not run.state.is_terminal or run.outcome_digest is None:
            raise ValueError("report requires a terminal run view")
        if type(self.outcome) is not PrivateAnalysisOutcome:
            raise TypeError("outcome must be PrivateAnalysisOutcome")
        outcome = private_analysis_outcome_from_json(
            private_analysis_outcome_json(self.outcome)
        )
        if outcome.outcome_digest != run.outcome_digest:
            raise ValueError("report outcome does not match its run view")
        outcome_request_digest = (
            outcome.result.request_digest
            if outcome.result is not None
            else outcome.error.request_digest
            if outcome.error is not None
            else None
        )
        if outcome_request_digest != run.request_digest:
            raise ValueError("report outcome does not match the run request")
        object.__setattr__(self, "run", run)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(
            self,
            "evidence_references",
            _cited_evidence_references(
                run,
                outcome,
                disclosed_references,
            ),
        )


class PrivateAnalysisService:
    """Resolve, admit, execute, and safely project private-analysis runs."""

    def __init__(
        self,
        sessions: SqliteSessionStore,
        runs: SqlitePrivateAnalysisRunStore,
        execution: PrivateAnalysisExecutionCoordinator,
        *,
        ceilings: PrivateAnalysisDeploymentCeilings | None = None,
    ) -> None:
        if type(sessions) is not SqliteSessionStore:
            raise TypeError("sessions must be an exact SqliteSessionStore")
        if type(runs) is not SqlitePrivateAnalysisRunStore:
            raise TypeError("runs must be an exact SqlitePrivateAnalysisRunStore")
        if type(execution) is not PrivateAnalysisExecutionCoordinator:
            raise TypeError(
                "execution must be an exact PrivateAnalysisExecutionCoordinator"
            )
        if not execution.is_bound_to_store(runs):
            raise ValueError("execution coordinator and run store do not match")
        selected_ceilings = ceilings or PrivateAnalysisDeploymentCeilings()
        if type(selected_ceilings) is not PrivateAnalysisDeploymentCeilings:
            raise TypeError(
                "ceilings must be PrivateAnalysisDeploymentCeilings or None"
            )
        selected_ceilings = PrivateAnalysisDeploymentCeilings(
            request_limits=selected_ceilings.request_limits,
            max_revisions=selected_ceilings.max_revisions,
            max_list_runs=selected_ceilings.max_list_runs,
        )
        self._sessions = sessions
        self._runs = runs
        self._execution = execution
        self._ceilings = selected_ceilings
        self._tool_catalog_digest = (
            default_private_analysis_tool_catalog().catalog_digest
        )

    def capabilities(self, scope: EvidenceScope) -> PrivateAnalysisCapabilities:
        """Return only core vocabulary intersected with current workspace policy."""

        try:
            selected_scope = self._resolve_scope(scope)
            policy = self._sessions.get_workspace_disclosure_policy(
                selected_scope.tenant_id,
                selected_scope.workspace_id,
            ).policy
            enabled = policy.mode is not PrivateAnalysisDisclosureMode.DISABLED
            return PrivateAnalysisCapabilities(
                scope=selected_scope,
                enabled=enabled,
                task_kinds=_PRIVATE_ANALYSIS_TASK_KINDS,
                request_limit_ceilings=self._ceilings.request_limits,
                max_revisions=self._ceilings.max_revisions,
                max_list_runs=self._ceilings.max_list_runs,
                transports=policy.transports if enabled else (),
                states=_PRIVATE_ANALYSIS_RUN_STATES,
                actions=_PRIVATE_ANALYSIS_LIFECYCLE_ACTIONS,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except SessionStoreError:
            raise PrivateAnalysisServiceUnavailable() from None

    def list_runners(
        self,
        scope: EvidenceScope,
    ) -> tuple[PrivateAnalysisRegisteredRunner, ...]:
        """List only locally registered runners approved by current policy."""

        try:
            selected_scope = self._resolve_scope(scope)
            policy = self._sessions.get_workspace_disclosure_policy(
                selected_scope.tenant_id,
                selected_scope.workspace_id,
            ).policy
            if policy.mode is PrivateAnalysisDisclosureMode.DISABLED:
                return ()
            return tuple(
                runner
                for runner in self._execution.list_runners()
                if runner.selection.transport in policy.transports
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (SessionStoreError, PrivateAnalysisExecutionError):
            raise PrivateAnalysisServiceUnavailable() from None

    def create(
        self,
        spec: PrivateAnalysisRequestSpec,
        *,
        actor_id: str,
        idempotency_key: str,
        run_id: str | None = None,
    ) -> PrivateAnalysisRunView:
        """Resolve caller intent and admit one exact durable request."""

        try:
            spec = _detached_spec(spec)
            scope = self._resolve_scope(spec.scope)
            policy_record = self._sessions.get_workspace_disclosure_policy(
                scope.tenant_id,
                scope.workspace_id,
            )
            policy = policy_record.policy
            if policy.mode is PrivateAnalysisDisclosureMode.DISABLED:
                raise PrivateAnalysisServicePolicyDenied()
            runner = self._resolve_runner(spec.runner_id, spec.runner_version)
            if runner.selection.transport not in policy.transports:
                raise PrivateAnalysisServicePolicyDenied()
            self._require_within_ceilings(spec)
            bindings = self._resolve_revisions(scope, spec.revision_ids)
            request = PrivateAnalysisRequest(
                scope=scope,
                revisions=bindings,
                runner=runner.selection,
                workspace_policy_digest=policy_record.policy_digest,
                instruction_profile_digest=runner.instruction_profile_digest,
                tool_catalog_digest=self._tool_catalog_digest,
                evidence_service_digest=runner.evidence_service_digest,
                task_kind=spec.task_kind,
                query=spec.query,
                clock_mode=spec.clock_mode,
                selected_time_ns=spec.selected_time_ns,
                limits=spec.limits,
            )
            record = self._runs.create_run(
                request,
                actor_id=actor_id,
                idempotency_key=idempotency_key,
                run_id=run_id,
            )
            return self._view(record)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except PrivateAnalysisRunConflict:
            raise PrivateAnalysisServiceConflict() from None
        except PrivateAnalysisExecutionUnavailable:
            raise PrivateAnalysisServiceRunnerUnavailable() from None
        except (KeyError, PrivateAnalysisRunNotFound):
            raise PrivateAnalysisServiceNotFound() from None
        except PrivateAnalysisEvidenceBindingError:
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (SessionStoreError, PrivateAnalysisRunStoreError):
            raise PrivateAnalysisServiceUnavailable() from None

    def get(self, scope: EvidenceScope, run_id: str) -> PrivateAnalysisRunView:
        try:
            return self._view(self._runs.get_run(self._resolve_scope(scope), run_id))
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisRunNotFound:
            raise PrivateAnalysisServiceNotFound() from None
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (SessionStoreError, PrivateAnalysisRunStoreError):
            raise PrivateAnalysisServiceUnavailable() from None

    def list(
        self,
        scope: EvidenceScope,
        *,
        limit: int = 100,
        after_created_at_ns: int | None = None,
        after_run_id: str | None = None,
    ) -> tuple[PrivateAnalysisRunView, ...]:
        try:
            if type(limit) is not int or not 1 <= limit <= self._ceilings.max_list_runs:
                raise PrivateAnalysisServiceInvalidRequest()
            return tuple(
                self._view(record)
                for record in self._runs.list_runs(
                    self._resolve_scope(scope),
                    limit=limit,
                    after_created_at_ns=after_created_at_ns,
                    after_run_id=after_run_id,
                )
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (SessionStoreError, PrivateAnalysisRunStoreError):
            raise PrivateAnalysisServiceUnavailable() from None

    def execute(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
        execution_id: str | None = None,
    ) -> PrivateAnalysisRunView:
        try:
            selected_scope = self._resolve_scope(scope)
            record = self._runs.get_run(selected_scope, run_id)
            _bounded_integer(
                expected_version,
                "expected_version",
                minimum=1,
                maximum=_MAX_SIGNED_64,
            )
            if record.version != expected_version:
                raise PrivateAnalysisServiceConflict()
            if not record.state.is_terminal:
                current_policy = self._sessions.get_workspace_disclosure_policy(
                    selected_scope.tenant_id,
                    selected_scope.workspace_id,
                ).policy
                if (
                    current_policy.mode is PrivateAnalysisDisclosureMode.DISABLED
                    or record.request.runner.transport not in current_policy.transports
                ):
                    raise PrivateAnalysisServicePolicyDenied()
            return self._view(
                self._execution.execute_run(
                    selected_scope,
                    run_id,
                    expected_version=expected_version,
                    actor_id=actor_id,
                    execution_id=execution_id,
                )
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisRunNotFound:
            raise PrivateAnalysisServiceNotFound() from None
        except PrivateAnalysisRunConflict:
            raise PrivateAnalysisServiceConflict() from None
        except PrivateAnalysisExecutionUnavailable:
            raise PrivateAnalysisServiceRunnerUnavailable() from None
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (
            SessionStoreError,
            PrivateAnalysisRunStoreError,
            PrivateAnalysisExecutionError,
        ):
            raise PrivateAnalysisServiceUnavailable() from None

    def cancel(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
    ) -> PrivateAnalysisRunView:
        try:
            return self._view(
                self._execution.request_cancellation(
                    self._resolve_scope(scope),
                    run_id,
                    expected_version=expected_version,
                    actor_id=actor_id,
                )
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisRunNotFound:
            raise PrivateAnalysisServiceNotFound() from None
        except PrivateAnalysisRunConflict:
            raise PrivateAnalysisServiceConflict() from None
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (
            SessionStoreError,
            PrivateAnalysisRunStoreError,
            PrivateAnalysisExecutionError,
        ):
            raise PrivateAnalysisServiceUnavailable() from None

    def recover_expired(
        self,
        scope: EvidenceScope,
        *,
        actor_id: str,
        limit: int = 100,
    ) -> tuple[PrivateAnalysisRunView, ...]:
        """Terminalize expired attempts in one scope without retrying a model."""

        try:
            selected_scope = self._resolve_scope(scope)
            if type(limit) is not int or not 1 <= limit <= self._ceilings.max_list_runs:
                raise PrivateAnalysisServiceInvalidRequest()
            return tuple(
                self._view(record)
                for record in self._execution.recover_expired_runs(
                    scope=selected_scope,
                    actor_id=actor_id,
                    limit=limit,
                )
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (
            SessionStoreError,
            PrivateAnalysisRunStoreError,
            PrivateAnalysisExecutionError,
        ):
            raise PrivateAnalysisServiceUnavailable() from None

    def get_report(
        self,
        scope: EvidenceScope,
        run_id: str,
    ) -> PrivateAnalysisRunReport:
        try:
            record = self._runs.get_run(self._resolve_scope(scope), run_id)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisRunNotFound:
            raise PrivateAnalysisServiceNotFound() from None
        except PrivateAnalysisServiceError:
            raise
        except KeyError:
            raise PrivateAnalysisServiceNotFound() from None
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceInvalidRequest() from None
        except (SessionStoreError, PrivateAnalysisRunStoreError):
            raise PrivateAnalysisServiceUnavailable() from None
        if not record.state.is_terminal or record.outcome is None:
            raise PrivateAnalysisServiceReportNotReady()
        try:
            return PrivateAnalysisRunReport(
                run=self._view(record),
                query=record.request.query,
                outcome=record.outcome,
                disclosed_references=record.disclosed_references,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except (TypeError, ValueError):
            raise PrivateAnalysisServiceUnavailable() from None

    @staticmethod
    def _view(record: PrivateAnalysisRunRecord) -> PrivateAnalysisRunView:
        if type(record) is not PrivateAnalysisRunRecord:
            raise PrivateAnalysisServiceUnavailable()
        try:
            request = record.request
            return PrivateAnalysisRunView(
                scope=_detached_scope(record.scope),
                run_id=record.run_id,
                state=record.state,
                version=record.version,
                request_digest=record.request_digest,
                task_kind=request.task_kind,
                revision_ids=tuple(item.revision_id for item in request.revisions),
                node_ids=tuple(item.node_id for item in request.revisions),
                runner=PrivateAnalysisRunnerSelection(
                    runner_id=request.runner.runner_id,
                    runner_version=request.runner.runner_version,
                    transport=request.runner.transport,
                    configuration_digest=request.runner.configuration_digest,
                ),
                workspace_policy_digest=request.workspace_policy_digest,
                instruction_profile_digest=request.instruction_profile_digest,
                tool_catalog_digest=request.tool_catalog_digest,
                evidence_service_digest=request.evidence_service_digest,
                clock_mode=request.clock_mode,
                selected_time_ns=request.selected_time_ns,
                limits=_detached_limits(request.limits),
                evidence_ledger_digest=record.evidence_ledger_digest,
                disclosed_reference_count=len(record.disclosed_references),
                budget_state=detached_private_analysis_budget_state(
                    record.budget_state
                ),
                outcome_digest=(
                    None if record.outcome is None else record.outcome.outcome_digest
                ),
                created_at_ns=record.created_at_ns,
                updated_at_ns=record.updated_at_ns,
                completed_at_ns=record.completed_at_ns,
                cleanup_pending=record.cleanup_pending,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceError:
            raise
        except (TypeError, ValueError, AttributeError):
            raise PrivateAnalysisServiceUnavailable() from None

    def _resolve_scope(self, scope: object) -> EvidenceScope:
        selected = _detached_scope(scope)
        workspace = self._sessions.get_workspace(
            selected.tenant_id,
            selected.workspace_id,
        )
        if workspace.project_id != selected.project_id:
            raise PrivateAnalysisServiceInvalidRequest()
        return EvidenceScope(
            tenant_id=workspace.tenant_id,
            project_id=workspace.project_id,
            workspace_id=workspace.workspace_id,
        )

    def _resolve_runner(
        self,
        runner_id: str,
        runner_version: str,
    ) -> PrivateAnalysisRegisteredRunner:
        try:
            return self._execution.resolve_runner(runner_id, runner_version)
        except PrivateAnalysisExecutionUnavailable:
            raise PrivateAnalysisServiceRunnerUnavailable() from None

    def _resolve_revisions(
        self,
        scope: EvidenceScope,
        revision_ids: tuple[str, ...],
    ) -> tuple[EvidenceRevisionBinding, ...]:
        workspace = self._sessions.get_workspace(
            scope.tenant_id,
            scope.workspace_id,
        )
        bindings: list[EvidenceRevisionBinding] = []
        for revision_id in revision_ids:
            revision = self._sessions.get_revision(scope.tenant_id, revision_id)
            if revision.workspace_id != scope.workspace_id:
                raise PrivateAnalysisServiceNotFound()
            fixture = self._sessions.get_fixture(
                scope.tenant_id,
                revision.fixture_id,
            )
            expected_scope, binding = bind_private_analysis_revision(
                workspace,
                fixture,
                revision,
            )
            if expected_scope != scope:
                raise PrivateAnalysisServiceInvalidRequest()
            bindings.append(binding)
        return tuple(
            sorted(
                bindings,
                key=lambda item: (
                    item.node_id,
                    item.revision_id,
                    item.fixture_id,
                    item.revision_identity_sha256,
                ),
            )
        )

    def _require_within_ceilings(self, spec: PrivateAnalysisRequestSpec) -> None:
        if len(spec.revision_ids) > self._ceilings.max_revisions:
            raise PrivateAnalysisServiceInvalidRequest()
        requested = spec.limits
        ceiling = self._ceilings.request_limits
        if any(
            requested_value > ceiling_value
            for requested_value, ceiling_value in (
                (requested.max_evidence_items, ceiling.max_evidence_items),
                (requested.max_evidence_bytes, ceiling.max_evidence_bytes),
                (requested.max_tool_calls, ceiling.max_tool_calls),
                (requested.max_output_bytes, ceiling.max_output_bytes),
                (requested.max_claims, ceiling.max_claims),
                (requested.max_proposals, ceiling.max_proposals),
                (requested.deadline_ms, ceiling.deadline_ms),
            )
        ):
            raise PrivateAnalysisServiceInvalidRequest()


__all__ = [
    "PrivateAnalysisCapabilities",
    "PrivateAnalysisCitedEvidenceReference",
    "PrivateAnalysisDeploymentCeilings",
    "PrivateAnalysisLifecycleAction",
    "PrivateAnalysisRequestSpec",
    "PrivateAnalysisRunReport",
    "PrivateAnalysisRunView",
    "PrivateAnalysisService",
    "PrivateAnalysisServiceConflict",
    "PrivateAnalysisServiceError",
    "PrivateAnalysisServiceErrorCode",
    "PrivateAnalysisServiceInvalidRequest",
    "PrivateAnalysisServiceNotFound",
    "PrivateAnalysisServicePolicyDenied",
    "PrivateAnalysisServiceReportNotReady",
    "PrivateAnalysisServiceRunnerUnavailable",
    "PrivateAnalysisServiceUnavailable",
]
