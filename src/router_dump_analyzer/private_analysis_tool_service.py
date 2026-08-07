"""Trusted, read-only execution service for private-analysis evidence tools.

The adjacent :mod:`tool_catalog` module remains an inert wire contract.  This
module is the narrow trusted adapter that binds those calls to deployment-
supplied authorization, policy, reference, and payload resolvers.  It owns no
filesystem, database, network, shell, plug-in, mutation, or model authority.

Every call is re-authorized and evaluated against the current workspace
policy.  References cross the boundary only after exact request scope,
revision, disclosure, and cumulative request-budget checks.  Callback
diagnostics never enter a returned error.
"""

# ruff: noqa: BLE001

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Any, Final

from .canonical import strict_canonical_json
from .private_analysis.contracts import (
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisRequest,
    private_analysis_request_from_json,
    private_analysis_request_json,
)
from .private_analysis.disclosure import (
    DisclosureDecision,
    PrivateAnalysisEvidenceClass,
    WorkspaceDisclosurePolicy,
    disclosure_scope_digest,
    evaluate_workspace_disclosure,
)
from .private_analysis.evidence import (
    EvidenceEnvelope,
    EvidenceReference,
    EvidenceScope,
    EvidenceTimeBasis,
    evidence_envelope_from_json,
    evidence_envelope_json,
    evidence_reference_dict,
    evidence_reference_from_dict,
    make_evidence_envelope,
)
from .private_analysis.policy import PrivateAnalysisPolicy
from .private_analysis.query_cancellation import (
    PrivateAnalysisEvidenceQueryCancellationProbeError,
    PrivateAnalysisEvidenceQueryCancelledError,
    check_private_analysis_evidence_query_cancellation,
)
from .private_analysis.tool_catalog import (
    MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES,
    PrivateAnalysisCapabilityArguments,
    PrivateAnalysisEvidenceCursorInvalidError,
    PrivateAnalysisEvidenceQueryPage,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolName,
    PrivateAnalysisToolResult,
    PrivateAnalysisToolResultKind,
    default_private_analysis_tool_catalog,
    make_private_analysis_query_page,
    make_private_analysis_query_page_from_snapshot,
    private_analysis_tool_call_dict,
    private_analysis_tool_call_from_dict,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS


class PrivateAnalysisAuthorizationReason(StrEnum):
    """Closed, payload-free reasons returned by a trusted authorizer."""

    ALLOWED = "allowed"
    TENANT_DENIED = "tenant_denied"
    PROJECT_DENIED = "project_denied"
    WORKSPACE_DENIED = "workspace_denied"
    PERMISSION_DENIED = "permission_denied"


@dataclass(frozen=True, slots=True)
class PrivateAnalysisAuthorizationDecision:
    """One ephemeral authorization result bound to an exact request and scope."""

    request_digest: str
    scope_digest: str
    allowed: bool
    reason: PrivateAnalysisAuthorizationReason

    def __post_init__(self) -> None:
        _sha256(self.request_digest, "request_digest", prefixed=True)
        _sha256(self.scope_digest, "scope_digest", prefixed=False)
        if type(self.allowed) is not bool:
            raise TypeError("allowed must be a boolean")
        if type(self.reason) is not PrivateAnalysisAuthorizationReason:
            raise TypeError("reason must be PrivateAnalysisAuthorizationReason")
        if self.allowed is not (
            self.reason is PrivateAnalysisAuthorizationReason.ALLOWED
        ):
            raise ValueError("authorization reason and allowed flag disagree")

    @classmethod
    def allow(
        cls,
        request: PrivateAnalysisRequest,
    ) -> PrivateAnalysisAuthorizationDecision:
        request = _detached_request(request)
        return cls(
            request_digest=request.request_digest,
            scope_digest=_scope_digest(request.scope),
            allowed=True,
            reason=PrivateAnalysisAuthorizationReason.ALLOWED,
        )

    @classmethod
    def deny(
        cls,
        request: PrivateAnalysisRequest,
        reason: PrivateAnalysisAuthorizationReason,
    ) -> PrivateAnalysisAuthorizationDecision:
        request = _detached_request(request)
        if type(reason) is not PrivateAnalysisAuthorizationReason:
            raise TypeError("reason must be PrivateAnalysisAuthorizationReason")
        if reason is PrivateAnalysisAuthorizationReason.ALLOWED:
            raise ValueError("a denial requires a denial reason")
        return cls(
            request_digest=request.request_digest,
            scope_digest=_scope_digest(request.scope),
            allowed=False,
            reason=reason,
        )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolBudgetState:
    """Detached counters for one ephemeral request-bound tool service."""

    max_tool_calls: int
    tool_calls_consumed: int
    max_evidence_items: int
    evidence_items_disclosed: int
    max_evidence_bytes: int
    evidence_bytes_disclosed: int

    def __post_init__(self) -> None:
        _bounded_counter(
            self.max_tool_calls,
            self.tool_calls_consumed,
            "tool_calls",
        )
        _bounded_counter(
            self.max_evidence_items,
            self.evidence_items_disclosed,
            "evidence_items",
        )
        _bounded_counter(
            self.max_evidence_bytes,
            self.evidence_bytes_disclosed,
            "evidence_bytes",
        )

    @property
    def remaining_tool_calls(self) -> int:
        return self.max_tool_calls - self.tool_calls_consumed

    @property
    def remaining_evidence_items(self) -> int:
        return self.max_evidence_items - self.evidence_items_disclosed

    @property
    def remaining_evidence_bytes(self) -> int:
        return self.max_evidence_bytes - self.evidence_bytes_disclosed


@dataclass(frozen=True, slots=True)
class PrivateAnalysisWorkspacePolicySnapshot:
    """Current policy content bound to the exact resolved workspace scope."""

    scope: EvidenceScope
    policy_version: int
    policy: WorkspaceDisclosurePolicy
    policy_digest: str

    def __post_init__(self) -> None:
        scope = _detached_scope(self.scope)
        if (
            type(self.policy_version) is not int
            or not 0 <= self.policy_version < 1 << 63
        ):
            raise ValueError(
                "policy_version must be a non-negative signed 64-bit integer"
            )
        if type(self.policy) is not WorkspaceDisclosurePolicy:
            raise TypeError("policy must be WorkspaceDisclosurePolicy")
        policy = WorkspaceDisclosurePolicy(
            mode=self.policy.mode,
            transports=self.policy.transports,
        )
        _sha256(self.policy_digest, "policy_digest", prefixed=False)
        if self.policy_digest != policy.digest:
            raise ValueError("policy_digest does not match policy")
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "policy", policy)


class PrivateAnalysisToolServiceError(RuntimeError):
    """A payload-free admission failure outside valid tool-error vocabulary."""

    __slots__ = ("_error",)

    def __init__(self, error: PrivateAnalysisError) -> None:
        if type(error) is not PrivateAnalysisError:
            raise TypeError("error must be PrivateAnalysisError")
        self._error = _detached_analysis_error(error)
        super().__init__(self._error.safe_message)

    @property
    def error(self) -> PrivateAnalysisError:
        return _detached_analysis_error(self._error)


PrivateAnalysisAuthorizer = Callable[
    [PrivateAnalysisRequest],
    PrivateAnalysisAuthorizationDecision,
]
PrivateAnalysisPolicyResolver = Callable[
    [EvidenceScope],
    PrivateAnalysisWorkspacePolicySnapshot,
]
PrivateAnalysisReferenceQuery = Callable[
    [PrivateAnalysisRequest, PrivateAnalysisQueryArguments],
    tuple[EvidenceReference, ...],
]
PrivateAnalysisReferencePageQuery = Callable[
    [
        PrivateAnalysisRequest,
        PrivateAnalysisQueryArguments,
        tuple[PrivateAnalysisEvidenceClass, ...],
        Callable[[], bool] | None,
    ],
    PrivateAnalysisEvidenceQueryPage,
]
PrivateAnalysisReferenceResolver = Callable[
    [PrivateAnalysisRequest, str],
    EvidenceReference | None,
]
PrivateAnalysisPayloadMaterializer = Callable[[EvidenceReference], dict[str, Any]]
PrivateAnalysisReferenceValidator = Callable[[EvidenceReference], bool]
PrivateAnalysisReferenceBatchValidator = Callable[[tuple[EvidenceReference, ...]], bool]
PrivateAnalysisCapabilityAnalyzer = Callable[
    [
        PrivateAnalysisRequest,
        PrivateAnalysisCapabilityArguments,
        tuple[EvidenceEnvelope, ...],
        Callable[[], bool] | None,
    ],
    tuple[EvidenceReference, dict[str, Any]],
]


_CALLBACK_COUNT: Final = 5


class PrivateAnalysisToolService:
    """Execute the closed evidence tools for one exact private-analysis request.

    The trusted deployment adapters have intentionally narrow authority and
    are never serialized or exposed to a runner. Deployments select exactly
    one legacy complete-snapshot query or bounded page-query mode; page mode
    may also supply batch binding validation. The cursor binds the immutable
    candidate snapshot, so continuation never requires reconstructing or
    revalidating the complete candidate set.
    """

    __slots__ = (
        "_active_executions",
        "_analyze_evidence",
        "_authorize",
        "_call_ids",
        "_cancellation_probe",
        "_direct_use_claimed",
        "_evidence_bytes_disclosed",
        "_ledger",
        "_lock",
        "_materialize_payload",
        "_materialized_envelopes",
        "_query_reference_pages",
        "_query_references",
        "_request_json",
        "_resolve_policy",
        "_resolve_reference",
        "_runner_full_fidelity",
        "_runner_lease",
        "_runner_lease_claimed",
        "_runner_lease_open",
        "_runner_transport",
        "_tool_calls_consumed",
        "_validate_reference",
        "_validate_references",
    )

    def __init__(
        self,
        request: PrivateAnalysisRequest,
        *,
        runner_policy: PrivateAnalysisPolicy,
        authorize: PrivateAnalysisAuthorizer,
        resolve_policy: PrivateAnalysisPolicyResolver,
        query_references: PrivateAnalysisReferenceQuery | None,
        resolve_reference: PrivateAnalysisReferenceResolver,
        validate_reference: PrivateAnalysisReferenceValidator,
        materialize_payload: PrivateAnalysisPayloadMaterializer,
        query_reference_pages: PrivateAnalysisReferencePageQuery | None = None,
        validate_references: PrivateAnalysisReferenceBatchValidator | None = None,
        analyze_evidence: PrivateAnalysisCapabilityAnalyzer | None = None,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> None:
        detached_request: PrivateAnalysisRequest | None = None
        detached_runner_policy: PrivateAnalysisPolicy | None = None
        try:
            detached_request = _detached_request(request)
            detached_runner_policy = _detached_runner_policy(runner_policy)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            # Leave the handler before raising so hostile diagnostics are not
            # retained in ``PrivateAnalysisToolServiceError.__context__``.
            detached_request = None
            detached_runner_policy = None
        if detached_request is None or detached_runner_policy is None:
            raise _service_error(
                None,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        expected_catalog = default_private_analysis_tool_catalog()
        if detached_request.tool_catalog_digest != expected_catalog.catalog_digest:
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        if detached_runner_policy.transport is not detached_request.runner.transport:
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        callbacks = (
            authorize,
            resolve_policy,
            resolve_reference,
            validate_reference,
            materialize_payload,
        )
        if len(callbacks) != _CALLBACK_COUNT or any(
            not callable(callback) for callback in callbacks
        ):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        if (query_references is None) == (query_reference_pages is None):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        selected_query = (
            query_reference_pages
            if query_reference_pages is not None
            else query_references
        )
        if not callable(selected_query):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        if validate_references is not None and not callable(validate_references):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        if analyze_evidence is not None and not callable(analyze_evidence):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise _service_error(
                detached_request,
                PrivateAnalysisErrorStage.REQUEST_VALIDATION,
                PrivateAnalysisErrorCode.INVALID_REQUEST,
            )
        self._request_json = private_analysis_request_json(detached_request)
        self._runner_transport = detached_runner_policy.transport
        self._runner_full_fidelity = detached_runner_policy.full_fidelity_workspace_data
        self._authorize = authorize
        self._resolve_policy = resolve_policy
        self._query_references = query_references
        self._query_reference_pages = query_reference_pages
        self._resolve_reference = resolve_reference
        self._validate_reference = validate_reference
        self._validate_references = validate_references
        self._analyze_evidence = analyze_evidence
        self._cancellation_probe = cancellation_probe
        self._materialize_payload = materialize_payload
        self._lock = Lock()
        self._tool_calls_consumed = 0
        self._evidence_bytes_disclosed = 0
        self._ledger: dict[str, EvidenceReference] = {}
        self._materialized_envelopes: dict[str, EvidenceEnvelope] = {}
        self._call_ids: set[str] = set()
        self._active_executions = 0
        self._direct_use_claimed = False
        self._runner_lease: object | None = None
        self._runner_lease_claimed = False
        self._runner_lease_open = False

    @property
    def request(self) -> PrivateAnalysisRequest:
        """Return a fresh detached request value."""

        return private_analysis_request_from_json(self._request_json)

    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState:
        """Return counters without exposing the mutable synchronization state."""

        request = self.request
        with self._lock:
            return PrivateAnalysisToolBudgetState(
                max_tool_calls=request.limits.max_tool_calls,
                tool_calls_consumed=self._tool_calls_consumed,
                max_evidence_items=request.limits.max_evidence_items,
                evidence_items_disclosed=len(self._ledger),
                max_evidence_bytes=request.limits.max_evidence_bytes,
                evidence_bytes_disclosed=self._evidence_bytes_disclosed,
            )

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]:
        """Return the detached, canonical unique citation ledger."""

        with self._lock:
            references = tuple(self._ledger[digest] for digest in sorted(self._ledger))
        return tuple(_detached_reference(reference) for reference in references)

    @property
    def runner_lease_eligible(self) -> bool:
        """Return whether this service can still be claimed by one runner.

        The value includes permanent zero-tool lifetime latches that are not
        visible in the public ledger or budget counters.  Deployment-owned
        factories hand a service to the coordinator and must not use it again;
        the runner's atomic lease acquisition remains the final authority.
        """

        with self._lock:
            return self._runner_lease_eligible_locked()

    def execute(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        """Execute one well-bound call without leaking callback diagnostics."""

        request = self.request
        self._enter_execution(request, None)
        try:
            return self._execute_admitted(request, call)
        finally:
            self._leave_execution()

    def acquire_run_lease(self) -> PrivateAnalysisToolRunLease:
        """Claim one pristine service for an exclusive private-runner execution.

        A service can back either direct tool calls or one runner execution,
        never both.  The permanent claim prevents a zero-tool run from being
        silently reused with a different model session after finalization.
        """

        request = self.request
        token = object()
        with self._lock:
            pristine = self._runner_lease_eligible_locked()
            if pristine:
                self._runner_lease_claimed = True
                self._runner_lease_open = True
                self._runner_lease = token
        if not pristine:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        return PrivateAnalysisToolRunLease(self, token)

    def _runner_lease_eligible_locked(self) -> bool:
        return (
            self._active_executions == 0
            and not self._direct_use_claimed
            and not self._runner_lease_claimed
            and self._tool_calls_consumed == 0
            and self._evidence_bytes_disclosed == 0
            and not self._call_ids
            and not self._ledger
            and not self._materialized_envelopes
        )

    def _execute_for_lease(
        self,
        lease_token: object,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        request = self.request
        self._enter_execution(request, lease_token)
        try:
            return self._execute_admitted(request, call)
        finally:
            self._leave_execution()

    def _execute_admitted(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        detached_call = self._validated_call(request, call)
        preflight = self._preflight_call_state(request, detached_call)
        if preflight == "duplicate":
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        if preflight == "budget":
            return _tool_error(
                detached_call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        self._require_authorization(request)
        reservation = self._reserve_tool_call(request, detached_call)
        if reservation == "duplicate":
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        if reservation == "budget":
            return _tool_error(
                detached_call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        policy = self._current_policy(request)
        if policy is None:
            return _tool_error(
                detached_call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if detached_call.binding.name is PrivateAnalysisToolName.QUERY_EVIDENCE:
            return self._execute_query(request, detached_call, policy)
        if detached_call.binding.name is PrivateAnalysisToolName.READ_EVIDENCE:
            return self._execute_read(request, detached_call, policy)
        return self._execute_analyze(request, detached_call, policy)

    def _require_run_access_for_lease(self, lease_token: object) -> None:
        """Re-authorize one leased run without charging evidence budgets."""

        request = self.request
        self._enter_execution(request, lease_token)
        try:
            self._require_authorization(request)
            if self._current_policy(request) is None:
                raise _service_error(
                    request,
                    PrivateAnalysisErrorStage.DISCLOSURE,
                    PrivateAnalysisErrorCode.POLICY_DENIED,
                )
        finally:
            self._leave_execution()

    def _enter_execution(
        self,
        request: PrivateAnalysisRequest,
        lease_token: object | None,
    ) -> None:
        admitted = False
        with self._lock:
            if self._runner_lease_claimed:
                admitted = (
                    self._runner_lease_open
                    and lease_token is not None
                    and lease_token is self._runner_lease
                )
            else:
                admitted = lease_token is None
                if admitted:
                    self._direct_use_claimed = True
            if admitted:
                self._active_executions += 1
        if not admitted:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )

    def _leave_execution(self) -> None:
        with self._lock:
            if self._active_executions <= 0:
                raise RuntimeError("private-analysis execution accounting failed")
            self._active_executions -= 1

    def _release_run_lease(self, lease_token: object) -> None:
        request = self.request
        released = False
        with self._lock:
            if (
                self._runner_lease_open
                and lease_token is self._runner_lease
                and self._active_executions == 0
            ):
                self._runner_lease_open = False
                self._runner_lease = None
                released = True
        if not released:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )

    def _validated_call(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolCall:
        detached: PrivateAnalysisToolCall | None = None
        try:
            if type(call) is not PrivateAnalysisToolCall:
                raise TypeError("call must be PrivateAnalysisToolCall")
            detached = private_analysis_tool_call_from_dict(
                private_analysis_tool_call_dict(call)
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            # Do not retain a hostile/tampered call failure as exception context.
            detached = None
        if detached is None:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        if (
            detached.binding.request_digest != request.request_digest
            or detached.binding.tool_catalog_digest != request.tool_catalog_digest
        ):
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        return detached

    def _preflight_call_state(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
    ) -> str:
        with self._lock:
            if call.call_id in self._call_ids:
                return "duplicate"
            if self._tool_calls_consumed >= request.limits.max_tool_calls:
                return "budget"
            return "available"

    def _reserve_tool_call(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
    ) -> str:
        with self._lock:
            if call.call_id in self._call_ids:
                return "duplicate"
            if self._tool_calls_consumed >= request.limits.max_tool_calls:
                return "budget"
            self._call_ids.add(call.call_id)
            self._tool_calls_consumed += 1
            return "reserved"

    def _require_authorization(self, request: PrivateAnalysisRequest) -> None:
        decision: PrivateAnalysisAuthorizationDecision | None = None
        try:
            raw = self._authorize(_detached_request(request))
            if type(raw) is not PrivateAnalysisAuthorizationDecision:
                raise TypeError("authorizer returned an invalid decision")
            decision = PrivateAnalysisAuthorizationDecision(
                request_digest=raw.request_digest,
                scope_digest=raw.scope_digest,
                allowed=raw.allowed,
                reason=raw.reason,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            # Raising after the handler prevents callback exception retention.
            decision = None
        if decision is None:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.AUTHORIZATION,
                PrivateAnalysisErrorCode.POLICY_DENIED,
            )
        if (
            not decision.allowed
            or decision.request_digest != request.request_digest
            or decision.scope_digest != _scope_digest(request.scope)
        ):
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.AUTHORIZATION,
                PrivateAnalysisErrorCode.POLICY_DENIED,
            )

    def _current_policy(
        self,
        request: PrivateAnalysisRequest,
    ) -> WorkspaceDisclosurePolicy | None:
        try:
            raw = self._resolve_policy(_detached_scope(request.scope))
            snapshot = _detached_policy_snapshot(raw)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return None
        if snapshot.scope != request.scope:
            return None
        if snapshot.policy_digest != request.workspace_policy_digest:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.DISCLOSURE,
                PrivateAnalysisErrorCode.POLICY_DENIED,
            )
        policy = snapshot.policy
        public_decision = self._disclosure_decision(
            request,
            policy,
            PrivateAnalysisEvidenceClass.PUBLIC_METADATA,
        )
        if not public_decision.allowed:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.DISCLOSURE,
                PrivateAnalysisErrorCode.POLICY_DENIED,
            )
        return policy

    def _disclosure_decision(
        self,
        request: PrivateAnalysisRequest,
        policy: WorkspaceDisclosurePolicy,
        evidence_class: PrivateAnalysisEvidenceClass,
    ) -> DisclosureDecision:
        return evaluate_workspace_disclosure(
            policy,
            tenant_id=request.scope.tenant_id,
            project_id=request.scope.project_id,
            workspace_id=request.scope.workspace_id,
            runner_policy=PrivateAnalysisPolicy(
                transport=self._runner_transport,
                full_fidelity_workspace_data=self._runner_full_fidelity,
            ),
            evidence_class=evidence_class,
        )

    def _execute_query(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
        policy: WorkspaceDisclosurePolicy,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        arguments = call.arguments
        if type(arguments) is not PrivateAnalysisQueryArguments:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        try:
            callback_arguments = private_analysis_tool_call_from_dict(
                private_analysis_tool_call_dict(call)
            ).arguments
            if type(callback_arguments) is not PrivateAnalysisQueryArguments:
                raise TypeError("detached query call has invalid arguments")
            evidence_classes = tuple(
                evidence_class
                for evidence_class in PrivateAnalysisEvidenceClass
                if self._disclosure_decision(
                    request,
                    policy,
                    evidence_class,
                ).allowed
            )
            if self._query_reference_pages is not None:
                check_private_analysis_evidence_query_cancellation(
                    self._cancellation_probe
                )
                raw = self._query_reference_pages(
                    _detached_request(request),
                    callback_arguments,
                    evidence_classes,
                    self._cancellation_probe,
                )
                check_private_analysis_evidence_query_cancellation(
                    self._cancellation_probe
                )
                query_page = self._validated_query_page(request, arguments, raw)
            else:
                assert self._query_references is not None
                raw = self._query_references(
                    _detached_request(request),
                    callback_arguments,
                )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisEvidenceCursorInvalidError:
            code = (
                PrivateAnalysisToolErrorCode.CURSOR_INVALID
                if arguments.cursor is not None
                else PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE
            )
            return _tool_error(call, code)
        except (
            PrivateAnalysisEvidenceQueryCancelledError,
            PrivateAnalysisEvidenceQueryCancellationProbeError,
        ):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if self._query_reference_pages is None:
            if type(raw) is not tuple:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
            return self._execute_legacy_query_snapshot(
                request,
                call,
                policy,
                raw,
            )
        if query_page is None:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            for reference in query_page.references:
                if not _reference_matches_query(reference, arguments):
                    raise ValueError("query callback returned an out-of-filter item")
                decision = self._disclosure_decision(
                    request,
                    policy,
                    reference.evidence_class,
                )
                if not decision.allowed:
                    raise ValueError("query callback returned ineligible evidence")
            result = make_private_analysis_query_page_from_snapshot(
                call,
                query_page.references,
                snapshot_digest=query_page.snapshot_digest,
                has_more=query_page.has_more,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if not self._readmit_before_release(request, result.references):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            transferred_bytes = sum(
                len(
                    strict_canonical_json(evidence_reference_dict(reference)).encode(
                        "utf-8"
                    )
                )
                for reference in result.references
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if not self._commit_disclosure(
            request,
            result.references,
            transferred_bytes,
        ):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        return result

    def _execute_legacy_query_snapshot(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
        policy: WorkspaceDisclosurePolicy,
        raw: tuple[EvidenceReference, ...],
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        """Contain legacy complete-snapshot adapters during the v2 transition."""

        references = self._validated_legacy_query_references(request, raw)
        if references is None:
            return _tool_error(call, PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE)
        try:
            eligible = tuple(
                reference
                for reference in references
                if _reference_matches_query(reference, call.arguments)
                and self._disclosure_decision(
                    request, policy, reference.evidence_class
                ).allowed
            )
            result = make_private_analysis_query_page(call, eligible)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            code = (
                PrivateAnalysisToolErrorCode.CURSOR_INVALID
                if call.arguments.cursor is not None
                else PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE
            )
            return _tool_error(call, code)
        if not self._readmit_before_release(request, result.references):
            return _tool_error(call, PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE)
        try:
            transferred_bytes = sum(
                len(
                    strict_canonical_json(evidence_reference_dict(reference)).encode(
                        "utf-8"
                    )
                )
                for reference in result.references
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(call, PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE)
        if not self._commit_disclosure(request, result.references, transferred_bytes):
            return _tool_error(call, PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED)
        return result

    def _execute_read(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
        policy: WorkspaceDisclosurePolicy,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        arguments = call.arguments
        if type(arguments) is not PrivateAnalysisReadArguments:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        with self._lock:
            overlay_envelope = self._materialized_envelopes.get(
                arguments.evidence_reference_digest
            )
        if overlay_envelope is None:
            try:
                raw_reference = self._resolve_reference(
                    _detached_request(request),
                    arguments.evidence_reference_digest,
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
            if raw_reference is None:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
                )
            try:
                reference = _detached_reference(raw_reference)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
        else:
            try:
                overlay_envelope = _detached_envelope(overlay_envelope)
                reference = overlay_envelope.reference
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
        if reference.reference_digest != arguments.evidence_reference_digest:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        membership = _reference_membership(reference, request)
        if membership == "foreign":
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
            )
        if membership == "conflict":
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if not self._reference_binding_is_valid(reference):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            decision = self._disclosure_decision(
                request,
                policy,
                reference.evidence_class,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if not decision.allowed:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
            )
        if not self._can_disclose_reference(request, reference):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        try:
            payload = (
                overlay_envelope.payload
                if overlay_envelope is not None
                else self._materialize_payload(_detached_reference(reference))
            )
            if type(payload) is not dict:
                raise TypeError("payload materializer returned an invalid payload")
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        final_policy = self._readmit_policy_before_release(request)
        if final_policy is None:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            decision = self._disclosure_decision(
                request,
                final_policy,
                reference.evidence_class,
            )
            if not decision.allowed:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
                )
            envelope = make_evidence_envelope(reference, decision, payload)
            result = PrivateAnalysisToolResult(
                call=call,
                kind=PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE,
                envelope=envelope,
            )
            transferred_bytes = len(evidence_envelope_json(envelope).encode("utf-8"))
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        if not self._commit_disclosure(
            request,
            (reference,),
            transferred_bytes,
            envelopes=(envelope,),
        ):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        return result

    def _execute_analyze(
        self,
        request: PrivateAnalysisRequest,
        call: PrivateAnalysisToolCall,
        policy: WorkspaceDisclosurePolicy,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        arguments = call.arguments
        if type(arguments) is not PrivateAnalysisCapabilityArguments:
            raise _service_error(
                request,
                PrivateAnalysisErrorStage.RUNNER,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        if self._analyze_evidence is None:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        targets = tuple(
            revision
            for revision in request.revisions
            if revision.node_id == arguments.node_id
            and revision.revision_id == arguments.revision_id
        )
        if len(targets) != 1:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        with self._lock:
            raw_parents = tuple(
                self._materialized_envelopes.get(digest)
                for digest in arguments.parent_reference_digests
            )
        if any(parent is None for parent in raw_parents):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
            )
        try:
            parents = tuple(
                _detached_envelope(parent)
                for parent in raw_parents
                if parent is not None
            )
            parent_references = tuple(parent.reference for parent in parents)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        if not self._readmit_before_release(request, parent_references):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            callback_arguments = private_analysis_tool_call_from_dict(
                private_analysis_tool_call_dict(call)
            ).arguments
            if type(callback_arguments) is not PrivateAnalysisCapabilityArguments:
                raise TypeError("detached analysis call has invalid arguments")
            check_private_analysis_evidence_query_cancellation(
                self._cancellation_probe
            )
            raw = self._analyze_evidence(
                _detached_request(request),
                callback_arguments,
                parents,
                self._cancellation_probe,
            )
            check_private_analysis_evidence_query_cancellation(
                self._cancellation_probe
            )
            if type(raw) is not tuple or len(raw) != 2:
                raise TypeError("analysis callback returned an invalid result")
            reference = _detached_reference(raw[0])
            payload = raw[1]
            if type(payload) is not dict:
                raise TypeError("analysis callback returned an invalid payload")
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        if (
            _reference_membership(reference, request) != "member"
            or reference.revision != targets[0]
            or not self._reference_binding_is_valid(reference)
        ):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        evidence_rank = {
            PrivateAnalysisEvidenceClass.PUBLIC_METADATA: 0,
            PrivateAnalysisEvidenceClass.CLIENT_SAFE: 1,
            PrivateAnalysisEvidenceClass.PROPRIETARY: 2,
            PrivateAnalysisEvidenceClass.NEVER_ASSISTANT: 3,
        }
        strongest_parent = max(
            (parent.reference.evidence_class for parent in parents),
            key=evidence_rank.__getitem__,
        )
        if reference.evidence_class is not strongest_parent:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        final_policy = self._readmit_policy_before_release(request)
        if final_policy is None:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
            )
        try:
            decision = self._disclosure_decision(
                request,
                final_policy,
                reference.evidence_class,
            )
            if not decision.allowed:
                return _tool_error(
                    call,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
            envelope = make_evidence_envelope(reference, decision, payload)
            result = PrivateAnalysisToolResult(
                call=call,
                kind=PrivateAnalysisToolResultKind.DERIVED_EVIDENCE_ENVELOPE,
                envelope=envelope,
            )
            transferred_bytes = len(evidence_envelope_json(envelope).encode("utf-8"))
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
            )
        if not self._commit_disclosure(
            request,
            (reference,),
            transferred_bytes,
            envelopes=(envelope,),
        ):
            return _tool_error(
                call,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        return result

    def _validated_query_page(
        self,
        request: PrivateAnalysisRequest,
        arguments: PrivateAnalysisQueryArguments,
        value: object,
    ) -> PrivateAnalysisEvidenceQueryPage | None:
        try:
            if type(value) is not PrivateAnalysisEvidenceQueryPage:
                return None
            if len(value.references) > arguments.page_size:
                return None
            detached: list[EvidenceReference] = []
            digests: set[str] = set()
            for item in value.references:
                reference = _detached_reference(item)
                if reference.reference_digest in digests:
                    return None
                digests.add(reference.reference_digest)
                membership = _reference_membership(reference, request)
                if membership != "member":
                    return None
                detached.append(reference)
            references = tuple(detached)
            if not self._reference_bindings_are_valid(references):
                return None
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest=value.snapshot_digest,
                references=references,
                has_more=value.has_more,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return None

    def _validated_legacy_query_references(
        self,
        request: PrivateAnalysisRequest,
        value: tuple[EvidenceReference, ...],
    ) -> tuple[EvidenceReference, ...] | None:
        if len(value) > MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES:
            return None
        detached: list[EvidenceReference] = []
        digests: set[str] = set()
        try:
            for item in value:
                reference = _detached_reference(item)
                if reference.reference_digest in digests:
                    return None
                digests.add(reference.reference_digest)
                membership = _reference_membership(reference, request)
                if membership == "foreign":
                    continue
                if membership == "conflict":
                    return None
                detached.append(reference)
            references = tuple(detached)
            if not self._reference_bindings_are_valid(references):
                return None
            return references
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return None

    def _reference_bindings_are_valid(
        self,
        references: tuple[EvidenceReference, ...],
    ) -> bool:
        detached = tuple(_detached_reference(item) for item in references)
        if self._validate_references is None:
            try:
                return all(
                    self._validate_reference(reference) is True
                    for reference in detached
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                return False
        try:
            return self._validate_references(detached) is True
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return False

    def _reference_binding_is_valid(self, reference: EvidenceReference) -> bool:
        return self._reference_bindings_are_valid((reference,))

    def _readmit_before_release(
        self,
        request: PrivateAnalysisRequest,
        references: tuple[EvidenceReference, ...],
    ) -> bool:
        self._require_authorization(request)
        policy = self._current_policy(request)
        if policy is None:
            return False
        try:
            return all(
                self._disclosure_decision(
                    request,
                    policy,
                    reference.evidence_class,
                ).allowed
                for reference in references
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return False

    def _readmit_policy_before_release(
        self,
        request: PrivateAnalysisRequest,
    ) -> WorkspaceDisclosurePolicy | None:
        self._require_authorization(request)
        return self._current_policy(request)

    def _can_disclose_reference(
        self,
        request: PrivateAnalysisRequest,
        reference: EvidenceReference,
    ) -> bool:
        with self._lock:
            new_item = reference.reference_digest not in self._ledger
            return (
                not new_item or len(self._ledger) < request.limits.max_evidence_items
            ) and self._evidence_bytes_disclosed < request.limits.max_evidence_bytes

    def _commit_disclosure(
        self,
        request: PrivateAnalysisRequest,
        references: tuple[EvidenceReference, ...],
        transferred_bytes: int,
        *,
        envelopes: tuple[EvidenceEnvelope, ...] = (),
    ) -> bool:
        if type(transferred_bytes) is not int or transferred_bytes < 0:
            return False
        detached = tuple(_detached_reference(reference) for reference in references)
        detached_envelopes = tuple(
            _detached_envelope(envelope) for envelope in envelopes
        )
        reference_digests = {reference.reference_digest for reference in detached}
        if any(
            envelope.reference.reference_digest not in reference_digests
            for envelope in detached_envelopes
        ):
            return False
        with self._lock:
            additions = {
                reference.reference_digest: reference
                for reference in detached
                if reference.reference_digest not in self._ledger
            }
            if (
                len(self._ledger) + len(additions) > request.limits.max_evidence_items
                or self._evidence_bytes_disclosed + transferred_bytes
                > request.limits.max_evidence_bytes
            ):
                return False
            self._ledger.update(additions)
            self._materialized_envelopes.update(
                {
                    envelope.reference.reference_digest: envelope
                    for envelope in detached_envelopes
                }
            )
            self._evidence_bytes_disclosed += transferred_bytes
            return True


class _PrivateAnalysisToolRunLeaseFacade:
    """Common lease lifecycle; concrete services retain their own authority."""

    __slots__ = ("_closed", "_service")

    def __init__(self, service: Any) -> None:
        self._service = service
        self._closed = False

    @property
    def request(self) -> PrivateAnalysisRequest:
        self._require_open()
        return self._service.request

    @property
    def budget_state(self) -> PrivateAnalysisToolBudgetState:
        self._require_open()
        return self._service.budget_state

    @property
    def disclosed_references(self) -> tuple[EvidenceReference, ...]:
        self._require_open()
        return self._service.disclosed_references

    def require_run_access(self) -> None:
        self._require_open()
        self._require_service_access()

    def execute(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        self._require_open()
        return self._execute_service_call(call)

    def close(self) -> None:
        if self._closed:
            return
        self._release_service_access()
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise self._closed_lease_error()

    def _require_service_access(self) -> None:
        raise NotImplementedError

    def _execute_service_call(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        raise NotImplementedError

    def _release_service_access(self) -> None:
        raise NotImplementedError

    def _closed_lease_error(self) -> PrivateAnalysisToolServiceError:
        raise NotImplementedError


class PrivateAnalysisToolRunLease(
    _PrivateAnalysisToolRunLeaseFacade
):
    """Exclusive, single-use authority over one pristine tool service.

    The lease is a core-composition object, not a runner wire value.  A model
    callback never receives it; the in-process gateway exposes only the closed
    tool-call contract.
    """

    __slots__ = ("_token",)

    def __init__(self, service: PrivateAnalysisToolService, token: object) -> None:
        if type(service) is not PrivateAnalysisToolService:
            raise TypeError("service must be PrivateAnalysisToolService")
        super().__init__(service)
        self._token = token

    def _require_service_access(self) -> None:
        self._service._require_run_access_for_lease(self._token)

    def _execute_service_call(
        self,
        call: PrivateAnalysisToolCall,
    ) -> PrivateAnalysisToolResult | PrivateAnalysisToolError:
        return self._service._execute_for_lease(self._token, call)

    def _release_service_access(self) -> None:
        self._service._release_run_lease(self._token)

    def _closed_lease_error(self) -> PrivateAnalysisToolServiceError:
        return _service_error(
            self._service.request,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )


def _bounded_counter(maximum: object, consumed: object, label: str) -> None:
    if type(maximum) is not int or maximum < 0:
        raise ValueError(f"max_{label} must be a non-negative integer")
    if type(consumed) is not int or not 0 <= consumed <= maximum:
        raise ValueError(f"{label}_consumed must be within its maximum")


def _sha256(value: object, label: str, *, prefixed: bool) -> str:
    prefix = "sha256:" if prefixed else ""
    if type(value) is not str or not value.startswith(prefix):
        raise ValueError(f"{label} must use the required SHA-256 form")
    hexadecimal = value[len(prefix) :]
    if len(hexadecimal) != 64 or not set(hexadecimal) <= set("0123456789abcdef"):
        raise ValueError(f"{label} must use the required SHA-256 form")
    return value


def _detached_request(value: object) -> PrivateAnalysisRequest:
    if type(value) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    return private_analysis_request_from_json(private_analysis_request_json(value))


def _detached_scope(value: object) -> EvidenceScope:
    if type(value) is not EvidenceScope:
        raise TypeError("scope must be EvidenceScope")
    return EvidenceScope(
        tenant_id=value.tenant_id,
        project_id=value.project_id,
        workspace_id=value.workspace_id,
    )


def _scope_digest(scope: EvidenceScope) -> str:
    scope = _detached_scope(scope)
    return disclosure_scope_digest(
        tenant_id=scope.tenant_id,
        project_id=scope.project_id,
        workspace_id=scope.workspace_id,
    )


def _detached_runner_policy(value: object) -> PrivateAnalysisPolicy:
    if type(value) is not PrivateAnalysisPolicy:
        raise TypeError("runner_policy must be PrivateAnalysisPolicy")
    return PrivateAnalysisPolicy(
        transport=value.transport,
        full_fidelity_workspace_data=value.full_fidelity_workspace_data,
    )


def _detached_policy_snapshot(
    value: object,
) -> PrivateAnalysisWorkspacePolicySnapshot:
    if type(value) is not PrivateAnalysisWorkspacePolicySnapshot:
        raise TypeError("policy resolver returned an invalid policy snapshot")
    return PrivateAnalysisWorkspacePolicySnapshot(
        scope=value.scope,
        policy_version=value.policy_version,
        policy=value.policy,
        policy_digest=value.policy_digest,
    )


def _detached_reference(value: object) -> EvidenceReference:
    if type(value) is not EvidenceReference:
        raise TypeError("reference must be EvidenceReference")
    return evidence_reference_from_dict(evidence_reference_dict(value))


def _detached_envelope(value: object) -> EvidenceEnvelope:
    if type(value) is not EvidenceEnvelope:
        raise TypeError("envelope must be EvidenceEnvelope")
    return evidence_envelope_from_json(evidence_envelope_json(value))


def _detached_analysis_error(value: PrivateAnalysisError) -> PrivateAnalysisError:
    return PrivateAnalysisError(
        request_digest=value.request_digest,
        stage=value.stage,
        code=value.code,
        retryable=value.retryable,
        contract_version=value.contract_version,
        error_digest=value.error_digest,
    )


def _service_error(
    request: PrivateAnalysisRequest | None,
    stage: PrivateAnalysisErrorStage,
    code: PrivateAnalysisErrorCode,
) -> PrivateAnalysisToolServiceError:
    return PrivateAnalysisToolServiceError(
        PrivateAnalysisError(
            request_digest=None if request is None else request.request_digest,
            stage=stage,
            code=code,
            retryable=False,
        )
    )


def _tool_error(
    call: PrivateAnalysisToolCall,
    code: PrivateAnalysisToolErrorCode,
) -> PrivateAnalysisToolError:
    return PrivateAnalysisToolError(
        call=call,
        code=code,
        retryable=code is PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
    )


def _reference_membership(
    reference: EvidenceReference,
    request: PrivateAnalysisRequest,
) -> str:
    if reference.scope != request.scope:
        return "foreign"
    if reference.revision in request.revisions:
        return "member"
    if any(
        candidate.node_id == reference.revision.node_id
        and candidate.revision_id == reference.revision.revision_id
        for candidate in request.revisions
    ):
        return "conflict"
    return "foreign"


def _reference_matches_query(
    reference: EvidenceReference,
    arguments: PrivateAnalysisQueryArguments,
) -> bool:
    filters = (
        (arguments.evidence_kinds, reference.kind),
        (arguments.node_ids, reference.revision.node_id),
        (arguments.producer_ids, reference.producer.producer_id),
        (arguments.subject_kinds, reference.subject_kind),
    )
    if not all(not accepted or actual in accepted for accepted, actual in filters):
        return False
    if arguments.time_basis is None:
        return True
    time_range = reference.time_range
    if not (
        time_range.basis is arguments.time_basis
        and time_range.clock_domain == arguments.time_clock_domain
        and time_range.start_ns is not None
        and time_range.end_ns is not None
    ):
        return False
    uncertainty = time_range.uncertainty_ns or 0
    minimum = (
        0 if time_range.basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else -(1 << 63)
    )
    start = max(minimum, time_range.start_ns - uncertainty)
    end = min((1 << 63) - 1, time_range.end_ns + uncertainty)
    return start <= arguments.time_end_ns and end >= arguments.time_start_ns


__all__ = [
    "PrivateAnalysisAuthorizationDecision",
    "PrivateAnalysisAuthorizationReason",
    "PrivateAnalysisAuthorizer",
    "PrivateAnalysisCapabilityAnalyzer",
    "PrivateAnalysisPayloadMaterializer",
    "PrivateAnalysisPolicyResolver",
    "PrivateAnalysisReferenceBatchValidator",
    "PrivateAnalysisReferencePageQuery",
    "PrivateAnalysisReferenceQuery",
    "PrivateAnalysisReferenceResolver",
    "PrivateAnalysisReferenceValidator",
    "PrivateAnalysisToolBudgetState",
    "PrivateAnalysisToolRunLease",
    "PrivateAnalysisToolService",
    "PrivateAnalysisToolServiceError",
    "PrivateAnalysisWorkspacePolicySnapshot",
]
