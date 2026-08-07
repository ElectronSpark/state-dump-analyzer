from __future__ import annotations

import json
import threading
import unittest
from bisect import bisect_right
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from router_dump_analyzer.canonical import strict_canonical_json
from router_dump_analyzer.private_analysis import (
    CoreEvidenceProducer,
    EvidenceAuthority,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeRange,
    PrivateAnalysisCapabilityArguments,
    PrivateAnalysisCapabilityIntent,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisEvidenceCursorInvalidError,
    PrivateAnalysisEvidenceQueryPage,
    PrivateAnalysisLimits,
    PrivateAnalysisPolicy,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisToolBinding,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolName,
    PrivateAnalysisToolResult,
    PrivateAnalysisToolResultKind,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    default_private_analysis_tool_catalog,
    evaluate_workspace_disclosure,
    evidence_envelope_json,
    evidence_locator_digest,
    evidence_payload_digest,
    evidence_reference_dict,
    make_evidence_envelope,
    private_analysis_tool_error_json,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisAuthorizationDecision,
    PrivateAnalysisAuthorizationReason,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
    PrivateAnalysisWorkspacePolicySnapshot,
)

_HOSTILE_DETAIL = (
    "failed at C:\\Users\\alice\\secret\\plugin.py with bearer prod-super-secret"
)


class _HostileFailure(BaseException):
    pass


def _scope(
    *,
    tenant_id: str = "tenant-a",
    project_id: str = "project-a",
    workspace_id: str = "workspace-a",
) -> EvidenceScope:
    return EvidenceScope(
        tenant_id=tenant_id,
        project_id=project_id,
        workspace_id=workspace_id,
    )


def _revision(
    ordinal: int = 1,
    *,
    node_id: str | None = None,
    revision_id: str | None = None,
    execution_plan_digest: str | None = None,
) -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{ordinal:03d}",
        fixture_content_sha256=f"{ordinal:064x}",
        node_id=node_id or f"node-{ordinal:03d}",
        revision_id=revision_id or f"revision-{ordinal:03d}",
        revision_identity_sha256=f"{ordinal + 100:064x}",
        plan_basis_revision_id=f"basis-{ordinal:03d}",
        execution_plan_digest=(
            execution_plan_digest or "sha256:" + f"{ordinal + 200:064x}"
        ),
    )


def _payload(ordinal: int = 1, *, padding: int = 0) -> dict[str, Any]:
    return {
        "event": "route_withdrawn",
        "ordinal": ordinal,
        "padding": "x" * padding,
        "prefix": f"203.0.113.{ordinal}/32",
    }


def _reference(
    ordinal: int = 1,
    *,
    scope: EvidenceScope | None = None,
    revision: EvidenceRevisionBinding | None = None,
    evidence_class: PrivateAnalysisEvidenceClass = (
        PrivateAnalysisEvidenceClass.PROPRIETARY
    ),
    padding: int = 0,
) -> EvidenceReference:
    payload = _payload(ordinal, padding=padding)
    return EvidenceReference(
        scope=scope or _scope(),
        revision=revision or _revision(ordinal),
        producer=EvidenceProducer(
            authority=EvidenceAuthority.CORE_CORROBORATION,
            producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
        ),
        kind=EvidenceKind.EVENT,
        subject_kind="route_event",
        locator_digest=evidence_locator_digest(
            "route_event",
            {"event_id": f"event-{ordinal}"},
        ),
        evidence_class=evidence_class,
        payload_schema="test.route-event.v1",
        fact_provenance=EvidenceFactProvenance.CORE_CORROBORATED,
        time_range=EvidenceTimeRange.not_applicable(),
        content_digest=evidence_payload_digest(
            "test.route-event.v1",
            payload,
        ),
    )


def _policy(
    mode: PrivateAnalysisDisclosureMode = PrivateAnalysisDisclosureMode.FULL_FIDELITY,
) -> WorkspaceDisclosurePolicy:
    if mode is PrivateAnalysisDisclosureMode.DISABLED:
        return WorkspaceDisclosurePolicy.disabled()
    return WorkspaceDisclosurePolicy(
        mode=mode,
        transports=(PrivateAnalysisTransport.IN_PROCESS,),
    )


def _runner_policy(*, full_fidelity: bool = True) -> PrivateAnalysisPolicy:
    return PrivateAnalysisPolicy(
        transport=PrivateAnalysisTransport.IN_PROCESS,
        full_fidelity_workspace_data=full_fidelity,
    )


def _limits(**changes: int) -> PrivateAnalysisLimits:
    values = {
        "max_evidence_items": 16,
        "max_evidence_bytes": 256 * 1024,
        "max_tool_calls": 16,
        "max_output_bytes": 64 * 1024,
        "max_claims": 8,
        "max_proposals": 4,
        "deadline_ms": 30_000,
    }
    values.update(changes)
    return PrivateAnalysisLimits(**values)


def _request(
    *,
    scope: EvidenceScope | None = None,
    revisions: tuple[EvidenceRevisionBinding, ...] | None = None,
    policy: WorkspaceDisclosurePolicy | None = None,
    limits: PrivateAnalysisLimits | None = None,
) -> PrivateAnalysisRequest:
    selected_policy = policy or _policy()
    return PrivateAnalysisRequest(
        scope=scope or _scope(),
        revisions=revisions or (_revision(),),
        runner=PrivateAnalysisRunnerSelection(
            runner_id="deployment.private-runner",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest="sha256:" + "a" * 64,
        ),
        workspace_policy_digest=selected_policy.digest,
        instruction_profile_digest="sha256:" + "b" * 64,
        tool_catalog_digest=(default_private_analysis_tool_catalog().catalog_digest),
        task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
        query="Explain the route withdrawal.",
        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
        selected_time_ns=None,
        limits=limits or _limits(),
    )


def _binding(
    request: PrivateAnalysisRequest,
    name: PrivateAnalysisToolName,
) -> PrivateAnalysisToolBinding:
    return PrivateAnalysisToolBinding(
        request_digest=request.request_digest,
        tool_catalog_digest=request.tool_catalog_digest,
        name=name,
    )


def _query_call(
    request: PrivateAnalysisRequest,
    *,
    call_id: str = "query-1",
    page_size: int = 8,
    cursor: object | None = None,
    node_ids: tuple[str, ...] = (),
) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id=call_id,
        binding=_binding(request, PrivateAnalysisToolName.QUERY_EVIDENCE),
        arguments=PrivateAnalysisQueryArguments(
            evidence_kinds=(EvidenceKind.EVENT,),
            node_ids=node_ids,
            producer_ids=(CoreEvidenceProducer.CORROBORATION_V1.value,),
            subject_kinds=("route_event",),
            page_size=page_size,
            cursor=cursor,  # type: ignore[arg-type]
        ),
    )


def _read_call(
    request: PrivateAnalysisRequest,
    reference: EvidenceReference,
    *,
    call_id: str = "read-1",
) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id=call_id,
        binding=_binding(request, PrivateAnalysisToolName.READ_EVIDENCE),
        arguments=PrivateAnalysisReadArguments(
            evidence_reference_digest=reference.reference_digest,
        ),
    )


def _analyze_call(
    request: PrivateAnalysisRequest,
    parent: EvidenceReference,
    *,
    call_id: str = "analyze-1",
) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id=call_id,
        binding=_binding(request, PrivateAnalysisToolName.ANALYZE_EVIDENCE),
        arguments=PrivateAnalysisCapabilityArguments(
            node_id=parent.revision.node_id,
            revision_id=parent.revision.revision_id,
            intent=PrivateAnalysisCapabilityIntent.TRACE_CORRELATION,
            parent_reference_digests=(parent.reference_digest,),
            parameters_json='{"vrf":"blue"}',
            max_observations=2,
        ),
    )


class _Harness:
    def __init__(
        self,
        request: PrivateAnalysisRequest,
        references: tuple[EvidenceReference, ...] = (),
        *,
        policy: WorkspaceDisclosurePolicy | None = None,
    ) -> None:
        self.original_request = request
        self.references = references
        self.policy = policy or _policy()
        self.payloads = {
            reference.reference_digest: _payload(
                int(reference.payload_schema == "test.route-event.v1")
                and int(reference.revision.fixture_id.rsplit("-", 1)[-1]),
            )
            for reference in references
        }
        self.authorization_calls = 0
        self.policy_calls = 0
        self.query_calls = 0
        self.resolve_calls = 0
        self.validate_calls = 0
        self.materialize_calls = 0
        self.denial_reason: PrivateAnalysisAuthorizationReason | None = None
        self.authorization_override: PrivateAnalysisAuthorizationDecision | None = None
        self.policy_sequence: list[WorkspaceDisclosurePolicy] = []
        self.policy_scope_override: EvidenceScope | None = None
        self.valid_reference_digests: set[str] | None = None

    def authorize(
        self,
        request: PrivateAnalysisRequest,
    ) -> PrivateAnalysisAuthorizationDecision:
        self.authorization_calls += 1
        if self.authorization_override is not None:
            return self.authorization_override
        if self.denial_reason is not None:
            return PrivateAnalysisAuthorizationDecision.deny(
                request,
                self.denial_reason,
            )
        return PrivateAnalysisAuthorizationDecision.allow(request)

    def resolve_policy(
        self,
        scope: EvidenceScope,
    ) -> PrivateAnalysisWorkspacePolicySnapshot:
        self.policy_calls += 1
        if self.policy_sequence:
            policy = self.policy_sequence.pop(0)
        else:
            policy = self.policy
        return PrivateAnalysisWorkspacePolicySnapshot(
            scope=self.policy_scope_override or scope,
            policy_version=self.policy_calls,
            policy=policy,
            policy_digest=policy.digest,
        )

    def query_references(
        self,
        request: PrivateAnalysisRequest,
        arguments: PrivateAnalysisQueryArguments,
    ) -> tuple[EvidenceReference, ...]:
        self.query_calls += 1
        return self.references

    def resolve_reference(
        self,
        request: PrivateAnalysisRequest,
        digest: str,
    ) -> EvidenceReference | None:
        self.resolve_calls += 1
        return next(
            (
                reference
                for reference in self.references
                if reference.reference_digest == digest
            ),
            None,
        )

    def validate_reference(self, reference: EvidenceReference) -> bool:
        self.validate_calls += 1
        return (
            self.valid_reference_digests is None
            or reference.reference_digest in self.valid_reference_digests
        )

    def materialize_payload(self, reference: EvidenceReference) -> dict[str, Any]:
        self.materialize_calls += 1
        return self.payloads[reference.reference_digest]

    def service(
        self,
        *,
        runner_policy: PrivateAnalysisPolicy | None = None,
        authorize: Callable[..., Any] | None = None,
        resolve_policy: Callable[..., Any] | None = None,
        query_references: Callable[..., Any] | None = None,
        query_reference_pages: Callable[..., Any] | None = None,
        resolve_reference: Callable[..., Any] | None = None,
        validate_reference: Callable[..., Any] | None = None,
        validate_references: Callable[..., Any] | None = None,
        materialize_payload: Callable[..., Any] | None = None,
        analyze_evidence: Callable[..., Any] | None = None,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> PrivateAnalysisToolService:
        return PrivateAnalysisToolService(
            self.original_request,
            runner_policy=runner_policy or _runner_policy(),
            authorize=authorize or self.authorize,
            resolve_policy=resolve_policy or self.resolve_policy,
            query_references=(
                None
                if query_reference_pages is not None
                else query_references or self.query_references
            ),
            query_reference_pages=query_reference_pages,
            resolve_reference=resolve_reference or self.resolve_reference,
            validate_reference=validate_reference or self.validate_reference,
            validate_references=validate_references,
            materialize_payload=materialize_payload or self.materialize_payload,
            analyze_evidence=analyze_evidence,
            cancellation_probe=cancellation_probe,
        )


def _assert_tool_error(
    testcase: unittest.TestCase,
    value: object,
    code: PrivateAnalysisToolErrorCode,
) -> PrivateAnalysisToolError:
    testcase.assertIs(type(value), PrivateAnalysisToolError)
    assert type(value) is PrivateAnalysisToolError
    testcase.assertIs(value.code, code)
    return value


def _is_budget_error(value: object) -> bool:
    return (
        type(value) is PrivateAnalysisToolError
        and value.code is PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED
    )


def _service_with_callback_override(
    harness: _Harness,
    callback_name: str,
    callback: Callable[..., Any],
) -> PrivateAnalysisToolService:
    if callback_name == "authorize":
        return harness.service(authorize=callback)
    if callback_name == "resolve_policy":
        return harness.service(resolve_policy=callback)
    if callback_name == "query_references":
        return harness.service(query_references=callback)
    if callback_name == "resolve_reference":
        return harness.service(resolve_reference=callback)
    if callback_name == "validate_reference":
        return harness.service(validate_reference=callback)
    if callback_name == "materialize_payload":
        return harness.service(materialize_payload=callback)
    raise AssertionError(f"unsupported test callback: {callback_name}")


class PrivateAnalysisToolServiceTests(unittest.TestCase):
    def test_analysis_requires_materialized_parents_and_retains_derived_overlay(
        self,
    ) -> None:
        parent = _reference()
        request = _request()
        harness = _Harness(request, (parent,))

        unavailable = harness.service().execute(_analyze_call(request, parent))
        _assert_tool_error(
            self,
            unavailable,
            PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE,
        )

        callback_calls: list[tuple[Any, ...]] = []

        def analyze(
            callback_request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisCapabilityArguments,
            parents: tuple[Any, ...],
            cancellation_probe: Callable[[], bool] | None,
        ) -> tuple[EvidenceReference, dict[str, Any]]:
            callback_calls.append(
                (callback_request, arguments, parents, cancellation_probe)
            )
            payload = {
                "arguments_digest": arguments.arguments_digest,
                "intent": arguments.intent.value,
                "parent_reference_digests": list(
                    arguments.parent_reference_digests
                ),
                "observations": [
                    {
                        "observation_id": "observation-1",
                        "category": "route_resolution",
                        "summary": "The retained event belongs to this route step.",
                        "cited_reference_digests": list(
                            arguments.parent_reference_digests
                        ),
                        "quality": "exact",
                        "details": {"vrf": "blue"},
                    }
                ],
            }
            revision = parents[0].reference.revision
            reference = EvidenceReference(
                scope=callback_request.scope,
                revision=revision,
                producer=EvidenceProducer(
                    authority=EvidenceAuthority.PLUGIN_INFERRED,
                    producer_id="vendor.private-analysis@1",
                    plugin_instance_id="deployment.analysis-instance",
                    plugin_capability="evidence_analysis",
                ),
                kind=EvidenceKind.PLUGIN_CAPABILITY_RESULT,
                subject_kind="evidence_analysis",
                locator_digest=evidence_locator_digest(
                    "evidence_analysis",
                    {"arguments_digest": arguments.arguments_digest},
                ),
                evidence_class=parents[0].reference.evidence_class,
                payload_schema=(
                    "router_dump_analyzer.plugin.evidence_analysis.result.v1"
                ),
                fact_provenance=EvidenceFactProvenance.PLUGIN_ANALYZED,
                time_range=EvidenceTimeRange.unknown(),
                content_digest=evidence_payload_digest(
                    "router_dump_analyzer.plugin.evidence_analysis.result.v1",
                    payload,
                ),
            )
            return reference, payload

        missing = harness.service(analyze_evidence=analyze).execute(
            _analyze_call(request, parent)
        )
        _assert_tool_error(
            self,
            missing,
            PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
        )
        self.assertEqual(callback_calls, [])

        service = harness.service(analyze_evidence=analyze)
        read = service.execute(_read_call(request, parent))
        self.assertIs(type(read), PrivateAnalysisToolResult)
        derived = service.execute(_analyze_call(request, parent))
        self.assertIs(type(derived), PrivateAnalysisToolResult, derived)
        assert type(derived) is PrivateAnalysisToolResult
        self.assertIs(
            derived.kind,
            PrivateAnalysisToolResultKind.DERIVED_EVIDENCE_ENVELOPE,
        )
        assert derived.envelope is not None
        self.assertEqual(len(callback_calls), 1)
        self.assertFalse(hasattr(callback_calls[0][1], "plugin_instance_id"))
        self.assertEqual(
            tuple(
                reference.reference_digest
                for reference in service.disclosed_references
            ),
            tuple(
                sorted(
                    (
                        parent.reference_digest,
                        derived.envelope.reference.reference_digest,
                    )
                )
            ),
        )

        resolved_before = harness.resolve_calls
        materialized_before = harness.materialize_calls
        reread = service.execute(
            _read_call(
                request,
                derived.envelope.reference,
                call_id="read-derived",
            )
        )
        self.assertIs(type(reread), PrivateAnalysisToolResult)
        assert type(reread) is PrivateAnalysisToolResult
        assert reread.envelope is not None
        self.assertEqual(reread.envelope, derived.envelope)
        self.assertEqual(harness.resolve_calls, resolved_before)
        self.assertEqual(harness.materialize_calls, materialized_before)

    def test_query_filters_orders_pages_and_read_returns_bound_envelope(self) -> None:
        references = (_reference(2), _reference(1))
        request = _request(revisions=(_revision(1), _revision(2)))
        harness = _Harness(request, references)
        service = harness.service()

        first = service.execute(_query_call(request, page_size=1))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIs(first.kind, PrivateAnalysisToolResultKind.QUERY_PAGE)
        self.assertEqual(len(first.references), 1)
        self.assertIsNotNone(first.next_cursor)
        self.assertEqual(
            first.references,
            tuple(sorted(references, key=lambda item: item.reference_digest))[:1],
        )

        second = service.execute(
            _query_call(
                request,
                call_id="query-2",
                page_size=1,
                cursor=first.next_cursor,
            )
        )
        self.assertIs(type(second), PrivateAnalysisToolResult)
        assert type(second) is PrivateAnalysisToolResult
        self.assertEqual(len(second.references), 1)
        self.assertIsNone(second.next_cursor)
        self.assertEqual(first.snapshot_digest, second.snapshot_digest)

        reference = references[0]
        read = service.execute(_read_call(request, reference))
        self.assertIs(type(read), PrivateAnalysisToolResult)
        assert type(read) is PrivateAnalysisToolResult
        self.assertIs(read.kind, PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE)
        assert read.envelope is not None
        self.assertEqual(read.envelope.reference, reference)
        self.assertEqual(read.envelope.payload, _payload(2))
        self.assertTrue(read.envelope.disclosure_decision.allowed)
        self.assertEqual(harness.materialize_calls, 1)
        self.assertGreaterEqual(harness.authorization_calls, 6)
        self.assertGreaterEqual(harness.policy_calls, 6)

    def test_every_authorization_denial_is_generic_and_runs_before_lookup(self) -> None:
        reference = _reference()
        request = _request()
        for reason in (
            PrivateAnalysisAuthorizationReason.TENANT_DENIED,
            PrivateAnalysisAuthorizationReason.PROJECT_DENIED,
            PrivateAnalysisAuthorizationReason.WORKSPACE_DENIED,
            PrivateAnalysisAuthorizationReason.PERMISSION_DENIED,
        ):
            with self.subTest(reason=reason):
                harness = _Harness(request, (reference,))
                harness.denial_reason = reason
                service = harness.service()
                with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                    service.execute(_read_call(request, reference))
                self.assertIs(
                    raised.exception.error.stage,
                    PrivateAnalysisErrorStage.AUTHORIZATION,
                )
                self.assertIs(
                    raised.exception.error.code,
                    PrivateAnalysisErrorCode.POLICY_DENIED,
                )
                self.assertNotIn(reason.value, str(raised.exception))
                self.assertEqual(harness.resolve_calls, 0)
                self.assertEqual(service.budget_state.tool_calls_consumed, 0)

    def test_authorization_decision_must_bind_exact_request_and_scope(self) -> None:
        reference = _reference()
        request = _request()
        invalid = (
            PrivateAnalysisAuthorizationDecision(
                request_digest="sha256:" + "9" * 64,
                scope_digest=PrivateAnalysisAuthorizationDecision.allow(
                    request
                ).scope_digest,
                allowed=True,
                reason=PrivateAnalysisAuthorizationReason.ALLOWED,
            ),
            PrivateAnalysisAuthorizationDecision(
                request_digest=request.request_digest,
                scope_digest="9" * 64,
                allowed=True,
                reason=PrivateAnalysisAuthorizationReason.ALLOWED,
            ),
        )
        for decision in invalid:
            with self.subTest(decision=decision):
                harness = _Harness(request, (reference,))
                harness.authorization_override = decision
                service = harness.service()
                with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                    service.execute(_read_call(request, reference))
                self.assertIs(
                    raised.exception.error.code,
                    PrivateAnalysisErrorCode.POLICY_DENIED,
                )
                self.assertEqual(harness.resolve_calls, 0)

    def test_foreign_scope_is_concealed_and_conflicting_plan_is_unavailable(
        self,
    ) -> None:
        request = _request()
        foreign = _reference(
            scope=_scope(tenant_id="tenant-b"),
            revision=_revision(),
        )
        conflict_revision = _revision(
            9,
            node_id=request.revisions[0].node_id,
            revision_id=request.revisions[0].revision_id,
        )
        conflict = _reference(9, revision=conflict_revision)

        foreign_harness = _Harness(request, (foreign,))
        foreign_service = foreign_harness.service()
        query = foreign_service.execute(_query_call(request))
        self.assertIs(type(query), PrivateAnalysisToolResult)
        assert type(query) is PrivateAnalysisToolResult
        self.assertEqual(query.references, ())
        read = foreign_service.execute(_read_call(request, foreign))
        _assert_tool_error(
            self,
            read,
            PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
        )
        self.assertEqual(foreign_harness.materialize_calls, 0)

        conflict_harness = _Harness(request, (conflict,))
        conflict_read = conflict_harness.service().execute(
            _read_call(request, conflict)
        )
        _assert_tool_error(
            self,
            conflict_read,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertEqual(conflict_harness.validate_calls, 0)
        self.assertEqual(conflict_harness.materialize_calls, 0)

    def test_stale_or_disabled_policy_fails_closed_before_any_evidence_lookup(
        self,
    ) -> None:
        reference = _reference()
        request = _request()
        for current in (
            _policy(PrivateAnalysisDisclosureMode.CLIENT_SAFE),
            _policy(PrivateAnalysisDisclosureMode.DISABLED),
        ):
            with self.subTest(mode=current.mode):
                harness = _Harness(request, (reference,), policy=current)
                service = harness.service()
                with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                    service.execute(_read_call(request, reference))
                self.assertIs(
                    raised.exception.error.stage,
                    PrivateAnalysisErrorStage.DISCLOSURE,
                )
                self.assertIs(
                    raised.exception.error.code,
                    PrivateAnalysisErrorCode.POLICY_DENIED,
                )
                self.assertEqual(harness.resolve_calls, 0)
                self.assertEqual(harness.materialize_calls, 0)

        wrong_scope = _Harness(request, (reference,))
        wrong_scope.policy_scope_override = _scope(workspace_id="workspace-other")
        result = wrong_scope.service().execute(_read_call(request, reference))
        _assert_tool_error(
            self,
            result,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertEqual(wrong_scope.resolve_calls, 0)
        self.assertEqual(wrong_scope.materialize_calls, 0)

    def test_disclosure_is_checked_before_payload_and_rechecked_before_release(
        self,
    ) -> None:
        proprietary = _reference()
        never = _reference(
            1,
            evidence_class=PrivateAnalysisEvidenceClass.NEVER_ASSISTANT,
        )

        client_policy = _policy(PrivateAnalysisDisclosureMode.CLIENT_SAFE)
        client_request = _request(policy=client_policy)
        for reference in (proprietary, never):
            with self.subTest(reference=reference.evidence_class):
                harness = _Harness(
                    client_request,
                    (reference,),
                    policy=client_policy,
                )
                result = harness.service().execute(
                    _read_call(client_request, reference)
                )
                _assert_tool_error(
                    self,
                    result,
                    PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
                )
                self.assertEqual(harness.materialize_calls, 0)

        full_policy = _policy()
        full_request = _request(policy=full_policy)
        harness = _Harness(full_request, (proprietary,), policy=full_policy)
        harness.policy_sequence = [
            full_policy,
            _policy(PrivateAnalysisDisclosureMode.CLIENT_SAFE),
        ]
        with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
            harness.service().execute(_read_call(full_request, proprietary))
        self.assertIs(
            raised.exception.error.code,
            PrivateAnalysisErrorCode.POLICY_DENIED,
        )
        self.assertEqual(harness.materialize_calls, 1)

    def test_query_cursor_detects_membership_drift(self) -> None:
        references = (_reference(1), _reference(2))
        request = _request(revisions=(_revision(1), _revision(2)))
        harness = _Harness(request, references)
        service = harness.service()
        first = service.execute(_query_call(request, page_size=1))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIsNotNone(first.next_cursor)

        harness.references = references[:1]
        drifted = service.execute(
            _query_call(
                request,
                call_id="query-after-drift",
                page_size=1,
                cursor=first.next_cursor,
            )
        )
        _assert_tool_error(
            self,
            drifted,
            PrivateAnalysisToolErrorCode.CURSOR_INVALID,
        )

    def test_query_cursor_is_stable_when_provider_order_changes(self) -> None:
        references = (_reference(1), _reference(2))
        request = _request(revisions=(_revision(1), _revision(2)))
        harness = _Harness(request, references)
        service = harness.service()
        first = service.execute(_query_call(request, page_size=1))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIsNotNone(first.next_cursor)

        harness.references = tuple(reversed(references))
        second = service.execute(
            _query_call(
                request,
                call_id="query-reordered",
                page_size=1,
                cursor=first.next_cursor,
            )
        )
        self.assertIs(type(second), PrivateAnalysisToolResult)
        assert type(second) is PrivateAnalysisToolResult
        self.assertEqual(second.snapshot_digest, first.snapshot_digest)
        self.assertEqual(harness.query_calls, 2)

    def test_runner_full_fidelity_ceiling_blocks_proprietary_payload(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        service = harness.service(runner_policy=_runner_policy(full_fidelity=False))

        query = service.execute(_query_call(request))
        self.assertIs(type(query), PrivateAnalysisToolResult)
        assert type(query) is PrivateAnalysisToolResult
        self.assertEqual(query.references, ())
        read = service.execute(_read_call(request, reference))
        _assert_tool_error(
            self,
            read,
            PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND,
        )
        self.assertEqual(harness.materialize_calls, 0)

    def test_read_resolver_substitution_is_unavailable_before_payload(self) -> None:
        requested = _reference(1)
        substituted = _reference(2)
        request = _request(revisions=(_revision(1), _revision(2)))
        harness = _Harness(request, (requested, substituted))

        def substitute(
            _request_value: PrivateAnalysisRequest,
            _digest: str,
        ) -> EvidenceReference:
            return substituted

        result = harness.service(resolve_reference=substitute).execute(
            _read_call(request, requested)
        )
        _assert_tool_error(
            self,
            result,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertEqual(harness.validate_calls, 0)
        self.assertEqual(harness.materialize_calls, 0)

    def test_plan_binding_validator_is_mandatory_for_query_and_read(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        harness.valid_reference_digests = set()
        service = harness.service()

        query = service.execute(_query_call(request))
        _assert_tool_error(
            self,
            query,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        read = service.execute(
            _read_call(request, reference, call_id="read-invalid-plan")
        )
        _assert_tool_error(
            self,
            read,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertEqual(harness.validate_calls, 2)
        self.assertEqual(harness.materialize_calls, 0)

    def test_all_callback_baseexceptions_are_contained_without_detail_leakage(
        self,
    ) -> None:
        reference = _reference()
        request = _request()

        def fail(*_args: object) -> object:
            raise _HostileFailure(_HOSTILE_DETAIL)

        cases = (
            ("authorize", "read", PrivateAnalysisToolServiceError),
            ("resolve_policy", "read", PrivateAnalysisToolError),
            ("query_references", "query", PrivateAnalysisToolError),
            ("resolve_reference", "read", PrivateAnalysisToolError),
            ("validate_reference", "read", PrivateAnalysisToolError),
            ("materialize_payload", "read", PrivateAnalysisToolError),
        )
        for callback_name, operation, expected_type in cases:
            with self.subTest(callback=callback_name):
                harness = _Harness(request, (reference,))
                service = _service_with_callback_override(
                    harness,
                    callback_name,
                    fail,
                )
                call = (
                    _query_call(request)
                    if operation == "query"
                    else _read_call(request, reference)
                )
                if expected_type is PrivateAnalysisToolServiceError:
                    with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                        service.execute(call)
                    rendered = str(raised.exception)
                    self.assertIsNone(raised.exception.__context__)
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertIs(
                        raised.exception.error.code,
                        PrivateAnalysisErrorCode.POLICY_DENIED,
                    )
                else:
                    result = service.execute(call)
                    error = _assert_tool_error(
                        self,
                        result,
                        PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                    )
                    rendered = private_analysis_tool_error_json(error)
                self.assertNotIn("alice", rendered)
                self.assertNotIn("secret", rendered)
                self.assertNotIn("bearer", rendered.casefold())
                self.assertNotIn("plugin.py", rendered)

    def test_process_control_exceptions_pass_through_every_callback_boundary(
        self,
    ) -> None:
        reference = _reference()
        request = _request()
        callback_operations = (
            ("authorize", "read"),
            ("resolve_policy", "read"),
            ("query_references", "query"),
            ("resolve_reference", "read"),
            ("validate_reference", "read"),
            ("materialize_payload", "read"),
        )
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for callback_name, operation in callback_operations:
                with self.subTest(
                    exception=exception_type.__name__,
                    callback=callback_name,
                ):
                    harness = _Harness(request, (reference,))

                    def stop(
                        *_args: object,
                        exception_type: type[BaseException] = exception_type,
                    ) -> object:
                        raise exception_type()

                    service = _service_with_callback_override(
                        harness,
                        callback_name,
                        stop,
                    )
                    call = (
                        _query_call(request)
                        if operation == "query"
                        else _read_call(request, reference)
                    )
                    with self.assertRaises(exception_type):
                        service.execute(call)

    def test_duplicate_call_ids_are_protocol_errors_and_are_race_safe(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        service = harness.service()
        call = _query_call(request, call_id="same-id")
        self.assertIs(type(service.execute(call)), PrivateAnalysisToolResult)
        with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
            service.execute(call)
        self.assertIs(
            raised.exception.error.code,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )
        self.assertEqual(service.budget_state.tool_calls_consumed, 1)

        barrier = threading.Barrier(2, timeout=2.0)
        authorization_lock = threading.Lock()
        authorization_count = 0

        def authorize(
            callback_request: PrivateAnalysisRequest,
        ) -> PrivateAnalysisAuthorizationDecision:
            nonlocal authorization_count
            with authorization_lock:
                authorization_count += 1
                current = authorization_count
            if current <= 2:
                barrier.wait()
            return PrivateAnalysisAuthorizationDecision.allow(callback_request)

        raced_harness = _Harness(request, (reference,))
        raced = raced_harness.service(authorize=authorize)
        raced_call = _query_call(request, call_id="raced-id")

        def invoke() -> object:
            try:
                return raced.execute(raced_call)
            except PrivateAnalysisToolServiceError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(lambda _value: invoke(), range(2)))
        self.assertEqual(
            sum(type(item) is PrivateAnalysisToolResult for item in outcomes),
            1,
        )
        self.assertEqual(
            sum(type(item) is PrivateAnalysisToolServiceError for item in outcomes),
            1,
        )
        self.assertEqual(raced.budget_state.tool_calls_consumed, 1)

    def test_tool_call_budget_is_reserved_once_even_when_callback_fails(self) -> None:
        reference = _reference()
        request = _request(limits=_limits(max_tool_calls=1))

        def fail(*_args: object) -> object:
            raise _HostileFailure(_HOSTILE_DETAIL)

        harness = _Harness(request, (reference,))
        service = harness.service(query_references=fail)
        first = service.execute(_query_call(request, call_id="call-1"))
        _assert_tool_error(
            self,
            first,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        second = service.execute(_query_call(request, call_id="call-2"))
        _assert_tool_error(
            self,
            second,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(service.budget_state.tool_calls_consumed, 1)

        zero_request = _request(limits=_limits(max_tool_calls=0))
        zero_harness = _Harness(zero_request, (reference,))
        zero = zero_harness.service()
        for _attempt in range(2):
            result = zero.execute(_query_call(zero_request, call_id="never-reserved"))
            _assert_tool_error(
                self,
                result,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
        self.assertEqual(zero_harness.authorization_calls, 0)
        self.assertEqual(zero.budget_state.tool_calls_consumed, 0)

    def test_unique_item_budget_commit_is_atomic_and_repeated_reads_do_not_recount(
        self,
    ) -> None:
        first_reference = _reference(1)
        second_reference = _reference(2)
        request = _request(
            revisions=(_revision(1), _revision(2)),
            limits=_limits(max_evidence_items=1),
        )
        harness = _Harness(request, (first_reference, second_reference))
        service = harness.service()

        oversized_page = service.execute(_query_call(request, page_size=2))
        _assert_tool_error(
            self,
            oversized_page,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(service.budget_state.evidence_items_disclosed, 0)
        self.assertEqual(service.budget_state.evidence_bytes_disclosed, 0)
        self.assertEqual(service.disclosed_references, ())

        read = service.execute(
            _read_call(request, first_reference, call_id="read-first")
        )
        self.assertIs(type(read), PrivateAnalysisToolResult)
        repeated = service.execute(
            _read_call(request, first_reference, call_id="read-first-again")
        )
        self.assertIs(type(repeated), PrivateAnalysisToolResult)
        self.assertEqual(service.budget_state.evidence_items_disclosed, 1)

        calls_before = harness.materialize_calls
        over = service.execute(
            _read_call(request, second_reference, call_id="read-second")
        )
        _assert_tool_error(
            self,
            over,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(harness.materialize_calls, calls_before)
        self.assertEqual(service.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(
            service.disclosed_references,
            (first_reference,),
        )

    def test_cumulative_byte_budget_is_exact_and_failed_commit_is_atomic(self) -> None:
        reference = _reference()
        policy = _policy()
        runner = _runner_policy()
        decision = evaluate_workspace_disclosure(
            policy,
            tenant_id=reference.scope.tenant_id,
            project_id=reference.scope.project_id,
            workspace_id=reference.scope.workspace_id,
            runner_policy=runner,
            evidence_class=reference.evidence_class,
        )
        envelope = make_evidence_envelope(reference, decision, _payload())
        envelope_bytes = len(evidence_envelope_json(envelope).encode("utf-8"))

        exact_request = _request(
            policy=policy,
            limits=_limits(max_evidence_bytes=envelope_bytes),
        )
        exact_harness = _Harness(exact_request, (reference,), policy=policy)
        exact_service = exact_harness.service(runner_policy=runner)
        success = exact_service.execute(_read_call(exact_request, reference))
        self.assertIs(type(success), PrivateAnalysisToolResult)
        self.assertEqual(
            exact_service.budget_state.evidence_bytes_disclosed,
            envelope_bytes,
        )
        blocked = exact_service.execute(
            _read_call(exact_request, reference, call_id="read-again")
        )
        _assert_tool_error(
            self,
            blocked,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(exact_harness.materialize_calls, 1)

        short_request = _request(
            policy=policy,
            limits=_limits(max_evidence_bytes=envelope_bytes - 1),
        )
        short_harness = _Harness(short_request, (reference,), policy=policy)
        short_service = short_harness.service(runner_policy=runner)
        too_large = short_service.execute(_read_call(short_request, reference))
        _assert_tool_error(
            self,
            too_large,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(short_harness.materialize_calls, 1)
        self.assertEqual(short_service.budget_state.evidence_bytes_disclosed, 0)
        self.assertEqual(short_service.budget_state.evidence_items_disclosed, 0)
        self.assertEqual(short_service.disclosed_references, ())

    def test_concurrent_item_budget_commits_only_one_complete_result(self) -> None:
        references = (_reference(1), _reference(2))
        request = _request(
            revisions=(_revision(1), _revision(2)),
            limits=_limits(max_evidence_items=1, max_tool_calls=2),
        )
        harness = _Harness(request, references)
        barrier = threading.Barrier(2, timeout=2.0)

        def query(
            callback_request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisQueryArguments,
        ) -> tuple[EvidenceReference, ...]:
            barrier.wait()
            return tuple(
                reference
                for reference in references
                if reference.revision.node_id in arguments.node_ids
            )

        service = harness.service(query_references=query)
        calls = tuple(
            _query_call(
                request,
                call_id=f"query-{ordinal}",
                page_size=1,
                node_ids=(reference.revision.node_id,),
            )
            for ordinal, reference in enumerate(references, start=1)
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(service.execute, calls))
        self.assertEqual(
            sum(type(item) is PrivateAnalysisToolResult for item in outcomes),
            1,
        )
        self.assertEqual(
            sum(_is_budget_error(item) for item in outcomes),
            1,
        )
        self.assertEqual(service.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(len(service.disclosed_references), 1)

    def test_request_callback_inputs_results_and_ledger_are_detached(self) -> None:
        reference = _reference()
        request = _request()
        original_tenant = request.scope.tenant_id
        payload = _payload()

        def query(
            callback_request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisQueryArguments,
        ) -> tuple[EvidenceReference, ...]:
            object.__setattr__(callback_request.scope, "tenant_id", "mutated-tenant")
            object.__setattr__(arguments, "page_size", 99)
            return (reference,)

        def validate(callback_reference: EvidenceReference) -> bool:
            object.__setattr__(callback_reference, "subject_kind", "mutated_kind")
            return True

        def materialize(callback_reference: EvidenceReference) -> dict[str, Any]:
            object.__setattr__(callback_reference, "subject_kind", "mutated_kind")
            return payload

        harness = _Harness(request, (reference,))
        service = harness.service(
            query_references=query,
            validate_reference=validate,
            materialize_payload=materialize,
        )
        object.__setattr__(request.scope, "tenant_id", "outside-mutation")
        self.assertEqual(service.request.scope.tenant_id, original_tenant)

        result = service.execute(_query_call(service.request))
        self.assertIs(type(result), PrivateAnalysisToolResult)
        assert type(result) is PrivateAnalysisToolResult
        self.assertEqual(result.references[0].subject_kind, "route_event")
        self.assertEqual(service.request.scope.tenant_id, original_tenant)

        read = service.execute(
            _read_call(service.request, reference, call_id="detached-read")
        )
        self.assertIs(type(read), PrivateAnalysisToolResult)
        assert type(read) is PrivateAnalysisToolResult
        assert read.envelope is not None
        payload["prefix"] = "198.51.100.0/24"
        self.assertEqual(read.envelope.payload["prefix"], "203.0.113.1/32")

        disclosed = service.disclosed_references
        object.__setattr__(disclosed[0], "subject_kind", "outside-ledger-mutation")
        self.assertEqual(
            service.disclosed_references[0].subject_kind,
            "route_event",
        )

    def test_binding_mismatch_and_invalid_constructor_inputs_are_payload_free(
        self,
    ) -> None:
        request = _request()
        reference = _reference()
        harness = _Harness(request, (reference,))
        service = harness.service()
        foreign_request = _request(scope=_scope(workspace_id="workspace-b"))
        foreign_call = _query_call(foreign_request)
        with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
            service.execute(foreign_call)
        self.assertIs(
            raised.exception.error.stage,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertIs(
            raised.exception.error.code,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )
        self.assertEqual(harness.authorization_calls, 0)

        bad_request = replace(
            request,
            tool_catalog_digest="sha256:" + "f" * 64,
            request_digest="",
        )
        with self.assertRaises(PrivateAnalysisToolServiceError) as admission:
            PrivateAnalysisToolService(
                bad_request,
                runner_policy=_runner_policy(),
                authorize=harness.authorize,
                resolve_policy=harness.resolve_policy,
                query_references=harness.query_references,
                resolve_reference=harness.resolve_reference,
                validate_reference=harness.validate_reference,
                materialize_payload=harness.materialize_payload,
            )
        self.assertIs(
            admission.exception.error.code,
            PrivateAnalysisErrorCode.INVALID_REQUEST,
        )
        rendered = json.dumps(
            {
                "exception": str(admission.exception),
                "error": admission.exception.error.safe_message,
            }
        )
        self.assertNotIn("catalog", rendered.casefold())
        self.assertNotIn("workspace-b", str(raised.exception))

    def test_query_reference_bytes_are_cumulative_and_unique_items_are_deduplicated(
        self,
    ) -> None:
        reference = _reference()
        transferred = len(
            strict_canonical_json(evidence_reference_dict(reference)).encode("utf-8")
        )
        request = _request(
            limits=_limits(max_evidence_bytes=transferred * 2),
        )
        harness = _Harness(request, (reference,))
        service = harness.service()
        for ordinal in (1, 2):
            result = service.execute(
                _query_call(request, call_id=f"query-repeat-{ordinal}")
            )
            self.assertIs(type(result), PrivateAnalysisToolResult)
        self.assertEqual(service.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(
            service.budget_state.evidence_bytes_disclosed,
            transferred * 2,
        )
        third = service.execute(_query_call(request, call_id="query-repeat-3"))
        _assert_tool_error(
            self,
            third,
            PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
        )
        self.assertEqual(
            service.budget_state.evidence_bytes_disclosed,
            transferred * 2,
        )

    def test_paged_query_batch_validates_only_each_returned_page(self) -> None:
        revision = _revision(1)
        references = tuple(
            sorted(
                (_reference(ordinal, revision=revision) for ordinal in range(1, 7)),
                key=lambda item: item.reference_digest,
            )
        )
        request = _request(limits=_limits(max_evidence_items=16))
        harness = _Harness(request, references)
        snapshot_digest = "sha256:" + "d" * 64
        batch_sizes: list[int] = []

        def query_page(
            _request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisQueryArguments,
            evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...],
            _cancellation_probe: Callable[[], bool] | None,
        ) -> PrivateAnalysisEvidenceQueryPage:
            self.assertIn(PrivateAnalysisEvidenceClass.PROPRIETARY, evidence_classes)
            start = (
                0
                if arguments.cursor is None
                else bisect_right(
                    tuple(item.reference_digest for item in references),
                    arguments.cursor.after_reference_digest,
                )
            )
            stop = min(start + arguments.page_size, len(references))
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest=snapshot_digest,
                references=references[start:stop],
                has_more=stop < len(references),
            )

        def validate_batch(items: tuple[EvidenceReference, ...]) -> bool:
            batch_sizes.append(len(items))
            return True

        service = harness.service(
            query_reference_pages=query_page,
            validate_references=validate_batch,
        )
        first = service.execute(_query_call(request, page_size=3))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIsNotNone(first.next_cursor)
        second = service.execute(
            _query_call(
                request,
                call_id="query-page-2",
                page_size=3,
                cursor=first.next_cursor,
            )
        )
        self.assertIs(type(second), PrivateAnalysisToolResult)
        self.assertEqual(batch_sizes, [3, 3])
        self.assertEqual(harness.validate_calls, 0)

    def test_page_query_wrong_tuple_result_never_enters_legacy_path(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))

        def wrong_page(*_args: object) -> tuple[EvidenceReference, ...]:
            return (reference,)

        result = harness.service(query_reference_pages=wrong_page).execute(
            _query_call(request)
        )
        _assert_tool_error(
            self,
            result,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertEqual(harness.validate_calls, 0)
        with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
            harness.service(query_reference_pages=42)  # type: ignore[arg-type]
        self.assertIs(
            raised.exception.error.code,
            PrivateAnalysisErrorCode.INVALID_REQUEST,
        )

    def test_page_query_contains_malformed_exact_pages_and_reconstruction(self) -> None:
        request = _request()
        harness = _Harness(request, ())
        malformed = object.__new__(PrivateAnalysisEvidenceQueryPage)
        invalid_digest = object.__new__(PrivateAnalysisEvidenceQueryPage)
        object.__setattr__(invalid_digest, "snapshot_digest", "not-a-digest")
        object.__setattr__(invalid_digest, "references", ())
        object.__setattr__(invalid_digest, "has_more", False)

        for label, page in (
            ("missing-slots", malformed),
            ("reconstruction", invalid_digest),
        ):
            with self.subTest(label=label):
                result = harness.service(
                    query_reference_pages=lambda *_args, selected=page: selected
                ).execute(_query_call(request))
                error = _assert_tool_error(
                    self,
                    result,
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
                self.assertTrue(error.retryable)

    def test_page_query_first_page_cursor_exception_is_unavailable(self) -> None:
        request = _request()
        harness = _Harness(request, ())

        def query_page(*_args: object) -> PrivateAnalysisEvidenceQueryPage:
            raise PrivateAnalysisEvidenceCursorInvalidError(
                "provider mislabeled a first-page failure"
            )

        result = harness.service(query_reference_pages=query_page).execute(
            _query_call(request)
        )
        error = _assert_tool_error(
            self,
            result,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        self.assertTrue(error.retryable)

    def test_page_query_evicted_cursor_maps_to_cursor_invalid(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        snapshot_digest = "sha256:" + "e" * 64

        def query_page(
            _request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisQueryArguments,
            _evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...],
            _cancellation_probe: Callable[[], bool] | None,
        ) -> PrivateAnalysisEvidenceQueryPage:
            if arguments.cursor is not None:
                raise PrivateAnalysisEvidenceCursorInvalidError(
                    "cursor evidence snapshot is no longer available"
                )
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest=snapshot_digest,
                references=(reference,),
                has_more=True,
            )

        service = harness.service(query_reference_pages=query_page)
        first = service.execute(_query_call(request, page_size=1))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIsNotNone(first.next_cursor)
        second = service.execute(
            _query_call(
                request,
                call_id="query-after-eviction",
                page_size=1,
                cursor=first.next_cursor,
            )
        )
        _assert_tool_error(
            self,
            second,
            PrivateAnalysisToolErrorCode.CURSOR_INVALID,
        )

    def test_valid_cursor_provider_failure_remains_retryable_unavailable(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        snapshot_digest = "sha256:" + "f" * 64

        def query_page(
            _request: PrivateAnalysisRequest,
            arguments: PrivateAnalysisQueryArguments,
            _evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...],
            _cancellation_probe: Callable[[], bool] | None,
        ) -> PrivateAnalysisEvidenceQueryPage:
            if arguments.cursor is not None:
                raise TimeoutError("private provider timed out")
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest=snapshot_digest,
                references=(reference,),
                has_more=True,
            )

        service = harness.service(query_reference_pages=query_page)
        first = service.execute(_query_call(request, page_size=1))
        self.assertIs(type(first), PrivateAnalysisToolResult)
        assert type(first) is PrivateAnalysisToolResult
        self.assertIsNotNone(first.next_cursor)
        second = service.execute(
            _query_call(
                request,
                call_id="query-provider-timeout",
                page_size=1,
                cursor=first.next_cursor,
            )
        )
        _assert_tool_error(
            self,
            second,
            PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
        )
        assert type(second) is PrivateAnalysisToolError
        self.assertTrue(second.retryable)

    def test_page_query_receives_cooperative_cancellation_probe(self) -> None:
        request = _request()
        harness = _Harness(request, ())
        probe = lambda: False
        received: list[Callable[[], bool] | None] = []

        def query_page(
            _request: PrivateAnalysisRequest,
            _arguments: PrivateAnalysisQueryArguments,
            _evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...],
            cancellation_probe: Callable[[], bool] | None,
        ) -> PrivateAnalysisEvidenceQueryPage:
            received.append(cancellation_probe)
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest="sha256:" + "a" * 64,
                references=(),
                has_more=False,
            )

        result = harness.service(
            query_reference_pages=query_page,
            cancellation_probe=probe,
        ).execute(_query_call(request))

        self.assertIs(type(result), PrivateAnalysisToolResult)
        self.assertEqual(received, [probe])

    def test_page_query_cancellation_and_probe_failures_map_fail_closed(self) -> None:
        request = _request()
        harness = _Harness(request, ())
        callback_calls = 0

        def query_page(*_args: object) -> PrivateAnalysisEvidenceQueryPage:
            nonlocal callback_calls
            callback_calls += 1
            return PrivateAnalysisEvidenceQueryPage(
                snapshot_digest="sha256:" + "a" * 64,
                references=(),
                has_more=False,
            )

        for label, probe in (
            ("cancelled", lambda: True),
            ("unavailable", lambda: (_ for _ in ()).throw(RuntimeError("secret"))),
            ("invalid", lambda: 1),
        ):
            with self.subTest(label=label):
                service = harness.service(
                    query_reference_pages=query_page,
                    cancellation_probe=probe,  # type: ignore[arg-type]
                )
                error = _assert_tool_error(
                    self,
                    service.execute(_query_call(request, call_id=f"query-{label}")),
                    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE,
                )
                self.assertTrue(error.retryable)
                self.assertEqual(service.budget_state.tool_calls_consumed, 1)
        self.assertEqual(callback_calls, 0)

        def interrupted() -> bool:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            harness.service(
                query_reference_pages=query_page,
                cancellation_probe=interrupted,
            ).execute(_query_call(request, call_id="query-interrupted"))

    def test_service_rejects_non_callable_query_cancellation_probe(self) -> None:
        request = _request()
        harness = _Harness(request, ())

        with self.assertRaises(PrivateAnalysisToolServiceError) as caught:
            harness.service(
                query_reference_pages=lambda *_args: PrivateAnalysisEvidenceQueryPage(
                    snapshot_digest="sha256:" + "a" * 64,
                    references=(),
                    has_more=False,
                ),
                cancellation_probe=object(),  # type: ignore[arg-type]
            )

        self.assertIs(caught.exception.error.code, PrivateAnalysisErrorCode.INVALID_REQUEST)


if __name__ == "__main__":
    unittest.main()
