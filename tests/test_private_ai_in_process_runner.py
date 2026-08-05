from __future__ import annotations

import json
import threading
import unittest
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import router_dump_analyzer.private_analysis_in_process_runner as in_process_runner_module
from router_dump_analyzer.canonical import (
    strict_canonical_json,
    strict_canonical_json_sha256,
)
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
    PrivateAnalysisCitation,
    PrivateAnalysisClaim,
    PrivateAnalysisClaimSupport,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisPolicy,
    PrivateAnalysisProposal,
    PrivateAnalysisProposalKind,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisRequest,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisToolBinding,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolName,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    default_private_analysis_tool_catalog,
    evidence_locator_digest,
    evidence_payload_digest,
    make_private_analysis_proposal,
    private_analysis_claim_dict,
    private_analysis_result_dict,
    private_analysis_result_from_json,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessContext,
    PrivateAnalysisInProcessExecutionReceipt,
    PrivateAnalysisInProcessGatewayAbort,
    PrivateAnalysisInProcessToolGateway,
    PrivateAnalysisInProcessToolResponse,
    PrivateAnalysisInProcessToolResponseKind,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisAuthorizationDecision,
    PrivateAnalysisAuthorizationReason,
    PrivateAnalysisToolRunLease,
    PrivateAnalysisToolService,
    PrivateAnalysisToolServiceError,
    PrivateAnalysisWorkspacePolicySnapshot,
)

_CONFIGURATION_DIGEST = "sha256:" + "a" * 64
_INSTRUCTION_PROFILE_DIGEST = "sha256:" + "b" * 64
_HOSTILE_DETAIL = (
    "failed at C:\\Users\\alice\\secret\\runner.py with bearer prod-super-secret"
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
) -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{ordinal:03d}",
        fixture_content_sha256=f"{ordinal:064x}",
        node_id=node_id or f"node-{ordinal:03d}",
        revision_id=revision_id or f"revision-{ordinal:03d}",
        revision_identity_sha256=f"{ordinal + 100:064x}",
        plan_basis_revision_id=f"basis-{ordinal:03d}",
        execution_plan_digest="sha256:" + f"{ordinal + 200:064x}",
    )


def _payload(ordinal: int = 1, *, sensitive: bool = False) -> dict[str, Any]:
    return {
        "event": "route_withdrawn",
        "ordinal": ordinal,
        "prefix": f"203.0.113.{ordinal}/32",
        "diagnostic": _HOSTILE_DETAIL if sensitive else "bounded diagnostic",
    }


def _reference(
    ordinal: int = 1,
    *,
    scope: EvidenceScope | None = None,
    revision: EvidenceRevisionBinding | None = None,
    sensitive: bool = False,
) -> EvidenceReference:
    payload = _payload(ordinal, sensitive=sensitive)
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
        # All runner tests exercise the strongest local disclosure tier.
        # Separate policy tests prove that revocation still wins.
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
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


def _selection(
    *,
    runner_id: str = "deployment.private-runner",
    runner_version: str = "1.0.0",
    transport: PrivateAnalysisTransport = PrivateAnalysisTransport.IN_PROCESS,
    configuration_digest: str = _CONFIGURATION_DIGEST,
) -> PrivateAnalysisRunnerSelection:
    return PrivateAnalysisRunnerSelection(
        runner_id=runner_id,
        runner_version=runner_version,
        transport=transport,
        configuration_digest=configuration_digest,
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
    selection: PrivateAnalysisRunnerSelection | None = None,
    policy: WorkspaceDisclosurePolicy | None = None,
    instruction_profile_digest: str = _INSTRUCTION_PROFILE_DIGEST,
    limits: PrivateAnalysisLimits | None = None,
    query: str = "Explain the observed route withdrawal.",
) -> PrivateAnalysisRequest:
    selected_policy = policy or _policy()
    return PrivateAnalysisRequest(
        scope=scope or _scope(),
        revisions=revisions or (_revision(),),
        runner=selection or _selection(),
        workspace_policy_digest=selected_policy.digest,
        instruction_profile_digest=instruction_profile_digest,
        tool_catalog_digest=default_private_analysis_tool_catalog().catalog_digest,
        task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
        query=query,
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
) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id=call_id,
        binding=_binding(request, PrivateAnalysisToolName.QUERY_EVIDENCE),
        arguments=PrivateAnalysisQueryArguments(
            evidence_kinds=(EvidenceKind.EVENT,),
            producer_ids=(CoreEvidenceProducer.CORROBORATION_V1.value,),
            subject_kinds=("route_event",),
            page_size=page_size,
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


def _citation(reference: EvidenceReference) -> PrivateAnalysisCitation:
    return PrivateAnalysisCitation(
        evidence_reference_digest=reference.reference_digest,
    )


def _claim(
    reference: EvidenceReference,
    *,
    claim_id: str = "claim-1",
    text: str = "The immutable evidence contains the route withdrawal.",
) -> PrivateAnalysisClaim:
    return PrivateAnalysisClaim(
        claim_id=claim_id,
        support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
        text=text,
        citations=(_citation(reference),),
    )


def _proposal(
    reference: EvidenceReference,
    *,
    proposal_id: str = "proposal-1",
) -> PrivateAnalysisProposal:
    return make_private_analysis_proposal(
        proposal_id=proposal_id,
        kind=PrivateAnalysisProposalKind.EVENT_CORRELATION,
        title="Review the causal event pair",
        rationale="The cited evidence shares a route key.",
        confidence_basis_points=7500,
        citations=(_citation(reference),),
        payload_schema="test.event-correlation-proposal.v1",
        payload={"left_event": "event-1", "right_event": "event-2"},
    )


def _supported_result(
    request: PrivateAnalysisRequest,
    reference: EvidenceReference,
    *,
    claims: tuple[PrivateAnalysisClaim, ...] = (),
    proposals: tuple[PrivateAnalysisProposal, ...] = (),
    summary_text: str = "The route withdrawal is present in disclosed evidence.",
) -> PrivateAnalysisResult:
    return PrivateAnalysisResult(
        request_digest=request.request_digest,
        summary=PrivateAnalysisClaim(
            claim_id="summary-1",
            support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
            text=summary_text,
            citations=(_citation(reference),),
        ),
        claims=claims,
        proposals=proposals,
    )


def _unsupported_result(
    request: PrivateAnalysisRequest,
    *,
    claims: tuple[PrivateAnalysisClaim, ...] = (),
    proposals: tuple[PrivateAnalysisProposal, ...] = (),
    text: str = "No evidence was requested; this is an unsupported hypothesis.",
) -> PrivateAnalysisResult:
    return PrivateAnalysisResult(
        request_digest=request.request_digest,
        summary=PrivateAnalysisClaim(
            claim_id="summary-1",
            support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
            text=text,
            citations=(),
        ),
        claims=claims,
        proposals=proposals,
    )


def _result_json_with_duplicate_summary_id(
    request: PrivateAnalysisRequest,
) -> str:
    result = _unsupported_result(
        request,
        claims=(
            PrivateAnalysisClaim(
                claim_id="claim-2",
                support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                text="A second bounded unsupported hypothesis.",
                citations=(),
            ),
        ),
    )
    wire = private_analysis_result_dict(result)
    wire["claims"] = [
        private_analysis_claim_dict(
            PrivateAnalysisClaim(
                claim_id="summary-1",
                support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                text="A duplicate identifier with an otherwise valid digest.",
                citations=(),
            )
        )
    ]
    payload = dict(wire)
    payload.pop("result_digest")
    wire["result_digest"] = "sha256:" + strict_canonical_json_sha256(payload)
    return strict_canonical_json(wire)


class _Harness:
    def __init__(
        self,
        request: PrivateAnalysisRequest,
        references: tuple[EvidenceReference, ...] = (),
        *,
        policy: WorkspaceDisclosurePolicy | None = None,
    ) -> None:
        self.request = request
        self.references = references
        self.policy = policy or _policy()
        self.policy_sequence: list[WorkspaceDisclosurePolicy] = []
        self.denial_reason: PrivateAnalysisAuthorizationReason | None = None
        self.authorization_calls = 0
        self.policy_calls = 0
        self.query_calls = 0
        self.resolve_calls = 0
        self.validate_calls = 0
        self.materialize_calls = 0
        self.payload_overrides: dict[str, dict[str, Any]] = {}

    def authorize(
        self,
        request: PrivateAnalysisRequest,
    ) -> PrivateAnalysisAuthorizationDecision:
        self.authorization_calls += 1
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
        policy = self.policy_sequence.pop(0) if self.policy_sequence else self.policy
        return PrivateAnalysisWorkspacePolicySnapshot(
            scope=scope,
            policy_version=self.policy_calls,
            policy=policy,
            policy_digest=policy.digest,
        )

    def query_references(
        self,
        _request: PrivateAnalysisRequest,
        _arguments: PrivateAnalysisQueryArguments,
    ) -> tuple[EvidenceReference, ...]:
        self.query_calls += 1
        return self.references

    def resolve_reference(
        self,
        _request: PrivateAnalysisRequest,
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

    def validate_reference(self, _reference: EvidenceReference) -> bool:
        self.validate_calls += 1
        return True

    def materialize_payload(self, reference: EvidenceReference) -> dict[str, Any]:
        self.materialize_calls += 1
        if reference.reference_digest in self.payload_overrides:
            return self.payload_overrides[reference.reference_digest]
        ordinal = int(reference.revision.fixture_id.rsplit("-", 1)[-1])
        return _payload(ordinal)

    def service(
        self,
        *,
        authorize: Callable[..., Any] | None = None,
        resolve_policy: Callable[..., Any] | None = None,
        query_references: Callable[..., Any] | None = None,
    ) -> PrivateAnalysisToolService:
        return PrivateAnalysisToolService(
            self.request,
            runner_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
            ),
            authorize=authorize or self.authorize,
            resolve_policy=resolve_policy or self.resolve_policy,
            query_references=query_references or self.query_references,
            resolve_reference=self.resolve_reference,
            validate_reference=self.validate_reference,
            materialize_payload=self.materialize_payload,
        )


def _runner(
    callback: Callable[
        [PrivateAnalysisInProcessContext, PrivateAnalysisInProcessToolGateway],
        str,
    ],
    *,
    selection: PrivateAnalysisRunnerSelection | None = None,
    instruction_profile_digest: str = _INSTRUCTION_PROFILE_DIGEST,
) -> ConfiguredPrivateAnalysisInProcessRunner:
    return ConfiguredPrivateAnalysisInProcessRunner(
        selection or _selection(),
        instruction_profile_digest=instruction_profile_digest,
        model_callback=callback,
    )


def _assert_receipt_error(
    testcase: unittest.TestCase,
    receipt: PrivateAnalysisInProcessExecutionReceipt,
    code: PrivateAnalysisErrorCode,
    stage: PrivateAnalysisErrorStage | None = None,
) -> None:
    outcome = receipt.outcome
    testcase.assertIs(outcome.kind, PrivateAnalysisOutcomeKind.ERROR)
    testcase.assertIsNone(outcome.result)
    testcase.assertIsNotNone(outcome.error)
    assert outcome.error is not None
    testcase.assertIs(outcome.error.code, code)
    if stage is not None:
        testcase.assertIs(outcome.error.stage, stage)


def _assert_service_error(
    testcase: unittest.TestCase,
    context: unittest.case._AssertRaisesContext[PrivateAnalysisToolServiceError],
    code: PrivateAnalysisErrorCode,
) -> None:
    testcase.assertIs(context.exception.error.code, code)
    testcase.assertNotIn("alice", str(context.exception))
    testcase.assertNotIn("secret", str(context.exception).casefold())


class PrivateAnalysisToolRunLeaseTests(unittest.TestCase):
    def test_concurrent_lease_claim_has_exactly_one_winner(self) -> None:
        request = _request()
        service = _Harness(request).service()
        barrier = threading.Barrier(2, timeout=2.0)
        result_lock = threading.Lock()
        leases: list[PrivateAnalysisToolRunLease] = []
        errors: list[PrivateAnalysisToolServiceError] = []
        unexpected: list[BaseException] = []

        def acquire() -> None:
            try:
                barrier.wait()
                outcome = service.acquire_run_lease()
                with result_lock:
                    leases.append(outcome)
            except PrivateAnalysisToolServiceError as error:
                with result_lock:
                    errors.append(error)
            except BaseException as error:  # noqa: BLE001 - test captures thread exit.
                with result_lock:
                    unexpected.append(error)

        threads = tuple(
            threading.Thread(target=acquire, daemon=False) for _index in range(2)
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2.0)
        try:
            self.assertTrue(
                all(not thread.is_alive() for thread in threads),
                "bounded lease race leaked a thread",
            )
            self.assertEqual(unexpected, [])
            self.assertEqual(len(leases), 1)
            self.assertEqual(len(errors), 1)
            self.assertIs(
                errors[0].error.code,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        finally:
            for lease in leases:
                lease.close()

    def test_lease_requires_a_pristine_service_and_permanently_claims_it(self) -> None:
        request = _request()
        harness = _Harness(request)
        used = harness.service()
        used.execute(_query_call(request))
        with self.assertRaises(PrivateAnalysisToolServiceError) as nonpristine:
            used.acquire_run_lease()
        _assert_service_error(
            self,
            nonpristine,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )

        zero_request = _request(limits=_limits(max_tool_calls=0))
        zero_service = _Harness(zero_request).service()
        zero_response = zero_service.execute(_query_call(zero_request))
        self.assertIs(type(zero_response), PrivateAnalysisToolError)
        assert isinstance(zero_response, PrivateAnalysisToolError)
        self.assertIs(zero_response.code, PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED)
        with self.assertRaises(PrivateAnalysisToolServiceError) as zero_nonpristine:
            zero_service.acquire_run_lease()
        _assert_service_error(
            self,
            zero_nonpristine,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )

        denied_harness = _Harness(request)
        denied_harness.denial_reason = (
            PrivateAnalysisAuthorizationReason.PERMISSION_DENIED
        )
        denied_service = denied_harness.service()
        with self.assertRaises(PrivateAnalysisToolServiceError):
            denied_service.execute(_query_call(request, call_id="direct-denied"))
        with self.assertRaises(PrivateAnalysisToolServiceError) as denied_nonpristine:
            denied_service.acquire_run_lease()
        _assert_service_error(
            self,
            denied_nonpristine,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )

        pristine = harness.service()
        lease = pristine.acquire_run_lease()
        self.assertIs(type(lease), PrivateAnalysisToolRunLease)
        with self.assertRaises(PrivateAnalysisToolServiceError) as direct:
            pristine.execute(_query_call(request, call_id="direct-during-lease"))
        _assert_service_error(
            self,
            direct,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )
        lease.close()
        with self.assertRaises(PrivateAnalysisToolServiceError) as after:
            pristine.execute(_query_call(request, call_id="direct-after-lease"))
        _assert_service_error(
            self,
            after,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )
        with self.assertRaises(PrivateAnalysisToolServiceError) as reused:
            pristine.acquire_run_lease()
        _assert_service_error(
            self,
            reused,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
        )

    def test_zero_tool_lease_is_single_use_and_closed_access_is_rejected(self) -> None:
        request = _request(limits=_limits(max_tool_calls=0))
        service = _Harness(request).service()
        lease = service.acquire_run_lease()
        self.assertEqual(lease.request, request)
        self.assertEqual(lease.budget_state.tool_calls_consumed, 0)
        self.assertEqual(lease.disclosed_references, ())
        lease.close()
        lease.close()

        operations = (
            lambda: lease.request,
            lambda: lease.budget_state,
            lambda: lease.disclosed_references,
            lease.require_run_access,
            lambda: lease.execute(_query_call(request)),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                    operation()
                _assert_service_error(
                    self,
                    raised,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                )

        with self.assertRaises(PrivateAnalysisToolServiceError):
            service.acquire_run_lease()

    def test_require_run_access_is_budget_neutral_and_preserves_process_control(
        self,
    ) -> None:
        request = _request()
        harness = _Harness(request)
        lease = harness.service().acquire_run_lease()
        before = lease.budget_state
        lease.require_run_access()
        lease.require_run_access()
        self.assertEqual(lease.budget_state, before)
        self.assertEqual(harness.authorization_calls, 2)
        self.assertEqual(harness.policy_calls, 2)
        self.assertEqual(harness.query_calls, 0)
        self.assertEqual(harness.resolve_calls, 0)
        self.assertEqual(harness.materialize_calls, 0)
        lease.close()

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception=exception_type.__name__):

                def stop(
                    _request: PrivateAnalysisRequest,
                    exception_type: type[BaseException] = exception_type,
                ) -> PrivateAnalysisAuthorizationDecision:
                    raise exception_type()

                service = _Harness(request).service(authorize=stop)
                interrupted = service.acquire_run_lease()
                try:
                    with self.assertRaises(exception_type):
                        interrupted.require_run_access()
                finally:
                    interrupted.close()

    def test_acquire_rejects_an_active_direct_execution_without_leaking_a_thread(
        self,
    ) -> None:
        request = _request()
        entered = threading.Event()
        release = threading.Event()

        def blocked_query(
            _request: PrivateAnalysisRequest,
            _arguments: PrivateAnalysisQueryArguments,
        ) -> tuple[EvidenceReference, ...]:
            entered.set()
            if not release.wait(2.0):
                raise AssertionError("test did not release the bounded provider")
            return ()

        service = _Harness(request).service(query_references=blocked_query)
        failures: list[BaseException] = []

        def execute() -> None:
            try:
                service.execute(_query_call(request))
            except BaseException as error:  # noqa: BLE001 - test captures thread exit.
                failures.append(error)

        thread = threading.Thread(target=execute, daemon=False)
        thread.start()
        try:
            self.assertTrue(entered.wait(2.0), "direct execution did not start")
            with self.assertRaises(PrivateAnalysisToolServiceError) as raised:
                service.acquire_run_lease()
            _assert_service_error(
                self,
                raised,
                PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            )
        finally:
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive(), "bounded direct execution leaked a thread")
        self.assertEqual(failures, [])


class PrivateAnalysisInProcessRunnerTests(unittest.TestCase):
    def test_query_read_and_citation_flow_returns_detached_bound_receipt(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))
        callback_count = 0
        observed: dict[str, object] = {}

        def callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal callback_count
            callback_count += 1
            observed["context"] = repr(context)
            observed["gateway"] = repr(gateway)
            self.assertEqual(context.request, request)
            self.assertIsNot(context.request, request)
            self.assertEqual(
                context.catalog.catalog_digest,
                request.tool_catalog_digest,
            )

            query_response = gateway.execute(
                private_analysis_tool_call_json(_query_call(request))
            )
            self.assertIs(type(query_response), PrivateAnalysisInProcessToolResponse)
            self.assertIs(
                query_response.kind,
                PrivateAnalysisInProcessToolResponseKind.RESULT,
            )
            self.assertIsNotNone(query_response.result)
            assert query_response.result is not None
            self.assertEqual(query_response.result.references, (reference,))
            observed["query_response"] = repr(query_response)

            read_response = gateway.execute(
                private_analysis_tool_call_json(_read_call(request, reference))
            )
            self.assertIs(
                read_response.kind,
                PrivateAnalysisInProcessToolResponseKind.RESULT,
            )
            self.assertIsNotNone(read_response.result)
            assert read_response.result is not None
            self.assertIsNotNone(read_response.result.envelope)
            assert read_response.result.envelope is not None
            self.assertEqual(read_response.result.envelope.payload, _payload())
            self.assertIn(
                read_response.response_digest,
                read_response.canonical_json,
            )
            return private_analysis_result_json(
                _supported_result(
                    request,
                    reference,
                    claims=(_claim(reference),),
                    proposals=(_proposal(reference),),
                )
            )

        runner = _runner(callback)
        receipt = runner.execute(harness.service())
        self.assertEqual(callback_count, 1)
        self.assertIs(type(receipt), PrivateAnalysisInProcessExecutionReceipt)
        self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertIsNotNone(receipt.outcome.result)
        self.assertEqual(receipt.disclosed_references, (reference,))
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 2)
        self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(receipt.transcript.exchange_count, 2)
        self.assertEqual(
            receipt.transcript.request_digest,
            request.request_digest,
        )
        self.assertEqual(
            receipt.transcript.catalog_digest,
            request.tool_catalog_digest,
        )
        self.assertEqual(
            receipt.transcript.instruction_profile_digest,
            request.instruction_profile_digest,
        )
        self.assertEqual(
            receipt.transcript.runner_configuration_digest,
            request.runner.configuration_digest,
        )
        self.assertEqual(
            receipt.transcript.outcome_digest,
            receipt.outcome.outcome_digest,
        )
        self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)
        self.assertGreater(receipt.transcript.exchange_metadata_bytes, 0)
        self.assertEqual(harness.query_calls, 1)
        self.assertEqual(harness.resolve_calls, 1)
        self.assertEqual(harness.materialize_calls, 1)
        for rendered in observed.values():
            self.assertNotIn("route_withdrawn", str(rendered))
            self.assertNotIn("203.0.113", str(rendered))

    def test_zero_tool_run_is_access_checked_before_and_after_callback(self) -> None:
        request = _request(limits=_limits(max_tool_calls=0))
        harness = _Harness(request)
        callback_count = 0

        def callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal callback_count
            callback_count += 1
            return private_analysis_result_json(_unsupported_result(context.request))

        receipt = _runner(callback).execute(harness.service())
        self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(callback_count, 1)
        self.assertEqual(harness.authorization_calls, 2)
        self.assertEqual(harness.policy_calls, 2)
        self.assertEqual(harness.query_calls, 0)
        self.assertEqual(harness.resolve_calls, 0)
        self.assertEqual(harness.materialize_calls, 0)
        self.assertEqual(receipt.transcript.exchange_count, 0)
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
        self.assertEqual(receipt.disclosed_references, ())

    def test_initial_denial_and_final_revocation_fail_closed(self) -> None:
        request = _request()
        initial = _Harness(request)
        initial.denial_reason = PrivateAnalysisAuthorizationReason.PERMISSION_DENIED
        initial_callback_count = 0

        def initial_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal initial_callback_count
            initial_callback_count += 1
            return private_analysis_result_json(_unsupported_result(context.request))

        initial_service = initial.service()
        denied = _runner(initial_callback).execute(initial_service)
        _assert_receipt_error(
            self,
            denied,
            PrivateAnalysisErrorCode.POLICY_DENIED,
            PrivateAnalysisErrorStage.AUTHORIZATION,
        )
        self.assertEqual(initial_callback_count, 0)
        self.assertEqual(initial.policy_calls, 0)
        self.assertEqual(denied.transcript.exchange_count, 0)
        with self.assertRaises(PrivateAnalysisToolServiceError):
            initial_service.execute(_query_call(request))

        final = _Harness(request)
        final_callback_count = 0

        def revoke_after_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal final_callback_count
            final_callback_count += 1
            final.policy = _policy(PrivateAnalysisDisclosureMode.DISABLED)
            return private_analysis_result_json(_unsupported_result(context.request))

        revoked = _runner(revoke_after_callback).execute(final.service())
        _assert_receipt_error(
            self,
            revoked,
            PrivateAnalysisErrorCode.POLICY_DENIED,
            PrivateAnalysisErrorStage.DISCLOSURE,
        )
        self.assertEqual(final_callback_count, 1)
        self.assertEqual(final.authorization_calls, 2)
        self.assertEqual(final.policy_calls, 2)
        self.assertEqual(revoked.transcript.exchange_count, 0)

    def test_runner_configuration_profile_and_service_binding_are_exact(self) -> None:
        callback_count = 0

        def callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal callback_count
            callback_count += 1
            return private_analysis_result_json(_unsupported_result(context.request))

        with self.assertRaises(ValueError):
            _runner(
                callback,
                selection=_selection(
                    transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                ),
            )

        mismatches = (
            _selection(runner_id="deployment.other-runner"),
            _selection(runner_version="2.0.0"),
            _selection(configuration_digest="sha256:" + "c" * 64),
        )
        for configured in mismatches:
            with self.subTest(configured=configured):
                request = _request()
                service = _Harness(request).service()
                receipt = _runner(callback, selection=configured).execute(service)
                _assert_receipt_error(
                    self,
                    receipt,
                    PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                    PrivateAnalysisErrorStage.RUNNER,
                )
                # Binding rejection happens before the service is claimed.
                lease = service.acquire_run_lease()
                lease.close()

        request = _request()
        profile_receipt = _runner(
            callback,
            instruction_profile_digest="sha256:" + "d" * 64,
        ).execute(_Harness(request).service())
        _assert_receipt_error(
            self,
            profile_receipt,
            PrivateAnalysisErrorCode.INVALID_REQUEST,
            PrivateAnalysisErrorStage.REQUEST_VALIDATION,
        )
        self.assertEqual(callback_count, 0)

        with self.assertRaises(TypeError):
            _runner(callback).execute(object())  # type: ignore[arg-type]

        selection = _selection()
        runner = _runner(callback, selection=selection)
        object.__setattr__(selection, "runner_id", "mutated-outside")
        detached = runner.selection
        self.assertEqual(detached.runner_id, "deployment.private-runner")
        object.__setattr__(detached, "runner_id", "mutated-copy")
        self.assertEqual(runner.selection.runner_id, "deployment.private-runner")

    def test_noncanonical_malformed_and_cross_request_tool_wires_latch_protocol(
        self,
    ) -> None:
        request = _request()
        valid = private_analysis_tool_call_json(_query_call(request))
        valid_dict = strict_canonical_json(
            {**json.loads(valid), "endpoint": "https://public-model.invalid/v1"}
        )
        bad_digest = json.loads(valid)
        bad_digest["call_digest"] = "sha256:" + "f" * 64
        foreign = _request(scope=_scope(workspace_id="workspace-b"))
        wires: tuple[tuple[object, int], ...] = (
            (" " + valid, 0),
            (
                valid.replace(
                    '"contract_version":',
                    '"contract_version":"duplicate","contract_version":',
                    1,
                ),
                0,
            ),
            (valid_dict, 0),
            (strict_canonical_json(bad_digest), 0),
            (private_analysis_tool_call_json(_query_call(foreign)), 1),
            (None, 0),
        )

        for wire, expected_exchanges in wires:
            with self.subTest(wire_type=type(wire).__name__):
                harness = _Harness(request)

                def callback(
                    context: PrivateAnalysisInProcessContext,
                    gateway: PrivateAnalysisInProcessToolGateway,
                    wire: object = wire,
                ) -> str:
                    with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                        gateway.execute(wire)  # type: ignore[arg-type]
                    return private_analysis_result_json(
                        _unsupported_result(context.request)
                    )

                receipt = _runner(callback).execute(harness.service())
                _assert_receipt_error(
                    self,
                    receipt,
                    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
                    PrivateAnalysisErrorStage.RUNNER,
                )
                self.assertEqual(
                    receipt.transcript.exchange_count,
                    expected_exchanges,
                )
                self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)
                self.assertEqual(harness.query_calls, 0)

    def test_caught_duplicate_and_reentrant_failures_win_over_callback_result(
        self,
    ) -> None:
        reference = _reference()
        request = _request(revisions=(_revision(),))
        duplicate_harness = _Harness(request, (reference,))

        def duplicate_callback(
            _context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            wire = private_analysis_tool_call_json(_query_call(request))
            first = gateway.execute(wire)
            self.assertIs(first.kind, PrivateAnalysisInProcessToolResponseKind.RESULT)
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute(wire)
            return private_analysis_result_json(_supported_result(request, reference))

        duplicate = _runner(duplicate_callback).execute(duplicate_harness.service())
        _assert_receipt_error(
            self,
            duplicate,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(duplicate.budget_state.tool_calls_consumed, 1)
        self.assertEqual(duplicate.transcript.exchange_count, 2)

        gateway_box: list[PrivateAnalysisInProcessToolGateway] = []

        def reentrant_query(
            _request: PrivateAnalysisRequest,
            _arguments: PrivateAnalysisQueryArguments,
        ) -> tuple[EvidenceReference, ...]:
            gateway_box[0].execute(
                private_analysis_tool_call_json(
                    _query_call(request, call_id="recursive-inner")
                )
            )
            return (reference,)

        reentrant_harness = _Harness(request, (reference,))

        def reentrant_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway_box.append(gateway)
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute(
                    private_analysis_tool_call_json(
                        _query_call(request, call_id="recursive-outer")
                    )
                )
            return private_analysis_result_json(_unsupported_result(context.request))

        reentrant = _runner(reentrant_callback).execute(
            reentrant_harness.service(query_references=reentrant_query)
        )
        _assert_receipt_error(
            self,
            reentrant,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(reentrant.budget_state.tool_calls_consumed, 1)

    def test_cross_thread_and_retained_gateway_use_is_bounded_and_closed(self) -> None:
        request = _request()
        retained: list[PrivateAnalysisInProcessToolGateway] = []
        thread_errors: list[BaseException] = []

        def cross_thread_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            retained.append(gateway)

            def invoke() -> None:
                try:
                    gateway.execute(
                        private_analysis_tool_call_json(
                            _query_call(request, call_id="foreign-thread")
                        )
                    )
                except BaseException as error:  # noqa: BLE001 - test boundary.
                    thread_errors.append(error)

            thread = threading.Thread(target=invoke, daemon=False)
            thread.start()
            thread.join(2.0)
            self.assertFalse(thread.is_alive(), "cross-thread gateway call hung")
            return private_analysis_result_json(_unsupported_result(context.request))

        service = _Harness(request).service()
        receipt = _runner(cross_thread_callback).execute(service)
        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(len(thread_errors), 1)
        self.assertIs(type(thread_errors[0]), PrivateAnalysisInProcessGatewayAbort)
        self.assertEqual(receipt.transcript.exchange_count, 0)
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)

        before_transcript = receipt.transcript
        before_budget = receipt.budget_state
        with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
            retained[0].execute(
                private_analysis_tool_call_json(
                    _query_call(request, call_id="retained-after-run")
                )
            )
        self.assertEqual(receipt.transcript, before_transcript)
        self.assertEqual(receipt.budget_state, before_budget)
        with self.assertRaises(PrivateAnalysisToolServiceError):
            service.execute(_query_call(request, call_id="direct-after-run"))

        close_errors: list[BaseException] = []

        def cross_thread_close_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            def close() -> None:
                try:
                    gateway.close()
                except BaseException as error:  # noqa: BLE001 - test boundary.
                    close_errors.append(error)

            thread = threading.Thread(target=close, daemon=False)
            thread.start()
            thread.join(2.0)
            self.assertFalse(thread.is_alive(), "cross-thread gateway close hung")
            return private_analysis_result_json(_unsupported_result(context.request))

        closed_cross_thread = _runner(cross_thread_close_callback).execute(
            _Harness(request).service()
        )
        _assert_receipt_error(
            self,
            closed_cross_thread,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(len(close_errors), 1)
        self.assertIs(type(close_errors[0]), PrivateAnalysisInProcessGatewayAbort)

        metadata_errors: list[BaseException] = []

        def cross_thread_metadata_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            def read_metadata() -> None:
                try:
                    _ = gateway.exchange_count  # type: ignore[attr-defined]
                except BaseException as error:  # noqa: BLE001 - test boundary.
                    metadata_errors.append(error)

            thread = threading.Thread(target=read_metadata, daemon=False)
            thread.start()
            thread.join(2.0)
            self.assertFalse(thread.is_alive(), "gateway metadata read hung")
            return private_analysis_result_json(_unsupported_result(context.request))

        metadata_receipt = _runner(cross_thread_metadata_callback).execute(
            _Harness(request).service()
        )
        self.assertIs(metadata_receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(len(metadata_errors), 1)
        self.assertIs(type(metadata_errors[0]), AttributeError)

    def test_callback_post_close_gateway_use_latches_protocol_error(self) -> None:
        request = _request()

        def callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway.close()
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute("not-json")
            return private_analysis_result_json(_unsupported_result(context.request))

        receipt = _runner(callback).execute(_Harness(request).service())
        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(receipt.transcript.exchange_count, 0)
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 0)

    def test_tool_call_budget_allows_exactly_one_exhaustion_response(self) -> None:
        zero_request = _request(limits=_limits(max_tool_calls=0))

        def zero_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            return private_analysis_result_json(_unsupported_result(context.request))

        zero = _runner(zero_callback).execute(_Harness(zero_request).service())
        self.assertIs(zero.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(zero.transcript.exchange_count, 0)

        def zero_plus_one_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            response = gateway.execute(
                private_analysis_tool_call_json(_query_call(zero_request))
            )
            self.assertIs(response.kind, PrivateAnalysisInProcessToolResponseKind.ERROR)
            self.assertIsNotNone(response.error)
            assert response.error is not None
            self.assertIs(
                response.error.code,
                PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            )
            return private_analysis_result_json(_unsupported_result(context.request))

        zero_plus_one = _runner(zero_plus_one_callback).execute(
            _Harness(zero_request).service()
        )
        self.assertIs(zero_plus_one.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(zero_plus_one.transcript.exchange_count, 1)
        self.assertEqual(zero_plus_one.budget_state.tool_calls_consumed, 0)

        def zero_plus_two_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway.execute(private_analysis_tool_call_json(_query_call(zero_request)))
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute(
                    private_analysis_tool_call_json(
                        _query_call(zero_request, call_id="zero-plus-two")
                    )
                )
            return private_analysis_result_json(_unsupported_result(context.request))

        zero_plus_two = _runner(zero_plus_two_callback).execute(
            _Harness(zero_request).service()
        )
        _assert_receipt_error(
            self,
            zero_plus_two,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(zero_plus_two.transcript.exchange_count, 1)

        reference = _reference()
        one_request = _request(limits=_limits(max_tool_calls=1))

        def run_with_attempts(
            attempts: int,
        ) -> PrivateAnalysisInProcessExecutionReceipt:
            harness = _Harness(one_request, (reference,))

            def callback(
                _context: PrivateAnalysisInProcessContext,
                gateway: PrivateAnalysisInProcessToolGateway,
            ) -> str:
                first = gateway.execute(
                    private_analysis_tool_call_json(_query_call(one_request))
                )
                self.assertIs(
                    first.kind,
                    PrivateAnalysisInProcessToolResponseKind.RESULT,
                )
                if attempts >= 2:
                    second = gateway.execute(
                        private_analysis_tool_call_json(
                            _query_call(one_request, call_id="one-plus-one")
                        )
                    )
                    self.assertIs(
                        second.kind,
                        PrivateAnalysisInProcessToolResponseKind.ERROR,
                    )
                if attempts >= 3:
                    with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                        gateway.execute(
                            private_analysis_tool_call_json(
                                _query_call(one_request, call_id="one-plus-two")
                            )
                        )
                return private_analysis_result_json(
                    _supported_result(one_request, reference)
                )

            return _runner(callback).execute(harness.service())

        exact = run_with_attempts(1)
        self.assertIs(exact.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(exact.transcript.exchange_count, 1)
        self.assertEqual(exact.budget_state.tool_calls_consumed, 1)

        plus_one = run_with_attempts(2)
        self.assertIs(plus_one.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(plus_one.transcript.exchange_count, 2)
        self.assertEqual(plus_one.budget_state.tool_calls_consumed, 1)

        plus_two = run_with_attempts(3)
        _assert_receipt_error(
            self,
            plus_two,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(plus_two.transcript.exchange_count, 2)
        self.assertEqual(plus_two.budget_state.tool_calls_consumed, 1)

    def test_callback_baseexceptions_are_static_and_process_controls_propagate(
        self,
    ) -> None:
        request = _request(query=_HOSTILE_DETAIL)

        def failure_callback(
            _context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            raise _HostileFailure(_HOSTILE_DETAIL)

        failed = _runner(failure_callback).execute(_Harness(request).service())
        _assert_receipt_error(
            self,
            failed,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorStage.RUNNER,
        )
        rendered = " ".join(
            (
                repr(failed),
                repr(failed.transcript),
                str(failed.outcome.error),
            )
        )
        for secret in ("alice", "secret", "bearer", "runner.py"):
            self.assertNotIn(secret, rendered.casefold())

        def timeout_callback(
            _context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            raise TimeoutError(_HOSTILE_DETAIL)

        arbitrary_timeout = _runner(timeout_callback).execute(
            _Harness(request).service()
        )
        _assert_receipt_error(
            self,
            arbitrary_timeout,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorStage.RUNNER,
        )

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception=exception_type.__name__):

                def stop(
                    _context: PrivateAnalysisInProcessContext,
                    _gateway: PrivateAnalysisInProcessToolGateway,
                    exception_type: type[BaseException] = exception_type,
                ) -> str:
                    raise exception_type()

                service = _Harness(request).service()
                with self.assertRaises(exception_type):
                    _runner(stop).execute(service)
                with self.assertRaises(PrivateAnalysisToolServiceError):
                    service.execute(
                        _query_call(request, call_id=f"after-{exception_type.__name__}")
                    )

    def test_cooperative_deadline_rejects_late_access_tool_and_callback(self) -> None:
        request = _request(limits=_limits(deadline_ms=1))
        deadline = 1_000_000

        now = {"value": 0}
        access_harness = _Harness(request)

        def late_authorize(
            callback_request: PrivateAnalysisRequest,
        ) -> PrivateAnalysisAuthorizationDecision:
            now["value"] = deadline + 1
            return PrivateAnalysisAuthorizationDecision.allow(callback_request)

        access_callback_count = 0

        def access_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            nonlocal access_callback_count
            access_callback_count += 1
            return private_analysis_result_json(_unsupported_result(context.request))

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
            side_effect=lambda: now["value"],
        ):
            late_access = _runner(access_callback).execute(
                access_harness.service(authorize=late_authorize)
            )
        _assert_receipt_error(
            self,
            late_access,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(access_callback_count, 0)

        now["value"] = 0

        def late_deny(
            callback_request: PrivateAnalysisRequest,
        ) -> PrivateAnalysisAuthorizationDecision:
            now["value"] = deadline + 1
            return PrivateAnalysisAuthorizationDecision.deny(
                callback_request,
                PrivateAnalysisAuthorizationReason.PERMISSION_DENIED,
            )

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
            side_effect=lambda: now["value"],
        ):
            late_denial = _runner(access_callback).execute(
                _Harness(request).service(authorize=late_deny)
            )
        _assert_receipt_error(
            self,
            late_denial,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

        now["value"] = 0
        reference = _reference()

        def late_query(
            _request: PrivateAnalysisRequest,
            _arguments: PrivateAnalysisQueryArguments,
        ) -> tuple[EvidenceReference, ...]:
            now["value"] = deadline + 1
            return (reference,)

        tool_harness = _Harness(request, (reference,))

        def tool_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            self.assertEqual(gateway.remaining_deadline_ms, 1)
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute(private_analysis_tool_call_json(_query_call(request)))
            return private_analysis_result_json(_unsupported_result(context.request))

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
            side_effect=lambda: now["value"],
        ):
            late_tool = _runner(tool_callback).execute(
                tool_harness.service(query_references=late_query)
            )
        _assert_receipt_error(
            self,
            late_tool,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

        now["value"] = 0
        authorization_calls = 0

        def late_tool_deny(
            callback_request: PrivateAnalysisRequest,
        ) -> PrivateAnalysisAuthorizationDecision:
            nonlocal authorization_calls
            authorization_calls += 1
            if authorization_calls == 1:
                return PrivateAnalysisAuthorizationDecision.allow(callback_request)
            now["value"] = deadline + 1
            return PrivateAnalysisAuthorizationDecision.deny(
                callback_request,
                PrivateAnalysisAuthorizationReason.PERMISSION_DENIED,
            )

        def late_tool_error_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute(private_analysis_tool_call_json(_query_call(request)))
            return private_analysis_result_json(_unsupported_result(context.request))

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
            side_effect=lambda: now["value"],
        ):
            late_tool_error = _runner(late_tool_error_callback).execute(
                _Harness(request).service(authorize=late_tool_deny)
            )
        _assert_receipt_error(
            self,
            late_tool_error,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

        now["value"] = 0

        def late_call_parse(_wire: str) -> None:
            now["value"] = deadline + 1
            raise ValueError("late malformed call")

        def late_protocol_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            with self.assertRaises(PrivateAnalysisInProcessGatewayAbort):
                gateway.execute("{}")
            return private_analysis_result_json(_unsupported_result(context.request))

        with (
            patch(
                "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
                side_effect=lambda: now["value"],
            ),
            patch(
                "router_dump_analyzer.private_analysis_in_process_runner."
                "private_analysis_tool_call_from_json",
                side_effect=late_call_parse,
            ),
        ):
            late_protocol = _runner(late_protocol_callback).execute(
                _Harness(request).service()
            )
        _assert_receipt_error(
            self,
            late_protocol,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

        now["value"] = 0

        def late_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            result = private_analysis_result_json(_unsupported_result(context.request))
            now["value"] = deadline + 1
            return result

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
            side_effect=lambda: now["value"],
        ):
            late_model = _runner(late_callback).execute(_Harness(request).service())
        _assert_receipt_error(
            self,
            late_model,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

        now["value"] = 0

        def late_result_parse(wire: str) -> PrivateAnalysisResult:
            result = private_analysis_result_from_json(wire)
            now["value"] = deadline + 1
            return result

        with (
            patch(
                "router_dump_analyzer.private_analysis_in_process_runner.monotonic_ns",
                side_effect=lambda: now["value"],
            ),
            patch(
                "router_dump_analyzer.private_analysis_runner_support."
                "private_analysis_result_from_json",
                side_effect=late_result_parse,
            ),
        ):
            late_validation = _runner(access_callback).execute(
                _Harness(request).service()
            )
        _assert_receipt_error(
            self,
            late_validation,
            PrivateAnalysisErrorCode.TIMEOUT,
            PrivateAnalysisErrorStage.RUNNER,
        )

    def test_unsupported_private_gateway_bypass_fails_closed(self) -> None:
        request = _request()
        reference = _reference()

        def bypass_callback(
            _context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            # Deliberate reflection is outside the trusted in-process contract.
            # Even so, an accidental private-attribute call must not leak an
            # invariant/constructor failure from runner finalization.
            response = gateway._lease.execute(_query_call(request))  # type: ignore[attr-defined]
            self.assertIsNotNone(response)
            return private_analysis_result_json(_supported_result(request, reference))

        bypass = _runner(bypass_callback).execute(
            _Harness(request, (reference,)).service()
        )
        _assert_receipt_error(
            self,
            bypass,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(bypass.disclosed_references, (reference,))
        self.assertEqual(bypass.budget_state.tool_calls_consumed, 1)
        self.assertEqual(bypass.transcript.exchange_count, 0)
        self.assertEqual(bypass.transcript.unattributed_tool_call_count, 1)

        def corrupt_callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway._exchange_count = -1  # type: ignore[attr-defined]
            return private_analysis_result_json(_unsupported_result(context.request))

        corrupted = _runner(corrupt_callback).execute(_Harness(request).service())
        _assert_receipt_error(
            self,
            corrupted,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )

    def test_result_wire_request_and_disclosure_validation_fail_closed(self) -> None:
        request = _request()
        valid_wire = private_analysis_result_json(_unsupported_result(request))
        tampered = private_analysis_result_dict(_unsupported_result(request))
        summary = tampered["summary"]
        assert isinstance(summary, dict)
        summary["text"] = "tampered without recomputing nested digests"
        foreign_request = _request(scope=_scope(workspace_id="workspace-b"))
        undisclosed_reference = _reference()
        cases: tuple[tuple[str, object], ...] = (
            ("wrong-type", None),
            ("missing-fields", "{}"),
            ("noncanonical", " " + valid_wire),
            ("tampered", strict_canonical_json(tampered)),
            (
                "wrong-request",
                private_analysis_result_json(_unsupported_result(foreign_request)),
            ),
            (
                "undisclosed-citation",
                private_analysis_result_json(
                    _supported_result(request, undisclosed_reference)
                ),
            ),
            ("duplicate-id", _result_json_with_duplicate_summary_id(request)),
        )

        for name, raw_result in cases:
            with self.subTest(name=name):
                callback_count = 0

                def callback(
                    _context: PrivateAnalysisInProcessContext,
                    _gateway: PrivateAnalysisInProcessToolGateway,
                    raw_result: object = raw_result,
                ) -> str:
                    nonlocal callback_count
                    callback_count += 1
                    return raw_result  # type: ignore[return-value]

                receipt = _runner(callback).execute(_Harness(request).service())
                _assert_receipt_error(
                    self,
                    receipt,
                    PrivateAnalysisErrorCode.INVALID_RESULT,
                    PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                )
                self.assertEqual(callback_count, 1)
                self.assertEqual(receipt.disclosed_references, ())
                self.assertEqual(receipt.transcript.exchange_count, 0)

    def test_output_byte_claim_and_proposal_budgets_have_exact_boundaries(
        self,
    ) -> None:
        sizing_request = _request()
        sizing_wire = private_analysis_result_json(_unsupported_result(sizing_request))
        exact_size = len(sizing_wire.encode("utf-8"))

        exact_request = _request(limits=_limits(max_output_bytes=exact_size))

        def exact_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            result = private_analysis_result_json(_unsupported_result(context.request))
            self.assertEqual(len(result.encode("utf-8")), exact_size)
            return result

        exact = _runner(exact_callback).execute(_Harness(exact_request).service())
        self.assertIs(exact.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)

        below_request = _request(limits=_limits(max_output_bytes=exact_size - 1))

        def below_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            return private_analysis_result_json(_unsupported_result(context.request))

        below = _runner(below_callback).execute(_Harness(below_request).service())
        _assert_receipt_error(
            self,
            below,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        )

        unicode_text = "Unsupported multibyte hypothesis: " + "é" * 128
        unicode_sizing = private_analysis_result_json(
            _unsupported_result(sizing_request, text=unicode_text)
        )
        character_size = len(unicode_sizing)
        self.assertLess(character_size, len(unicode_sizing.encode("utf-8")))
        unicode_request = _request(
            limits=_limits(max_output_bytes=character_size),
        )

        def unicode_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            result = private_analysis_result_json(
                _unsupported_result(context.request, text=unicode_text)
            )
            self.assertEqual(len(result), character_size)
            self.assertGreater(len(result.encode("utf-8")), character_size)
            return result

        unicode_over = _runner(unicode_callback).execute(
            _Harness(unicode_request).service()
        )
        _assert_receipt_error(
            self,
            unicode_over,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        )

        claim_request = _request(limits=_limits(max_claims=1))
        extra_claim = PrivateAnalysisClaim(
            claim_id="claim-2",
            support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
            text="An extra unsupported hypothesis.",
            citations=(),
        )

        def claim_callback(
            context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            return private_analysis_result_json(
                _unsupported_result(context.request, claims=(extra_claim,))
            )

        claim_over = _runner(claim_callback).execute(_Harness(claim_request).service())
        _assert_receipt_error(
            self,
            claim_over,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        )

        proposal_request = _request(limits=_limits(max_proposals=0))
        proposal_reference = _reference()

        def proposal_callback(
            _context: PrivateAnalysisInProcessContext,
            _gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            return private_analysis_result_json(
                _unsupported_result(
                    proposal_request,
                    proposals=(_proposal(proposal_reference),),
                )
            )

        proposal_over = _runner(proposal_callback).execute(
            _Harness(proposal_request).service()
        )
        _assert_receipt_error(
            self,
            proposal_over,
            PrivateAnalysisErrorCode.BUDGET_EXCEEDED,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        )

    def test_transcript_is_deterministic_order_sensitive_and_outcome_bound(
        self,
    ) -> None:
        reference = _reference()
        request = _request()

        def execute_order(
            order: tuple[str, ...],
            *,
            summary_text: str = "The disclosed evidence contains the withdrawal.",
        ) -> PrivateAnalysisInProcessExecutionReceipt:
            harness = _Harness(request, (reference,))

            def callback(
                _context: PrivateAnalysisInProcessContext,
                gateway: PrivateAnalysisInProcessToolGateway,
            ) -> str:
                for operation in order:
                    call = (
                        _query_call(request, call_id="ordered-query")
                        if operation == "query"
                        else _read_call(request, reference, call_id="ordered-read")
                    )
                    response = gateway.execute(private_analysis_tool_call_json(call))
                    self.assertIs(
                        response.kind,
                        PrivateAnalysisInProcessToolResponseKind.RESULT,
                    )
                return private_analysis_result_json(
                    _supported_result(
                        request,
                        reference,
                        summary_text=summary_text,
                    )
                )

            return _runner(callback).execute(harness.service())

        first = execute_order(("query", "read"))
        replay = execute_order(("query", "read"))
        reversed_order = execute_order(("read", "query"))
        changed_outcome = execute_order(
            ("query", "read"),
            summary_text="The same evidence supports a differently worded result.",
        )

        self.assertEqual(first.transcript, replay.transcript)
        self.assertEqual(first.outcome.outcome_digest, replay.outcome.outcome_digest)
        self.assertNotEqual(
            first.transcript.exchange_chain_digest,
            reversed_order.transcript.exchange_chain_digest,
        )
        self.assertEqual(
            first.transcript.evidence_ledger_digest,
            reversed_order.transcript.evidence_ledger_digest,
        )
        self.assertNotEqual(
            first.outcome.outcome_digest,
            changed_outcome.outcome.outcome_digest,
        )
        self.assertNotEqual(
            first.transcript.transcript_digest,
            changed_outcome.transcript.transcript_digest,
        )
        for receipt in (first, replay, reversed_order, changed_outcome):
            self.assertEqual(
                receipt.transcript.outcome_digest,
                receipt.outcome.outcome_digest,
            )
            self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)

    def test_transcript_and_safe_reprs_retain_no_sensitive_content(self) -> None:
        reference = _reference(sensitive=True)
        request = _request(query=_HOSTILE_DETAIL)
        harness = _Harness(request, (reference,))
        harness.payload_overrides[reference.reference_digest] = _payload(sensitive=True)
        rendered_inside: list[str] = []

        def callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            response = gateway.execute(
                private_analysis_tool_call_json(_read_call(request, reference))
            )
            self.assertIsNotNone(response.result)
            assert response.result is not None
            self.assertIsNotNone(response.result.envelope)
            assert response.result.envelope is not None
            self.assertIn("prod-super-secret", str(response.result.envelope.payload))
            rendered_inside.extend((repr(context), repr(gateway), repr(response)))
            return private_analysis_result_json(_supported_result(request, reference))

        runner = _runner(callback)
        receipt = runner.execute(harness.service())
        rendered = " ".join(
            (
                *rendered_inside,
                repr(runner),
                repr(receipt),
                repr(receipt.transcript),
            )
        ).casefold()
        for secret in (
            "alice",
            "prod-super-secret",
            "bearer",
            "runner.py",
            "route_withdrawn",
            "203.0.113",
        ):
            self.assertNotIn(secret, rendered)
        transcript_fields = set(receipt.transcript.__dataclass_fields__)
        for forbidden in (
            "query",
            "payload",
            "model_output",
            "exception",
            "path",
            "timestamp",
        ):
            self.assertNotIn(forbidden, transcript_fields)

    def test_context_response_and_receipt_snapshots_are_detached(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))

        def callback(
            context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            object.__setattr__(
                context.request.scope,
                "tenant_id",
                "mutated-callback-tenant",
            )
            response = gateway.execute(
                private_analysis_tool_call_json(_query_call(request))
            )
            self.assertIsNotNone(response.result)
            assert response.result is not None
            object.__setattr__(
                response.result.references[0],
                "subject_kind",
                "mutated-response-kind",
            )
            return private_analysis_result_json(_supported_result(request, reference))

        receipt = _runner(callback).execute(harness.service())
        self.assertIs(receipt.outcome.kind, PrivateAnalysisOutcomeKind.RESULT)
        self.assertEqual(
            receipt.disclosed_references[0].subject_kind,
            "route_event",
        )
        self.assertEqual(receipt.transcript.request_digest, request.request_digest)

        references = receipt.disclosed_references
        object.__setattr__(references[0], "subject_kind", "mutated-receipt-kind")
        self.assertEqual(
            receipt.disclosed_references[0].subject_kind,
            "route_event",
        )

        outcome = receipt.outcome
        assert outcome.result is not None
        object.__setattr__(outcome.result.summary, "text", "mutated outcome")
        assert receipt.outcome.result is not None
        self.assertNotEqual(receipt.outcome.result.summary.text, "mutated outcome")

        transcript = receipt.transcript
        reconstructed_receipt = PrivateAnalysisInProcessExecutionReceipt(
            outcome=receipt.outcome,
            transcript=transcript,
            disclosed_references=receipt.disclosed_references,
            budget_state=receipt.budget_state,
        )
        expected_outcome_digest = reconstructed_receipt.outcome.outcome_digest
        object.__setattr__(
            transcript,
            "outcome_digest",
            "sha256:" + "e" * 64,
        )
        object.__setattr__(transcript, "transcript_digest", "")
        self.assertEqual(
            reconstructed_receipt.transcript.outcome_digest,
            expected_outcome_digest,
        )
        self.assertEqual(
            reconstructed_receipt.transcript.outcome_digest,
            reconstructed_receipt.outcome.outcome_digest,
        )

        transcript = receipt.transcript
        object.__setattr__(transcript, "exchange_count", 999)
        self.assertEqual(receipt.transcript.exchange_count, 1)

        budget = receipt.budget_state
        object.__setattr__(budget, "tool_calls_consumed", 999)
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)

    def test_attestation_fallback_preserves_real_disclosure_accounting(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))

        def callback(
            _context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway.execute(private_analysis_tool_call_json(_query_call(request)))
            return private_analysis_result_json(_supported_result(request, reference))

        seal_attempts = 0
        real_seal = in_process_runner_module._sealed_transcript

        def fail_result_seal(*args: Any, **kwargs: Any) -> Any:
            nonlocal seal_attempts
            seal_attempts += 1
            outcome = kwargs["outcome"]
            if outcome.kind is PrivateAnalysisOutcomeKind.RESULT:
                raise RuntimeError("synthetic final attestation failure")
            return real_seal(*args, **kwargs)

        with patch(
            "router_dump_analyzer.private_analysis_in_process_runner."
            "_sealed_transcript",
            new=fail_result_seal,
        ):
            receipt = _runner(callback).execute(harness.service())

        self.assertEqual(seal_attempts, 2)
        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(harness.query_calls, 1)
        self.assertEqual(receipt.disclosed_references, (reference,))
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
        self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(receipt.transcript.exchange_count, 1)
        self.assertEqual(receipt.transcript.budget_state, receipt.budget_state)

    def test_snapshot_failure_retains_last_complete_accounting(self) -> None:
        reference = _reference()
        request = _request()
        harness = _Harness(request, (reference,))

        def callback(
            _context: PrivateAnalysisInProcessContext,
            gateway: PrivateAnalysisInProcessToolGateway,
        ) -> str:
            gateway.execute(private_analysis_tool_call_json(_query_call(request)))
            return private_analysis_result_json(_supported_result(request, reference))

        disclosed_reads = 0
        disclosed_property = PrivateAnalysisToolRunLease.disclosed_references
        assert disclosed_property.fget is not None

        def fail_post_callback_snapshot(
            lease: PrivateAnalysisToolRunLease,
        ) -> Any:
            nonlocal disclosed_reads
            disclosed_reads += 1
            if disclosed_reads == 3:
                raise RuntimeError("synthetic final ledger snapshot failure")
            return disclosed_property.fget(lease)

        with patch.object(
            PrivateAnalysisToolRunLease,
            "disclosed_references",
            new=property(fail_post_callback_snapshot),
        ):
            receipt = _runner(callback).execute(harness.service())

        self.assertEqual(disclosed_reads, 4)
        _assert_receipt_error(
            self,
            receipt,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorStage.RUNNER,
        )
        self.assertEqual(harness.query_calls, 1)
        self.assertEqual(receipt.disclosed_references, (reference,))
        self.assertEqual(receipt.budget_state.tool_calls_consumed, 1)
        self.assertEqual(receipt.budget_state.evidence_items_disclosed, 1)
        self.assertEqual(receipt.transcript.exchange_count, 1)


if __name__ == "__main__":
    unittest.main()
