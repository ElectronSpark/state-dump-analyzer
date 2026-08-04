from __future__ import annotations

import copy
import json
import math
import unittest
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
    CoreEvidenceProducer,
    DisclosureDecision,
    DisclosureDecisionReason,
    EvidenceAuthority,
    EvidenceEnvelope,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeRange,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    evidence_locator_digest,
    evidence_payload_digest,
)
from router_dump_analyzer.private_analysis.contracts import (
    MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES,
    PrivateAnalysisCitation,
    PrivateAnalysisClaim,
    PrivateAnalysisClaimSupport,
    PrivateAnalysisClockMode,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisProposal,
    PrivateAnalysisProposalKind,
    PrivateAnalysisRequest,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    make_private_analysis_proposal,
    private_analysis_citation_dict,
    private_analysis_claim_dict,
    private_analysis_claim_from_dict,
    private_analysis_error_dict,
    private_analysis_error_from_dict,
    private_analysis_error_from_json,
    private_analysis_error_json,
    private_analysis_outcome_dict,
    private_analysis_outcome_from_dict,
    private_analysis_outcome_from_json,
    private_analysis_outcome_json,
    private_analysis_proposal_dict,
    private_analysis_request_dict,
    private_analysis_request_from_dict,
    private_analysis_request_from_json,
    private_analysis_request_json,
    private_analysis_result_dict,
    private_analysis_result_from_dict,
    private_analysis_result_from_json,
    private_analysis_result_json,
    validate_private_analysis_result,
)

_SHA_A = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64
_SHA_C = "sha256:" + "c" * 64
_POLICY_A = "d" * 64
_POLICY_B = "e" * 64


def _scope(suffix: str = "a") -> EvidenceScope:
    return EvidenceScope(
        tenant_id=f"tenant-{suffix}",
        project_id=f"project-{suffix}",
        workspace_id=f"workspace-{suffix}",
    )


def _revision(suffix: str = "a", *, ordinal: int = 1) -> EvidenceRevisionBinding:
    digest = f"{ordinal:064x}"
    other_digest = f"{ordinal + 1024:064x}"
    plan_digest = f"{ordinal + 2048:064x}"
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{suffix}-{ordinal:03d}",
        fixture_content_sha256=digest,
        node_id=f"node-{suffix}-{ordinal:03d}",
        revision_id=f"revision-{suffix}-{ordinal:03d}",
        revision_identity_sha256=other_digest,
        plan_basis_revision_id=f"basis-{suffix}-{ordinal:03d}",
        execution_plan_digest="sha256:" + plan_digest,
    )


def _runner() -> PrivateAnalysisRunnerSelection:
    return PrivateAnalysisRunnerSelection(
        runner_id="deployment.private-runner",
        runner_version="3.1.4",
        transport=PrivateAnalysisTransport.IN_PROCESS,
        configuration_digest=_SHA_A,
    )


def _limits(**changes: int) -> PrivateAnalysisLimits:
    values = {
        "max_evidence_items": 16,
        "max_evidence_bytes": 256 * 1024,
        "max_tool_calls": 8,
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
    limits: PrivateAnalysisLimits | None = None,
) -> PrivateAnalysisRequest:
    return PrivateAnalysisRequest(
        scope=scope or _scope(),
        revisions=revisions if revisions is not None else (_revision(),),
        runner=_runner(),
        workspace_policy_digest=_POLICY_A,
        instruction_profile_digest=_SHA_B,
        task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
        query="Explain the observed BGP withdrawal and its downstream effect. \U0001f50e",
        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
        selected_time_ns=None,
        limits=limits or _limits(),
    )


def _reference(
    *,
    scope: EvidenceScope | None = None,
    revision: EvidenceRevisionBinding | None = None,
    ordinal: int = 1,
) -> EvidenceReference:
    payload = {
        "event": "route_withdrawn",
        "prefix": "203.0.113.0/24",
        "ordinal": ordinal,
    }
    return EvidenceReference(
        scope=scope or _scope(),
        revision=revision or _revision(),
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
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        payload_schema="vendor.route-event.v1",
        fact_provenance=EvidenceFactProvenance.CORE_CORROBORATED,
        time_range=EvidenceTimeRange.not_applicable(),
        content_digest=evidence_payload_digest(
            "vendor.route-event.v1",
            payload,
        ),
    )


def _citation(reference: EvidenceReference | None = None) -> PrivateAnalysisCitation:
    selected = reference or _reference()
    return PrivateAnalysisCitation(
        evidence_reference_digest=selected.reference_digest,
    )


def _claim(
    reference: EvidenceReference | None = None,
    *,
    claim_id: str = "claim-1",
) -> PrivateAnalysisClaim:
    return PrivateAnalysisClaim(
        claim_id=claim_id,
        support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
        text="The withdrawal is present in the immutable event evidence.",
        citations=(_citation(reference),),
    )


def _proposal(
    reference: EvidenceReference | None = None,
    *,
    proposal_id: str = "proposal-1",
    payload: dict[str, Any] | None = None,
) -> PrivateAnalysisProposal:
    return make_private_analysis_proposal(
        proposal_id=proposal_id,
        kind=PrivateAnalysisProposalKind.EVENT_CORRELATION,
        title="Review the likely causal event pair",
        rationale="The cited events share an exact route key and ordered times.",
        confidence_basis_points=7500,
        citations=(_citation(reference),),
        payload_schema="router_dump_analyzer.event-correlation-proposal.v1",
        payload=(
            payload
            if payload is not None
            else {"left_event": "event-1", "right_event": "event-2"}
        ),
    )


def _result(
    request: PrivateAnalysisRequest | None = None,
    reference: EvidenceReference | None = None,
    *,
    claims: tuple[PrivateAnalysisClaim, ...] | None = None,
    proposals: tuple[PrivateAnalysisProposal, ...] | None = None,
) -> PrivateAnalysisResult:
    selected_request = request or _request()
    selected_reference = reference or _reference()
    return PrivateAnalysisResult(
        request_digest=selected_request.request_digest,
        summary=PrivateAnalysisClaim(
            claim_id="summary-1",
            support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
            text="One evidence-supported withdrawal and one advisory correlation.",
            citations=(_citation(selected_reference),),
        ),
        claims=claims if claims is not None else (_claim(selected_reference),),
        proposals=(
            proposals
            if proposals is not None
            else (_proposal(selected_reference),)
        ),
    )


def _error(
    request: PrivateAnalysisRequest | None = None,
) -> PrivateAnalysisError:
    selected_request = request or _request()
    return PrivateAnalysisError(
        request_digest=selected_request.request_digest,
        stage=PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        code=PrivateAnalysisErrorCode.INVALID_RESULT,
        retryable=False,
    )


def _set_path(value: dict[str, Any], path: tuple[object, ...], replacement: Any) -> None:
    current: Any = value
    for component in path[:-1]:
        current = current[component]
    current[path[-1]] = replacement


def _nonempty_digest_paths(
    value: object,
    path: tuple[object, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    paths: list[tuple[object, ...]] = []
    if type(value) is dict:
        for key, child in value.items():
            child_path = (*path, key)
            if key.endswith("_digest") and type(child) is str and child:
                paths.append(child_path)
            paths.extend(_nonempty_digest_paths(child, child_path))
    elif type(value) is list:
        for index, child in enumerate(value):
            paths.extend(_nonempty_digest_paths(child, (*path, index)))
    return tuple(paths)


class PrivateAnalysisContractTests(unittest.TestCase):
    def test_private_analysis_value_classes_are_runtime_sealed(self) -> None:
        value_types = (
            PrivateAnalysisPolicy,
            WorkspaceDisclosurePolicy,
            DisclosureDecision,
            EvidenceRevisionBinding,
            EvidenceScope,
            EvidenceProducer,
            EvidenceTimeRange,
            EvidenceReference,
            EvidenceEnvelope,
            PrivateAnalysisRunnerSelection,
            PrivateAnalysisLimits,
            PrivateAnalysisRequest,
            PrivateAnalysisCitation,
            PrivateAnalysisClaim,
            PrivateAnalysisProposal,
            PrivateAnalysisResult,
            PrivateAnalysisError,
            PrivateAnalysisOutcome,
        )
        for value_type in value_types:
            with self.subTest(value_type=value_type.__name__), self.assertRaises(
                TypeError
            ):
                type(f"Derived{value_type.__name__}", (value_type,), {})

    def test_request_result_error_and_outcome_round_trip_canonical_wire(self) -> None:
        request = _request()
        result = _result(request)
        error = _error(request)
        success = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )
        failure = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.ERROR,
            result=None,
            error=error,
        )

        round_trips: tuple[
            tuple[
                object,
                Callable[[Any], dict[str, Any]],
                Callable[[object], object],
                Callable[[Any], str],
                Callable[[str], object],
            ],
            ...,
        ] = (
            (
                request,
                private_analysis_request_dict,
                private_analysis_request_from_dict,
                private_analysis_request_json,
                private_analysis_request_from_json,
            ),
            (
                result,
                private_analysis_result_dict,
                private_analysis_result_from_dict,
                private_analysis_result_json,
                private_analysis_result_from_json,
            ),
            (
                error,
                private_analysis_error_dict,
                private_analysis_error_from_dict,
                private_analysis_error_json,
                private_analysis_error_from_json,
            ),
            (
                success,
                private_analysis_outcome_dict,
                private_analysis_outcome_from_dict,
                private_analysis_outcome_json,
                private_analysis_outcome_from_json,
            ),
            (
                failure,
                private_analysis_outcome_dict,
                private_analysis_outcome_from_dict,
                private_analysis_outcome_json,
                private_analysis_outcome_from_json,
            ),
        )
        for value, to_dict, from_dict, to_json, from_json in round_trips:
            with self.subTest(value=type(value).__name__):
                wire = to_dict(value)
                self.assertEqual(from_dict(wire), value)
                encoded = to_json(value)
                self.assertEqual(from_json(encoded), value)
                self.assertEqual(
                    encoded,
                    json.dumps(
                        json.loads(encoded),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
                self.assertTrue(value.contract_version.endswith(".v1"))

        self.assertIn("\U0001f50e", private_analysis_request_json(request))
        self.assertTrue(request.request_digest.startswith("sha256:"))
        self.assertTrue(result.result_digest.startswith("sha256:"))
        self.assertTrue(error.error_digest.startswith("sha256:"))
        self.assertTrue(success.outcome_digest.startswith("sha256:"))

    def test_values_are_frozen_and_json_payloads_are_deeply_detached(self) -> None:
        request = _request()
        reference = _reference()
        payload: dict[str, Any] = {"nested": {"items": [1, 2]}}
        proposal = _proposal(reference, payload=payload)
        result = _result(request, reference, proposals=(proposal,))
        error = _error(request)
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )

        nested = payload["nested"]
        assert isinstance(nested, dict)
        items = nested["items"]
        assert isinstance(items, list)
        items.append(3)
        self.assertEqual(proposal.payload, {"nested": {"items": [1, 2]}})

        detached = proposal.payload
        detached_nested = detached["nested"]
        assert isinstance(detached_nested, dict)
        detached_nested["items"] = []
        self.assertEqual(proposal.payload, {"nested": {"items": [1, 2]}})

        wire = private_analysis_result_dict(result)
        summary_wire = wire["summary"]
        assert isinstance(summary_wire, dict)
        summary_wire["text"] = "mutated"
        proposal_wire = wire["proposals"][0]
        assert isinstance(proposal_wire, dict)
        proposal_payload = proposal_wire["payload"]
        assert isinstance(proposal_payload, dict)
        proposal_payload["nested"] = None
        self.assertEqual(
            result.summary.text,
            "One evidence-supported withdrawal and one advisory correlation.",
        )
        self.assertEqual(result.proposals[0].payload, {"nested": {"items": [1, 2]}})

        frozen_mutations = (
            (request, "query", "changed"),
            (request.runner, "runner_id", "changed"),
            (request.limits, "max_claims", 1),
            (result.claims[0], "text", "changed"),
            (proposal, "title", "changed"),
            (result.summary, "text", "changed"),
            (error, "retryable", True),
            (outcome, "result", None),
        )
        for value, field_name, changed in frozen_mutations:
            with (
                self.subTest(value=type(value).__name__, field=field_name),
                self.assertRaises(FrozenInstanceError),
            ):
                setattr(value, field_name, changed)

    def test_composite_values_revalidate_and_detach_nested_contracts(self) -> None:
        scope = _scope()
        revision = _revision()
        runner = _runner()
        limits = _limits()
        request = PrivateAnalysisRequest(
            scope=scope,
            revisions=(revision,),
            runner=runner,
            workspace_policy_digest=_POLICY_A,
            instruction_profile_digest=_SHA_B,
            task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
            query="Explain the event.",
            clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
            limits=limits,
        )
        self.assertIsNot(request.scope, scope)
        self.assertIsNot(request.revisions[0], revision)
        self.assertIsNot(request.runner, runner)
        self.assertIsNot(request.limits, limits)

        corrupted_limits = _limits()
        object.__setattr__(corrupted_limits, "max_claims", 0)
        with self.assertRaisesRegex(ValueError, "max_claims"):
            _request(limits=corrupted_limits)

        claim = _claim()
        result = PrivateAnalysisResult(
            request_digest=request.request_digest,
            summary=claim,
            claims=(),
            proposals=(),
        )
        self.assertIsNot(result.summary, claim)
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
        )
        self.assertIsNot(outcome.result, result)

        object.__setattr__(claim, "text", "stale claim text")
        with self.assertRaisesRegex(ValueError, "claim digest does not match"):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary=claim,
                claims=(),
                proposals=(),
            )

    def test_public_serializers_revalidate_cached_digests(self) -> None:
        values = (
            (_request(), "query", "tampered", private_analysis_request_dict),
            (
                _citation(),
                "evidence_reference_digest",
                _SHA_B,
                private_analysis_citation_dict,
            ),
            (_claim(), "text", "tampered", private_analysis_claim_dict),
            (_proposal(), "title", "tampered", private_analysis_proposal_dict),
            (
                _result(),
                "request_digest",
                _SHA_C,
                private_analysis_result_dict,
            ),
            (_error(), "retryable", True, private_analysis_error_dict),
        )
        for value, field_name, replacement, serializer in values:
            object.__setattr__(value, field_name, replacement)
            with (
                self.subTest(value=type(value).__name__),
                self.assertRaises(ValueError),
            ):
                serializer(value)

        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=_result(),
        )
        assert outcome.result is not None
        object.__setattr__(outcome.result, "request_digest", _SHA_C)
        with self.assertRaises(ValueError):
            private_analysis_outcome_dict(outcome)

    def test_request_digest_binds_scope_revision_runner_policy_instructions_and_limits(
        self,
    ) -> None:
        base = _request()
        changes = (
            replace(base, scope=_scope("b"), request_digest=""),
            replace(
                base,
                revisions=(_revision("b", ordinal=2),),
                request_digest="",
            ),
            replace(
                base,
                runner=replace(
                    base.runner,
                    runner_id="deployment.other-runner",
                ),
                request_digest="",
            ),
            replace(base, workspace_policy_digest=_POLICY_B, request_digest=""),
            replace(base, instruction_profile_digest=_SHA_C, request_digest=""),
            replace(
                base,
                task_kind=PrivateAnalysisTaskKind.RESOURCE_CORRELATION,
                request_digest="",
            ),
            replace(base, query="A different bounded question", request_digest=""),
            replace(
                base,
                clock_mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                selected_time_ns=1_700_000_000_000_000_000,
                request_digest="",
            ),
            replace(
                base,
                limits=replace(base.limits, max_claims=7),
                request_digest="",
            ),
        )
        for changed in changes:
            with self.subTest(changed=changed):
                self.assertNotEqual(changed.request_digest, base.request_digest)

    def test_result_error_and_outcome_digests_bind_their_complete_values(self) -> None:
        request = _request()
        reference = _reference()
        result = _result(request, reference)
        changed_claim = replace(
            result.claims[0],
            text="Changed advisory text",
            claim_digest="",
        )
        changed_proposal = make_private_analysis_proposal(
            proposal_id="proposal-1",
            kind=PrivateAnalysisProposalKind.IDENTITY_MAPPING,
            title="Changed proposal",
            rationale="Still advisory and citation-bound.",
            confidence_basis_points=5000,
            citations=(_citation(reference),),
            payload_schema="router_dump_analyzer.identity-mapping.v1",
            payload={"left": "opaque-a", "right": "opaque-b"},
        )
        result_changes = (
            replace(result, request_digest=_SHA_C, result_digest=""),
            replace(
                result,
                summary=replace(
                    result.summary,
                    text="Changed summary",
                    claim_digest="",
                ),
                result_digest="",
            ),
            replace(result, claims=(changed_claim,), result_digest=""),
            replace(result, proposals=(changed_proposal,), result_digest=""),
        )
        for changed in result_changes:
            with self.subTest(changed=changed):
                self.assertNotEqual(changed.result_digest, result.result_digest)

        error = _error(request)
        other_error = PrivateAnalysisError(
            request_digest=request.request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=PrivateAnalysisErrorCode.RUNNER_FAILED,
            retryable=True,
        )
        self.assertNotEqual(error.error_digest, other_error.error_digest)

        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )
        changed_outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=replace(
                result,
                summary=replace(
                    result.summary,
                    text="changed",
                    claim_digest="",
                ),
                result_digest="",
            ),
            error=None,
        )
        self.assertNotEqual(outcome.outcome_digest, changed_outcome.outcome_digest)

    def test_revision_vector_is_canonical_unique_and_bounded(self) -> None:
        first = _revision("a", ordinal=1)
        second = _revision("b", ordinal=2)
        request = _request(revisions=(first, second))
        self.assertEqual(request.revisions, (first, second))

        invalid_vectors: tuple[object, ...] = (
            (),
            (first, first),
            (second, first),
            [first],
            tuple(
                _revision(f"item-{index:03d}", ordinal=index + 1)
                for index in range(129)
            ),
        )
        for revisions in invalid_vectors:
            with self.subTest(size=len(revisions)), self.assertRaises(
                (TypeError, ValueError)
            ):
                _request(revisions=revisions)  # type: ignore[arg-type]

    def test_claim_support_and_citations_cannot_be_confused(self) -> None:
        citation = _citation()
        with self.assertRaises(ValueError):
            PrivateAnalysisClaim(
                claim_id="claim-supported-without-source",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="This must have evidence.",
                citations=(),
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisClaim(
                claim_id="claim-hypothesis-with-source",
                support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                text="This is explicitly unsupported.",
                citations=(citation,),
            )
        unsupported = PrivateAnalysisClaim(
            claim_id="claim-hypothesis",
            support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
            text="The missing peer might have reset independently.",
            citations=(),
        )
        self.assertEqual(unsupported.citations, ())

        with self.assertRaises(ValueError):
            PrivateAnalysisClaim(
                claim_id="claim-duplicate-citation",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="Duplicate references are non-canonical.",
                citations=(citation, citation),
            )

    def test_claim_and_proposal_revalidate_and_detach_citations(self) -> None:
        citation = _citation()
        original_reference_digest = citation.evidence_reference_digest
        proposal = make_private_analysis_proposal(
            proposal_id="proposal-detached-citation",
            kind=PrivateAnalysisProposalKind.EVENT_CORRELATION,
            title="Detached citation",
            rationale="The proposal must retain a validated citation snapshot.",
            confidence_basis_points=5000,
            citations=(citation,),
            payload_schema="router_dump_analyzer.event-correlation-proposal.v1",
            payload={"left_event": "event-1", "right_event": "event-2"},
        )
        self.assertIsNot(proposal.citations[0], citation)
        object.__setattr__(citation, "evidence_reference_digest", _SHA_B)
        self.assertEqual(
            proposal.citations[0].evidence_reference_digest,
            original_reference_digest,
        )
        with self.assertRaisesRegex(ValueError, "citation digest does not match"):
            make_private_analysis_proposal(
                proposal_id="proposal-reject-stale-citation",
                kind=PrivateAnalysisProposalKind.EVENT_CORRELATION,
                title="Reject stale citation",
                rationale="A cached citation digest must never be trusted.",
                confidence_basis_points=5000,
                citations=(citation,),
                payload_schema=(
                    "router_dump_analyzer.event-correlation-proposal.v1"
                ),
                payload={"left_event": "event-1", "right_event": "event-2"},
            )

    def test_summary_is_a_support_labeled_claim_not_free_form_text(self) -> None:
        request = _request()
        reference = _reference()
        with self.assertRaises(TypeError):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary="An uncited factual conclusion.",  # type: ignore[arg-type]
                claims=(),
                proposals=(),
            )

        supported = _result(request, reference, claims=(), proposals=())
        with self.assertRaises(ValueError):
            validate_private_analysis_result(supported, request, ())

        unsupported_summary = PrivateAnalysisClaim(
            claim_id="summary-hypothesis",
            support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
            text="The missing peer might have reset independently.",
            citations=(),
        )
        hypothesis_only = PrivateAnalysisResult(
            request_digest=request.request_digest,
            summary=unsupported_summary,
            claims=(),
            proposals=(),
        )
        validate_private_analysis_result(hypothesis_only, request, ())

    def test_result_ids_are_unique_across_claims_and_proposals(self) -> None:
        request = _request()
        reference = _reference()
        first_claim = _claim(reference, claim_id="item-1")
        second_claim = replace(
            first_claim,
            text="Different text under the same identifier",
            claim_digest="",
        )
        with self.assertRaises(ValueError):
            _result(
                request,
                reference,
                claims=(first_claim, second_claim),
                proposals=(),
            )

        first_proposal = _proposal(reference, proposal_id="item-2")
        second_proposal = _proposal(
            reference,
            proposal_id="item-2",
            payload={"different": True},
        )
        with self.assertRaises(ValueError):
            _result(
                request,
                reference,
                claims=(),
                proposals=(first_proposal, second_proposal),
            )

        with self.assertRaises(ValueError):
            _result(
                request,
                reference,
                claims=(_claim(reference, claim_id="shared-item"),),
                proposals=(_proposal(reference, proposal_id="shared-item"),),
            )

    def test_validator_rejects_cross_scope_and_cross_revision_citation_laundering(
        self,
    ) -> None:
        request = _request()
        valid_reference = _reference()
        valid_result = _result(request, valid_reference)
        validate_private_analysis_result(
            valid_result,
            request,
            (valid_reference,),
        )

        other_scope_reference = _reference(
            scope=_scope("other"),
            revision=request.revisions[0],
            ordinal=2,
        )
        scope_laundered = _result(request, other_scope_reference)
        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                scope_laundered,
                request,
                (other_scope_reference,),
            )

        other_revision = _revision("other", ordinal=9)
        other_revision_reference = _reference(
            scope=request.scope,
            revision=other_revision,
            ordinal=3,
        )
        revision_laundered = _result(request, other_revision_reference)
        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                revision_laundered,
                request,
                (other_revision_reference,),
            )

        forged_reference = _reference(
            scope=valid_reference.scope,
            revision=valid_reference.revision,
            ordinal=8,
        )
        object.__setattr__(
            forged_reference,
            "reference_digest",
            valid_reference.reference_digest,
        )
        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                valid_result,
                request,
                (forged_reference,),
            )

    def test_validator_requires_exact_disclosure_and_request_binding(self) -> None:
        request = _request()
        reference = _reference()
        result = _result(request, reference)

        with self.assertRaises(ValueError):
            validate_private_analysis_result(result, request, ())

        unrelated = _reference(ordinal=7)
        with self.assertRaises(ValueError):
            validate_private_analysis_result(result, request, (unrelated,))

        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                result,
                request,
                (reference, reference),
            )

        other_request = replace(
            request,
            query="A different request with the same evidence scope",
            request_digest="",
        )
        with self.assertRaises(ValueError):
            validate_private_analysis_result(result, other_request, (reference,))

    def test_validator_enforces_request_specific_output_budgets(self) -> None:
        reference = _reference()
        request = _request(
            limits=_limits(
                max_claims=1,
                max_proposals=1,
                max_output_bytes=1024,
            )
        )
        claims = (
            _claim(reference, claim_id="claim-1"),
            _claim(reference, claim_id="claim-2"),
        )
        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                _result(request, reference, claims=claims, proposals=()),
                request,
                (reference,),
            )

        proposals = (
            _proposal(reference, proposal_id="proposal-1"),
            _proposal(reference, proposal_id="proposal-2"),
        )
        with self.assertRaises(ValueError):
            validate_private_analysis_result(
                _result(request, reference, claims=(), proposals=proposals),
                request,
                (reference,),
            )

        large = _result(
            request,
            reference,
            claims=(
                replace(
                    _claim(reference),
                    text="x" * 4_096,
                    claim_digest="",
                ),
            ),
            proposals=(),
        )
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "_private_analysis_result_payload",
                side_effect=AssertionError("aggregate result must not be built"),
            ),
            self.assertRaises(ValueError),
        ):
            validate_private_analysis_result(large, request, (reference,))

        exact_size_request = _request()
        exact_size_result = _result(exact_size_request, reference)
        exact_size = len(private_analysis_result_json(exact_size_result).encode("utf-8"))
        exact_request = _request(limits=_limits(max_output_bytes=exact_size))
        exact_result = _result(exact_request, reference)
        validate_private_analysis_result(exact_result, exact_request, (reference,))
        below_request = _request(limits=_limits(max_output_bytes=exact_size - 1))
        below_result = _result(below_request, reference)
        with self.assertRaises(ValueError):
            validate_private_analysis_result(below_result, below_request, (reference,))

    def test_runner_request_limits_and_clock_values_are_bounded_and_typed(self) -> None:
        unsafe_identifiers = (
            r"C:\\Users\\alice\\private-runner",
            "/var/lib/private-runner",
            "../../private-runner",
            "https://public-model.invalid/v1",
            "runner\u202esecret",
            " runner ",
            "x" * 4096,
        )
        for value in unsafe_identifiers:
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(_runner(), runner_id=value)

        invalid_limits = (
            {"max_evidence_items": 0},
            {"max_evidence_bytes": 0},
            {"max_tool_calls": -1},
            {"max_output_bytes": 0},
            {"max_claims": 0},
            {"max_proposals": -1},
            {"deadline_ms": 0},
            {"max_evidence_bytes": 1 << 63},
            {"deadline_ms": True},
        )
        for changes in invalid_limits:
            with self.subTest(changes=changes), self.assertRaises(
                (TypeError, ValueError)
            ):
                _limits(**changes)

        request = _request()
        with self.assertRaises(ValueError):
            replace(request, query="", request_digest="")
        with self.assertRaises(ValueError):
            replace(request, query="x" * (2 * 1024 * 1024), request_digest="")
        with self.assertRaises((TypeError, ValueError)):
            replace(
                request,
                task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS.value,
                request_digest="",
            )
        with self.assertRaises((TypeError, ValueError)):
            replace(
                request,
                clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION.value,
                request_digest="",
            )
        with self.assertRaises(ValueError):
            replace(request, selected_time_ns=1, request_digest="")
        with self.assertRaises(ValueError):
            replace(
                request,
                clock_mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                selected_time_ns=None,
                request_digest="",
            )

    def test_wire_collections_fail_before_unbounded_nested_parsing(self) -> None:
        request_wire = private_analysis_request_dict(_request())
        request_wire["revisions"] = [None] * 129
        with self.assertRaises(ValueError):
            private_analysis_request_from_dict(request_wire)

        result_wire = private_analysis_result_dict(
            _result(_request(), _reference())
        )
        result_wire["claims"] = [None] * 512
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "private_analysis_claim_from_dict"
            ) as claim_parser,
            self.assertRaises(ValueError),
        ):
            private_analysis_result_from_dict(result_wire)
        claim_parser.assert_not_called()

        result_wire = private_analysis_result_dict(
            _result(_request(), _reference())
        )
        result_wire["proposals"] = [None] * 257
        with self.assertRaises(ValueError):
            private_analysis_result_from_dict(result_wire)

        result_wire = private_analysis_result_dict(
            _result(_request(), _reference())
        )
        base_proposal = copy.deepcopy(result_wire["proposals"][0])
        large_atom = "x" * 60_000
        oversized_proposals = []
        for index in range(40):
            proposal = copy.deepcopy(base_proposal)
            proposal["proposal_id"] = f"oversized-{index:03d}"
            proposal["payload"] = {
                "blobs": [large_atom] * 4,
                "index": index,
            }
            oversized_proposals.append(proposal)
        result_wire["proposals"] = oversized_proposals
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "private_analysis_proposal_from_dict"
            ) as proposal_parser,
            self.assertRaises(ValueError),
        ):
            private_analysis_result_from_dict(result_wire)
        proposal_parser.assert_not_called()

        claim_wire = private_analysis_claim_dict(_claim(_reference()))
        claim_wire["citations"] = [None] * 129
        with self.assertRaises(ValueError):
            private_analysis_claim_from_dict(claim_wire)

    def test_wire_integer_width_is_bounded_before_decimal_parsing(self) -> None:
        request_wire = private_analysis_request_dict(_request())
        request_wire["revisions"] = []
        request_wire["clock_mode"] = "absolute_unix_ns"
        request_wire["selected_time_ns"] = "-" + "1" * 2_000_000
        with (
            patch(
                "router_dump_analyzer.private_analysis._wire."
                "parse_canonical_decimal_integer"
            ) as decimal_parser,
            self.assertRaises(ValueError),
        ):
            private_analysis_request_from_dict(request_wire)
        decimal_parser.assert_not_called()

    def test_aggregate_wire_limit_includes_required_digest_members(self) -> None:
        request = _request()
        claims = tuple(
            PrivateAnalysisClaim(
                claim_id=f"claim-{index:03d}",
                support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                text="x" * 16_384,
                citations=(),
            )
            for index in range(504)
        )
        with self.assertRaises(ValueError):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary=PrivateAnalysisClaim(
                    claim_id="summary-large",
                    support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                    text="s" * 11_207,
                    citations=(),
                ),
                claims=claims,
                proposals=(),
            )

        escaped_text = "\x00" * 16_384
        escaped_summary = PrivateAnalysisClaim(
            claim_id="summary-escaped",
            support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
            text=escaped_text,
            citations=(),
        )
        escaped_claims = tuple(
            PrivateAnalysisClaim(
                claim_id=f"escaped-{index:03d}",
                support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                text=escaped_text,
                citations=(),
            )
            for index in range(85)
        )
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "strict_canonical_json_sha256"
            ) as aggregate_digest,
            self.assertRaises(ValueError),
        ):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary=escaped_summary,
                claims=escaped_claims,
                proposals=(),
            )
        aggregate_digest.assert_not_called()

    def test_result_bounds_nested_citations_before_wire_projection(self) -> None:
        request = _request()
        summary = _claim()
        citation = _citation()
        object.__setattr__(summary, "citations", (citation,) * 129)
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "_private_analysis_citation_dict_unchecked"
            ) as citation_projection,
            self.assertRaisesRegex(ValueError, "too many citations"),
        ):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary=summary,
                claims=(),
                proposals=(),
            )
        citation_projection.assert_not_called()

        summary = _claim()
        object.__setattr__(summary, "claim_id", "x" * 257)
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "_private_analysis_claim_dict_unchecked"
            ) as claim_projection,
            self.assertRaisesRegex(ValueError, "claim_id"),
        ):
            PrivateAnalysisResult(
                request_digest=request.request_digest,
                summary=summary,
                claims=(),
                proposals=(),
            )
        claim_projection.assert_not_called()

    def test_contract_versions_require_exact_builtin_strings(self) -> None:
        class ForeignString(str):
            pass

        request = _request()
        reference = _reference()
        citation = _citation(reference)
        claim = _claim(reference)
        proposal = _proposal(reference)
        result = _result(request, reference)
        error = PrivateAnalysisError(
            request_digest=request.request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=PrivateAnalysisErrorCode.RUNNER_FAILED,
            retryable=True,
        )
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
        )
        values = (
            (request, "request_digest"),
            (citation, "citation_digest"),
            (claim, "claim_digest"),
            (proposal, "proposal_digest"),
            (result, "result_digest"),
            (error, "error_digest"),
            (outcome, "outcome_digest"),
        )
        for value, digest_field in values:
            with self.subTest(value=type(value).__name__), self.assertRaises(
                ValueError
            ):
                replace(
                    value,
                    contract_version=ForeignString(value.contract_version),
                    **{digest_field: ""},
                )

        request_wire = private_analysis_request_dict(request)
        oversized_key_set = {f"field-{index}": None for index in range(10_000)}
        with self.assertRaises(ValueError):
            private_analysis_request_from_dict(oversized_key_set)

        foreign_key_wire = {
            ForeignString(key): value for key, value in request_wire.items()
        }
        with self.assertRaises(ValueError):
            private_analysis_request_from_dict(foreign_key_wire)

    def test_closed_enums_reject_class_spoofing_objects(self) -> None:
        class FakeEnum:
            def __init__(self, enum_type: type[object], value: str) -> None:
                self._enum_type = enum_type
                self.value = value

            @property
            def __class__(self) -> type[object]:
                return self._enum_type

        request = _request()
        reference = _reference()
        claim = _claim(reference)
        proposal = _proposal(reference)
        error = _error(request)
        result = _result(request, reference)
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
        )
        cases = (
            (
                request.runner,
                {
                    "transport": FakeEnum(
                        PrivateAnalysisTransport,
                        "public_network",
                    )
                },
            ),
            (
                request,
                {
                    "task_kind": FakeEnum(
                        PrivateAnalysisTaskKind,
                        PrivateAnalysisTaskKind.LTTNG_ANALYSIS.value,
                    ),
                    "request_digest": "",
                },
            ),
            (
                request,
                {
                    "clock_mode": FakeEnum(
                        PrivateAnalysisClockMode,
                        PrivateAnalysisClockMode.LATEST_PER_REVISION.value,
                    ),
                    "selected_time_ns": 1,
                    "request_digest": "",
                },
            ),
            (
                claim,
                {
                    "support": FakeEnum(
                        PrivateAnalysisClaimSupport,
                        PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED.value,
                    ),
                    "citations": (),
                    "claim_digest": "",
                },
            ),
            (
                proposal,
                {
                    "kind": FakeEnum(
                        PrivateAnalysisProposalKind,
                        PrivateAnalysisProposalKind.EVENT_CORRELATION.value,
                    ),
                    "proposal_digest": "",
                },
            ),
            (
                error,
                {
                    "stage": FakeEnum(
                        PrivateAnalysisErrorStage,
                        PrivateAnalysisErrorStage.OUTPUT_VALIDATION.value,
                    ),
                    "error_digest": "",
                },
            ),
            (
                error,
                {
                    "code": FakeEnum(
                        PrivateAnalysisErrorCode,
                        PrivateAnalysisErrorCode.INVALID_RESULT.value,
                    ),
                    "error_digest": "",
                },
            ),
            (
                outcome,
                {
                    "kind": FakeEnum(
                        PrivateAnalysisOutcomeKind,
                        PrivateAnalysisOutcomeKind.RESULT.value,
                    ),
                    "result": None,
                    "error": error,
                    "outcome_digest": "",
                },
            ),
        )
        for value, changes in cases:
            with self.subTest(value=type(value).__name__), self.assertRaises(
                TypeError
            ):
                replace(value, **changes)

        direct_constructors = (
            lambda: PrivateAnalysisPolicy(
                transport=FakeEnum(
                    PrivateAnalysisTransport,
                    PrivateAnalysisTransport.IN_PROCESS.value,
                )  # type: ignore[arg-type]
            ),
            lambda: WorkspaceDisclosurePolicy(
                mode=FakeEnum(
                    PrivateAnalysisDisclosureMode,
                    PrivateAnalysisDisclosureMode.DISABLED.value,
                ),  # type: ignore[arg-type]
            ),
            lambda: WorkspaceDisclosurePolicy(
                mode=PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                transports=(
                    FakeEnum(
                        PrivateAnalysisTransport,
                        PrivateAnalysisTransport.IN_PROCESS.value,
                    ),  # type: ignore[arg-type]
                ),
            ),
            lambda: DisclosureDecision(
                policy_digest="1" * 64,
                scope_digest="2" * 64,
                transport=FakeEnum(
                    PrivateAnalysisTransport,
                    PrivateAnalysisTransport.IN_PROCESS.value,
                ),  # type: ignore[arg-type]
                evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
                allowed=True,
                reason=DisclosureDecisionReason.ALLOWED,
            ),
            lambda: EvidenceProducer(
                authority=FakeEnum(
                    EvidenceAuthority,
                    EvidenceAuthority.CORE_CORROBORATION.value,
                ),  # type: ignore[arg-type]
                producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
            ),
            lambda: EvidenceTimeRange(
                basis=FakeEnum(
                    type(reference.time_range.basis),
                    reference.time_range.basis.value,
                )  # type: ignore[arg-type]
            ),
        )
        for constructor in direct_constructors:
            with self.assertRaises(TypeError):
                constructor()

        reference_enum_changes = (
            {
                "kind": FakeEnum(EvidenceKind, reference.kind.value),
                "reference_digest": "",
            },
            {
                "evidence_class": FakeEnum(
                    PrivateAnalysisEvidenceClass,
                    reference.evidence_class.value,
                ),
                "reference_digest": "",
            },
            {
                "fact_provenance": FakeEnum(
                    EvidenceFactProvenance,
                    reference.fact_provenance.value,
                ),
                "reference_digest": "",
            },
        )
        for changes in reference_enum_changes:
            with self.assertRaises(TypeError):
                replace(reference, **changes)

    def test_proposal_payload_is_canonical_bounded_and_advisory_only(self) -> None:
        reference = _reference()

        class BombInt(int):
            def bit_length(self) -> int:
                raise RuntimeError("subclass method must not run")

        class BombList(list[object]):
            def __iter__(self):  # type: ignore[no-untyped-def]
                raise RuntimeError("subclass method must not run")

        class BombDict(dict[str, object]):
            def items(self):  # type: ignore[no-untyped-def]
                raise RuntimeError("subclass method must not run")

        metaclass_calls: list[str] = []

        class TrapMeta(type):
            def __getattribute__(cls, name: str) -> object:
                if name == "__name__":
                    metaclass_calls.append(name)
                return super().__getattribute__(name)

        class Trap(metaclass=TrapMeta):
            pass

        invalid_payloads: tuple[object, ...] = (
            {"tuple": (1, 2)},
            {"set": {1, 2}},
            {"nan": math.nan},
            {"infinite": math.inf},
            {"unsafe_integer": 1 << 60},
            {"surrogate": "\ud800"},
            {"large": "x" * (2 * 1024 * 1024)},
            {"subclass": BombInt(1)},
            {"subclass": BombList([1])},
            {"subclass": BombDict({"value": 1})},
            {"subclass": Trap()},
        )
        for payload in invalid_payloads:
            with self.subTest(payload_type=type(payload).__name__), self.assertRaises(
                (TypeError, ValueError)
            ):
                _proposal(reference, payload=payload)  # type: ignore[arg-type]

        self.assertEqual(metaclass_calls, [])

        for payload in invalid_payloads[-4:]:
            with self.assertRaises(ValueError):
                evidence_locator_digest(
                    "adversarial-locator",
                    payload,  # type: ignore[arg-type]
                )
        self.assertEqual(metaclass_calls, [])

        shared_atom = "x" * 65_536
        aggregate_oversize = {"items": [shared_atom] * 5}
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts."
                "strict_canonical_json"
            ) as proposal_serializer,
            self.assertRaises(ValueError),
        ):
            _proposal(reference, payload=aggregate_oversize)
        proposal_serializer.assert_not_called()

        with (
            patch(
                "router_dump_analyzer.private_analysis.evidence."
                "strict_canonical_json"
            ) as locator_serializer,
            self.assertRaises(ValueError),
        ):
            evidence_locator_digest("large-locator", aggregate_oversize)
        locator_serializer.assert_not_called()

        evidence_oversize = {"items": [shared_atom] * 17}
        with (
            patch(
                "router_dump_analyzer.private_analysis.evidence."
                "strict_canonical_json"
            ) as evidence_serializer,
            self.assertRaises(ValueError),
        ):
            evidence_payload_digest("large-evidence.v1", evidence_oversize)
        evidence_serializer.assert_not_called()

        cyclic: dict[str, Any] = {}
        cyclic["self"] = cyclic
        with self.assertRaises(ValueError):
            _proposal(reference, payload=cyclic)

        proposal = _proposal(reference)
        oversized_wire = (
            " " * (MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES + 1) + "{}"
        )
        with (
            patch(
                "router_dump_analyzer.private_analysis.contracts.json.loads"
            ) as json_loads,
            self.assertRaises(ValueError),
        ):
            replace(
                proposal,
                payload_json=oversized_wire,
                proposal_digest="",
            )
        json_loads.assert_not_called()

        self.assertEqual(proposal.provenance, "assistant_suggested")
        with self.assertRaises((TypeError, ValueError)):
            replace(
                proposal,
                provenance="plugin_inferred",
                proposal_digest="",
            )
        with self.assertRaises((TypeError, ValueError)):
            replace(
                proposal,
                confidence_basis_points=10_001,
                proposal_digest="",
            )

        for forbidden in (
            "plugin_inferred",
            "core_corroboration",
            "user_assertion",
            "ground_truth_mutation",
            "derived_revision_write",
        ):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                PrivateAnalysisProposalKind(forbidden)

    def test_error_taxonomy_is_closed_retryability_is_fixed_and_message_is_safe(
        self,
    ) -> None:
        request = _request()
        error = _error(request)
        self.assertEqual(error.stage, PrivateAnalysisErrorStage.OUTPUT_VALIDATION)
        self.assertEqual(error.code, PrivateAnalysisErrorCode.INVALID_RESULT)
        self.assertFalse(error.retryable)
        self.assertTrue(error.safe_message)
        self.assertLessEqual(len(error.safe_message), 256)
        self.assertNotIn(request.query, error.safe_message)
        self.assertNotIn("/", error.safe_message)
        self.assertNotIn("\\", error.safe_message)

        retryable_codes = {
            PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
            PrivateAnalysisErrorCode.TIMEOUT,
        }
        for code in PrivateAnalysisErrorCode:
            expected = code in retryable_codes
            # INVALID_RESULT is the canonical output-stage error; runner codes
            # are runner-stage errors. Other code/stage pairings are covered by
            # the exact closed taxonomy in their own parser tests.
            stage = (
                PrivateAnalysisErrorStage.OUTPUT_VALIDATION
                if code is PrivateAnalysisErrorCode.INVALID_RESULT
                else PrivateAnalysisErrorStage.RUNNER
            )
            try:
                value = PrivateAnalysisError(
                    request_digest=request.request_digest,
                    stage=stage,
                    code=code,
                    retryable=expected,
                )
            except ValueError:
                continue
            with self.subTest(code=code), self.assertRaises(ValueError):
                replace(value, retryable=not expected, error_digest="")

        with self.assertRaises((TypeError, ValueError)):
            replace(error, stage="runner", error_digest="")
        with self.assertRaises((TypeError, ValueError)):
            replace(error, code="invalid_result", error_digest="")
        with self.assertRaises(TypeError):
            PrivateAnalysisError(
                request_digest=request.request_digest,
                stage=PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                code=PrivateAnalysisErrorCode.INVALID_RESULT,
                retryable=False,
                detail=r"C:\\Users\\alice\\secret.txt",  # type: ignore[call-arg]
            )
        with self.assertRaises(TypeError):
            PrivateAnalysisError(
                request_digest=request.request_digest,
                stage=PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
                code=PrivateAnalysisErrorCode.INVALID_RESULT,
                retryable=False,
                message="arbitrary model output",  # type: ignore[call-arg]
            )

        pre_request = PrivateAnalysisError(
            request_digest=None,
            stage=PrivateAnalysisErrorStage.REQUEST_VALIDATION,
            code=PrivateAnalysisErrorCode.INVALID_REQUEST,
            retryable=False,
        )
        self.assertIsNone(pre_request.request_digest)

    def test_outcome_is_exactly_one_of_result_or_error(self) -> None:
        request = _request()
        result = _result(request)
        error = _error(request)
        with self.assertRaises(ValueError):
            PrivateAnalysisOutcome(
                kind=PrivateAnalysisOutcomeKind.RESULT,
                result=None,
                error=None,
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisOutcome(
                kind=PrivateAnalysisOutcomeKind.RESULT,
                result=result,
                error=error,
            )

        success = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )
        failure = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.ERROR,
            result=None,
            error=error,
        )
        self.assertEqual(success.result, result)
        self.assertIsNot(success.result, result)
        self.assertIsNone(success.error)
        self.assertIsNone(failure.result)
        self.assertEqual(failure.error, error)
        self.assertIsNot(failure.error, error)

    def test_exact_wire_parsers_reject_unknown_missing_and_duplicate_fields(self) -> None:
        request = _request()
        result = _result(request)
        error = _error(request)
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )
        cases = (
            (
                private_analysis_request_dict(request),
                private_analysis_request_from_dict,
                private_analysis_request_json(request),
                private_analysis_request_from_json,
            ),
            (
                private_analysis_result_dict(result),
                private_analysis_result_from_dict,
                private_analysis_result_json(result),
                private_analysis_result_from_json,
            ),
            (
                private_analysis_error_dict(error),
                private_analysis_error_from_dict,
                private_analysis_error_json(error),
                private_analysis_error_from_json,
            ),
            (
                private_analysis_outcome_dict(outcome),
                private_analysis_outcome_from_dict,
                private_analysis_outcome_json(outcome),
                private_analysis_outcome_from_json,
            ),
        )
        for wire, from_dict, encoded, from_json in cases:
            with self.subTest(contract=wire.get("contract_version")):
                unknown = copy.deepcopy(wire)
                unknown["detail"] = "must never cross this boundary"
                with self.assertRaises(ValueError):
                    from_dict(unknown)

                missing = copy.deepcopy(wire)
                missing.pop("contract_version")
                with self.assertRaises(ValueError):
                    from_dict(missing)

                future = copy.deepcopy(wire)
                future["contract_version"] = "future"
                with self.assertRaises(ValueError):
                    from_dict(future)

                pretty = json.dumps(wire, ensure_ascii=False, indent=2)
                with self.assertRaises(ValueError):
                    from_json(pretty)

                duplicate = encoded.replace(
                    '"contract_version":',
                    '"contract_version":"duplicate","contract_version":',
                    1,
                )
                with self.assertRaises(ValueError):
                    from_json(duplicate)

    def test_exact_wire_parsers_require_all_digests_and_detect_tampering(self) -> None:
        request = _request()
        result = _result(request)
        error = _error(request)
        outcome = PrivateAnalysisOutcome(
            kind=PrivateAnalysisOutcomeKind.RESULT,
            result=result,
            error=None,
        )
        cases = (
            (private_analysis_request_dict(request), private_analysis_request_from_dict),
            (private_analysis_result_dict(result), private_analysis_result_from_dict),
            (private_analysis_error_dict(error), private_analysis_error_from_dict),
            (private_analysis_outcome_dict(outcome), private_analysis_outcome_from_dict),
        )
        for wire, parser in cases:
            digest_paths = _nonempty_digest_paths(wire)
            self.assertTrue(digest_paths)
            for path in digest_paths:
                with self.subTest(contract=wire.get("contract_version"), path=path):
                    missing_digest = copy.deepcopy(wire)
                    _set_path(missing_digest, path, "")
                    with self.assertRaises((TypeError, ValueError)):
                        parser(missing_digest)

        tampered_request = private_analysis_request_dict(request)
        tampered_request["query"] = "tampered query"
        with self.assertRaises(ValueError):
            private_analysis_request_from_dict(tampered_request)

        tampered_result = private_analysis_result_dict(result)
        tampered_result["summary"] = "tampered summary"
        with self.assertRaises(ValueError):
            private_analysis_result_from_dict(tampered_result)

        tampered_error = private_analysis_error_dict(error)
        tampered_error["retryable"] = True
        with self.assertRaises(ValueError):
            private_analysis_error_from_dict(tampered_error)

        tampered_outcome = private_analysis_outcome_dict(outcome)
        nested_result = tampered_outcome["result"]
        assert isinstance(nested_result, dict)
        nested_result["summary"] = "tampered nested result"
        with self.assertRaises(ValueError):
            private_analysis_outcome_from_dict(tampered_outcome)

    def test_nested_wire_values_reject_unknown_fields_and_authority_spoofing(self) -> None:
        request_wire = private_analysis_request_dict(_request())
        runner = request_wire["runner"]
        assert isinstance(runner, dict)
        runner["endpoint"] = "https://public-model.invalid/v1"
        with self.assertRaises(ValueError):
            private_analysis_request_from_dict(request_wire)

        result_wire = private_analysis_result_dict(_result())
        claim = result_wire["claims"][0]
        assert isinstance(claim, dict)
        claim["plugin_authority"] = True
        with self.assertRaises(ValueError):
            private_analysis_result_from_dict(result_wire)

        result_wire = private_analysis_result_dict(_result())
        proposal = result_wire["proposals"][0]
        assert isinstance(proposal, dict)
        proposal["provenance"] = "plugin_inferred"
        with self.assertRaises(ValueError):
            private_analysis_result_from_dict(result_wire)

        result_wire = private_analysis_result_dict(_result())
        citation = result_wire["claims"][0]["citations"][0]
        assert isinstance(citation, dict)
        citation["source_path"] = r"C:\\private\\dump.json"
        with self.assertRaises(ValueError):
            private_analysis_result_from_dict(result_wire)

    def test_public_identifiers_reject_paths_urls_controls_and_bidi_text(self) -> None:
        unsafe = (
            r"C:\\Users\\alice\\secret",
            r"\\server\\share\\dump",
            "/var/lib/router/dump",
            "../../tenant-secret",
            "file:///tmp/dump",
            "https://model.invalid/v1",
            "identifier\u0000suffix",
            "safe\u202eevil",
            " leading",
            "trailing ",
        )
        for value in unsafe:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    replace(_claim(), claim_id=value, claim_digest="")
                with self.assertRaises(ValueError):
                    _proposal(proposal_id=value)


if __name__ == "__main__":
    unittest.main()
