from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from router_dump_analyzer.annotation_store import ReviewScope
from router_dump_analyzer.canonical import strict_canonical_json
from router_dump_analyzer.control_plane import ControlPlane, ControlPlaneError
from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
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
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisLimits,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    evidence_locator_digest,
    evidence_payload_digest,
)
from router_dump_analyzer.private_analysis_binding import (
    bind_private_analysis_revision,
)
from router_dump_analyzer.private_analysis_run_store import (
    PrivateAnalysisRunConflict,
    PrivateAnalysisRunCorruptionError,
    PrivateAnalysisRunNotFound,
    PrivateAnalysisRunRetentionDisabled,
    PrivateAnalysisRunRetentionPolicy,
    PrivateAnalysisRunStaleVersion,
    PrivateAnalysisRunState,
    SqlitePrivateAnalysisRunStore,
)
from router_dump_analyzer.private_analysis_runner_support import (
    PrivateAnalysisInProcessTranscriptSummaryMetadata,
    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
    PrivateAnalysisTranscriptSummary,
    private_analysis_budget_payload,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
)
from router_dump_analyzer.session_store import CatalogRetentionPolicy

_SHA_A = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64
_SHA_C = "sha256:" + "c" * 64
_SHA_D = "sha256:" + "d" * 64
_SHA_E = "sha256:" + "e" * 64
_POLICY = "f" * 64


def _scope(suffix: str = "a") -> EvidenceScope:
    return EvidenceScope(
        tenant_id=f"tenant-{suffix}",
        project_id=f"project-{suffix}",
        workspace_id=f"workspace-{suffix}",
    )


def _revision(ordinal: int) -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{ordinal:03d}",
        fixture_content_sha256=f"{ordinal:064x}",
        node_id=f"node-{ordinal:03d}",
        revision_id=f"revision-{ordinal:03d}",
        revision_identity_sha256=f"{ordinal + 100:064x}",
        plan_basis_revision_id=f"basis-{ordinal:03d}",
        execution_plan_digest="sha256:" + f"{ordinal + 200:064x}",
    )


def _execution_plan(node_id: str, suffix: str) -> PluginExecutionPlan:
    pin = PluginExecutionPin(
        instance_id=f"parser-{suffix}",
        plugin_id="test.private-analysis",
        plugin_version="1.0.0",
        core_api_version="1",
        artifact=PluginArtifactIdentity(
            distribution_name="test-private-analysis",
            distribution_version="1.0.0",
            package_hash="sha256:" + suffix * 64,
            entry_point_name=f"parser-{suffix}",
            module_target="test_private_analysis:plugin",
        ),
        configuration_digest="sha256:" + "c" * 64,
        schema_digest="sha256:" + "d" * 64,
        capabilities=("source_record_parser",),
        roles=("primary_parser",),
    )
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id=f"basis-{suffix}",
        plugins=(pin,),
    )


def _request(
    *,
    scope: EvidenceScope | None = None,
    revisions: tuple[EvidenceRevisionBinding, ...] | None = None,
    transport: PrivateAnalysisTransport = PrivateAnalysisTransport.IN_PROCESS,
    query: str = "Correlate the private route and LTTng evidence.",
) -> PrivateAnalysisRequest:
    return PrivateAnalysisRequest(
        scope=scope or _scope(),
        revisions=revisions or (_revision(1), _revision(2)),
        runner=PrivateAnalysisRunnerSelection(
            runner_id="deployment.private-runner",
            runner_version="1.0.0",
            transport=transport,
            configuration_digest=_SHA_A,
        ),
        workspace_policy_digest=_POLICY,
        instruction_profile_digest=_SHA_B,
        tool_catalog_digest=_SHA_C,
        task_kind=PrivateAnalysisTaskKind.ROUTE_TRACE_ANALYSIS,
        query=query,
        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
        selected_time_ns=None,
        limits=PrivateAnalysisLimits(
            max_evidence_items=8,
            max_evidence_bytes=65_536,
            max_tool_calls=4,
            max_output_bytes=65_536,
            max_claims=4,
            max_proposals=2,
            deadline_ms=30_000,
        ),
    )


def _budget(
    request: PrivateAnalysisRequest,
    *,
    calls: int = 0,
    items: int = 0,
    evidence_bytes: int = 0,
) -> PrivateAnalysisToolBudgetState:
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=request.limits.max_tool_calls,
        tool_calls_consumed=calls,
        max_evidence_items=request.limits.max_evidence_items,
        evidence_items_disclosed=items,
        max_evidence_bytes=request.limits.max_evidence_bytes,
        evidence_bytes_disclosed=evidence_bytes,
    )


def _outcome(
    request: PrivateAnalysisRequest,
    code: PrivateAnalysisErrorCode = PrivateAnalysisErrorCode.RUNNER_FAILED,
) -> PrivateAnalysisOutcome:
    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=PrivateAnalysisError(
            request_digest=request.request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=code,
            retryable=code
            in {
                PrivateAnalysisErrorCode.RUNNER_FAILED,
                PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
                PrivateAnalysisErrorCode.TIMEOUT,
            },
        ),
    )


def _result_outcome(
    request: PrivateAnalysisRequest,
    reference: EvidenceReference,
) -> PrivateAnalysisOutcome:
    citation = PrivateAnalysisCitation(
        evidence_reference_digest=reference.reference_digest,
    )
    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.RESULT,
        result=PrivateAnalysisResult(
            request_digest=request.request_digest,
            summary=PrivateAnalysisClaim(
                claim_id="summary-1",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="The private route event is present.",
                citations=(citation,),
            ),
            claims=(),
            proposals=(),
        ),
    )


def _summary(
    request: PrivateAnalysisRequest,
    outcome: PrivateAnalysisOutcome,
    budget: PrivateAnalysisToolBudgetState,
    ledger_digest: str,
) -> PrivateAnalysisTranscriptSummary:
    if request.runner.transport is PrivateAnalysisTransport.IN_PROCESS:
        metadata = PrivateAnalysisInProcessTranscriptSummaryMetadata(
            transcript_digest=_SHA_D,
            exchange_count=budget.tool_calls_consumed,
            unattributed_tool_call_count=0,
            exchange_metadata_bytes=32,
            exchange_chain_digest=_SHA_E,
        )
    else:
        metadata = PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
            transcript_digest=_SHA_D,
            launch_configuration_digest=_SHA_E,
            run_digest=_SHA_B,
            message_count=2,
            tool_call_count=budget.tool_calls_consumed,
            message_metadata_bytes=64,
            message_chain_digest=_SHA_C,
            stderr_bytes=0,
        )
    return PrivateAnalysisTranscriptSummary(
        transport=request.runner.transport,
        request_digest=request.request_digest,
        catalog_digest=request.tool_catalog_digest,
        instruction_profile_digest=request.instruction_profile_digest,
        runner_configuration_digest=request.runner.configuration_digest,
        outcome_digest=outcome.outcome_digest,
        evidence_ledger_digest=ledger_digest,
        budget_state=budget,
        metadata=metadata,
    )


def _reference(request: PrivateAnalysisRequest) -> EvidenceReference:
    payload = {"event": "route_withdrawn", "prefix": "203.0.113.0/24"}
    return EvidenceReference(
        scope=request.scope,
        revision=request.revisions[0],
        producer=EvidenceProducer(
            authority=EvidenceAuthority.CORE_CORROBORATION,
            producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
        ),
        kind=EvidenceKind.EVENT,
        subject_kind="route_event",
        locator_digest=evidence_locator_digest("route_event", {"event_id": "event-1"}),
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        payload_schema="vendor.route-event.v1",
        fact_provenance=EvidenceFactProvenance.CORE_CORROBORATED,
        time_range=EvidenceTimeRange.not_applicable(),
        content_digest=evidence_payload_digest("vendor.route-event.v1", payload),
    )


class PrivateAnalysisRunStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "runs.sqlite3"
        self.validated: list[str] = []

        def validator(request: PrivateAnalysisRequest) -> None:
            self.validated.append(request.request_digest)

        self.validator = validator
        self.store = SqlitePrivateAnalysisRunStore(
            self.database,
            admission_validator=self.validator,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def test_multi_revision_admission_is_scoped_idempotent_and_reopenable(self) -> None:
        request = _request()
        created = self.store.create_run(
            request,
            actor_id="operator-1",
            idempotency_key="admission-1",
            run_id="run-1",
            now_ns=100,
        )
        replay = self.store.create_run(
            request,
            actor_id="operator-1",
            idempotency_key="admission-1",
            run_id="ignored-on-replay",
            now_ns=101,
        )
        self.assertEqual(replay, created)
        self.assertEqual(
            self.store.referenced_revision_ids(request.scope),
            ("revision-001", "revision-002"),
        )
        with self.assertRaises(PrivateAnalysisRunConflict):
            self.store.create_run(
                _request(query="Different proprietary request"),
                actor_id="operator-1",
                idempotency_key="admission-1",
                now_ns=102,
            )
        with self.assertRaises(PrivateAnalysisRunNotFound):
            self.store.get_run(_scope("foreign"), "run-1")
        self.store.close()
        self.store = SqlitePrivateAnalysisRunStore(
            self.database,
            admission_validator=self.validator,
        )
        self.assertEqual(self.store.get_run(request.scope, "run-1"), created)
        self.assertEqual(len(self.validated), 3)

    def test_claim_accounting_and_terminal_receipt_are_sealed(self) -> None:
        for index, transport in enumerate(
            (
                PrivateAnalysisTransport.IN_PROCESS,
                PrivateAnalysisTransport.LOCAL_SUBPROCESS,
            ),
            1,
        ):
            request = _request(transport=transport)
            record = self.store.create_run(
                request,
                actor_id="operator-1",
                idempotency_key=f"admission-{index}",
                run_id=f"run-{index}",
                now_ns=100 * index,
            )
            record = self.store.claim_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                actor_id="worker-1",
                execution_id=f"attempt-{index}",
                lease_duration_ns=10_000,
                now_ns=100 * index + 1,
            )
            reference = _reference(request)
            budget = _budget(request, calls=1, items=1, evidence_bytes=512)
            record = self.store.commit_accounting(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id=f"attempt-{index}",
                references=(reference,),
                budget_state=budget,
                actor_id="worker-1",
                now_ns=100 * index + 2,
            )
            outcome = _outcome(request)
            summary = _summary(
                request,
                outcome,
                budget,
                record.evidence_ledger_digest,
            )
            completed = self.store.complete_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id=f"attempt-{index}",
                outcome=outcome,
                transcript_summary=summary,
                references=(reference,),
                budget_state=budget,
                actor_id="worker-1",
                now_ns=100 * index + 3,
            )
            replay = self.store.complete_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id=f"attempt-{index}",
                outcome=outcome,
                transcript_summary=summary,
                references=(reference,),
                budget_state=budget,
                actor_id="worker-1",
                now_ns=100 * index + 4,
            )
            self.assertEqual(replay, completed)
            self.assertEqual(completed.state, PrivateAnalysisRunState.COMPLETED)
            self.assertEqual(completed.transcript_summary, summary)
            self.assertEqual(
                tuple(
                    item.sequence
                    for item in self.store.list_audit(request.scope, record.run_id)
                ),
                (1, 2, 3, 4),
            )

    def test_terminal_receipt_requires_write_ahead_accounting(self) -> None:
        request = _request()
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="admission",
            run_id="run",
            now_ns=10,
        )
        record = self.store.claim_run(
            request.scope,
            "run",
            expected_version=record.version,
            actor_id="worker",
            execution_id="attempt",
            lease_duration_ns=100,
            now_ns=11,
        )
        reference = _reference(request)
        budget = _budget(request, calls=1, items=1, evidence_bytes=64)
        outcome = _outcome(request)
        from router_dump_analyzer.private_analysis import evidence_snapshot_digest

        summary = _summary(
            request,
            outcome,
            budget,
            evidence_snapshot_digest((reference,)),
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRunConflict,
            "write-ahead ledger",
        ):
            self.store.complete_run(
                request.scope,
                "run",
                expected_version=record.version,
                execution_id="attempt",
                outcome=outcome,
                transcript_summary=summary,
                references=(reference,),
                budget_state=budget,
                actor_id="worker",
                now_ns=12,
            )
        self.assertEqual(self.store.get_run(request.scope, "run"), record)

    def test_terminal_result_is_revalidated_against_exact_durable_ledger(
        self,
    ) -> None:
        request = _request()
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="result-validation",
            run_id="result-validation",
            now_ns=10,
        )
        record = self.store.claim_run(
            request.scope,
            record.run_id,
            expected_version=record.version,
            actor_id="worker",
            execution_id="result-attempt",
            lease_duration_ns=100,
            now_ns=11,
        )
        # The result cites a real request-bound reference, but that reference
        # was never disclosed or committed to this run's durable ledger.
        outcome = _result_outcome(request, _reference(request))
        with self.assertRaisesRegex(
            PrivateAnalysisRunConflict,
            "terminal result violates",
        ):
            self.store.complete_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id="result-attempt",
                outcome=outcome,
                transcript_summary=_summary(
                    request,
                    outcome,
                    record.budget_state,
                    record.evidence_ledger_digest,
                ),
                references=(),
                budget_state=record.budget_state,
                actor_id="worker",
                now_ns=12,
            )
        self.assertEqual(self.store.get_run(request.scope, record.run_id), record)

    def test_cancellation_and_expired_claims_are_race_linearized(self) -> None:
        request = _request()
        queued = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="queued",
            run_id="queued",
            now_ns=10,
        )
        cancelled = self.store.request_cancellation(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="operator",
            now_ns=11,
        )
        self.assertEqual(cancelled.state, PrivateAnalysisRunState.CANCELLED)

        running = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="running",
            run_id="running",
            now_ns=20,
        )
        running = self.store.claim_run(
            request.scope,
            running.run_id,
            expected_version=running.version,
            actor_id="worker",
            execution_id="attempt-running",
            lease_duration_ns=10,
            now_ns=21,
        )
        running = self.store.request_cancellation(
            request.scope,
            running.run_id,
            expected_version=running.version,
            actor_id="operator",
            now_ns=22,
        )
        recovered = self.store.recover_expired_runs(
            actor_id="recovery",
            now_ns=32,
        )
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].state, PrivateAnalysisRunState.CANCELLED)

        expired = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="expired",
            run_id="expired",
            now_ns=40,
        )
        self.store.claim_run(
            request.scope,
            expired.run_id,
            expected_version=expired.version,
            actor_id="worker",
            execution_id="attempt-expired",
            lease_duration_ns=10,
            now_ns=41,
        )
        failed = self.store.recover_expired_runs(actor_id="recovery", now_ns=52)
        self.assertEqual(failed[0].state, PrivateAnalysisRunState.COMPLETED)
        self.assertEqual(
            failed[0].outcome.error.code
            if failed[0].outcome and failed[0].outcome.error
            else None,
            PrivateAnalysisErrorCode.RUNNER_FAILED,
        )

    def test_concurrent_claim_uses_one_execution_fence(self) -> None:
        request = _request()
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="admission",
            run_id="run",
            now_ns=10,
        )
        other = SqlitePrivateAnalysisRunStore(
            self.database,
            admission_validator=self.validator,
        )
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def claim(store: SqlitePrivateAnalysisRunStore, suffix: str) -> None:
            barrier.wait(timeout=5)
            try:
                store.claim_run(
                    request.scope,
                    record.run_id,
                    expected_version=record.version,
                    actor_id="worker",
                    execution_id=f"attempt-{suffix}",
                    lease_duration_ns=100,
                    now_ns=11,
                )
            except (PrivateAnalysisRunStaleVersion, PrivateAnalysisRunConflict):
                outcomes.append("conflict")
            else:
                outcomes.append("claimed")

        threads = (
            threading.Thread(target=claim, args=(self.store, "a")),
            threading.Thread(target=claim, args=(other, "b")),
        )
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertEqual(sorted(outcomes), ["claimed", "conflict"])
        finally:
            other.close()

    def test_multi_statement_read_uses_one_wal_snapshot(self) -> None:
        request = _request()
        queued = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="snapshot",
            run_id="snapshot-run",
            now_ns=10,
        )
        running = self.store.claim_run(
            request.scope,
            queued.run_id,
            expected_version=queued.version,
            actor_id="worker",
            execution_id="snapshot-attempt",
            lease_duration_ns=100,
            now_ns=11,
        )
        writer = SqlitePrivateAnalysisRunStore(
            self.database,
            admission_validator=self.validator,
        )
        try:
            with self.store._read_cursor() as cursor:
                old_row = self.store._require_run_row(
                    cursor,
                    request.scope,
                    running.run_id,
                )
                committed = writer.commit_accounting(
                    request.scope,
                    running.run_id,
                    expected_version=running.version,
                    execution_id="snapshot-attempt",
                    references=(),
                    budget_state=_budget(request, calls=1),
                    actor_id="worker",
                    now_ns=12,
                )
                reconstructed = self.store._record_from_row(cursor, old_row)
            self.assertEqual(reconstructed, running)
            self.assertEqual(
                self.store.get_run(request.scope, running.run_id), committed
            )
        finally:
            writer.close()

    def test_audit_seals_budget_and_retention_timestamps(self) -> None:
        for field in ("budget_json", "completed_at_ns"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                database = Path(directory) / "runs.sqlite3"
                store = SqlitePrivateAnalysisRunStore(
                    database,
                    admission_validator=self.validator,
                )
                request = _request()
                record = store.create_run(
                    request,
                    actor_id="operator",
                    idempotency_key="audit",
                    run_id="audit-run",
                    now_ns=10,
                )
                record = store.claim_run(
                    request.scope,
                    record.run_id,
                    expected_version=record.version,
                    actor_id="worker",
                    execution_id="audit-attempt",
                    lease_duration_ns=100,
                    now_ns=11,
                )
                budget = _budget(request, calls=1)
                record = store.commit_accounting(
                    request.scope,
                    record.run_id,
                    expected_version=record.version,
                    execution_id="audit-attempt",
                    references=(),
                    budget_state=budget,
                    actor_id="worker",
                    now_ns=12,
                )
                outcome = _outcome(request)
                completed = store.complete_run(
                    request.scope,
                    record.run_id,
                    expected_version=record.version,
                    execution_id="audit-attempt",
                    outcome=outcome,
                    transcript_summary=_summary(
                        request,
                        outcome,
                        budget,
                        record.evidence_ledger_digest,
                    ),
                    references=(),
                    budget_state=budget,
                    actor_id="worker",
                    now_ns=13,
                )
                connection = sqlite3.connect(database)
                try:
                    if field == "budget_json":
                        connection.execute(
                            """
                            UPDATE private_analysis_runs SET budget_json = ?
                            WHERE run_id = ?
                            """,
                            (
                                strict_canonical_json(
                                    private_analysis_budget_payload(
                                        _budget(request, calls=0)
                                    )
                                ),
                                completed.run_id,
                            ),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE private_analysis_runs SET completed_at_ns = ?
                            WHERE run_id = ?
                            """,
                            (14, completed.run_id),
                        )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(PrivateAnalysisRunCorruptionError):
                    store.get_run(request.scope, completed.run_id)
                store.close()

    def test_committed_cancellation_cannot_be_overridden_by_completion(self) -> None:
        request = _request()
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="cancel-race",
            run_id="cancel-race",
            now_ns=10,
        )
        record = self.store.claim_run(
            request.scope,
            record.run_id,
            expected_version=record.version,
            actor_id="worker",
            execution_id="cancel-attempt",
            lease_duration_ns=100,
            now_ns=11,
        )
        record = self.store.request_cancellation(
            request.scope,
            record.run_id,
            expected_version=record.version,
            actor_id="operator",
            now_ns=12,
        )
        ordinary_outcome = _outcome(request)
        with self.assertRaisesRegex(
            PrivateAnalysisRunConflict,
            "requires a cancelled outcome",
        ):
            self.store.complete_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id="cancel-attempt",
                outcome=ordinary_outcome,
                transcript_summary=_summary(
                    request,
                    ordinary_outcome,
                    record.budget_state,
                    record.evidence_ledger_digest,
                ),
                references=(),
                budget_state=record.budget_state,
                actor_id="worker",
                now_ns=13,
            )
        self.assertEqual(
            self.store.get_run(request.scope, record.run_id).state,
            PrivateAnalysisRunState.CANCEL_REQUESTED,
        )

    def test_corrupt_revision_vector_cannot_shrink_retention_protection(self) -> None:
        request = _request()
        self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="references",
            run_id="references",
            now_ns=10,
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                """
                DELETE FROM private_analysis_run_revisions
                WHERE run_id = 'references' AND ordinal = 0
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(PrivateAnalysisRunCorruptionError):
            self.store.referenced_revision_ids(request.scope)

    def test_missing_whole_run_head_cannot_shrink_retention_protection(self) -> None:
        request = _request()
        self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="whole-head",
            run_id="whole-head",
            now_ns=10,
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "DELETE FROM private_analysis_runs WHERE run_id = 'whole-head'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            PrivateAnalysisRunCorruptionError,
            "active guard has no run head",
        ):
            self.store.referenced_revision_ids(request.scope)

    def test_missing_active_guard_is_not_repaired_on_reopen(self) -> None:
        request = _request()
        self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="missing-guard",
            run_id="missing-guard",
            now_ns=10,
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                """
                DELETE FROM private_analysis_active_run_guards
                WHERE run_id = 'missing-guard'
                """
            )
            connection.commit()
        finally:
            connection.close()
        self.store.close()
        self.store = SqlitePrivateAnalysisRunStore(
            self.database,
            admission_validator=self.validator,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRunCorruptionError,
            "missing its active guard",
        ):
            self.store.referenced_revision_ids(request.scope)

    def test_missing_head_and_guard_still_leave_admission_fail_closed(self) -> None:
        request = _request()
        self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="two-row-loss",
            run_id="two-row-loss",
            now_ns=10,
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "DELETE FROM private_analysis_runs WHERE run_id = 'two-row-loss'"
            )
            connection.execute(
                """
                DELETE FROM private_analysis_active_run_guards
                WHERE run_id = 'two-row-loss'
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            PrivateAnalysisRunCorruptionError,
            "guards and admissions disagree",
        ):
            self.store.referenced_revision_ids(request.scope)

    def test_active_run_and_catalog_reference_work_are_bounded(self) -> None:
        request = _request()
        with patch(
            "router_dump_analyzer.private_analysis_run_store."
            "_MAX_REFERENCE_PROTECTION_RUNS",
            2,
        ):
            for ordinal in (1, 2):
                self.store.create_run(
                    request,
                    actor_id="operator",
                    idempotency_key=f"bounded-{ordinal}",
                    run_id=f"bounded-{ordinal}",
                    now_ns=ordinal,
                )
            self.assertEqual(
                self.store.referenced_revision_ids(request.scope),
                ("revision-001", "revision-002"),
            )
            with self.assertRaisesRegex(
                PrivateAnalysisRunConflict,
                "active-run safety bound",
            ):
                self.store.create_run(
                    request,
                    actor_id="operator",
                    idempotency_key="bounded-3",
                    run_id="bounded-3",
                    now_ns=3,
                )
        with (
            patch(
                "router_dump_analyzer.private_analysis_run_store."
                "_MAX_REFERENCE_PROTECTION_RUNS",
                1,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisRunCorruptionError,
                "catalog-protection bound",
            ),
        ):
            self.store.referenced_revision_ids(request.scope)

    def test_audit_bound_reserves_cancellation_and_terminal_entries(self) -> None:
        request = _request()
        with patch(
            "router_dump_analyzer.private_analysis_run_store."
            "_MAX_AUDIT_ENTRIES_PER_RUN",
            4,
        ):
            record = self.store.create_run(
                request,
                actor_id="operator",
                idempotency_key="audit-bound",
                run_id="audit-bound",
                now_ns=10,
            )
            record = self.store.claim_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                actor_id="worker",
                execution_id="audit-bound-attempt",
                lease_duration_ns=100,
                now_ns=11,
            )
            with self.assertRaisesRegex(
                PrivateAnalysisRunConflict,
                "terminal reserve",
            ):
                self.store.renew_lease(
                    request.scope,
                    record.run_id,
                    expected_version=record.version,
                    execution_id="audit-bound-attempt",
                    lease_duration_ns=100,
                    actor_id="worker",
                    now_ns=12,
                )
            record = self.store.request_cancellation(
                request.scope,
                record.run_id,
                expected_version=record.version,
                actor_id="operator",
                now_ns=12,
            )
            outcome = _outcome(request, PrivateAnalysisErrorCode.CANCELLED)
            record = self.store.complete_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                execution_id="audit-bound-attempt",
                outcome=outcome,
                transcript_summary=_summary(
                    request,
                    outcome,
                    record.budget_state,
                    record.evidence_ledger_digest,
                ),
                references=(),
                budget_state=record.budget_state,
                actor_id="worker",
                now_ns=13,
            )
            self.assertEqual(record.state, PrivateAnalysisRunState.CANCELLED)
            self.assertEqual(record.audit_tip_sequence, 4)

    def test_transition_time_cannot_move_backwards_and_duplicate_id_conflicts(
        self,
    ) -> None:
        request = _request()
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="time",
            run_id="stable-id",
            now_ns=100,
        )
        with self.assertRaisesRegex(ValueError, "cannot move backwards"):
            self.store.claim_run(
                request.scope,
                record.run_id,
                expected_version=record.version,
                actor_id="worker",
                execution_id="attempt",
                lease_duration_ns=100,
                now_ns=50,
            )
        self.assertEqual(self.store.get_run(request.scope, record.run_id), record)
        with self.assertRaises(PrivateAnalysisRunConflict):
            self.store.create_run(
                request,
                actor_id="operator",
                idempotency_key="another-admission",
                run_id="stable-id",
                now_ns=101,
            )

    def test_retention_is_disabled_bounded_idempotent_and_payload_free(self) -> None:
        query = "PROPRIETARY-QUERY-NEEDLE"
        request = _request(query=query)
        record = self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="admission",
            run_id="run",
            now_ns=10,
        )
        self.store.request_cancellation(
            request.scope,
            record.run_id,
            expected_version=record.version,
            actor_id="operator",
            now_ns=20,
        )
        disabled = PrivateAnalysisRunRetentionPolicy(
            completed_before_ns=30,
            max_runs=10,
        )
        inventory = self.store.inventory_retention(request.scope, disabled)
        self.assertEqual(tuple(item.run_id for item in inventory.candidates), ("run",))
        with self.assertRaises(PrivateAnalysisRunRetentionDisabled):
            self.store.run_retention(
                request.scope,
                disabled,
                actor_id="operator",
                operation_id="retention-1",
                now_ns=30,
            )
        enabled = replace(disabled, enabled=True)
        expected = self.store.inventory_retention(request.scope, enabled)
        statements: list[str] = []
        self.store._connection.set_trace_callback(statements.append)
        result = self.store.run_retention(
            request.scope,
            enabled,
            actor_id="operator",
            operation_id="retention-1",
            expected_inventory_digest=expected.inventory_digest,
            now_ns=30,
        )
        self.store._connection.set_trace_callback(None)
        self.assertFalse(
            any(statement.strip().upper() == "VACUUM" for statement in statements)
        )
        replay = self.store.run_retention(
            request.scope,
            enabled,
            actor_id="operator",
            operation_id="retention-1",
            now_ns=31,
        )
        self.assertEqual(result, replay)
        with self.assertRaises(PrivateAnalysisRunNotFound):
            self.store.get_run(request.scope, "run")
        self.assertEqual(self.store.referenced_revision_ids(request.scope), ())
        self.assertEqual(len(self.store.list_retention_journal(request.scope)), 1)
        connection = sqlite3.connect(self.database)
        try:
            audit_rows = connection.execute(
                "SELECT * FROM private_analysis_run_tombstones"
            ).fetchall()
            journal_rows = connection.execute(
                "SELECT * FROM private_analysis_run_retention_journal"
            ).fetchall()
            active_guard_rows = connection.execute(
                "SELECT * FROM private_analysis_active_run_guards"
            ).fetchall()
            admission_rows = connection.execute(
                "SELECT * FROM private_analysis_run_admissions"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(active_guard_rows, [])
        self.assertEqual(admission_rows, [])
        self.assertNotIn(query, repr(audit_rows) + repr(journal_rows))
        with self.assertRaisesRegex(
            PrivateAnalysisRunConflict,
            "run id was already retained",
        ):
            self.store.create_run(
                request,
                actor_id="operator",
                idempotency_key="replacement-admission",
                run_id="run",
                now_ns=32,
            )
        with self.assertRaisesRegex(
            PrivateAnalysisRunConflict,
            "admission was already retained",
        ):
            self.store.create_run(
                request,
                actor_id="operator",
                idempotency_key="admission",
                run_id="different-run-id",
                now_ns=33,
            )
        encoded_query = query.encode("utf-8")
        for candidate in (
            self.database,
            self.database.with_name(self.database.name + "-wal"),
        ):
            if candidate.exists():
                self.assertNotIn(encoded_query, candidate.read_bytes())

    def test_audit_tamper_fails_closed(self) -> None:
        request = _request()
        self.store.create_run(
            request,
            actor_id="operator",
            idempotency_key="admission",
            run_id="run",
            now_ns=10,
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                """
                UPDATE private_analysis_run_audit
                SET actor_id = 'tampered'
                WHERE run_id = 'run' AND sequence = 1
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(PrivateAnalysisRunCorruptionError):
            self.store.get_run(request.scope, "run")

    def test_real_control_plane_admission_and_catalog_protection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control = ControlPlane(
                Path(directory),
                registry=PluginRegistry((), require_executable_identity=True),
            )
            try:
                control.sessions.create_project(
                    "tenant-real",
                    "Project",
                    project_id="project-real",
                )
                workspace = control.sessions.create_workspace(
                    "tenant-real",
                    "project-real",
                    "Workspace",
                    workspace_id="workspace-real",
                )
                bindings: list[EvidenceRevisionBinding] = []
                for index, suffix in enumerate(("a", "b"), 1):
                    fixture = control.sessions.attach_fixture(
                        "tenant-real",
                        "workspace-real",
                        f"fixture-{suffix}",
                        label=f"Fixture {suffix}",
                        content_digest=str(index) * 64,
                    )
                    revision = control.sessions.publish_revision(
                        "tenant-real",
                        "workspace-real",
                        fixture.fixture_id,
                        f"revision-{suffix}",
                        node_id=f"node-{suffix}",
                        identity_digest=str(index + 2) * 64,
                        execution_plan=_execution_plan(f"node-{suffix}", suffix),
                    )
                    scope, binding = bind_private_analysis_revision(
                        workspace,
                        fixture,
                        revision,
                    )
                    bindings.append(binding)
                request = _request(scope=scope, revisions=tuple(bindings))
                control.private_analysis_runs.create_run(
                    request,
                    actor_id="operator",
                    idempotency_key="real-admission",
                    run_id="real-run",
                )

                inventory = control.retention_inventory(
                    ReviewScope(
                        "tenant-real",
                        "project-real",
                        "workspace-real",
                    ),
                    catalog_policy=CatalogRetentionPolicy(
                        enabled=True,
                        revision_before_ns=(1 << 63) - 1,
                        preserve_latest_snapshot_per_session=False,
                    ),
                ).catalog
                revision_candidates = {
                    item.identifier: item
                    for item in inventory.candidates
                    if item.category == "analysis_revision"
                }
                self.assertEqual(set(revision_candidates), {"revision-a", "revision-b"})
                self.assertTrue(
                    all(
                        "externally_protected" in item.blockers
                        for item in revision_candidates.values()
                    )
                )

                drifted = _request(
                    scope=request.scope,
                    revisions=(
                        replace(
                            request.revisions[0],
                            execution_plan_digest="sha256:" + "e" * 64,
                        ),
                        request.revisions[1],
                    ),
                )
                with self.assertRaises(PrivateAnalysisRunConflict):
                    control.private_analysis_runs.create_run(
                        drifted,
                        actor_id="operator",
                        idempotency_key="drifted-admission",
                    )
            finally:
                control.close()

    def test_control_plane_refuses_missing_binding_for_existing_run_store(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = ControlPlane(
                root,
                registry=PluginRegistry((), require_executable_identity=True),
            )
            control.close()
            (root / ".private-analysis-run-store.binding.json").unlink()
            with self.assertRaisesRegex(
                ControlPlaneError,
                "binding is missing",
            ):
                ControlPlane(
                    root,
                    registry=PluginRegistry((), require_executable_identity=True),
                )

    def test_control_plane_retention_unions_exact_run_scope_references(self) -> None:
        review_scope = ReviewScope("tenant-a", "project-a", "workspace-a")
        observed: list[EvidenceScope] = []

        class RunReferences:
            def referenced_revision_ids(
                self,
                scope: EvidenceScope,
            ) -> tuple[str, ...]:
                self_scope = EvidenceScope(
                    scope.tenant_id,
                    scope.project_id,
                    scope.workspace_id,
                )
                observed.append(self_scope)
                return ("revision-run", "revision-shared")

        control = cast(ControlPlane, object.__new__(ControlPlane))
        control.annotations = cast(
            object,
            SimpleNamespace(
                referenced_revision_ids=lambda scope: (
                    "revision-review",
                    "revision-shared",
                )
            ),
        )
        control.private_analysis_runs = cast(object, RunReferences())
        effective = control._catalog_retention_policy(
            review_scope,
            CatalogRetentionPolicy(
                protected_revision_ids=("revision-manual",),
            ),
        )
        self.assertEqual(observed, [_scope()])
        self.assertTrue(effective.external_references_checked)
        self.assertEqual(
            effective.protected_revision_ids,
            (
                "revision-manual",
                "revision-review",
                "revision-run",
                "revision-shared",
            ),
        )


if __name__ == "__main__":
    unittest.main()
