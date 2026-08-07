from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections.abc import Iterable
from contextlib import closing, nullcontext
from pathlib import Path
from types import SimpleNamespace

import router_dump_analyzer.private_analysis_promotion as promotion_module
from router_dump_analyzer.annotation_store import (
    ManualCorrelationEdge,
    ManualEventCorrelation,
    ReviewAnnotation,
    ReviewAnnotationKind,
    ReviewOverlayStore,
    ReviewRetentionPolicy,
    ReviewScope,
    ReviewSubject,
    ReviewSubjectKind,
)
from router_dump_analyzer.canonical import strict_canonical_json
from router_dump_analyzer.private_analysis import (
    EvidenceScope,
    PrivateAnalysisProposalKind,
)
from router_dump_analyzer.private_analysis_promotion import (
    AnnotationPromotionTarget,
    CorrelationPromotionTarget,
    PrivateAnalysisProposalReviewService,
    ProposalReviewConflictError,
    ProposalReviewDisposition,
    ProposalReviewState,
    ProposalReviewUnavailableError,
    ProposalReviewValidationError,
    SqliteProposalReviewStore,
)

PROPOSAL_DIGEST = "sha256:" + ("1" * 64)
RESULT_DIGEST = "sha256:" + ("2" * 64)
AUTHORITY_KEY = bytes(range(32))


class _PrivateAnalysis:
    def __init__(
        self,
        *,
        proposal_kind: PrivateAnalysisProposalKind = (
            PrivateAnalysisProposalKind.EVENT_CORRELATION
        ),
    ) -> None:
        self.report = SimpleNamespace(
            run=SimpleNamespace(
                version=7,
                revision_ids=("revision-a",),
                cleanup_pending=False,
            ),
            outcome=SimpleNamespace(
                result=SimpleNamespace(
                    result_digest=RESULT_DIGEST,
                    proposals=(
                        SimpleNamespace(
                            proposal_id="proposal-a",
                            proposal_digest=PROPOSAL_DIGEST,
                            kind=proposal_kind,
                        ),
                    ),
                ),
            ),
        )

    def get_report(self, scope: EvidenceScope, run_id: str):
        if scope.tenant_id != "tenant-a" or run_id != "run-a":
            raise KeyError(run_id)
        return self.report


class _ReviewWriter:
    def __init__(self, overlay: ReviewOverlayStore) -> None:
        self.overlay = overlay

    @staticmethod
    def validate_subjects(
        scope: ReviewScope,
        subjects: Iterable[ReviewSubject],
    ) -> tuple[ReviewSubject, ...]:
        materialized = tuple(subjects)
        for subject in materialized:
            if (
                subject.revision_id != "revision-a"
                or subject.node_id != "node-a"
                or subject.kind is not ReviewSubjectKind.EVENT
                or subject.subject_id not in {"event-a", "event-b"}
            ):
                raise ValueError("subject does not resolve")
        return materialized

    def get_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ReviewAnnotation:
        return self.overlay.get_annotation(
            scope,
            annotation_id,
            include_deleted=include_deleted,
        )

    def create_annotation(self, scope: ReviewScope, **kwargs) -> ReviewAnnotation:
        return self.overlay.create_annotation(scope, **kwargs)

    def get_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ManualEventCorrelation:
        return self.overlay.get_correlation(
            scope,
            correlation_id,
            include_deleted=include_deleted,
        )

    def create_correlation(
        self,
        scope: ReviewScope,
        **kwargs,
    ) -> ManualEventCorrelation:
        return self.overlay.create_correlation(scope, **kwargs)


class _FailCreateOnceWriter(_ReviewWriter):
    def __init__(self, overlay: ReviewOverlayStore) -> None:
        super().__init__(overlay)
        self.fail_create = True

    def create_annotation(self, scope: ReviewScope, **kwargs) -> ReviewAnnotation:
        if self.fail_create:
            self.fail_create = False
            raise RuntimeError("simulated crash before overlay commit")
        return super().create_annotation(scope, **kwargs)


class _FailCompletionOnceStore(SqliteProposalReviewStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path, authority_key=AUTHORITY_KEY)
        self.fail_completion = True

    def complete(self, scope: ReviewScope, decision_id: str):
        if self.fail_completion:
            self.fail_completion = False
            raise RuntimeError("simulated crash after overlay commit")
        return super().complete(scope, decision_id)


class ProposalPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scope = EvidenceScope("tenant-a", "project-a", "workspace-a")
        self.review_scope = ReviewScope("tenant-a", "project-a", "workspace-a")
        self.subjects = (
            ReviewSubject(
                revision_id="revision-a",
                node_id="node-a",
                kind=ReviewSubjectKind.EVENT,
                subject_id="event-a",
            ),
            ReviewSubject(
                revision_id="revision-a",
                node_id="node-a",
                kind=ReviewSubjectKind.EVENT,
                subject_id="event-b",
            ),
        )
        self.overlay = ReviewOverlayStore(self.root / "annotations.sqlite3")
        self.writer = _ReviewWriter(self.overlay)
        self.store = SqliteProposalReviewStore(
            self.root / "decisions.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        self.service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            self.store,
            self.writer,
            admission_fence=nullcontext,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.overlay.close()
        self.temp.cleanup()

    def _decide(self, **updates):
        values = {
            "scope": self.scope,
            "run_id": "run-a",
            "proposal_id": "proposal-a",
            "proposal_digest": PROPOSAL_DIGEST,
            "result_digest": RESULT_DIGEST,
            "expected_run_version": 7,
            "disposition": ProposalReviewDisposition.REJECT,
            "actor": "reviewer-a",
            "rationale": "Reviewed every cited item.",
            "idempotency_key": "decision-a",
            "target": None,
        }
        values.update(updates)
        return self.service.decide(**values)

    def test_rejection_is_durable_idempotent_and_non_mutating(self) -> None:
        first = self._decide()
        replay = self._decide()
        self.assertEqual(first, replay)
        self.assertEqual(first.state, ProposalReviewState.COMPLETED)
        self.assertEqual(first.disposition, ProposalReviewDisposition.REJECT)
        self.assertIsNone(first.target_id)
        self.assertEqual(self.overlay.list_annotations(self.review_scope), ())
        self.assertEqual(self.overlay.list_correlations(self.review_scope), ())

        with self.assertRaises(ProposalReviewConflictError):
            self._decide(rationale="A different decision body.")
        with self.assertRaises(ProposalReviewConflictError):
            self._decide(
                idempotency_key="decision-b",
                disposition=ProposalReviewDisposition.PROMOTE,
                target=AnnotationPromotionTarget(
                    kind=ReviewAnnotationKind.NOTE,
                    subjects=(self.subjects[0],),
                    body="promote",
                ),
            )

    def test_idempotency_replay_rejects_redirect_to_another_valid_decision(
        self,
    ) -> None:
        def reserve_rejection(
            *,
            run_id: str,
            proposal_id: str,
            actor: str,
            idempotency_key: str,
        ):
            request_digest = promotion_module._proposal_review_request_digest(
                scope=self.review_scope,
                run_id=run_id,
                proposal_id=proposal_id,
                proposal_digest=PROPOSAL_DIGEST,
                result_digest=RESULT_DIGEST,
                run_version=7,
                disposition=ProposalReviewDisposition.REJECT,
                actor=actor,
                rationale="Reviewed independently.",
                target_kind=None,
                target_document=None,
            )
            return self.store.reserve(
                self.review_scope,
                decision_id=promotion_module._proposal_review_decision_id(
                    request_digest
                ),
                run_id=run_id,
                proposal_id=proposal_id,
                proposal_digest=PROPOSAL_DIGEST,
                result_digest=RESULT_DIGEST,
                run_version=7,
                disposition=ProposalReviewDisposition.REJECT,
                actor=actor,
                rationale="Reviewed independently.",
                request_digest=request_digest,
                target_kind=None,
                target_id=None,
                target_document=None,
                idempotency_key=idempotency_key,
            ).decision

        decision_a = reserve_rejection(
            run_id="run-a",
            proposal_id="proposal-a",
            actor="reviewer-a",
            idempotency_key="key-a",
        )
        decision_b = reserve_rejection(
            run_id="run-b",
            proposal_id="proposal-b",
            actor="reviewer-b",
            idempotency_key="key-b",
        )
        self.assertNotEqual(decision_a.decision_id, decision_b.decision_id)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                "UPDATE proposal_review_idempotency SET decision_id = ? "
                "WHERE tenant_id = ? AND project_id = ? AND workspace_id = ? "
                "AND idempotency_key = ?",
                (
                    decision_b.decision_id,
                    self.review_scope.tenant_id,
                    self.review_scope.project_id,
                    self.review_scope.workspace_id,
                    "key-a",
                ),
            )
            connection.commit()

        with self.assertRaisesRegex(
            ProposalReviewUnavailableError,
            "idempotency authority",
        ):
            reserve_rejection(
                run_id="run-a",
                proposal_id="proposal-a",
                actor="reviewer-a",
                idempotency_key="key-a",
            )

    def test_annotation_promotion_is_human_asserted_and_replay_safe(self) -> None:
        target = AnnotationPromotionTarget(
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.subjects[0],),
            title="Reviewed interpretation",
            body="A human accepted this advisory interpretation.",
            tags=("reviewed",),
        )
        first = self._decide(
            disposition=ProposalReviewDisposition.PROMOTE,
            target=target,
        )
        replay = self._decide(
            disposition=ProposalReviewDisposition.PROMOTE,
            target=target,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first.state, ProposalReviewState.COMPLETED)
        self.assertEqual(first.version, 2)
        annotation = self.overlay.get_annotation(
            self.review_scope,
            first.target_id or "",
        )
        self.assertEqual(annotation.author, "reviewer-a")
        self.assertEqual(annotation.tags, ("assistant-promoted", "reviewed"))
        self.assertEqual(len(self.overlay.list_annotations(self.review_scope)), 1)

    def test_pending_promotion_resumes_after_restart_without_caller_target(
        self,
    ) -> None:
        self.store.close()
        failing = _FailCompletionOnceStore(self.root / "resume.sqlite3")
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            failing,
            self.writer,
            admission_fence=nullcontext,
        )
        target = AnnotationPromotionTarget(
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.subjects[0],),
            body="resume me",
        )
        request = {
            "scope": self.scope,
            "run_id": "run-a",
            "proposal_id": "proposal-a",
            "proposal_digest": PROPOSAL_DIGEST,
            "result_digest": RESULT_DIGEST,
            "expected_run_version": 7,
            "disposition": ProposalReviewDisposition.PROMOTE,
            "actor": "reviewer-a",
            "rationale": "Explicit promotion.",
            "idempotency_key": "resume-a",
            "target": target,
        }
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            service.decide(**request)
        pending = failing.list(self.review_scope)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].state, ProposalReviewState.PENDING)
        self.assertEqual(len(self.overlay.list_annotations(self.review_scope)), 1)

        # Replaying the original decision request is observational only.  It
        # cannot bypass the explicit versioned recovery mutation.
        replayed_pending = service.decide(**request)
        self.assertEqual(replayed_pending.state, ProposalReviewState.PENDING)
        self.assertEqual(replayed_pending.version, 1)

        references = failing.pending_retention_references(self.review_scope)
        self.assertEqual(references.revision_ids, ("revision-a",))
        self.assertEqual(
            references.overlay_idempotency_keys,
            (f"private-analysis-proposal:{pending[0].decision_id}",),
        )
        retention_policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=(1 << 63) - 1,
            maximum_candidates=100,
        )
        protected_inventory = self.overlay.inventory_retention(
            self.review_scope,
            retention_policy,
            protected_idempotency_keys=references.overlay_idempotency_keys,
        )
        protected_receipts = tuple(
            candidate
            for candidate in protected_inventory.candidates
            if candidate.category == "review_idempotency"
        )
        self.assertEqual(len(protected_receipts), 1)
        self.assertEqual(
            protected_receipts[0].blockers,
            ("pending_proposal_decision",),
        )
        protected_result = self.overlay.purge_retention(
            self.review_scope,
            retention_policy,
            actor="retention-test",
            operation_id="retain-pending-receipt",
            protected_idempotency_keys=references.overlay_idempotency_keys,
        )
        self.assertEqual(protected_result.purged, ())

        # Even a legacy caller that omits protection cannot make recovery
        # duplicate an already committed exact target.
        purged = self.overlay.purge_retention(
            self.review_scope,
            retention_policy,
            actor="retention-test",
            operation_id="purge-unprotected-receipt",
        )
        self.assertEqual(
            tuple(item.category for item in purged.purged),
            ("review_idempotency",),
        )

        decision_id = pending[0].decision_id
        failing.close()
        recovered_store = SqliteProposalReviewStore(
            self.root / "resume.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        recovered_service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            recovered_store,
            self.writer,
            admission_fence=nullcontext,
        )
        with self.assertRaises(ProposalReviewConflictError):
            recovered_service.recover(
                self.scope,
                decision_id,
                expected_decision_version=2,
            )
        completed = recovered_service.recover(
            self.scope,
            decision_id,
            expected_decision_version=1,
        )
        self.assertEqual(completed.state, ProposalReviewState.COMPLETED)
        self.assertEqual(len(self.overlay.list_annotations(self.review_scope)), 1)
        recovered_store.close()
        self.store = SqliteProposalReviewStore(
            self.root / "decisions.sqlite3",
            authority_key=AUTHORITY_KEY,
        )

    def test_invalid_subject_does_not_reserve_the_proposal(self) -> None:
        invalid = AnnotationPromotionTarget(
            kind=ReviewAnnotationKind.NOTE,
            subjects=(
                ReviewSubject(
                    revision_id="revision-a",
                    node_id="node-a",
                    kind=ReviewSubjectKind.EVENT,
                    subject_id="event-missing",
                ),
            ),
            body="invalid",
        )
        with self.assertRaisesRegex(
            ProposalReviewValidationError,
            "do not resolve",
        ):
            self._decide(
                disposition=ProposalReviewDisposition.PROMOTE,
                target=invalid,
            )
        self.assertEqual(self.store.list(self.review_scope), ())

        corrected = self._decide(
            disposition=ProposalReviewDisposition.PROMOTE,
            target=AnnotationPromotionTarget(
                kind=ReviewAnnotationKind.NOTE,
                subjects=(self.subjects[0],),
                body="corrected",
            ),
        )
        self.assertEqual(corrected.state, ProposalReviewState.COMPLETED)

    def test_cleanup_pending_run_cannot_reserve_a_decision(self) -> None:
        analysis = _PrivateAnalysis()
        analysis.report.run.cleanup_pending = True
        store = SqliteProposalReviewStore(
            self.root / "cleanup-pending.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        service = PrivateAnalysisProposalReviewService(
            analysis,
            store,
            self.writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(
                ProposalReviewConflictError,
                "cleanup is not complete",
            ):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.REJECT,
                    actor="reviewer-a",
                    rationale="not yet",
                    idempotency_key="cleanup-pending",
                )
            self.assertEqual(store.list(self.review_scope), ())
        finally:
            store.close()

    def test_recovery_rejects_target_bytes_that_do_not_match_request_digest(
        self,
    ) -> None:
        failing = _FailCompletionOnceStore(self.root / "tampered.sqlite3")
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            failing,
            self.writer,
            admission_fence=nullcontext,
        )
        request = {
            "scope": self.scope,
            "run_id": "run-a",
            "proposal_id": "proposal-a",
            "proposal_digest": PROPOSAL_DIGEST,
            "result_digest": RESULT_DIGEST,
            "expected_run_version": 7,
            "disposition": ProposalReviewDisposition.PROMOTE,
            "actor": "reviewer-a",
            "rationale": "Explicit promotion.",
            "idempotency_key": "tampered-target",
            "target": AnnotationPromotionTarget(
                kind=ReviewAnnotationKind.NOTE,
                subjects=(self.subjects[0],),
                body="ORIGINAL",
            ),
        }
        try:
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                service.decide(**request)
            pending = failing.list(self.review_scope)[0]
            connection = sqlite3.connect(self.root / "tampered.sqlite3")
            try:
                raw = connection.execute(
                    "SELECT target_document_json FROM proposal_review_decision "
                    "WHERE decision_id = ?",
                    (pending.decision_id,),
                ).fetchone()[0]
                document = json.loads(raw)
                document["body"] = "FORGED"
                connection.execute(
                    "UPDATE proposal_review_decision SET target_document_json = ? "
                    "WHERE decision_id = ?",
                    (strict_canonical_json(document), pending.decision_id),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "request digest",
            ):
                service.recover(
                    self.scope,
                    pending.decision_id,
                    expected_decision_version=1,
                )
            with closing(sqlite3.connect(self.root / "tampered.sqlite3")) as connection:
                stored_state = connection.execute(
                    "SELECT state FROM proposal_review_decision WHERE decision_id = ?",
                    (pending.decision_id,),
                ).fetchone()[0]
            self.assertEqual(stored_state, ProposalReviewState.PENDING.value)
        finally:
            failing.close()

    def test_recovery_rejects_a_forged_generated_target_identity(self) -> None:
        path = self.root / "forged-target-identity.sqlite3"
        store = SqliteProposalReviewStore(path, authority_key=AUTHORITY_KEY)
        writer = _FailCreateOnceWriter(self.overlay)
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            store,
            writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "before overlay commit"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="forged-target-identity",
                    target=AnnotationPromotionTarget(
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(self.subjects[0],),
                        body="retained human target",
                    ),
                )
            pending = store.list(self.review_scope)[0]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE proposal_review_decision SET target_id = ? "
                    "WHERE decision_id = ?",
                    ("forged-target-id", pending.decision_id),
                )
                connection.commit()
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "target identity",
            ):
                service.recover(
                    self.scope,
                    pending.decision_id,
                    expected_decision_version=1,
                )
            self.assertEqual(self.overlay.list_annotations(self.review_scope), ())
        finally:
            store.close()

    def test_recovery_rejects_a_forged_generated_decision_identity(self) -> None:
        path = self.root / "forged-decision-identity.sqlite3"
        store = SqliteProposalReviewStore(path, authority_key=AUTHORITY_KEY)
        writer = _FailCreateOnceWriter(self.overlay)
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            store,
            writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "before overlay commit"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="forged-decision-identity",
                    target=AnnotationPromotionTarget(
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(self.subjects[0],),
                        body="retained human target",
                    ),
                )
            pending = store.list(self.review_scope)[0]
            forged_id = "forged-decision-id"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE proposal_review_decision SET decision_id = ? "
                    "WHERE decision_id = ?",
                    (forged_id, pending.decision_id),
                )
                connection.commit()
                connection.execute(
                    "UPDATE proposal_review_idempotency SET decision_id = ? "
                    "WHERE decision_id = ?",
                    (forged_id, pending.decision_id),
                )
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "decision identity",
            ):
                service.recover(
                    self.scope,
                    forged_id,
                    expected_decision_version=1,
                )
            self.assertEqual(self.overlay.list_annotations(self.review_scope), ())
        finally:
            store.close()

    def test_retention_authenticates_lifecycle_before_pending_classification(
        self,
    ) -> None:
        path = self.root / "forged-lifecycle.sqlite3"
        store = SqliteProposalReviewStore(path, authority_key=AUTHORITY_KEY)
        writer = _FailCreateOnceWriter(self.overlay)
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            store,
            writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "before overlay commit"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="forged-lifecycle",
                    target=AnnotationPromotionTarget(
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(self.subjects[0],),
                        body="retained human target",
                    ),
                )
            pending = store.list(self.review_scope)[0]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE proposal_review_decision SET state = ? "
                    "WHERE decision_id = ?",
                    (ProposalReviewState.COMPLETED.value, pending.decision_id),
                )
                connection.commit()
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "authority attestation",
            ):
                store.pending_retention_references(self.review_scope)
            self.assertEqual(self.overlay.list_annotations(self.review_scope), ())
        finally:
            store.close()

    def test_recovery_rejects_a_decision_moved_to_another_scope(self) -> None:
        path = self.root / "forged-scope.sqlite3"
        store = SqliteProposalReviewStore(path, authority_key=AUTHORITY_KEY)
        writer = _FailCreateOnceWriter(self.overlay)
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            store,
            writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "before overlay commit"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="forged-scope",
                    target=AnnotationPromotionTarget(
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(self.subjects[0],),
                        body="retained human target",
                    ),
                )
            pending = store.list(self.review_scope)[0]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE proposal_review_decision SET tenant_id = ? "
                    "WHERE decision_id = ?",
                    ("tenant-b", pending.decision_id),
                )
                connection.commit()
                connection.execute(
                    "UPDATE proposal_review_idempotency SET tenant_id = ? "
                    "WHERE decision_id = ?",
                    ("tenant-b", pending.decision_id),
                )
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "request digest",
            ):
                store.pending_retention_references(self.review_scope)
            other_scope = EvidenceScope("tenant-b", "project-a", "workspace-a")
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "request digest",
            ):
                service.recover(
                    other_scope,
                    pending.decision_id,
                    expected_decision_version=1,
                )
            self.assertEqual(
                self.overlay.list_annotations(
                    ReviewScope("tenant-b", "project-a", "workspace-a")
                ),
                (),
            )
        finally:
            store.close()

    def test_recovery_rejects_coherently_reprojected_sqlite_authority(self) -> None:
        path = self.root / "coherent-authority-forgery.sqlite3"
        store = SqliteProposalReviewStore(path, authority_key=AUTHORITY_KEY)
        writer = _FailCreateOnceWriter(self.overlay)
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            store,
            writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "before overlay commit"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="coherent-authority-forgery",
                    target=AnnotationPromotionTarget(
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(self.subjects[0],),
                        body="retained human target",
                    ),
                )
            pending = store.list(self.review_scope)[0]
            forged_scope = ReviewScope("tenant-b", "project-a", "workspace-a")
            forged_actor = "forged-reviewer"
            with closing(sqlite3.connect(path)) as connection:
                raw_document = connection.execute(
                    "SELECT target_document_json FROM proposal_review_decision "
                    "WHERE decision_id = ?",
                    (pending.decision_id,),
                ).fetchone()[0]
                forged_document = json.loads(raw_document)
                forged_document["body"] = "coherently forged human target"
                forged_request_digest = (
                    promotion_module._proposal_review_request_digest(
                        scope=forged_scope,
                        run_id=pending.run_id,
                        proposal_id=pending.proposal_id,
                        proposal_digest=pending.proposal_digest,
                        result_digest=pending.result_digest,
                        run_version=pending.run_version,
                        disposition=pending.disposition,
                        actor=forged_actor,
                        rationale=pending.rationale,
                        target_kind=pending.target_kind.value,
                        target_document=forged_document,
                    )
                )
                forged_decision_id = promotion_module._proposal_review_decision_id(
                    forged_request_digest
                )
                forged_target_id = promotion_module._proposal_review_target_id(
                    forged_request_digest
                )
                connection.execute(
                    "UPDATE proposal_review_decision SET tenant_id = ?, actor = ?, "
                    "request_digest = ?, decision_id = ?, target_id = ?, "
                    "target_document_json = ? WHERE decision_id = ?",
                    (
                        forged_scope.tenant_id,
                        forged_actor,
                        forged_request_digest,
                        forged_decision_id,
                        forged_target_id,
                        strict_canonical_json(forged_document),
                        pending.decision_id,
                    ),
                )
                connection.execute(
                    "UPDATE proposal_review_idempotency SET tenant_id = ?, "
                    "request_digest = ?, decision_id = ? WHERE decision_id = ?",
                    (
                        forged_scope.tenant_id,
                        forged_request_digest,
                        forged_decision_id,
                        pending.decision_id,
                    ),
                )
                connection.commit()
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "authority attestation",
            ):
                store.promotion_target_document(forged_scope, forged_decision_id)
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "authority attestation",
            ):
                service.recover(
                    EvidenceScope("tenant-b", "project-a", "workspace-a"),
                    forged_decision_id,
                    expected_decision_version=1,
                )
            self.assertEqual(
                self.overlay.list_annotations(forged_scope),
                (),
            )
        finally:
            store.close()

    def test_recovery_rejects_an_existing_target_changed_after_overlay_commit(
        self,
    ) -> None:
        failing = _FailCompletionOnceStore(self.root / "changed-target.sqlite3")
        service = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(),
            failing,
            self.writer,
            admission_fence=nullcontext,
        )
        target = AnnotationPromotionTarget(
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.subjects[0],),
            body="original human target",
        )
        try:
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                service.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="Explicit promotion.",
                    idempotency_key="changed-target",
                    target=target,
                )
            pending = failing.list(self.review_scope)[0]
            self.overlay.update_annotation(
                self.review_scope,
                pending.target_id or "",
                expected_version=1,
                actor="another-reviewer",
                body="changed after the crash",
            )
            with self.assertRaisesRegex(
                ProposalReviewConflictError,
                "conflicts with retained human intent",
            ):
                service.recover(
                    self.scope,
                    pending.decision_id,
                    expected_decision_version=1,
                )
            self.assertEqual(
                failing.get(self.review_scope, pending.decision_id).state,
                ProposalReviewState.PENDING,
            )
        finally:
            failing.close()

    def test_event_correlation_promotion_and_kind_restriction(self) -> None:
        target = CorrelationPromotionTarget(
            subjects=self.subjects,
            edges=(ManualCorrelationEdge(0, 1, "causes"),),
            rationale="Human-reviewed causal relationship.",
            tags=("causal",),
            confidence=0.75,
        )
        decision = self._decide(
            disposition=ProposalReviewDisposition.PROMOTE,
            target=target,
        )
        correlation = self.overlay.get_correlation(
            self.review_scope,
            decision.target_id or "",
        )
        self.assertEqual(correlation.author, "reviewer-a")
        self.assertEqual(correlation.tags, ("assistant-promoted", "causal"))

        other_store = SqliteProposalReviewStore(
            self.root / "other.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        other = PrivateAnalysisProposalReviewService(
            _PrivateAnalysis(
                proposal_kind=PrivateAnalysisProposalKind.ROUTE_HYPOTHESIS
            ),
            other_store,
            self.writer,
            admission_fence=nullcontext,
        )
        try:
            with self.assertRaisesRegex(
                ProposalReviewValidationError,
                "only an event-correlation proposal",
            ):
                other.decide(
                    self.scope,
                    run_id="run-a",
                    proposal_id="proposal-a",
                    proposal_digest=PROPOSAL_DIGEST,
                    result_digest=RESULT_DIGEST,
                    expected_run_version=7,
                    disposition=ProposalReviewDisposition.PROMOTE,
                    actor="reviewer-a",
                    rationale="invalid target kind",
                    idempotency_key="other-a",
                    target=target,
                )
        finally:
            other_store.close()

    def test_digest_version_and_revision_pins_fail_before_reservation(self) -> None:
        target = AnnotationPromotionTarget(
            kind=ReviewAnnotationKind.NOTE,
            subjects=(
                ReviewSubject(
                    revision_id="revision-other",
                    kind=ReviewSubjectKind.EVENT,
                    subject_id="event-a",
                ),
            ),
        )
        with self.assertRaises(ProposalReviewConflictError):
            self._decide(expected_run_version=8)
        with self.assertRaises(ProposalReviewConflictError):
            self._decide(result_digest="sha256:" + ("3" * 64))
        with self.assertRaises(ProposalReviewConflictError):
            self._decide(proposal_digest="sha256:" + ("4" * 64))
        with self.assertRaisesRegex(
            ProposalReviewValidationError,
            "run revisions",
        ):
            self._decide(
                disposition=ProposalReviewDisposition.PROMOTE,
                target=target,
            )
        self.assertEqual(self.store.list(self.review_scope), ())

    def test_store_persists_and_isolates_scope(self) -> None:
        decision = self._decide()
        self.store.close()
        self.store = SqliteProposalReviewStore(
            self.root / "decisions.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        loaded = self.store.get(self.review_scope, decision.decision_id)
        self.assertEqual(loaded, decision)
        other_scope = ReviewScope("tenant-b", "project-a", "workspace-a")
        self.assertEqual(self.store.list(other_scope), ())
        with self.assertRaises(KeyError):
            self.store.get(other_scope, decision.decision_id)

    def test_store_requires_the_same_external_authority_key_after_restart(
        self,
    ) -> None:
        decision = self._decide()
        self.store.close()
        wrong_key_store = SqliteProposalReviewStore(
            self.root / "decisions.sqlite3",
            authority_key=b"x" * 32,
        )
        try:
            with self.assertRaisesRegex(
                ProposalReviewUnavailableError,
                "authority attestation",
            ):
                wrong_key_store.get(self.review_scope, decision.decision_id)
        finally:
            wrong_key_store.close()
        self.store = SqliteProposalReviewStore(
            self.root / "decisions.sqlite3",
            authority_key=AUTHORITY_KEY,
        )
        self.assertEqual(
            self.store.get(self.review_scope, decision.decision_id),
            decision,
        )


if __name__ == "__main__":
    unittest.main()
