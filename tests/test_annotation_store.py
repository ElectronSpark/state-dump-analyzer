from __future__ import annotations

import itertools
import json
import math
import sqlite3
import tempfile
import threading
import unittest
from hashlib import sha256
from pathlib import Path

from router_dump_analyzer.annotation_store import (
    CORRELATION_REPORT_SCHEMA_VERSION,
    CorrelationReportProvenanceClass,
    ManualCorrelationEdge,
    ReviewAnnotationKind,
    ReviewAuditRetentionMode,
    ReviewConflictError,
    ReviewIdempotencyConflictError,
    ReviewOverlayStore,
    ReviewRetentionDisabledError,
    ReviewRetentionPolicy,
    ReviewScope,
    ReviewSubject,
    ReviewSubjectKind,
    ReviewValidationError,
    build_correlation_report,
)
from router_dump_analyzer.canonical import (
    strict_canonical_json,
    strict_canonical_json_bytes,
)


class _Clock:
    def __init__(self, start: int = 1_000) -> None:
        self.value = start

    def __call__(self) -> int:
        self.value += 1
        return self.value


class _FaultingConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        fail_rollback: bool = False,
        commit_before_failure: bool = False,
    ) -> None:
        self.connection = connection
        self.fail_commit_once = True
        self.fail_rollback = fail_rollback
        self.commit_before_failure = commit_before_failure

    def __getattr__(self, name: str):
        return getattr(self.connection, name)

    def commit(self) -> None:
        if self.fail_commit_once:
            self.fail_commit_once = False
            if self.commit_before_failure:
                self.connection.commit()
            raise sqlite3.OperationalError("injected commit failure")
        self.connection.commit()

    def rollback(self) -> None:
        if self.fail_rollback:
            raise sqlite3.OperationalError("injected rollback failure")
        self.connection.rollback()


class ReviewOverlayStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "review.sqlite3"
        self.scope = ReviewScope("tenant-a", "project-a", "workspace-a")
        self.other_scope = ReviewScope(
            "tenant-b",
            "project-a",
            "workspace-a",
        )
        self.clock = _Clock()
        self.store = ReviewOverlayStore(self.database, clock_ns=self.clock)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    @staticmethod
    def event(
        event_id: str,
        *,
        revision_id: str = "revision-a",
        node_id: str = "node-a",
    ) -> ReviewSubject:
        return ReviewSubject(
            revision_id=revision_id,
            node_id=node_id,
            kind=ReviewSubjectKind.EVENT,
            subject_id=event_id,
        )

    def test_annotation_crud_restart_audit_and_tombstone(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="annotation-1",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-1"),),
            author="alice",
            title="Investigate",
            body="First observation",
            tags=("failure", "evpn"),
        )
        self.assertEqual(annotation.version, 1)
        self.assertEqual(annotation.tags, ("evpn", "failure"))

        self.store.close()
        self.store = ReviewOverlayStore(self.database, clock_ns=self.clock)
        loaded = self.store.get_annotation(self.scope, "annotation-1")
        self.assertEqual(loaded, annotation)

        updated = self.store.update_annotation(
            self.scope,
            "annotation-1",
            expected_version=1,
            actor="bob",
            body="Confirmed in the packet trace",
            tags=("confirmed",),
        )
        self.assertEqual(updated.version, 2)
        self.assertEqual(updated.author, "alice")
        self.assertEqual(updated.body, "Confirmed in the packet trace")

        deleted = self.store.delete_annotation(
            self.scope,
            "annotation-1",
            expected_version=2,
            actor="carol",
        )
        self.assertEqual(deleted.version, 3)
        self.assertTrue(deleted.tombstoned)
        with self.assertRaises(KeyError):
            self.store.get_annotation(self.scope, "annotation-1")
        self.assertEqual(
            self.store.get_annotation(
                self.scope,
                "annotation-1",
                include_deleted=True,
            ),
            deleted,
        )
        self.assertEqual(self.store.list_annotations(self.scope), ())
        self.assertEqual(
            self.store.list_annotations(
                self.scope,
                include_deleted=True,
            ),
            (deleted,),
        )

        audit = self.store.list_audit(self.scope)
        self.assertEqual(
            [entry.operation for entry in audit],
            ["create", "update", "delete"],
        )
        self.assertEqual([entry.version for entry in audit], [1, 2, 3])
        self.assertEqual([entry.actor for entry in audit], ["alice", "bob", "carol"])
        self.assertEqual(self.store.audit_watermark(self.scope), audit[-1].sequence)
        self.assertTrue(audit[-1].snapshot["tombstoned"])

    def test_annotation_pages_are_bound_to_one_atomic_audit_watermark(self) -> None:
        for suffix in ("a", "b", "c"):
            self.store.create_annotation(
                self.scope,
                annotation_id=f"annotation-{suffix}",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event(f"event-{suffix}"),),
                author="alice",
            )

        first_page, watermark = self.store.list_annotations_page(
            self.scope,
            limit=2,
        )
        self.assertEqual(
            [item.annotation_id for item in first_page],
            ["annotation-a", "annotation-b"],
        )
        self.assertEqual(watermark, 3)

        self.store.delete_annotation(
            self.scope,
            "annotation-a",
            expected_version=1,
            actor="alice",
        )
        with self.assertRaisesRegex(ReviewConflictError, "watermark changed"):
            self.store.list_annotations_page(
                self.scope,
                limit=2,
                offset=2,
                expected_audit_watermark=watermark,
            )

        current_page, current_watermark = self.store.list_annotations_page(
            self.scope,
            limit=2,
        )
        self.assertEqual(
            [item.annotation_id for item in current_page],
            ["annotation-b", "annotation-c"],
        )
        self.assertGreater(current_watermark, watermark)

    def test_review_text_rejects_controls_but_allows_multiline_body(self) -> None:
        with self.assertRaisesRegex(ReviewValidationError, "control characters"):
            self.store.create_annotation(
                self.scope,
                kind=ReviewAnnotationKind.NOTE,
                subjects=(self.event("event-control"),),
                author="alice",
                title="hidden\x1fseparator",
            )
        with self.assertRaisesRegex(
            ReviewValidationError,
            "bidirectional formatting controls",
        ):
            self.store.create_annotation(
                self.scope,
                kind=ReviewAnnotationKind.NOTE,
                subjects=(self.event("event-bidi"),),
                author="alice",
                title="safe\u202eevil",
            )

        annotation = self.store.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.event("event-multiline"),),
            author="alice",
            body="first line\nsecond line",
        )
        self.assertEqual(annotation.body, "first line\nsecond line")

    def test_failed_commit_is_rolled_back_and_connection_remains_usable(
        self,
    ) -> None:
        connection = self.store._connection
        fault = _FaultingConnection(connection)
        self.store._connection = fault  # type: ignore[assignment]

        with self.assertRaisesRegex(sqlite3.OperationalError, "commit failure"):
            self.store.create_annotation(
                self.scope,
                annotation_id="not-committed",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event("event-a"),),
                author="alice",
            )

        self.assertFalse(connection.in_transaction)
        with self.assertRaises(KeyError):
            self.store.get_annotation(self.scope, "not-committed")
        committed = self.store.create_annotation(
            self.scope,
            annotation_id="committed-after-recovery",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-b"),),
            author="alice",
        )
        self.assertEqual(committed.annotation_id, "committed-after-recovery")

    def test_failed_rollback_discards_and_reopens_file_connection(self) -> None:
        original = self.store._connection
        self.store._connection = _FaultingConnection(  # type: ignore[assignment]
            original,
            fail_rollback=True,
        )

        with self.assertRaisesRegex(sqlite3.OperationalError, "commit failure"):
            self.store.create_annotation(
                self.scope,
                annotation_id="ambiguous-write",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event("event-a"),),
                author="alice",
            )

        self.assertIsNot(self.store._connection, original)
        with self.assertRaises(KeyError):
            self.store.get_annotation(self.scope, "ambiguous-write")
        committed = self.store.create_annotation(
            self.scope,
            annotation_id="write-after-reopen",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-b"),),
            author="alice",
        )
        self.assertEqual(committed.annotation_id, "write-after-reopen")

    def test_ambiguous_commit_is_reconciled_by_idempotency(self) -> None:
        original = self.store._connection
        self.store._connection = _FaultingConnection(  # type: ignore[assignment]
            original,
            commit_before_failure=True,
        )
        request = {
            "scope": self.scope,
            "annotation_id": "ambiguous-but-committed",
            "kind": ReviewAnnotationKind.MARKER,
            "subjects": (self.event("event-a"),),
            "author": "alice",
            "idempotency_key": "ambiguous-request",
        }

        with self.assertRaisesRegex(sqlite3.OperationalError, "commit failure"):
            self.store.create_annotation(**request)
        replay = self.store.create_annotation(**request)

        self.assertEqual(replay.annotation_id, "ambiguous-but-committed")
        self.assertEqual(len(self.store.list_annotations(self.scope)), 1)
        self.assertEqual(len(self.store.list_audit(self.scope)), 1)

    def test_poisoned_memory_connection_reopens_without_losing_state(
        self,
    ) -> None:
        memory_store = ReviewOverlayStore(":memory:", clock_ns=self.clock)
        try:
            existing = memory_store.create_annotation(
                self.scope,
                annotation_id="existing",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event("event-a"),),
                author="alice",
            )
            original = memory_store._connection
            memory_store._connection = _FaultingConnection(  # type: ignore[assignment]
                original,
                fail_rollback=True,
            )

            with self.assertRaisesRegex(
                sqlite3.OperationalError,
                "commit failure",
            ):
                memory_store.create_annotation(
                    self.scope,
                    annotation_id="failed",
                    kind=ReviewAnnotationKind.MARKER,
                    subjects=(self.event("event-b"),),
                    author="alice",
                )

            self.assertEqual(
                memory_store.get_annotation(self.scope, "existing"),
                existing,
            )
            with self.assertRaises(KeyError):
                memory_store.get_annotation(self.scope, "failed")
        finally:
            memory_store.close()

    def test_annotation_idempotency_and_request_conflict(self) -> None:
        first = self.store.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.event("event-1"),),
            author="alice",
            body="same request",
            idempotency_key="request-1",
        )
        replay = self.store.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.event("event-1"),),
            author="alice",
            body="same request",
            idempotency_key="request-1",
        )
        self.assertEqual(replay, first)
        self.assertEqual(len(self.store.list_annotations(self.scope)), 1)
        self.assertEqual(len(self.store.list_audit(self.scope)), 1)
        with self.assertRaises(ReviewIdempotencyConflictError):
            self.store.create_annotation(
                self.scope,
                kind=ReviewAnnotationKind.NOTE,
                subjects=(self.event("event-1"),),
                author="alice",
                body="different request",
                idempotency_key="request-1",
            )

    def test_retention_is_disabled_and_audit_preserving_by_default(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="retained",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        self.store.delete_annotation(
            self.scope,
            annotation.annotation_id,
            expected_version=1,
            actor="alice",
        )

        inventory = self.store.inventory_retention(self.scope)
        self.assertEqual(inventory.total_candidate_count, 0)
        with self.assertRaises(ReviewRetentionDisabledError):
            self.store.purge_retention(
                self.scope,
                ReviewRetentionPolicy(tombstone_before_ns=self.clock.value + 1),
            )
        self.assertEqual(len(self.store.list_audit(self.scope)), 2)
        self.assertEqual(
            self.store.get_annotation(
                self.scope,
                annotation.annotation_id,
                include_deleted=True,
            ).annotation_id,
            annotation.annotation_id,
        )
        with self.assertRaisesRegex(
            ReviewValidationError,
            "requires prune_explicit",
        ):
            ReviewRetentionPolicy(audit_before_sequence=10)

    def test_review_retention_is_reference_aware_and_dry_runnable(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="old-annotation",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
            idempotency_key="annotation-create",
        )
        deleted_annotation = self.store.delete_annotation(
            self.scope,
            annotation.annotation_id,
            expected_version=1,
            actor="alice",
        )
        correlation = self.store.create_correlation(
            self.scope,
            correlation_id="old-correlation",
            subjects=(self.event("event-a"), self.event("event-b")),
            edges=(ManualCorrelationEdge(0, 1, "user.related"),),
            author="alice",
            idempotency_key="correlation-create",
        )
        deleted_correlation = self.store.delete_correlation(
            self.scope,
            correlation.correlation_id,
            expected_version=1,
            actor="alice",
        )
        cutoff = self.clock.value + 1

        blocked = self.store.inventory_retention(
            self.scope,
            ReviewRetentionPolicy(tombstone_before_ns=cutoff),
        )
        self.assertEqual(
            {candidate.category for candidate in blocked.candidates},
            {"annotation_tombstone", "correlation_tombstone"},
        )
        self.assertTrue(
            all(
                candidate.blockers == ("unexpired_idempotency_receipt",)
                for candidate in blocked.candidates
            )
        )

        preview_policy = ReviewRetentionPolicy(
            tombstone_before_ns=cutoff,
            idempotency_before_ns=cutoff,
        )
        preview = self.store.inventory_retention(self.scope, preview_policy)
        self.assertEqual(preview.total_candidate_count, 4)
        self.assertFalse(preview.truncated)
        self.assertTrue(all(candidate.eligible for candidate in preview.candidates))
        self.assertEqual(
            self.store.get_annotation(
                self.scope,
                annotation.annotation_id,
                include_deleted=True,
            ),
            deleted_annotation,
        )

        result = self.store.purge_retention(
            self.scope,
            ReviewRetentionPolicy(
                enabled=True,
                tombstone_before_ns=cutoff,
                idempotency_before_ns=cutoff,
            ),
        )
        self.assertEqual(len(result.purged), 4)
        with self.assertRaises(KeyError):
            self.store.get_annotation(
                self.scope,
                annotation.annotation_id,
                include_deleted=True,
            )
        with self.assertRaises(KeyError):
            self.store.get_correlation(
                self.scope,
                correlation.correlation_id,
                include_deleted=True,
            )
        self.assertEqual(len(self.store.list_audit(self.scope)), 4)
        self.assertEqual(deleted_correlation.correlation_id, "old-correlation")

    def test_audit_pruning_requires_explicit_compliance_mode(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="audit-subject",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        self.store.delete_annotation(
            self.scope,
            annotation.annotation_id,
            expected_version=1,
            actor="alice",
        )
        watermark = self.store.audit_watermark(self.scope)
        policy = ReviewRetentionPolicy(
            enabled=True,
            audit_mode=ReviewAuditRetentionMode.PRUNE_EXPLICIT,
            audit_before_sequence=watermark + 1,
        )

        inventory = self.store.inventory_retention(self.scope, policy)
        self.assertEqual(inventory.total_candidate_count, 2)
        result = self.store.purge_retention(
            self.scope,
            policy,
            actor="compliance-bot",
            operation_id="prune-audit-1",
        )

        self.assertEqual(len(result.purged), 2)
        self.assertEqual(self.store.list_audit(self.scope), ())
        self.assertEqual(self.store.audit_watermark(self.scope), 0)
        retention_audit = self.store.list_retention_audit(self.scope)
        self.assertEqual(len(retention_audit), 1)
        self.assertEqual(retention_audit[0].actor, "compliance-bot")
        self.assertEqual(retention_audit[0].operation_id, "prune-audit-1")
        self.assertEqual(retention_audit[0].purged_count, 2)
        self.assertEqual(
            retention_audit[0].purged_sha256,
            sha256(
                json.dumps(
                    list(retention_audit[0].purged),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            self.store.get_annotation(
                self.scope,
                annotation.annotation_id,
                include_deleted=True,
            ).annotation_id,
            annotation.annotation_id,
        )

        self.store.close()
        self.store = ReviewOverlayStore(self.database, clock_ns=self.clock)
        self.assertEqual(
            self.store.list_retention_audit(self.scope)[0].operation_id,
            "prune-audit-1",
        )
        self.assertEqual(
            self.store.purge_retention(
                self.scope,
                policy,
                actor="compliance-bot",
                operation_id="prune-audit-1",
            ),
            result,
        )

    def test_retention_operation_replays_exact_result_after_restart(self) -> None:
        for index in range(3):
            self.store.create_annotation(
                self.scope,
                annotation_id=f"replay-{index}",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event(f"event-{index}"),),
                author="alice",
                idempotency_key=f"replay-receipt-{index}",
            )
        policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=10_000,
            maximum_candidates=2,
        )
        first = self.store.purge_retention(
            self.scope,
            policy,
            actor="retention-bot",
            operation_id="replay-operation",
        )
        self.assertEqual(first.inventory.total_candidate_count, 3)
        self.assertEqual(len(first.inventory.candidates), 2)
        self.assertTrue(first.inventory.truncated)
        self.assertEqual(len(first.purged), 2)

        self.store.create_annotation(
            self.scope,
            annotation_id="replay-later",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-later"),),
            author="alice",
            idempotency_key="replay-receipt-later",
        )
        self.store.close()
        self.store = ReviewOverlayStore(self.database, clock_ns=self.clock)

        clock_before_replay = self.clock.value
        replay = self.store.purge_retention(
            self.scope,
            policy,
            actor="retention-bot",
            operation_id="replay-operation",
        )
        self.assertEqual(replay, first)
        self.assertEqual(self.clock.value, clock_before_replay)
        self.assertEqual(
            self.store.inventory_retention(self.scope, policy).total_candidate_count,
            2,
        )
        self.assertEqual(len(self.store.list_retention_audit(self.scope)), 1)
        result_json = self.store._connection.execute(
            """
            SELECT result_json FROM review_retention_audit
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND operation_id = ?
            """,
            (*self.scope.to_dict().values(), "replay-operation"),
        ).fetchone()["result_json"]
        self.assertEqual(
            json.loads(result_json)["inventory"]["candidates"],
            [
                {
                    "blockers": list(candidate.blockers),
                    "category": candidate.category,
                    "identifier": candidate.identifier,
                    "retention_value": candidate.retention_value,
                }
                for candidate in first.inventory.candidates
            ],
        )

    def test_retention_operation_conflict_is_checked_before_deletion(self) -> None:
        self.store.create_annotation(
            self.scope,
            annotation_id="conflict-initial",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-initial"),),
            author="alice",
            idempotency_key="conflict-receipt-initial",
        )
        policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=10_000,
        )
        self.store.purge_retention(
            self.scope,
            policy,
            actor="retention-bot",
            operation_id="conflicting-operation",
        )
        self.store.create_annotation(
            self.scope,
            annotation_id="conflict-later",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-later"),),
            author="alice",
            idempotency_key="conflict-receipt-later",
        )

        statements: list[str] = []
        self.store._connection.set_trace_callback(statements.append)
        try:
            with self.assertRaisesRegex(
                ReviewConflictError,
                "different actor or policy",
            ):
                self.store.purge_retention(
                    self.scope,
                    policy,
                    actor="different-actor",
                    operation_id="conflicting-operation",
                )
            self.assertFalse(
                any(
                    statement.lstrip().upper().startswith("DELETE")
                    for statement in statements
                )
            )
            statements.clear()
            with self.assertRaisesRegex(
                ReviewConflictError,
                "different actor or policy",
            ):
                self.store.purge_retention(
                    self.scope,
                    ReviewRetentionPolicy(
                        enabled=True,
                        idempotency_before_ns=9_999,
                    ),
                    actor="retention-bot",
                    operation_id="conflicting-operation",
                )
            self.assertFalse(
                any(
                    statement.lstrip().upper().startswith("DELETE")
                    for statement in statements
                )
            )
        finally:
            self.store._connection.set_trace_callback(None)
        self.assertEqual(
            self.store.inventory_retention(self.scope, policy).total_candidate_count,
            1,
        )

    def test_retention_retry_reconciles_commit_before_failure(self) -> None:
        for index in range(3):
            self.store.create_annotation(
                self.scope,
                annotation_id=f"ambiguous-retention-{index}",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event(f"ambiguous-event-{index}"),),
                author="alice",
                idempotency_key=f"ambiguous-receipt-{index}",
            )
        policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=10_000,
            maximum_candidates=2,
        )
        original = self.store._connection
        self.store._connection = _FaultingConnection(  # type: ignore[assignment]
            original,
            commit_before_failure=True,
        )
        with self.assertRaisesRegex(sqlite3.OperationalError, "commit failure"):
            self.store.purge_retention(
                self.scope,
                policy,
                actor="coordinator",
                operation_id="ambiguous-retention-operation",
            )

        replay = self.store.purge_retention(
            self.scope,
            policy,
            actor="coordinator",
            operation_id="ambiguous-retention-operation",
        )
        self.assertEqual(replay.inventory.total_candidate_count, 3)
        self.assertEqual(len(replay.inventory.candidates), 2)
        self.assertTrue(replay.inventory.truncated)
        self.assertEqual(len(replay.purged), 2)
        self.assertEqual(
            self.store.purge_retention(
                self.scope,
                policy,
                actor="coordinator",
                operation_id="ambiguous-retention-operation",
            ),
            replay,
        )
        self.assertEqual(
            self.store.inventory_retention(self.scope, policy).total_candidate_count,
            1,
        )
        self.assertEqual(len(self.store.list_retention_audit(self.scope)), 1)

    def test_retention_audit_schema_migrates_legacy_rows_fail_closed(self) -> None:
        legacy_database = Path(self.temporary.name) / "legacy-review.sqlite3"
        legacy_policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=10_000,
        )
        policy_json = strict_canonical_json(
            {
                "enabled": True,
                "tombstone_before_ns": None,
                "idempotency_before_ns": 10_000,
                "audit_mode": "preserve",
                "audit_before_sequence": None,
                "maximum_candidates": 1_000,
            }
        )
        connection = sqlite3.connect(legacy_database)
        connection.execute(
            """
            CREATE TABLE review_retention_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at_ns INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                candidate_count INTEGER NOT NULL,
                purged_count INTEGER NOT NULL,
                purged_json TEXT NOT NULL,
                purged_sha256 TEXT NOT NULL,
                UNIQUE (tenant_id, project_id, workspace_id, operation_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO review_retention_audit (
                tenant_id, project_id, workspace_id, operation_id, actor,
                occurred_at_ns, policy_json, candidate_count, purged_count,
                purged_json, purged_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.scope.tenant_id,
                self.scope.project_id,
                self.scope.workspace_id,
                "legacy-operation",
                "retention-bot",
                1,
                policy_json,
                0,
                0,
                "[]",
                sha256(b"[]").hexdigest(),
            ),
        )
        connection.commit()
        connection.close()

        legacy_store = ReviewOverlayStore(legacy_database, clock_ns=self.clock)
        try:
            columns = {
                row[1]
                for row in legacy_store._connection.execute(
                    "PRAGMA table_info(review_retention_audit)"
                )
            }
            self.assertIn("result_json", columns)
            with self.assertRaisesRegex(
                ReviewConflictError,
                "legacy operation",
            ):
                legacy_store.purge_retention(
                    self.scope,
                    legacy_policy,
                    actor="retention-bot",
                    operation_id="legacy-operation",
                )
            self.assertIsNone(
                legacy_store._connection.execute(
                    """
                    SELECT result_json FROM review_retention_audit
                    WHERE operation_id = 'legacy-operation'
                    """
                ).fetchone()["result_json"]
            )
        finally:
            legacy_store.close()

    def test_retained_tombstones_are_in_exact_revision_reference_query(
        self,
    ) -> None:
        live = self.store.create_annotation(
            self.scope,
            annotation_id="live-reference",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-live", revision_id="revision-live"),),
            author="alice",
        )
        deleted = self.store.create_annotation(
            self.scope,
            annotation_id="deleted-reference",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-deleted", revision_id="revision-deleted"),),
            author="alice",
        )
        self.store.delete_annotation(
            self.scope,
            deleted.annotation_id,
            expected_version=1,
            actor="alice",
        )
        self.assertEqual(
            self.store.referenced_revision_ids(self.scope),
            ("revision-deleted", "revision-live"),
        )
        with self.assertRaisesRegex(
            ReviewValidationError,
            "no partial result",
        ):
            self.store.referenced_revision_ids(
                self.scope,
                maximum_revision_ids=1,
            )

        self.store.purge_retention(
            self.scope,
            ReviewRetentionPolicy(
                enabled=True,
                tombstone_before_ns=self.clock.value + 1,
            ),
            actor="retention-bot",
            operation_id="purge-deleted-reference",
        )
        self.assertEqual(
            self.store.referenced_revision_ids(self.scope),
            (live.subjects[0].revision_id,),
        )

    def test_retention_inventory_and_purge_are_bounded(self) -> None:
        for index in range(3):
            self.store.create_annotation(
                self.scope,
                annotation_id=f"bounded-{index}",
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event(f"event-{index}"),),
                author="alice",
                idempotency_key=f"bounded-request-{index}",
            )
        cutoff = self.clock.value + 1
        policy = ReviewRetentionPolicy(
            enabled=True,
            idempotency_before_ns=cutoff,
            maximum_candidates=2,
        )

        preview = self.store.inventory_retention(self.scope, policy)
        self.assertEqual(preview.total_candidate_count, 3)
        self.assertEqual(len(preview.candidates), 2)
        self.assertTrue(preview.truncated)
        first = self.store.purge_retention(self.scope, policy)
        second = self.store.inventory_retention(self.scope, policy)

        self.assertEqual(len(first.purged), 2)
        self.assertEqual(second.total_candidate_count, 1)
        self.assertFalse(second.truncated)

    def test_scope_isolation_is_hidden_and_versions_are_optimistic(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="shared-id",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-1"),),
            author="alice",
        )
        with self.assertRaises(KeyError):
            self.store.get_annotation(self.other_scope, annotation.annotation_id)
        with self.assertRaises(KeyError):
            self.store.update_annotation(
                self.other_scope,
                annotation.annotation_id,
                expected_version=1,
                actor="mallory",
                body="cross-tenant",
            )
        with self.assertRaises(ReviewConflictError):
            self.store.update_annotation(
                self.scope,
                annotation.annotation_id,
                expected_version=2,
                actor="alice",
                body="stale",
            )
        other = self.store.create_annotation(
            self.other_scope,
            annotation_id="shared-id",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-other"),),
            author="other",
        )
        self.assertEqual(other.annotation_id, annotation.annotation_id)
        self.assertEqual(len(self.store.list_annotations(self.scope)), 1)
        self.assertEqual(len(self.store.list_annotations(self.other_scope)), 1)
        self.assertEqual(len(self.store.list_audit(self.other_scope)), 1)

    def test_project_and_workspace_scope_components_are_independent(self) -> None:
        sibling_workspace = ReviewScope(
            "tenant-a",
            "project-a",
            "workspace-b",
        )
        sibling_project = ReviewScope(
            "tenant-a",
            "project-b",
            "workspace-a",
        )
        original = self.store.create_annotation(
            self.scope,
            annotation_id="scoped-id",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        for sibling in (sibling_workspace, sibling_project):
            with self.subTest(scope=sibling), self.assertRaises(KeyError):
                self.store.get_annotation(sibling, original.annotation_id)
            created = self.store.create_annotation(
                sibling,
                annotation_id=original.annotation_id,
                kind=ReviewAnnotationKind.MARKER,
                subjects=(self.event("event-b"),),
                author="bob",
            )
            self.assertEqual(created.scope, sibling)
            self.assertEqual(len(self.store.list_audit(sibling)), 1)
        self.assertEqual(len(self.store.list_audit(self.scope)), 1)

    def test_manual_correlation_preserves_subject_and_edge_order(self) -> None:
        subjects = (
            self.event("event-b", revision_id="revision-b", node_id="node-b"),
            self.event("event-a"),
            self.event("event-c"),
        )
        edges = (
            ManualCorrelationEdge(1, 0, "user.causes"),
            ManualCorrelationEdge(0, 2, "user.precedes", directed=False),
        )
        correlation = self.store.create_correlation(
            self.scope,
            correlation_id="correlation-1",
            subjects=subjects,
            edges=edges,
            author="alice",
            rationale="Cross-node timing and matching evidence",
            tags=("manual",),
            confidence=0.75,
            idempotency_key="correlation-request-1",
        )
        replay = self.store.create_correlation(
            self.scope,
            correlation_id="correlation-1",
            subjects=subjects,
            edges=edges,
            author="alice",
            rationale="Cross-node timing and matching evidence",
            tags=("manual",),
            confidence=0.75,
            idempotency_key="correlation-request-1",
        )
        self.assertEqual(replay, correlation)
        self.assertEqual(correlation.subjects, subjects)
        self.assertEqual(correlation.edges, edges)

        updated = self.store.update_correlation(
            self.scope,
            correlation.correlation_id,
            expected_version=1,
            actor="bob",
            rationale="Corroborated by source record identity",
            confidence=None,
        )
        self.assertEqual(updated.version, 2)
        self.assertIsNone(updated.confidence)
        self.assertEqual(updated.subjects, subjects)
        self.assertEqual(updated.edges, edges)

        deleted = self.store.delete_correlation(
            self.scope,
            correlation.correlation_id,
            expected_version=2,
            actor="bob",
        )
        self.assertTrue(deleted.tombstoned)
        with self.assertRaises(KeyError):
            self.store.get_correlation(
                self.other_scope,
                correlation.correlation_id,
                include_deleted=True,
            )
        audit = self.store.list_audit(self.scope)
        self.assertEqual(
            [entry.entity_kind for entry in audit],
            [
                "manual_event_correlation",
                "manual_event_correlation",
                "manual_event_correlation",
            ],
        )

    def test_subject_and_edge_validation_fails_closed(self) -> None:
        with self.assertRaises(ReviewValidationError):
            ReviewSubject(
                revision_id="revision-a",
                kind=ReviewSubjectKind.TIME_RANGE,
                start_ns=20,
                end_ns=10,
            )
        with self.assertRaises(ReviewValidationError):
            self.store.create_correlation(
                self.scope,
                subjects=(
                    self.event("event-a"),
                    ReviewSubject(
                        revision_id="revision-a",
                        kind=ReviewSubjectKind.RESOURCE,
                        subject_id="resource-a",
                    ),
                ),
                edges=(ManualCorrelationEdge(0, 1, "related"),),
                author="alice",
            )
        with self.assertRaises(ReviewValidationError):
            self.store.create_correlation(
                self.scope,
                subjects=(self.event("event-a"), self.event("event-b")),
                edges=(ManualCorrelationEdge(0, 2, "related"),),
                author="alice",
            )

    def test_thread_safe_transactions_keep_unique_audit_sequence(self) -> None:
        errors: list[BaseException] = []

        def create(index: int) -> None:
            try:
                self.store.create_annotation(
                    self.scope,
                    annotation_id=f"thread-{index:02}",
                    kind=ReviewAnnotationKind.MARKER,
                    subjects=(self.event(f"event-{index:02}"),),
                    author="worker",
                )
            except Exception as error:  # noqa: BLE001  # pragma: no cover
                errors.append(error)

        threads = [
            threading.Thread(target=create, args=(index,)) for index in range(20)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(self.store.list_annotations(self.scope)), 20)
        sequences = [entry.sequence for entry in self.store.list_audit(self.scope)]
        self.assertEqual(sequences, sorted(set(sequences)))

    def test_report_snapshot_binds_records_to_one_audit_watermark(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="snapshot-marker",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        correlation = self.store.create_correlation(
            self.scope,
            correlation_id="snapshot-correlation",
            subjects=(self.event("event-a"), self.event("event-b")),
            edges=(ManualCorrelationEdge(0, 1, "user.related"),),
            author="alice",
        )

        snapshot = self.store.snapshot_for_report(self.scope)
        self.assertEqual(snapshot.annotations, (annotation,))
        self.assertEqual(snapshot.correlations, (correlation,))
        self.assertEqual(
            snapshot.audit_watermark,
            self.store.audit_watermark(self.scope),
        )

        self.store.update_annotation(
            self.scope,
            annotation.annotation_id,
            expected_version=1,
            actor="bob",
            body="later edit",
        )
        later = self.store.snapshot_for_report(self.scope)
        self.assertEqual(snapshot.annotations[0].version, 1)
        self.assertEqual(later.annotations[0].version, 2)
        self.assertGreater(later.audit_watermark, snapshot.audit_watermark)

    def test_report_is_deterministic_and_separates_provenance(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="annotation-report",
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.event("event-b"),),
            author="alice",
            body="Inspect the withdrawal",
        )
        correlation = self.store.create_correlation(
            self.scope,
            correlation_id="manual-report",
            subjects=(self.event("event-b"), self.event("event-a")),
            edges=(ManualCorrelationEdge(0, 1, "user.related"),),
            author="alice",
            rationale="The events appear related",
        )
        common = {
            "scope": self.scope,
            "annotation_watermark": self.store.audit_watermark(self.scope),
            "annotations": (annotation,),
            "manual_correlations": (correlation,),
        }
        forward = build_correlation_report(
            **common,
            revision_vector=(
                {"node_id": "node-b", "revision_id": "revision-b"},
                {"node_id": "node-a", "revision_id": "revision-a"},
            ),
            events=(
                {
                    "revision_id": "revision-b",
                    "event_uid": "event-b",
                    "timestamp_ns": "200",
                },
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": "100",
                },
            ),
            source_records=(
                {
                    "revision_id": "revision-a",
                    "source_record_uid": "source-a",
                    "timestamp_ns": "90",
                },
            ),
            plugin_causal_links=(
                {
                    "source_event_uid": "event-a",
                    "target_event_uid": "event-b",
                    "link_type": "plugin.causes",
                },
            ),
            corroboration_facts=(
                {
                    "fact_type": "shared_resource",
                    "result": "supports",
                    "resource_id": "resource-a",
                },
            ),
            unresolved_references=(
                {"revision_id": "missing", "event_uid": "missing-event"},
            ),
            warnings=("clock uncertainty overlaps",),
        )
        reverse = build_correlation_report(
            **common,
            revision_vector=tuple(
                reversed(
                    (
                        {"node_id": "node-b", "revision_id": "revision-b"},
                        {"node_id": "node-a", "revision_id": "revision-a"},
                    )
                )
            ),
            events=tuple(
                reversed(
                    (
                        {
                            "revision_id": "revision-b",
                            "event_uid": "event-b",
                            "timestamp_ns": "200",
                        },
                        {
                            "revision_id": "revision-a",
                            "event_uid": "event-a",
                            "timestamp_ns": "100",
                        },
                    )
                )
            ),
            source_records=(
                {
                    "revision_id": "revision-a",
                    "source_record_uid": "source-a",
                    "timestamp_ns": "90",
                },
            ),
            plugin_causal_links=(
                {
                    "source_event_uid": "event-a",
                    "target_event_uid": "event-b",
                    "link_type": "plugin.causes",
                },
            ),
            corroboration_facts=(
                {
                    "fact_type": "shared_resource",
                    "result": "supports",
                    "resource_id": "resource-a",
                },
            ),
            unresolved_references=(
                {"revision_id": "missing", "event_uid": "missing-event"},
            ),
            warnings=("clock uncertainty overlaps",),
        )
        self.assertEqual(forward.json_document, reverse.json_document)
        self.assertEqual(forward.canonical_json, reverse.canonical_json)
        self.assertEqual(forward.markdown, reverse.markdown)
        self.assertEqual(forward.sha256, reverse.sha256)
        self.assertNotIn("generated_at", forward.canonical_json)
        self.assertEqual(
            json.loads(forward.canonical_json),
            forward.json_document,
        )
        plugin = forward.json_document["correlations"]["plugin_causal_links"]
        manual = forward.json_document["correlations"]["manual_event_correlations"]
        self.assertEqual(
            plugin[0]["provenance_class"],
            CorrelationReportProvenanceClass.PLUGIN_INFERRED.value,
        )
        self.assertEqual(
            manual[0]["provenance_class"],
            CorrelationReportProvenanceClass.USER_ASSERTED.value,
        )
        self.assertEqual(
            forward.json_document["corroboration_facts"][0]["provenance_class"],
            CorrelationReportProvenanceClass.CORE_CORROBORATION.value,
        )
        self.assertNotIn("plugin.causes", json.dumps(manual))
        self.assertIn(forward.sha256, forward.markdown)
        self.assertEqual(
            forward.json_document["summary"]["unresolved_reference_count"],
            1,
        )

    def test_report_rejects_cross_scope_and_noncanonical_values(self) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        with self.assertRaises(KeyError):
            build_correlation_report(
                self.other_scope,
                revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
                annotation_watermark=0,
                annotations=(annotation,),
            )
        with self.assertRaises(ReviewValidationError):
            build_correlation_report(
                self.scope,
                revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
                annotation_watermark=1,
                corroboration_facts=(
                    {
                        "fact_type": "time_delta",
                        "result": "supports",
                        "score": math.nan,
                    },
                ),
            )
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        with self.assertRaises(ReviewValidationError):
            build_correlation_report(
                self.scope,
                revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
                annotation_watermark=1,
                events=(cyclic,),
            )

    def test_report_v2_uses_lossless_nanosecond_strings_only_on_wire(
        self,
    ) -> None:
        time_range = ReviewSubject(
            revision_id="revision-a",
            kind=ReviewSubjectKind.TIME_RANGE,
            start_ns=9_007_199_254_740_993,
            end_ns=9_007_199_254_740_999,
        )
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="wide-time",
            kind=ReviewAnnotationKind.MARKER,
            subjects=(time_range,),
            author="alice",
        )
        report = build_correlation_report(
            self.scope,
            revision_vector=(
                {
                    "revision_id": "revision-a",
                    "node_id": "node-a",
                    "published_at_ns": 9_007_199_254_740_991,
                },
            ),
            annotation_watermark=1,
            annotations=(annotation,),
            events=(
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": "9007199254740993",
                    "timestamp_uncertainty_ns": 2,
                },
            ),
            source_records=(
                {
                    "revision_id": "revision-a",
                    "source_record_uid": "source-a",
                    "timestamp_ns": 9_007_199_254_740_992,
                },
            ),
        )

        self.assertEqual(
            report.json_document["schema_version"],
            CORRELATION_REPORT_SCHEMA_VERSION,
        )

        revision = report.json_document["revision_vector"][0]
        projected_annotation = report.json_document["annotations"][0]
        projected_event = report.json_document["observations"]["events"][0]
        projected_source = report.json_document["observations"]["source_records"][0]
        for value in (
            revision["published_at_ns"],
            projected_annotation["created_at_ns"],
            projected_annotation["updated_at_ns"],
            projected_annotation["subjects"][0]["start_ns"],
            projected_annotation["subjects"][0]["end_ns"],
            projected_event["timestamp_ns"],
            projected_event["timestamp_uncertainty_ns"],
            projected_source["timestamp_ns"],
        ):
            self.assertIsInstance(value, str)
            self.assertEqual(str(int(value)), value)
        self.assertEqual(
            time_range.to_dict()["start_ns"],
            9_007_199_254_740_993,
        )
        self.assertIsInstance(time_range.to_dict()["start_ns"], int)
        self.assertEqual(
            report.sha256,
            sha256(report.canonical_json.encode("utf-8")).hexdigest(),
        )

    def test_report_v2_preserves_plugin_owned_ns_suffix_values(self) -> None:
        wide_time = 9_007_199_254_740_993
        attributes = {
            "hold_down_ns": "fast",
            "opaque_counter_ns": 7,
            "nested": {
                "preference_ns": False,
                "signed_ns": -4,
            },
        }
        report = build_correlation_report(
            self.scope,
            revision_vector=(
                {
                    "revision_id": "revision-a",
                    "node_id": "node-a",
                    "published_at_ns": wide_time,
                },
            ),
            annotation_watermark=0,
            events=(
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": wide_time,
                    "timestamp_uncertainty_ns": 2,
                    "attributes": attributes,
                    "effects": [
                        {
                            "attributes": {
                                "retry_ns": "operator-controlled",
                            }
                        }
                    ],
                    "evidence": {
                        "raw_timestamp_ns": wide_time,
                        "locator": "line:1",
                        "plugin_detail": {
                            "raw_timestamp_ns": "derived-on-demand",
                        },
                    },
                },
            ),
            plugin_causal_links=(
                {
                    "source_event_uid": "event-a",
                    "target_event_uid": "event-b",
                    "plugin_delay_ns": "adaptive",
                },
            ),
            corroboration_facts=(
                {
                    "fact_type": "plugin-opaque-evidence",
                    "result": "unknown",
                    "evidence": [{"hold_down_ns": "fast"}],
                },
            ),
            warnings=({"plugin_retry_ns": "when-ready"},),
        )

        event = report.json_document["observations"]["events"][0]
        self.assertEqual(event["attributes"], attributes)
        self.assertEqual(
            event["effects"][0]["attributes"]["retry_ns"],
            "operator-controlled",
        )
        self.assertEqual(event["timestamp_ns"], str(wide_time))
        self.assertEqual(event["timestamp_uncertainty_ns"], "2")
        self.assertEqual(
            event["evidence"]["raw_timestamp_ns"],
            str(wide_time),
        )
        self.assertEqual(
            event["evidence"]["plugin_detail"]["raw_timestamp_ns"],
            "derived-on-demand",
        )
        self.assertEqual(
            report.json_document["correlations"]["plugin_causal_links"][0]["link"][
                "plugin_delay_ns"
            ],
            "adaptive",
        )
        self.assertEqual(
            report.json_document["corroboration_facts"][0]["fact"]["evidence"][0][
                "hold_down_ns"
            ],
            "fast",
        )
        self.assertEqual(
            report.json_document["warnings"][0]["plugin_retry_ns"],
            "when-ready",
        )

    def test_report_v2_rejects_noncanonical_time_and_duplicate_identity(
        self,
    ) -> None:
        common = {
            "scope": self.scope,
            "revision_vector": ({"revision_id": "revision-a", "node_id": "node-a"},),
            "annotation_watermark": 0,
        }
        for invalid in ("01", "+1", "-0", 1.5, True):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(
                    ReviewValidationError,
                    "canonical decimal",
                ),
            ):
                build_correlation_report(
                    **common,
                    events=(
                        {
                            "revision_id": "revision-a",
                            "event_uid": "event-a",
                            "timestamp_ns": invalid,
                        },
                    ),
                )

        duplicate = {
            "revision_id": "revision-a",
            "event_uid": "event-a",
            "timestamp_ns": "1",
        }
        with self.assertRaisesRegex(ReviewValidationError, "duplicate"):
            build_correlation_report(
                **common,
                events=(duplicate, dict(duplicate)),
            )

    def test_report_markdown_contains_no_untrusted_structure(self) -> None:
        scope = ReviewScope(
            "tenant`value ## injected heading",
            "project",
            "workspace",
        )
        report = build_correlation_report(
            scope,
            revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
            annotation_watermark=0,
            warnings=("warning\n## injected heading",),
        )

        self.assertNotIn("\n## injected heading", report.markdown)
        self.assertIn("tenant`value ## injected heading", report.markdown)

    def test_report_scope_is_sanitized_before_json_and_markdown_rendering(self) -> None:
        raw_scope_text = "tenant\u200bhidden\u3164"
        report = build_correlation_report(
            ReviewScope(raw_scope_text, "project", "workspace"),
            revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
            annotation_watermark=0,
        )

        escaped_scope_text = "tenant\\u200bhidden\\u3164"
        self.assertEqual(
            report.json_document["scope"]["tenant_id"],
            escaped_scope_text,
        )
        self.assertIn(escaped_scope_text, report.markdown)
        for character in ("\u200b", "\u3164"):
            self.assertNotIn(character, report.canonical_json)
            self.assertNotIn(character, report.markdown)

    def test_report_exposes_invisible_ai_controls_in_values_and_keys(self) -> None:
        unsafe_codepoints = (
            0x0085,  # next line
            0x00A0,  # no-break space
            0x200B,  # zero-width space
            0x2028,  # line separator
            0x2029,  # paragraph separator
            0xFEFF,  # byte-order mark / zero-width no-break space
            0x202E,  # right-to-left override
            0x2066,  # left-to-right isolate
            0xE0000,  # unassigned TAG-block code point
            0xE0061,  # TAG LATIN SMALL LETTER A
            0x115F,  # Hangul choseong filler
            0x1160,  # Hangul jungseong filler
            0x17B4,  # Khmer vowel inherent AQ
            0x17B5,  # Khmer vowel inherent AA
            0x2800,  # Braille pattern blank
            0x3164,  # Hangul filler
            0xFFA0,  # halfwidth Hangul filler
            0x13441,  # Egyptian hieroglyph full blank
            0x13442,  # Egyptian hieroglyph half blank
            0x034F,  # combining grapheme joiner
            0x180B,  # Mongolian free variation selector one
            0xFE0D,  # standard variation selector 14
            0xE0100,  # supplementary variation selector
            0xFFFC,  # object replacement character
            0xE000,  # BMP private-use character
            0xF0000,  # supplementary private-use character
        )

        def escaped_codepoint(codepoint: int) -> str:
            return (
                f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
            )

        metadata = {
            f"field{chr(codepoint)}": f"value{chr(codepoint)}"
            for codepoint in unsafe_codepoints
        }
        # Annotation admission rejects bidi controls before report rendering;
        # exercise every other unsafe value through the label path as well.
        label_codepoints = unsafe_codepoints[:6] + unsafe_codepoints[8:]
        annotation = self.store.create_annotation(
            self.scope,
            annotation_id="unsafe-label",
            kind=ReviewAnnotationKind.NOTE,
            subjects=(self.event("event-a"),),
            author="alice",
            title="status" + "".join(map(chr, label_codepoints)),
        )
        report = build_correlation_report(
            self.scope,
            revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
            annotation_watermark=1,
            annotations=(annotation,),
            events=(
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": "1",
                    "message": "safe" + "".join(map(chr, unsafe_codepoints)),
                    "metadata": metadata,
                },
            ),
        )

        event = report.json_document["observations"]["events"][0]
        expected_message = "safe" + "".join(
            escaped_codepoint(codepoint) for codepoint in unsafe_codepoints
        )
        self.assertEqual(event["message"], expected_message)
        self.assertEqual(
            report.json_document["annotations"][0]["title"],
            "status"
            + "".join(escaped_codepoint(codepoint) for codepoint in label_codepoints),
        )
        for codepoint in unsafe_codepoints:
            raw_control = chr(codepoint)
            escaped = escaped_codepoint(codepoint)
            self.assertEqual(
                event["metadata"][f"field{escaped}"],
                f"value{escaped}",
            )
            self.assertNotIn(raw_control, report.canonical_json)
            self.assertNotIn(raw_control, report.markdown)
            self.assertIn(escaped.replace("\\", "\\\\"), report.canonical_json)

    def test_report_preserves_presentation_sequences_and_mongolian_base(self) -> None:
        presentation_sequences = (
            "warning \u26a0\ufe0f",
            "heart \u2764\ufe0f",
            "info \u2139\ufe0f",
            "rainbow \U0001f3f3\ufe0f\u200d\U0001f308",
        )
        report = build_correlation_report(
            self.scope,
            revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
            annotation_watermark=0,
            events=(
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": "1",
                    "message": "; ".join(presentation_sequences)
                    + "; Mongolian \u1820\u180b",
                },
            ),
        )

        message = report.json_document["observations"]["events"][0]["message"]
        self.assertEqual(
            message,
            "; ".join(presentation_sequences) + "; Mongolian \u1820\\u180b",
        )
        for sequence in presentation_sequences:
            self.assertIn(sequence, message)
            self.assertIn(sequence, report.markdown)
        self.assertIn("\u1820", report.markdown)
        self.assertNotIn("\u180b", report.markdown)

    def test_report_preserves_keys_that_previously_collided_after_sanitizing(
        self,
    ) -> None:
        report = build_correlation_report(
            self.scope,
            revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
            annotation_watermark=0,
            events=(
                {
                    "revision_id": "revision-a",
                    "event_uid": "event-a",
                    "timestamp_ns": "1",
                    "metadata": {
                        "field\u2028": "unsafe",
                        "field\\u2028": "literal escape",
                    },
                },
            ),
        )

        metadata = report.json_document["observations"]["events"][0]["metadata"]
        self.assertEqual(metadata["field\\u2028"], "unsafe")
        self.assertEqual(metadata["field\\\\u2028"], "literal escape")

    def test_report_digest_distinguishes_unsafe_text_from_literal_escape(self) -> None:
        common = {
            "scope": self.scope,
            "revision_vector": ({"revision_id": "revision-a", "node_id": "node-a"},),
            "annotation_watermark": 0,
        }
        unsafe = build_correlation_report(
            **common,
            warnings=("state\u2028changed",),
        )
        literal = build_correlation_report(
            **common,
            warnings=("state\\u2028changed",),
        )

        self.assertNotEqual(unsafe.json_document, literal.json_document)
        self.assertNotEqual(unsafe.canonical_json, literal.canonical_json)
        self.assertNotEqual(unsafe.sha256, literal.sha256)

    def test_strict_report_canonical_golden_vectors(self) -> None:
        path = (
            Path(__file__).parent
            / "fixtures"
            / ("correlation-report-v2-canonical.json")
        )
        vectors = json.loads(path.read_text(encoding="utf-8"))
        for vector in vectors:
            with self.subTest(name=vector["name"]):
                self.assertEqual(
                    strict_canonical_json(vector["value"]),
                    vector["canonical"],
                )
                self.assertEqual(
                    strict_canonical_json_bytes(vector["value"]),
                    vector["canonical"].encode("utf-8"),
                )

    def test_report_bounds_streams_and_total_json_before_materialization(
        self,
    ) -> None:
        annotation = self.store.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.MARKER,
            subjects=(self.event("event-a"),),
            author="alice",
        )
        tombstone = self.store.delete_annotation(
            self.scope,
            annotation.annotation_id,
            expected_version=1,
            actor="alice",
        )
        with self.assertRaisesRegex(
            ReviewValidationError,
            "too many annotations",
        ):
            build_correlation_report(
                self.scope,
                revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
                annotation_watermark=2,
                annotations=itertools.repeat(tombstone),
            )

        oversized_stream = (
            {
                "revision_id": "revision-a",
                "event_uid": f"event-{index}",
                "payload": list(range(1_000)),
            }
            for index in range(600)
        )
        with self.assertRaisesRegex(
            ReviewValidationError,
            "exceeds 500000 JSON units",
        ):
            build_correlation_report(
                self.scope,
                revision_vector=({"revision_id": "revision-a", "node_id": "node-a"},),
                annotation_watermark=2,
                events=oversized_stream,
            )


if __name__ == "__main__":
    unittest.main()
