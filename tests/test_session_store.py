from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

from router_dump_analyzer.canonical import (
    canonical_json,
    canonical_json_sha256,
    strict_canonical_json,
)
from router_dump_analyzer.private_analysis import (
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    workspace_disclosure_policy_dict,
    workspace_disclosure_policy_digest,
)
from router_dump_analyzer.session_store import (
    CatalogRetentionDisabledError,
    CatalogRetentionPolicy,
    IdempotencyConflict,
    SessionConflictError,
    SessionStoreDeadlineExceeded,
    SessionStoreError,
    SqliteSessionStore,
    StaleSessionVersion,
    StaleWorkspaceDisclosurePolicyVersion,
    validate_catalog_identifier,
    validate_catalog_label,
    validate_catalog_metadata,
)
from router_dump_analyzer.value_core import MAX_JSON_SAFE_INTEGER


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class _FailOnceCommitConnection:
    """Connection proxy used to inject commit and rollback failures."""

    def __init__(
        self,
        delegate: sqlite3.Connection,
        *,
        leave_transaction_open: bool = False,
    ) -> None:
        self.delegate = delegate
        self.leave_transaction_open = leave_transaction_open
        self.failed = False

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    @property
    def in_transaction(self) -> bool:
        return self.delegate.in_transaction

    def cursor(self) -> sqlite3.Cursor:
        return self.delegate.cursor()

    def commit(self) -> None:
        if not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("injected commit failure")
        self.delegate.commit()

    def rollback(self) -> None:
        if not self.leave_transaction_open:
            self.delegate.rollback()

    def close(self) -> None:
        self.delegate.close()


class SqliteSessionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "sessions.sqlite3"
        self.store = SqliteSessionStore(self.database)

    def test_deadline_bounds_store_lock_acquisition(self) -> None:
        acquired = threading.Event()
        release = threading.Event()

        def hold_store_lock() -> None:
            self.store._lock.acquire()
            try:
                acquired.set()
                release.wait(5)
            finally:
                self.store._lock.release()

        holder = threading.Thread(target=hold_store_lock, daemon=True)
        holder.start()
        self.assertTrue(acquired.wait(1))
        started = time.monotonic()
        try:
            with self.assertRaises(SessionStoreDeadlineExceeded):
                self.store.get_workspace(
                    "tenant-a",
                    "workspace-a",
                    deadline_ns=time.monotonic_ns() + 50_000_000,
                )
        finally:
            release.set()
            holder.join(1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(holder.is_alive())

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _workspace(
        self,
        *,
        tenant: str = "tenant-a",
        project: str = "project-a",
        workspace: str = "workspace-a",
    ) -> None:
        self.store.create_project(
            tenant,
            "Project A",
            project_id=project,
            metadata={"owner": "network-team"},
        )
        self.store.create_workspace(
            tenant,
            project,
            "Workspace A",
            workspace_id=workspace,
            metadata={"purpose": "incident-review"},
        )

    def _fixture_revision(
        self,
        *,
        tenant: str = "tenant-a",
        workspace: str = "workspace-a",
        fixture: str,
        revision: str,
        node: str,
    ) -> None:
        self.store.attach_fixture(
            tenant,
            workspace,
            fixture,
            label=fixture,
            content_digest=_digest(fixture),
            metadata={"source": f"{fixture}.tgz"},
        )
        self.store.publish_revision(
            tenant,
            workspace,
            fixture,
            revision,
            node_id=node,
            identity_digest=_digest(revision),
            plugin_ids=("vendor.router",),
            metadata={"capture": revision},
        )

    @staticmethod
    def _full_fidelity_policy() -> WorkspaceDisclosurePolicy:
        return WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )

    def test_workspace_disclosure_policy_defaults_disabled_outside_metadata(self) -> None:
        self.store.create_project(
            "tenant-a",
            "Project A",
            project_id="project-a",
        )
        self.store.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace A",
            workspace_id="workspace-a",
            metadata={
                "private_analysis_policy": "full_fidelity",
                "allow_proprietary_ai": True,
            },
        )
        record = self.store.get_workspace_disclosure_policy(
            "tenant-a", "workspace-a"
        )
        self.assertEqual(record.version, 0)
        self.assertFalse(record.explicit)
        self.assertEqual(record.policy, WorkspaceDisclosurePolicy.disabled())

    def test_legacy_workspace_without_policy_table_migrates_to_disabled(self) -> None:
        self._workspace()
        self.store._connection.execute(
            "DROP TABLE workspace_disclosure_policies"
        )
        self.store.close()
        self.store = SqliteSessionStore(self.database)
        record = self.store.get_workspace_disclosure_policy(
            "tenant-a", "workspace-a"
        )
        self.assertEqual(record.version, 0)
        self.assertFalse(record.explicit)
        self.assertEqual(record.policy, WorkspaceDisclosurePolicy.disabled())

    def test_v1_workspace_policy_history_migrates_to_rooted_record_chain(
        self,
    ) -> None:
        self.store.close()
        self.database.unlink()
        policy = self._full_fidelity_policy()
        policy_json = strict_canonical_json(
            workspace_disclosure_policy_dict(policy)
        )
        policy_digest = workspace_disclosure_policy_digest(policy)
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            PRAGMA user_version = 1;
            CREATE TABLE tenants (
                tenant_id TEXT PRIMARY KEY,
                created_at_ns INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE projects (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                label TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, project_id)
            ) STRICT;
            CREATE TABLE workspaces (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                label TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, workspace_id)
            ) STRICT;
            CREATE TABLE workspace_disclosure_policies (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, workspace_id, version)
            ) STRICT;
            CREATE TABLE workspace_disclosure_policy_heads (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                current_version INTEGER NOT NULL,
                current_policy_digest TEXT NOT NULL,
                updated_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, workspace_id)
            ) STRICT;
            CREATE TABLE idempotency_keys (
                tenant_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, operation, idempotency_key)
            ) STRICT;
            """
        )
        connection.execute(
            "INSERT INTO tenants VALUES (?, ?)", ("tenant-a", 10)
        )
        connection.execute(
            "INSERT INTO projects VALUES (?, ?, ?, ?, ?)",
            ("tenant-a", "project-a", "Project A", "{}", 20),
        )
        connection.execute(
            "INSERT INTO workspaces VALUES (?, ?, ?, ?, ?, ?)",
            (
                "tenant-a",
                "workspace-a",
                "project-a",
                "Workspace A",
                "{}",
                30,
            ),
        )
        connection.execute(
            """
            INSERT INTO workspace_disclosure_policies
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "tenant-a",
                "workspace-a",
                1,
                policy_json,
                policy_digest,
                "admin-a",
                40,
            ),
        )
        connection.execute(
            "INSERT INTO workspace_disclosure_policy_heads VALUES (?, ?, ?, ?, ?)",
            ("tenant-a", "workspace-a", 1, policy_digest, 40),
        )
        legacy_request = {
            "workspace_id": "workspace-a",
            "policy": workspace_disclosure_policy_dict(policy),
            "actor_id": "admin-a",
            "expected_version": 0,
        }
        legacy_response = {
            "tenant_id": "tenant-a",
            "project_id": "project-a",
            "workspace_id": "workspace-a",
            "version": 1,
            "policy": workspace_disclosure_policy_dict(policy),
            "policy_digest": policy_digest,
            "actor_id": "admin-a",
            "created_at_ns": 40,
            "explicit": True,
        }
        connection.execute(
            "INSERT INTO idempotency_keys VALUES (?, ?, ?, ?, ?, ?)",
            (
                "tenant-a",
                "set_workspace_disclosure_policy",
                "legacy-policy",
                canonical_json_sha256(legacy_request),
                canonical_json(legacy_response),
                41,
            ),
        )
        connection.commit()
        connection.close()

        self.store = SqliteSessionStore(self.database)
        record = self.store.get_workspace_disclosure_policy(
            "tenant-a", "workspace-a"
        )
        self.assertEqual(record.version, 1)
        self.assertEqual(record.policy, policy)
        self.assertEqual(record.actor_id, "admin-a")
        replay = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            policy,
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="legacy-policy",
        )
        self.assertEqual(replay, record)
        self.assertEqual(
            self.store._connection.execute("PRAGMA user_version").fetchone()[0],
            2,
        )
        foreign_key_errors = self.store._connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        self.assertEqual(foreign_key_errors, [])

    def test_workspace_disclosure_policy_is_durable_versioned_and_audited(self) -> None:
        self._workspace()
        first = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        replay = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.assertEqual(replay, first)
        second = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-b",
            expected_version=1,
        )
        self.assertEqual(second.version, 2)
        self.assertEqual(
            [entry.version for entry in self.store.list_workspace_disclosure_policy_history(
                "tenant-a", "workspace-a"
            )],
            [2, 1],
        )
        self.store.close()
        self.store = SqliteSessionStore(self.database)
        self.assertEqual(
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            ),
            second,
        )

    def test_workspace_disclosure_policy_rejects_stale_noop_and_cross_tenant(self) -> None:
        self._workspace()
        policy = self._full_fidelity_policy()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            policy,
            actor_id="admin-a",
            expected_version=0,
        )
        with self.assertRaises(StaleWorkspaceDisclosurePolicyVersion):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                WorkspaceDisclosurePolicy.disabled(),
                actor_id="admin-a",
                expected_version=0,
            )
        with self.assertRaises(SessionConflictError):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                policy,
                actor_id="admin-a",
                expected_version=1,
            )
        with self.assertRaises(KeyError):
            self.store.get_workspace_disclosure_policy(
                "tenant-b", "workspace-a"
            )

    def test_workspace_disclosure_policy_corruption_fails_closed(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_immutable"
        )
        self.store._connection.execute(
            """
            UPDATE workspace_disclosure_policies
            SET policy_digest = ?
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            ("0" * 64, "tenant-a", "workspace-a"),
        )
        with self.assertRaisesRegex(SessionStoreError, "stored workspace"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )

    def test_workspace_disclosure_policy_history_deletion_cannot_rollback(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
        )
        disabled = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-a",
            expected_version=1,
            idempotency_key="disable-policy",
        )
        self.assertEqual(disabled.version, 2)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute(
                """
                DELETE FROM workspace_disclosure_policies
                WHERE tenant_id = ? AND workspace_id = ? AND version = ?
                """,
                ("tenant-a", "workspace-a", 2),
            )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_no_direct_delete"
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_seal_no_direct_delete"
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_receipt_no_direct_delete"
        )
        self.store._connection.execute(
            """
            DELETE FROM workspace_disclosure_policies
            WHERE tenant_id = ? AND workspace_id = ? AND version = ?
            """,
            ("tenant-a", "workspace-a", 2),
        )
        with self.assertRaisesRegex(SessionStoreError, "(?:history|tip) is invalid"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "(?:history|tip) is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                WorkspaceDisclosurePolicy.disabled(),
                actor_id="admin-a",
                expected_version=1,
                idempotency_key="disable-policy",
            )

    def test_workspace_disclosure_policy_head_and_old_history_are_required(self) -> None:
        for suffix, delete_target in (("old", "history"), ("head", "head")):
            with self.subTest(delete_target=delete_target):
                project = f"project-{suffix}"
                workspace = f"workspace-{suffix}"
                self._workspace(project=project, workspace=workspace)
                self.store.set_workspace_disclosure_policy(
                    "tenant-a",
                    workspace,
                    self._full_fidelity_policy(),
                    actor_id="admin-a",
                    expected_version=0,
                )
                self.store.set_workspace_disclosure_policy(
                    "tenant-a",
                    workspace,
                    WorkspaceDisclosurePolicy.disabled(),
                    actor_id="admin-a",
                    expected_version=1,
                )
                if delete_target == "history":
                    self.store._connection.execute(
                        "DROP TRIGGER IF EXISTS "
                        "workspace_disclosure_policy_no_direct_delete"
                    )
                    self.store._connection.execute(
                        "DROP TRIGGER IF EXISTS "
                        "workspace_disclosure_policy_seal_no_direct_delete"
                    )
                    self.store._connection.execute(
                        """
                        DELETE FROM workspace_disclosure_policies
                        WHERE tenant_id = ? AND workspace_id = ? AND version = 1
                        """,
                        ("tenant-a", workspace),
                    )
                else:
                    with self.assertRaises(sqlite3.IntegrityError):
                        self.store._connection.execute(
                            """
                            DELETE FROM workspace_disclosure_policy_heads
                            WHERE tenant_id = ? AND workspace_id = ?
                            """,
                            ("tenant-a", workspace),
                        )
                    self.store._connection.execute(
                        "DROP TRIGGER IF EXISTS "
                        "workspace_disclosure_policy_head_no_direct_delete"
                    )
                    self.store._connection.execute(
                        """
                        DELETE FROM workspace_disclosure_policy_heads
                        WHERE tenant_id = ? AND workspace_id = ?
                        """,
                        ("tenant-a", workspace),
                    )
                with self.assertRaisesRegex(SessionStoreError, "history is invalid"):
                    self.store.get_workspace_disclosure_policy(
                        "tenant-a", workspace
                    )

    def test_old_workspace_disclosure_policy_corruption_blocks_read_and_write(
        self,
    ) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-a",
            expected_version=0,
        )
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=1,
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_immutable"
        )
        self.store._connection.execute(
            """
            UPDATE workspace_disclosure_policies
            SET policy_digest = ?
            WHERE tenant_id = ? AND workspace_id = ? AND version = 1
            """,
            ("0" * 64, "tenant-a", "workspace-a"),
        )
        with self.assertRaisesRegex(SessionStoreError, "stored workspace"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "stored workspace"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                WorkspaceDisclosurePolicy.disabled(),
                actor_id="admin-a",
                expected_version=2,
            )

    def test_workspace_policy_total_ledger_erasure_cannot_reset_to_v0(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-a",
            expected_version=1,
        )
        for trigger in (
            "workspace_disclosure_policy_no_direct_delete",
            "workspace_disclosure_policy_seal_no_direct_delete",
            "workspace_disclosure_policy_head_no_direct_delete",
            "workspace_disclosure_policy_receipt_no_direct_delete",
        ):
            self.store._connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        self.store._connection.execute(
            """
            DELETE FROM workspace_disclosure_policy_receipts
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            ("tenant-a", "workspace-a"),
        )
        self.store._connection.execute(
            """
            DELETE FROM workspace_disclosure_policies
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            ("tenant-a", "workspace-a"),
        )
        self.store._connection.execute(
            """
            DELETE FROM workspace_disclosure_policy_heads
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            ("tenant-a", "workspace-a"),
        )
        with self.assertRaisesRegex(SessionStoreError, "tip is invalid"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "tip is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-a",
                expected_version=0,
                idempotency_key="new-policy",
            )

    def test_workspace_policy_tip_cannot_be_rewritten_through_normal_sql(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
        )
        root_digest = self.store._connection.execute(
            """
            SELECT disclosure_policy_root_digest
            FROM workspaces
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            ("tenant-a", "workspace-a"),
        ).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute(
                """
                UPDATE workspaces
                SET disclosure_policy_tip_version = 0,
                    disclosure_policy_tip_record_digest = ?
                WHERE tenant_id = ? AND workspace_id = ?
                """,
                (root_digest, "tenant-a", "workspace-a"),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute(
                """
                UPDATE workspaces
                SET disclosure_policy_root_digest = ?
                WHERE tenant_id = ? AND workspace_id = ?
                """,
                ("0" * 64, "tenant-a", "workspace-a"),
            )

    def test_workspace_policy_audit_field_tampering_breaks_record_chain(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
        )
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-b",
            expected_version=1,
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_immutable"
        )
        self.store._connection.execute(
            """
            UPDATE workspace_disclosure_policies
            SET actor_id = 'forged-admin'
            WHERE tenant_id = ? AND workspace_id = ? AND version = 1
            """,
            ("tenant-a", "workspace-a"),
        )
        with self.assertRaisesRegex(SessionStoreError, "seal is invalid"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "seal is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-c",
                expected_version=2,
            )

    def test_workspace_policy_receipt_is_bound_to_scope_and_history(self) -> None:
        self._workspace()
        first = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-b",
            expected_version=1,
        )
        replay = self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.assertEqual(replay, first)
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_receipt_immutable"
        )
        self.store._connection.execute(
            """
            UPDATE workspace_disclosure_policy_receipts
            SET project_id = 'project-forged'
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            ("tenant-a", "policy-1"),
        )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-a",
                expected_version=0,
                idempotency_key="policy-1",
            )

    def test_workspace_policy_receipt_loss_invalidates_the_sealed_history(
        self,
    ) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            WorkspaceDisclosurePolicy.disabled(),
            actor_id="admin-b",
            expected_version=1,
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_receipt_no_direct_delete"
        )
        self.store._connection.execute(
            """
            DELETE FROM workspace_disclosure_policy_receipts
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            ("tenant-a", "policy-1"),
        )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-c",
                expected_version=2,
            )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-a",
                expected_version=0,
                idempotency_key="policy-1",
            )

    def test_workspace_policy_receipt_timestamp_is_sealed(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
            idempotency_key="policy-1",
        )
        self.store._connection.execute(
            "DROP TRIGGER workspace_disclosure_policy_receipt_immutable"
        )
        self.store._connection.execute(
            """
            UPDATE workspace_disclosure_policy_receipts
            SET created_at_ns = created_at_ns + 1
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            ("tenant-a", "policy-1"),
        )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.get_workspace_disclosure_policy(
                "tenant-a", "workspace-a"
            )
        with self.assertRaisesRegex(SessionStoreError, "receipt is invalid"):
            self.store.set_workspace_disclosure_policy(
                "tenant-a",
                "workspace-a",
                self._full_fidelity_policy(),
                actor_id="admin-a",
                expected_version=0,
                idempotency_key="policy-1",
            )

    def test_workspace_deletion_cascades_policy_history_and_head_together(self) -> None:
        self._workspace()
        self.store.set_workspace_disclosure_policy(
            "tenant-a",
            "workspace-a",
            self._full_fidelity_policy(),
            actor_id="admin-a",
            expected_version=0,
        )
        self.store._connection.execute(
            "DELETE FROM workspaces WHERE tenant_id = ? AND workspace_id = ?",
            ("tenant-a", "workspace-a"),
        )
        for table in (
            "workspace_disclosure_policies",
            "workspace_disclosure_policy_heads",
            "workspace_disclosure_policy_seals",
            "workspace_disclosure_policy_receipts",
        ):
            count = self.store._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            self.assertEqual(count, 0)

    def test_public_catalog_text_rejects_property_based_invisibles(self) -> None:
        unsafe = (
            "\u0085",
            "\u2003",
            "\u2028",
            "\u202e",
            "\U000e0061",
            "\U000e0000",
            "\u115f",
            "\u1160",
            "\u17b4",
            "\u17b5",
            "\u2800",
            "\u3164",
            "\uffa0",
            "\U00013441",
            "\U00013442",
        )
        for character in unsafe:
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                with self.assertRaisesRegex(ValueError, "visible characters"):
                    validate_catalog_identifier(
                        f"tenant{character}hidden",
                        "tenant_id",
                    )
                with self.assertRaisesRegex(ValueError, "visible characters"):
                    validate_catalog_label(
                        f"Project{character}Hidden",
                        "project label",
                    )
                with self.assertRaisesRegex(ValueError, "unsafe invisible"):
                    validate_catalog_metadata(
                        {f"key{character}": f"value{character}"},
                        "project metadata",
                    )

        ordinary = "Réseau 東😀"
        self.assertEqual(
            validate_catalog_identifier(ordinary, "tenant_id"),
            ordinary,
        )
        self.assertEqual(
            validate_catalog_label(ordinary, "project label"),
            ordinary,
        )
        self.assertEqual(
            validate_catalog_metadata(
                {"description": f"{ordinary}\nsecond line"},
                "project metadata",
            ),
            {"description": f"{ordinary}\nsecond line"},
        )

        for unanchored in (
            "\u200c",
            "\u200d\u200c",
            "\ue000",
            "\u0301",
            "\u200c \u200d",
        ):
            with self.subTest(unanchored=repr(unanchored)):
                with self.assertRaisesRegex(ValueError, "visible characters"):
                    validate_catalog_identifier(unanchored, "tenant_id")
                with self.assertRaisesRegex(ValueError, "visible characters"):
                    validate_catalog_label(unanchored, "project label")

        self.assertEqual(
            validate_catalog_identifier("tenant\u200cشناسه", "tenant_id"),
            "tenant\u200cشناسه",
        )
        self.assertEqual(
            validate_catalog_identifier(
                "khitan\U00016fe4cluster",
                "tenant_id",
            ),
            "khitan\U00016fe4cluster",
        )
        self.assertEqual(
            validate_catalog_label("Project \ue000 A", "project label"),
            "Project \ue000 A",
        )

    def test_catalog_identifiers_reject_spoofing_but_preserve_real_scripts(
        self,
    ) -> None:
        for character in (
            "\u034f",  # combining grapheme joiner
            "\ufe0e",  # text variation selector
            "\ufe0f",  # emoji variation selector
            "\U000e0100",  # variation selector supplement
            "\ufffc",  # object replacement character
            "\ue000",  # BMP private use
            "\U000f0000",  # supplementary private use
        ):
            with (
                self.subTest(codepoint=f"U+{ord(character):04X}"),
                self.assertRaisesRegex(ValueError, "visible characters"),
            ):
                validate_catalog_identifier(
                    f"alpha{character}",
                    "project_id",
                )

        legitimate = (
            "cafe\u0301",
            "شناسه\u200cشبکه",
            "क्\u200dषेत्र",
            "family\U0001f469\u200d\U0001f4bb",
            "中文-项目",
        )
        for identifier in legitimate:
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    validate_catalog_identifier(identifier, "project_id"),
                    identifier,
                )

    def _set_catalog_time(
        self,
        table: str,
        column: str,
        value: int,
        *,
        tenant: str = "tenant-a",
    ) -> None:
        allowed = {
            ("fixtures", "created_at_ns"),
            ("analysis_revisions", "published_at_ns"),
            ("revision_set_snapshots", "created_at_ns"),
            ("idempotency_keys", "created_at_ns"),
        }
        if (table, column) not in allowed:
            raise AssertionError("test requested an unsupported timestamp")
        with self.store._transaction() as cursor:
            cursor.execute(
                f"UPDATE {table} SET {column} = ? WHERE tenant_id = ?",
                (value, tenant),
            )

    def test_commit_failure_rolls_back_without_wedging_shared_connection(
        self,
    ) -> None:
        proxy = _FailOnceCommitConnection(self.store._connection)
        self.store._connection = proxy  # type: ignore[assignment]

        with self.assertRaisesRegex(
            sqlite3.OperationalError,
            "injected commit failure",
        ):
            self.store.create_project(
                "tenant-a",
                "Failed project",
                project_id="failed-project",
            )

        self.assertFalse(proxy.in_transaction)
        self.assertEqual(self.store.list_projects("tenant-a"), ())
        created = self.store.create_project(
            "tenant-a",
            "Recovered project",
            project_id="recovered-project",
        )
        self.assertEqual(created.project_id, "recovered-project")

    def test_catalog_retention_is_disabled_and_externally_gated(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
        )
        snapshot = self.store.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )
        for table, column in (
            ("fixtures", "created_at_ns"),
            ("analysis_revisions", "published_at_ns"),
            ("revision_set_snapshots", "created_at_ns"),
        ):
            self._set_catalog_time(table, column, 10)

        self.assertEqual(
            self.store.inventory_retention(
                "tenant-a", "workspace-a"
            ).total_candidate_count,
            0,
        )
        policy = CatalogRetentionPolicy(
            snapshot_before_ns=20,
            revision_before_ns=20,
            fixture_before_ns=20,
        )
        preview = self.store.inventory_retention(
            "tenant-a", "workspace-a", policy
        )
        self.assertEqual(preview.total_candidate_count, 3)
        self.assertTrue(
            all(
                "external_references_not_checked" in candidate.blockers
                for candidate in preview.candidates
            )
        )
        with self.assertRaises(CatalogRetentionDisabledError):
            self.store.purge_retention("tenant-a", "workspace-a", policy)

        blocked = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            CatalogRetentionPolicy(
                enabled=True,
                snapshot_before_ns=20,
                revision_before_ns=20,
                fixture_before_ns=20,
            ),
        )
        self.assertEqual(blocked.purged, ())
        self.assertEqual(
            self.store.get_snapshot(
                "tenant-a", snapshot.snapshot_id
            ).snapshot_id,
            snapshot.snapshot_id,
        )
        self.assertEqual(
            self.store.get_revision("tenant-a", "revision-a").revision_id,
            "revision-a",
        )

    def test_catalog_retention_respects_local_dependency_order(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        self._fixture_revision(
            fixture="fixture-b",
            revision="revision-b",
            node="node-b",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
        )
        snapshot_a = self.store.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-b",
            fixture_id="fixture-b",
            revision_id="revision-b",
            expected_version=session.version,
        )
        snapshot_b = self.store.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )
        with self.store._transaction() as cursor:
            cursor.execute(
                """
                UPDATE revision_set_snapshots SET created_at_ns = 10
                WHERE tenant_id = ? AND snapshot_id = ?
                """,
                ("tenant-a", snapshot_a.snapshot_id),
            )
            cursor.execute(
                """
                UPDATE revision_set_snapshots SET created_at_ns = 11
                WHERE tenant_id = ? AND snapshot_id = ?
                """,
                ("tenant-a", snapshot_b.snapshot_id),
            )
            cursor.execute(
                """
                UPDATE analysis_revisions SET published_at_ns = 10
                WHERE tenant_id = ?
                """,
                ("tenant-a",),
            )
            cursor.execute(
                """
                UPDATE fixtures SET created_at_ns = 10
                WHERE tenant_id = ?
                """,
                ("tenant-a",),
            )

        snapshot_policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            snapshot_before_ns=20,
        )
        preview = self.store.inventory_retention(
            "tenant-a",
            "workspace-a",
            snapshot_policy,
        )
        by_id = {candidate.identifier: candidate for candidate in preview.candidates}
        self.assertTrue(by_id[snapshot_a.snapshot_id].eligible)
        self.assertEqual(
            by_id[snapshot_b.snapshot_id].blockers,
            ("latest_snapshot_for_session",),
        )
        first = self.store.purge_retention(
            "tenant-a", "workspace-a", snapshot_policy
        )
        self.assertEqual(
            tuple(item.identifier for item in first.purged),
            (snapshot_a.snapshot_id,),
        )
        with self.assertRaises(KeyError):
            self.store.get_snapshot("tenant-a", snapshot_a.snapshot_id)

        second = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            CatalogRetentionPolicy(
                enabled=True,
                external_references_checked=True,
                snapshot_before_ns=20,
                preserve_latest_snapshot_per_session=False,
            ),
        )
        self.assertEqual(
            tuple(item.identifier for item in second.purged),
            (snapshot_b.snapshot_id,),
        )
        session = self.store.delete_member(
            "tenant-a",
            session.session_id,
            "member-a",
            expected_version=session.version,
        )
        session = self.store.delete_member(
            "tenant-a",
            session.session_id,
            "member-b",
            expected_version=session.version,
        )
        self.store.delete_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )

        entity_policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            revision_before_ns=20,
            fixture_before_ns=20,
        )
        entity_preview = self.store.inventory_retention(
            "tenant-a",
            "workspace-a",
            entity_policy,
        )
        self.assertEqual(
            {
                candidate.identifier
                for candidate in entity_preview.candidates
                if candidate.category == "analysis_revision"
                and candidate.eligible
            },
            {"revision-a", "revision-b"},
        )
        self.assertTrue(
            all(
                candidate.blockers == ("retained_by_revision",)
                for candidate in entity_preview.candidates
                if candidate.category == "fixture"
            )
        )
        revision_pass = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            entity_policy,
        )
        self.assertEqual(
            {
                item.identifier
                for item in revision_pass.purged
                if item.category == "analysis_revision"
            },
            {"revision-a", "revision-b"},
        )
        fixture_pass = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            entity_policy,
        )
        self.assertEqual(
            {
                item.identifier
                for item in fixture_pass.purged
                if item.category == "fixture"
            },
            {"fixture-a", "fixture-b"},
        )

    def test_expired_catalog_receipts_unblock_reference_aware_purge(self) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
            idempotency_key="attach-fixture-a",
        )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        self._set_catalog_time("idempotency_keys", "created_at_ns", 10)

        blocked = self.store.inventory_retention(
            "tenant-a",
            "workspace-a",
            CatalogRetentionPolicy(
                external_references_checked=True,
                fixture_before_ns=20,
            ),
        )
        self.assertEqual(
            blocked.candidates[0].blockers,
            ("unexpired_idempotency_receipt",),
        )

        policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            idempotency_before_ns=20,
            fixture_before_ns=20,
        )
        preview = self.store.inventory_retention(
            "tenant-a", "workspace-a", policy
        )
        self.assertEqual(preview.total_candidate_count, 2)
        self.assertTrue(all(item.eligible for item in preview.candidates))
        result = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            actor="retention-bot",
            operation_id="expire-receipt-1",
        )
        self.assertEqual(
            tuple(item.category for item in result.purged),
            ("catalog_idempotency", "fixture"),
        )
        with self.assertRaises(KeyError):
            self.store.get_fixture("tenant-a", "fixture-a")
        audit = self.store.list_retention_audit(
            "tenant-a",
            "workspace-a",
        )
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0].actor, "retention-bot")
        self.assertEqual(audit[0].operation_id, "expire-receipt-1")
        self.assertEqual(audit[0].purged_count, 2)

    def test_catalog_purge_returns_exact_ingestion_pin_releases(self) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
            metadata={
                "blob_ref": "aa/bb/blob.tgz",
                "admission_operation_id": "admission:upload-a",
            },
        )
        self.store.publish_revision(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            "revision-a",
            node_id="node-a",
            identity_digest=_digest("revision-a"),
            metadata={
                "dataset_ref": "cc/dd/revision.json",
                "publication_operation_id": "publication:upload-a",
            },
        )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        self._set_catalog_time("analysis_revisions", "published_at_ns", 10)
        policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            revision_before_ns=20,
            fixture_before_ns=20,
        )

        revision_result = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            actor="retention-bot",
            operation_id="release-revision",
        )
        self.assertEqual(len(revision_result.artifact_releases), 1)
        revision_release = revision_result.artifact_releases[0]
        self.assertEqual(revision_release.artifact_kind, "dataset")
        self.assertEqual(revision_release.artifact_ref, "cc/dd/revision.json")
        self.assertEqual(
            revision_release.owner_operation_id,
            "publication:upload-a",
        )

        fixture_result = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            actor="retention-bot",
            operation_id="release-fixture",
        )
        self.assertEqual(len(fixture_result.artifact_releases), 1)
        fixture_release = fixture_result.artifact_releases[0]
        self.assertEqual(fixture_release.artifact_kind, "blob")
        self.assertEqual(fixture_release.artifact_ref, "aa/bb/blob.tgz")
        self.assertEqual(
            fixture_release.owner_operation_id,
            "admission:upload-a",
        )
        audit = self.store.list_retention_audit(
            "tenant-a",
            "workspace-a",
        )
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[0].artifact_releases[0]["artifact_kind"], "dataset")
        self.assertEqual(audit[1].artifact_releases[0]["artifact_kind"], "blob")
        self.assertTrue(all(len(item.purged_sha256) == 64 for item in audit))
        self.assertEqual(
            tuple(
                item.operation_id
                for item in self.store.pending_artifact_release_audits(
                    "tenant-a",
                    "workspace-a",
                )
            ),
            ("release-revision", "release-fixture"),
        )
        self.assertTrue(
            self.store.acknowledge_artifact_releases(
                "tenant-a",
                "workspace-a",
                "release-revision",
                acknowledged_at_ns=123,
            )
        )
        self.assertFalse(
            self.store.acknowledge_artifact_releases(
                "tenant-a",
                "workspace-a",
                "release-revision",
                acknowledged_at_ns=124,
            )
        )
        self.assertEqual(
            tuple(
                item.operation_id
                for item in self.store.pending_artifact_release_audits(
                    "tenant-a",
                    "workspace-a",
                )
            ),
            ("release-fixture",),
        )

        self.store.close()
        self.store = SqliteSessionStore(self.database)
        reopened_audit = self.store.list_retention_audit(
            "tenant-a",
            "workspace-a",
        )
        self.assertEqual(len(reopened_audit), 2)
        self.assertEqual(
            reopened_audit[0].artifact_releases_acknowledged_at_ns,
            123,
        )
        self.assertIsNone(
            reopened_audit[1].artifact_releases_acknowledged_at_ns
        )
        replayed = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            actor="retention-bot",
            operation_id="release-fixture",
        )
        self.assertEqual(replayed, fixture_result)
        with self.assertRaises(SessionConflictError):
            self.store.purge_retention(
                "tenant-a",
                "workspace-a",
                policy,
                actor="different-actor",
                operation_id="release-fixture",
            )

    def test_catalog_retention_audit_accepts_json_safe_sequence_boundary(self) -> None:
        self._workspace()
        self.store._connection.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
            ("catalog_retention_audit", MAX_JSON_SAFE_INTEGER - 1),
        )

        self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            CatalogRetentionPolicy(enabled=True),
            operation_id="safe-sequence-boundary",
        )

        entries = self.store.list_retention_audit(
            "tenant-a",
            "workspace-a",
            after_sequence=MAX_JSON_SAFE_INTEGER - 1,
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].sequence, MAX_JSON_SAFE_INTEGER)
        self.assertEqual(
            self.store.list_retention_audit(
                "tenant-a",
                "workspace-a",
                after_sequence=MAX_JSON_SAFE_INTEGER,
            ),
            (),
        )
        for invalid in (-1, MAX_JSON_SAFE_INTEGER + 1, True):
            with self.subTest(after_sequence=invalid), self.assertRaisesRegex(
                ValueError,
                "JSON-safe",
            ):
                self.store.list_retention_audit(
                    "tenant-a",
                    "workspace-a",
                    after_sequence=invalid,
                )

    def test_catalog_retention_audit_sequence_exhaustion_rolls_back_purge(self) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
        )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        self.store._connection.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
            ("catalog_retention_audit", MAX_JSON_SAFE_INTEGER),
        )

        with self.assertRaisesRegex(SessionStoreError, "outside the safe domain"):
            self.store.purge_retention(
                "tenant-a",
                "workspace-a",
                CatalogRetentionPolicy(
                    enabled=True,
                    external_references_checked=True,
                    fixture_before_ns=20,
                ),
                operation_id="exhausted-sequence",
            )

        self.assertEqual(
            self.store.get_fixture("tenant-a", "fixture-a").fixture_id,
            "fixture-a",
        )
        self.assertIsNone(
            self.store.get_retention_audit(
                "tenant-a",
                "workspace-a",
                "exhausted-sequence",
            )
        )
        sqlite_sequence = self.store._connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = ?",
            ("catalog_retention_audit",),
        ).fetchone()
        self.assertEqual(sqlite_sequence["seq"], MAX_JSON_SAFE_INTEGER)

    def test_catalog_retention_audit_corrupt_sequence_fails_all_projections(
        self,
    ) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
            metadata={
                "blob_ref": "aa/bb/blob.tgz",
                "admission_operation_id": "admission:upload-a",
            },
        )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        self.store._connection.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
            ("catalog_retention_audit", MAX_JSON_SAFE_INTEGER - 1),
        )
        policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            fixture_before_ns=20,
        )
        self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            operation_id="corrupt-sequence",
        )
        unsafe_sequence = MAX_JSON_SAFE_INTEGER + 1
        self.store._connection.execute(
            "UPDATE catalog_retention_audit SET sequence = ? WHERE operation_id = ?",
            (unsafe_sequence, "corrupt-sequence"),
        )

        reads = (
            lambda: self.store.list_retention_audit("tenant-a", "workspace-a"),
            lambda: self.store.get_retention_audit(
                "tenant-a", "workspace-a", "corrupt-sequence"
            ),
            lambda: self.store.pending_artifact_release_audits(
                "tenant-a", "workspace-a"
            ),
            lambda: self.store.purge_retention(
                "tenant-a",
                "workspace-a",
                policy,
                operation_id="corrupt-sequence",
            ),
        )
        for read in reads:
            with self.subTest(read=read), self.assertRaisesRegex(
                SessionStoreError,
                "outside the safe domain",
            ):
                read()

    def test_catalog_retention_inventory_is_bounded_and_workspace_scoped(
        self,
    ) -> None:
        for tenant in ("tenant-a", "tenant-b"):
            self._workspace(tenant=tenant)
            for index in range(3):
                self.store.create_session(
                    tenant,
                    "workspace-a",
                    f"Session {index}",
                    session_id=f"session-{index}",
                    idempotency_key=f"create-session-{index}",
                )
            self._set_catalog_time(
                "idempotency_keys",
                "created_at_ns",
                10,
                tenant=tenant,
            )
        self._workspace(project="project-b", workspace="workspace-b")
        for index in range(3):
            self.store.create_session(
                "tenant-a",
                "workspace-b",
                f"Workspace B session {index}",
                session_id=f"workspace-b-session-{index}",
                idempotency_key=f"workspace-b-create-session-{index}",
            )
        self._set_catalog_time(
            "idempotency_keys",
            "created_at_ns",
            10,
            tenant="tenant-a",
        )

        policy = CatalogRetentionPolicy(
            enabled=True,
            idempotency_before_ns=20,
            maximum_candidates=2,
        )
        preview = self.store.inventory_retention(
            "tenant-a", "workspace-a", policy
        )
        self.assertEqual(preview.total_candidate_count, 3)
        self.assertEqual(len(preview.candidates), 2)
        self.assertTrue(preview.truncated)
        first = self.store.purge_retention(
            "tenant-a", "workspace-a", policy
        )
        self.assertEqual(len(first.purged), 2)
        self.assertEqual(
            self.store.inventory_retention(
                "tenant-a",
                "workspace-a",
                policy,
            ).total_candidate_count,
            1,
        )
        self.assertEqual(
            self.store.inventory_retention(
                "tenant-b",
                "workspace-a",
                policy,
            ).total_candidate_count,
            3,
        )
        self.assertEqual(
            self.store.inventory_retention(
                "tenant-a",
                "workspace-b",
                policy,
            ).total_candidate_count,
            3,
        )

    def test_retention_saga_is_exact_replayable_and_durable(self) -> None:
        self._workspace()
        request = {
            "schema": "test.retention-saga.v1",
            "catalog": {"enabled": True, "revision_before_ns": "20"},
            "review": {"enabled": False},
            "ingestion": {"enabled": True},
        }
        started = self.store.begin_retention_saga(
            "tenant-a",
            "project-a",
            "workspace-a",
            "saga-a",
            actor="retention-bot",
            request=request,
            requested_now_ns=100,
        )
        self.assertEqual(started.effective_now_ns, 100)
        self.assertFalse(started.complete)
        self.assertEqual(
            self.store.begin_retention_saga(
                "tenant-a",
                "project-a",
                "workspace-a",
                "saga-a",
                actor="retention-bot",
                request=request,
                requested_now_ns=100,
            ),
            started,
        )
        changed_request = {
            **request,
            "catalog": {"enabled": False},
        }
        for changed_actor, changed_policy in (
            ("different-actor", request),
            ("retention-bot", changed_request),
        ):
            with self.assertRaises(IdempotencyConflict):
                self.store.begin_retention_saga(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                    "saga-a",
                    actor=changed_actor,
                    request=changed_policy,
                    requested_now_ns=100,
                )
        with self.assertRaises(IdempotencyConflict):
            self.store.begin_retention_saga(
                "tenant-a",
                "project-a",
                "workspace-a",
                "saga-a",
                actor="retention-bot",
                request=request,
                requested_now_ns=101,
            )

        review = self.store.record_retention_saga_phase(
            "tenant-a",
            "workspace-a",
            "saga-a",
            "review",
            {"kind": "inventory", "items": []},
        )
        assert review.review_result is not None
        self.assertEqual(review.review_result["kind"], "inventory")
        self.assertEqual(
            self.store.record_retention_saga_phase(
                "tenant-a",
                "workspace-a",
                "saga-a",
                "review",
                {"kind": "inventory", "items": []},
            ).review_result,
            review.review_result,
        )
        with self.assertRaises(SessionConflictError):
            self.store.record_retention_saga_phase(
                "tenant-a",
                "workspace-a",
                "saga-a",
                "review",
                {"kind": "different"},
            )
        with self.assertRaises(SessionConflictError):
            self.store.complete_retention_saga(
                "tenant-a", "workspace-a", "saga-a"
            )
        for phase in ("catalog", "ingestion"):
            self.store.record_retention_saga_phase(
                "tenant-a",
                "workspace-a",
                "saga-a",
                phase,
                {"kind": phase},
            )
        self.store.add_retention_saga_replay_counts(
            "tenant-a",
            "workspace-a",
            "saga-a",
            release_actions=2,
            artifact_releases=3,
        )
        completed = self.store.complete_retention_saga(
            "tenant-a", "workspace-a", "saga-a"
        )
        self.assertTrue(completed.complete)
        self.assertEqual(completed.replayed_release_actions, 2)
        self.assertEqual(completed.replayed_artifact_releases, 3)

        self.store.close()
        self.store = SqliteSessionStore(self.database)
        reopened = self.store.begin_retention_saga(
            "tenant-a",
            "project-a",
            "workspace-a",
            "saga-a",
            actor="retention-bot",
            request=request,
        )
        self.assertEqual(reopened, completed)

    def test_retention_saga_rejects_counter_overflow_and_corruption(self) -> None:
        self._workspace()
        request = {"schema": "test.retention-saga.v1"}
        self.store.begin_retention_saga(
            "tenant-a",
            "project-a",
            "workspace-a",
            "saga-b",
            actor="retention-bot",
            request=request,
            requested_now_ns=100,
        )
        self.store._connection.execute(
            """
            UPDATE control_plane_retention_saga
            SET replayed_release_actions = ?
            WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
            """,
            ((1 << 63) - 1, "tenant-a", "workspace-a", "saga-b"),
        )
        with self.assertRaisesRegex(SessionStoreError, "exceed SQLite bounds"):
            self.store.add_retention_saga_replay_counts(
                "tenant-a",
                "workspace-a",
                "saga-b",
                release_actions=1,
                artifact_releases=0,
            )

        self.store._connection.execute(
            """
            UPDATE control_plane_retention_saga
            SET request_json = ?
            WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
            """,
            ('{ "schema": "test.retention-saga.v1" }', "tenant-a", "workspace-a", "saga-b"),
        )
        with self.assertRaisesRegex(SessionStoreError, "stored retention saga"):
            self.store.begin_retention_saga(
                "tenant-a",
                "project-a",
                "workspace-a",
                "saga-b",
                actor="retention-bot",
                request=request,
                requested_now_ns=100,
            )

    def test_catalog_retention_protection_and_policy_validation(self) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
        )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            fixture_before_ns=20,
            protected_fixture_ids=("fixture-a",),
        )
        preview = self.store.inventory_retention(
            "tenant-a", "workspace-a", policy
        )
        self.assertEqual(preview.candidates[0].blockers, ("externally_protected",))
        self.assertEqual(
            self.store.purge_retention(
                "tenant-a", "workspace-a", policy
            ).purged,
            (),
        )
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            CatalogRetentionPolicy(
                protected_fixture_ids=("fixture-a", "fixture-a")
            )
        with self.assertRaisesRegex(ValueError, "SQLite-sized"):
            CatalogRetentionPolicy(fixture_before_ns=-1)

    def test_catalog_entity_cleanup_cannot_cross_workspace_scope(self) -> None:
        self._workspace()
        self._workspace(project="project-b", workspace="workspace-b")
        for workspace, fixture in (
            ("workspace-a", "fixture-a"),
            ("workspace-b", "fixture-b"),
        ):
            self.store.attach_fixture(
                "tenant-a",
                workspace,
                fixture,
                label=fixture,
                content_digest=_digest(fixture),
            )
        self._set_catalog_time("fixtures", "created_at_ns", 10)
        policy = CatalogRetentionPolicy(
            enabled=True,
            external_references_checked=True,
            fixture_before_ns=20,
        )

        result = self.store.purge_retention(
            "tenant-a",
            "workspace-a",
            policy,
            operation_id="workspace-a-only",
        )
        self.assertEqual(
            tuple(item.identifier for item in result.purged),
            ("fixture-a",),
        )
        with self.assertRaises(KeyError):
            self.store.get_fixture("tenant-a", "fixture-a")
        self.assertEqual(
            self.store.get_fixture("tenant-a", "fixture-b").workspace_id,
            "workspace-b",
        )
        self.assertEqual(
            self.store.inventory_retention(
                "tenant-a",
                "workspace-b",
                policy,
            ).total_candidate_count,
            1,
        )
        self.assertEqual(
            self.store.list_retention_audit(
                "tenant-a", "workspace-b"
            ),
            (),
        )

    def test_poisoned_connection_is_replaced_after_commit_failure(self) -> None:
        proxy = _FailOnceCommitConnection(
            self.store._connection,
            leave_transaction_open=True,
        )
        self.store._connection = proxy  # type: ignore[assignment]

        with self.assertRaisesRegex(
            sqlite3.OperationalError,
            "injected commit failure",
        ):
            self.store.create_project(
                "tenant-a",
                "Failed project",
                project_id="failed-project",
            )

        self.assertIsNot(self.store._connection, proxy)
        self.assertEqual(self.store.list_projects("tenant-a"), ())
        created = self.store.create_project(
            "tenant-a",
            "Recovered project",
            project_id="recovered-project",
        )
        self.assertEqual(created.project_id, "recovered-project")

    def test_memory_catalog_survives_poisoned_connection_replacement(self) -> None:
        memory_store = SqliteSessionStore(":memory:")
        try:
            memory_store.create_project(
                "tenant-a",
                "Existing project",
                project_id="existing-project",
            )
            proxy = _FailOnceCommitConnection(
                memory_store._connection,
                leave_transaction_open=True,
            )
            memory_store._connection = proxy  # type: ignore[assignment]

            with self.assertRaisesRegex(
                sqlite3.OperationalError,
                "injected commit failure",
            ):
                memory_store.create_project(
                    "tenant-a",
                    "Failed project",
                    project_id="failed-project",
                )

            self.assertEqual(
                tuple(
                    item.project_id
                    for item in memory_store.list_projects("tenant-a")
                ),
                ("existing-project",),
            )
        finally:
            memory_store.close()

    def test_project_workspace_and_session_crud_are_durable_and_bounded(
        self,
    ) -> None:
        project = self.store.create_project(
            "tenant-a",
            "Production",
            project_id="project-a",
            metadata={"sites": ["east", "west"]},
        )
        workspace = self.store.create_workspace(
            "tenant-a",
            project.project_id,
            "Incident 42",
            workspace_id="workspace-a",
        )
        session = self.store.create_session(
            "tenant-a",
            workspace.workspace_id,
            "Reviewer session",
            session_id="session-a",
            metadata={"view": "topology"},
        )

        self.assertEqual(
            [item.project_id for item in self.store.list_projects("tenant-a")],
            ["project-a"],
        )
        self.assertEqual(
            self.store.get_project("tenant-a", "project-a").metadata["sites"],
            ["east", "west"],
        )
        self.assertEqual(
            self.store.list_workspaces("tenant-a", "project-a"),
            (workspace,),
        )
        self.assertEqual(
            self.store.list_sessions("tenant-a", "workspace-a"),
            (session,),
        )
        self.assertEqual(session.version, 0)
        self.assertEqual(session.members, ())
        self.assertIsNone(session.default_member_id)

        # Returned metadata is detached from durable state.
        project.metadata["sites"].append("corrupt")
        self.assertEqual(
            self.store.get_project("tenant-a", "project-a").metadata["sites"],
            ["east", "west"],
        )

        with self.assertRaisesRegex(ValueError, "project label"):
            self.store.create_project("tenant-a", " bad ")
        with self.assertRaisesRegex(ValueError, "metadata"):
            self.store.create_project(
                "tenant-a",
                "Bad metadata",
                metadata={"not_json": object()},
            )

    def test_multiple_fixtures_and_same_node_revisions_are_explicit_members(
        self,
    ) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-old",
            revision="node-a/revision-old",
            node="node-a",
        )
        self._fixture_revision(
            fixture="fixture-new",
            revision="node-a/revision-new",
            node="node-a",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Compare captures",
            session_id="session-a",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "before",
            fixture_id="fixture-old",
            revision_id="node-a/revision-old",
            expected_version=0,
            role="baseline",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "after",
            fixture_id="fixture-new",
            revision_id="node-a/revision-new",
            expected_version=1,
            role="candidate",
            make_default=True,
        )

        revisions = self.store.list_revisions(
            "tenant-a",
            "workspace-a",
            node_id="node-a",
        )
        self.assertEqual(
            {item.revision_id for item in revisions},
            {"node-a/revision-old", "node-a/revision-new"},
        )
        self.assertEqual(
            [item.fixture_id for item in self.store.list_fixtures(
                "tenant-a",
                "workspace-a",
            )],
            ["fixture-new", "fixture-old"],
        )
        self.assertEqual(session.version, 2)
        self.assertEqual(session.default_member_id, "after")
        self.assertEqual(
            [(item.member_id, item.node_id) for item in session.members],
            [("after", "node-a"), ("before", "node-a")],
        )

        with self.assertRaisesRegex(
            SessionConflictError,
            "each immutable revision only once",
        ):
            self.store.put_member(
                "tenant-a",
                session.session_id,
                "duplicate-after",
                fixture_id="fixture-new",
                revision_id="node-a/revision-new",
                expected_version=2,
            )

    def test_one_fixture_can_contribute_multiple_immutable_revisions(self) -> None:
        self._workspace()
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
        )
        for revision in ("revision-before", "revision-after"):
            self.store.publish_revision(
                "tenant-a",
                "workspace-a",
                "fixture-a",
                revision,
                node_id="node-a",
                identity_digest=_digest(revision),
            )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Reprocess one fixture",
            session_id="session-a",
        )
        for ordinal, revision in enumerate(
            ("revision-before", "revision-after")
        ):
            session = self.store.put_member(
                "tenant-a",
                session.session_id,
                revision,
                fixture_id="fixture-a",
                revision_id=revision,
                expected_version=ordinal,
            )

        self.assertEqual(
            {member.revision_id for member in session.members},
            {"revision-before", "revision-after"},
        )
        self.assertEqual(
            {member.fixture_id for member in session.members},
            {"fixture-a"},
        )

    def test_session_update_snapshot_listing_and_delete_lifecycle(self) -> None:
        self._workspace()
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Initial",
            session_id="session-a",
        )
        updated = self.store.update_session(
            "tenant-a",
            session.session_id,
            expected_version=0,
            label="Renamed",
            metadata={"incident": "INC-42"},
            replace_metadata=True,
            idempotency_key="rename-session",
        )
        replay = self.store.update_session(
            "tenant-a",
            session.session_id,
            expected_version=0,
            label="Renamed",
            metadata={"incident": "INC-42"},
            replace_metadata=True,
            idempotency_key="rename-session",
        )
        self.assertEqual(updated, replay)
        self.assertEqual(updated.version, 1)
        self.assertEqual(updated.label, "Renamed")
        snapshot = self.store.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=1,
        )
        self.assertEqual(
            self.store.list_snapshots(
                "tenant-a",
                "workspace-a",
                session_id=session.session_id,
            ),
            (snapshot,),
        )
        with self.assertRaisesRegex(
            SessionConflictError,
            "immutable snapshots",
        ):
            self.store.delete_session(
                "tenant-a",
                session.session_id,
                expected_version=1,
            )

        removable = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Removable",
            session_id="session-removable",
        )
        deleted = self.store.delete_session(
            "tenant-a",
            removable.session_id,
            expected_version=0,
            idempotency_key="delete-removable",
        )
        replay_deleted = self.store.delete_session(
            "tenant-a",
            removable.session_id,
            expected_version=0,
            idempotency_key="delete-removable",
        )
        self.assertEqual(deleted, replay_deleted)
        with self.assertRaises(KeyError):
            self.store.get_session("tenant-a", removable.session_id)

    def test_optimistic_version_and_idempotent_mutation(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        first = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
            idempotency_key="put-member-a",
        )
        retry = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
            idempotency_key="put-member-a",
        )
        self.assertEqual(retry, first)
        self.assertEqual(self.store.get_session(
            "tenant-a",
            "session-a",
        ).version, 1)

        with self.assertRaises(StaleSessionVersion):
            self.store.put_member(
                "tenant-a",
                "session-a",
                "member-a",
                fixture_id="fixture-a",
                revision_id="revision-a",
                expected_version=0,
            )
        with self.assertRaises(IdempotencyConflict):
            self.store.put_member(
                "tenant-a",
                "session-a",
                "different-member",
                fixture_id="fixture-a",
                revision_id="revision-a",
                expected_version=1,
                idempotency_key="put-member-a",
            )

    def test_idempotent_generated_ids_and_immutable_fixture_revision(self) -> None:
        project = self.store.create_project(
            "tenant-a",
            "Generated ID",
            idempotency_key="create-project",
        )
        retry = self.store.create_project(
            "tenant-a",
            "Generated ID",
            idempotency_key="create-project",
        )
        self.assertEqual(retry, project)

        workspace = self.store.create_workspace(
            "tenant-a",
            project.project_id,
            "Generated workspace",
            idempotency_key="create-workspace",
        )
        self.store.attach_fixture(
            "tenant-a",
            workspace.workspace_id,
            "fixture-a",
            label="Fixture A",
            content_digest=_digest("fixture-a"),
        )
        with self.assertRaises(SessionConflictError):
            self.store.attach_fixture(
                "tenant-a",
                workspace.workspace_id,
                "fixture-a",
                label="Changed fixture",
                content_digest=_digest("changed"),
            )
        self.store.publish_revision(
            "tenant-a",
            workspace.workspace_id,
            "fixture-a",
            "revision-a",
            node_id="node-a",
            identity_digest=_digest("revision-a"),
        )
        with self.assertRaises(SessionConflictError):
            self.store.publish_revision(
                "tenant-a",
                workspace.workspace_id,
                "fixture-a",
                "revision-a",
                node_id="node-b",
                identity_digest=_digest("different"),
            )

    def test_cross_tenant_records_are_hidden_as_not_found(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Private",
            session_id="session-a",
        )

        for operation in (
            lambda: self.store.get_project("tenant-b", "project-a"),
            lambda: self.store.get_workspace("tenant-b", "workspace-a"),
            lambda: self.store.get_fixture("tenant-b", "fixture-a"),
            lambda: self.store.get_revision("tenant-b", "revision-a"),
            lambda: self.store.get_session("tenant-b", "session-a"),
        ):
            with self.subTest(operation=operation), self.assertRaises(KeyError):
                operation()

        # Tenant B may use the same opaque IDs without colliding with tenant A.
        self._workspace(tenant="tenant-b")
        self._fixture_revision(
            tenant="tenant-b",
            fixture="fixture-a",
            revision="revision-a",
            node="node-b",
        )
        other = self.store.create_session(
            "tenant-b",
            "workspace-a",
            "Other",
            session_id="session-a",
        )
        self.assertEqual(other.tenant_id, "tenant-b")
        self.assertEqual(
            self.store.get_revision("tenant-a", "revision-a").node_id,
            "node-a",
        )
        self.assertEqual(
            self.store.get_revision("tenant-b", "revision-a").node_id,
            "node-b",
        )

    def test_cross_workspace_revisions_and_snapshots_cannot_be_spliced(
        self,
    ) -> None:
        self._workspace()
        self._workspace(
            project="project-b",
            workspace="workspace-b",
        )
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        self._fixture_revision(
            workspace="workspace-b",
            fixture="fixture-b",
            revision="revision-b",
            node="node-b",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Workspace A only",
            session_id="session-a",
        )
        with self.assertRaises(KeyError):
            self.store.put_member(
                "tenant-a",
                session.session_id,
                "foreign",
                fixture_id="fixture-b",
                revision_id="revision-b",
                expected_version=0,
            )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "local",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
        )
        snapshot = self.store.snapshot_session(
            "tenant-a",
            session.session_id,
            expected_version=session.version,
        )
        with self.assertRaises(KeyError):
            self.store.list_snapshots(
                "tenant-a",
                "workspace-b",
                session_id=session.session_id,
            )
        self.assertEqual(
            self.store.list_snapshots(
                "tenant-a",
                "workspace-a",
                session_id=session.session_id,
            ),
            (snapshot,),
        )

    def test_snapshot_is_exact_deterministic_and_immutable(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        self._fixture_revision(
            fixture="fixture-b",
            revision="revision-b",
            node="node-b",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
        )
        snapshot_a = self.store.snapshot_session(
            "tenant-a",
            "session-a",
            expected_version=1,
        )
        same_snapshot = self.store.snapshot_session(
            "tenant-a",
            "session-a",
            expected_version=1,
        )
        self.assertEqual(snapshot_a, same_snapshot)

        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-b",
            fixture_id="fixture-b",
            revision_id="revision-b",
            expected_version=1,
        )
        snapshot_b = self.store.snapshot_session(
            "tenant-a",
            "session-a",
            expected_version=2,
        )

        self.assertNotEqual(snapshot_a.snapshot_id, snapshot_b.snapshot_id)
        self.assertNotEqual(snapshot_a.digest, snapshot_b.digest)
        self.assertEqual(
            [item.revision_id for item in snapshot_a.members],
            ["revision-a"],
        )
        self.assertEqual(
            [item.revision_id for item in snapshot_b.members],
            ["revision-a", "revision-b"],
        )
        self.assertEqual(
            self.store.get_snapshot("tenant-a", snapshot_a.snapshot_id),
            snapshot_a,
        )
        with self.assertRaises(KeyError):
            self.store.get_snapshot("tenant-b", snapshot_a.snapshot_id)

    def test_delete_member_updates_default_and_is_idempotent(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        self._fixture_revision(
            fixture="fixture-b",
            revision="revision-b",
            node="node-b",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-b",
            fixture_id="fixture-b",
            revision_id="revision-b",
            expected_version=0,
        )
        session = self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=1,
            make_default=True,
        )
        deleted = self.store.delete_member(
            "tenant-a",
            "session-a",
            "member-a",
            expected_version=2,
            idempotency_key="delete-member-a",
        )
        retry = self.store.delete_member(
            "tenant-a",
            "session-a",
            "member-a",
            expected_version=2,
            idempotency_key="delete-member-a",
        )
        self.assertEqual(retry, deleted)
        self.assertEqual(deleted.version, 3)
        self.assertEqual(deleted.default_member_id, "member-b")

    def test_concurrent_mutations_with_one_version_have_one_winner(self) -> None:
        self._workspace()
        for suffix in ("a", "b"):
            self._fixture_revision(
                fixture=f"fixture-{suffix}",
                revision=f"revision-{suffix}",
                node=f"node-{suffix}",
            )
        self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )

        def mutate(suffix: str) -> str:
            try:
                self.store.put_member(
                    "tenant-a",
                    "session-a",
                    f"member-{suffix}",
                    fixture_id=f"fixture-{suffix}",
                    revision_id=f"revision-{suffix}",
                    expected_version=0,
                )
            except StaleSessionVersion:
                return "stale"
            return "updated"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(mutate, ("a", "b")))
        self.assertEqual(sorted(results), ["stale", "updated"])
        self.assertEqual(
            self.store.get_session("tenant-a", "session-a").version,
            1,
        )

    def test_restart_preserves_catalog_sessions_and_snapshots(self) -> None:
        self._workspace()
        self._fixture_revision(
            fixture="fixture-a",
            revision="revision-a",
            node="node-a",
        )
        session = self.store.create_session(
            "tenant-a",
            "workspace-a",
            "Session",
            session_id="session-a",
        )
        self.store.put_member(
            "tenant-a",
            session.session_id,
            "member-a",
            fixture_id="fixture-a",
            revision_id="revision-a",
            expected_version=0,
        )
        snapshot = self.store.snapshot_session("tenant-a", "session-a")
        self.store.close()

        self.store = SqliteSessionStore(self.database)
        reopened = self.store.get_session("tenant-a", "session-a")
        self.assertEqual(reopened.version, 1)
        self.assertEqual(reopened.members[0].revision_id, "revision-a")
        self.assertEqual(
            self.store.get_snapshot("tenant-a", snapshot.snapshot_id),
            snapshot,
        )
        self.assertEqual(
            self.store.get_fixture("tenant-a", "fixture-a").content_digest,
            _digest("fixture-a"),
        )


if __name__ == "__main__":
    unittest.main()
