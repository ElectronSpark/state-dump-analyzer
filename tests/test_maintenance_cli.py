from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.control_plane import ControlPlane, ControlPlaneError
from router_dump_analyzer.ingestion_pipeline import ImportScope, PluginRegistry
from router_dump_analyzer.maintenance_cli import (
    POLICY_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    RetentionMaintenanceConfiguration,
    RetentionMaintenanceInputError,
    RetentionMaintenanceScopeError,
    load_policy,
    main,
    parse_args,
    run,
)
from router_dump_analyzer.private_analysis_run_store import (
    SqlitePrivateAnalysisRunStore,
)


class RetentionMaintenanceCliTests(unittest.TestCase):
    @staticmethod
    def _create_scope(state_dir: Path) -> None:
        control_plane = ControlPlane(
            state_dir,
            registry=PluginRegistry((), require_executable_identity=True),
        )
        try:
            control_plane.sessions.create_project(
                "tenant-a",
                "Project A",
                project_id="project-a",
            )
            control_plane.sessions.create_workspace(
                "tenant-a",
                "project-a",
                "Workspace A",
                workspace_id="workspace-a",
            )
        finally:
            control_plane.close()

    @staticmethod
    def _write_policy(
        directory: Path,
        *,
        enabled: bool = False,
    ) -> Path:
        path = directory / "retention-policy.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": POLICY_SCHEMA_VERSION,
                    "ingestion": {
                        "enabled": enabled,
                        "terminal_import_grace_seconds": 0,
                        "idempotency_replay_seconds": 0,
                        "orphan_artifact_grace_seconds": 0,
                        "stale_partial_seconds": 0,
                    },
                    "catalog": {
                        "enabled": enabled,
                        "idempotency_before_ns": 2_000,
                        "snapshot_before_ns": 2_000,
                        "revision_before_ns": 2_000,
                        "fixture_before_ns": 2_000,
                    },
                    "review": {
                        "enabled": enabled,
                        "tombstone_before_ns": 2_000,
                        "idempotency_before_ns": 2_000,
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _configuration(
        state_dir: Path,
        policy_path: Path,
        *,
        execute: bool = False,
    ) -> RetentionMaintenanceConfiguration:
        return RetentionMaintenanceConfiguration(
            state_dir=state_dir,
            tenant_id="tenant-a",
            project_id="project-a",
            workspace_id="workspace-a",
            policy_path=policy_path,
            execute=execute,
            actor="ci-maintenance" if execute else None,
            operation_id="ci-retention-001" if execute else None,
            now_ns=1_000,
            output_path=None,
            pretty=False,
        )

    def test_parser_defaults_to_dry_run_and_accepts_fixed_clock(self) -> None:
        parsed = parse_args(
            [
                "--state-dir",
                "state",
                "--tenant",
                "tenant-a",
                "--project",
                "project-a",
                "--workspace",
                "workspace-a",
                "--policy",
                "policy.json",
                "--now-ns",
                "123",
            ]
        )
        self.assertFalse(parsed.execute)
        self.assertIsNone(parsed.actor)
        self.assertIsNone(parsed.operation_id)
        self.assertEqual(parsed.now_ns, 123)

    def test_execute_requires_explicit_audit_identity(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            parse_args(
                [
                    "--state-dir",
                    "state",
                    "--tenant",
                    "tenant-a",
                    "--project",
                    "project-a",
                    "--workspace",
                    "workspace-a",
                    "--policy",
                    "policy.json",
                    "--execute",
                ]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_policy_loader_rejects_duplicate_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"'
                + POLICY_SCHEMA_VERSION
                + '","catalog":{"enabled":false,"enabled":true}}',
                encoding="utf-8",
            )
            with self.assertRaises(RetentionMaintenanceInputError):
                load_policy(duplicate)

            unknown = root / "unknown.json"
            unknown.write_text(
                json.dumps(
                    {
                        "schema_version": POLICY_SCHEMA_VERSION,
                        "review": {"enabled": False, "device_rule": "delete"},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(RetentionMaintenanceInputError):
                load_policy(unknown)

            precise = root / "precise.json"
            precise.write_text(
                json.dumps(
                    {
                        "schema_version": POLICY_SCHEMA_VERSION,
                        "catalog": {
                            "revision_before_ns": "9007199254740993",
                        },
                        "review": {
                            "tombstone_before_ns": "9007199254740994",
                        },
                    }
                ),
                encoding="utf-8",
            )
            policies = load_policy(precise)
            self.assertEqual(
                policies.catalog.revision_before_ns,
                9_007_199_254_740_993,
            )
            self.assertEqual(
                policies.review.tombstone_before_ns,
                9_007_199_254_740_994,
            )

    def test_dry_run_is_read_only_repeatable_and_does_not_start_workers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            self._create_scope(state_dir)
            stale = state_dir / "spool" / "aged.partial"
            stale.write_bytes(b"partial")
            os.utime(stale, ns=(0, 0))
            policy_path = self._write_policy(root, enabled=True)
            configuration = self._configuration(state_dir, policy_path)
            first = io.StringIO()
            second = io.StringIO()
            with patch(
                "router_dump_analyzer.ingestion_pipeline."
                "DurableIngestionPipeline.start",
                side_effect=AssertionError("workers must not start"),
            ):
                self.assertEqual(run(configuration, stdout=first), 0)
                self.assertEqual(run(configuration, stdout=second), 0)
            self.assertTrue(stale.exists())
            self.assertEqual(first.getvalue(), second.getvalue())
            document = json.loads(first.getvalue())
            self.assertEqual(document["schema_version"], RESULT_SCHEMA_VERSION)
            self.assertEqual(document["mode"], "dry_run")
            self.assertFalse(document["executed"])
            self.assertEqual(
                document["observation_mode"],
                "best_effort_preview",
            )
            self.assertFalse(document["ingestion"]["executed"])
            self.assertEqual(
                document["ingestion"]["host_storage_orphan_inventory"],
                "not_observed",
            )
            self.assertFalse(document["catalog"]["executed"])
            self.assertFalse(document["review"]["executed"])
            self.assertEqual(document["ingestion"]["evaluated_at_ns"], "1000")
            self.assertEqual(document["ingestion"]["stale_partials"], 0)

            reopened = ControlPlane(
                state_dir,
                registry=PluginRegistry((), require_executable_identity=True),
            )
            try:
                hidden_audits = reopened.ingestion.list_retention_audits(
                    ImportScope(
                        "system-retention",
                        "system-retention",
                        "startup-sweep",
                    )
                )
            finally:
                reopened.close()
            self.assertEqual(hidden_audits, ())

    def test_execute_records_all_enabled_store_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            self._create_scope(state_dir)
            policy_path = self._write_policy(root, enabled=True)
            configuration = self._configuration(
                state_dir,
                policy_path,
                execute=True,
            )
            stdout = io.StringIO()
            self.assertEqual(run(configuration, stdout=stdout), 0)
            document = json.loads(stdout.getvalue())
            self.assertEqual(document["mode"], "execute")
            self.assertTrue(document["executed"])
            self.assertEqual(
                document["observation_mode"],
                "coordinated_execution",
            )
            self.assertTrue(document["ingestion"]["executed"])
            self.assertEqual(
                document["ingestion"]["host_storage_orphan_inventory"],
                "bounded_host_scan",
            )
            self.assertTrue(document["catalog"]["executed"])
            self.assertTrue(document["review"]["executed"])

            control_plane = ControlPlane(
                state_dir,
                registry=PluginRegistry((), require_executable_identity=True),
            )
            try:
                scope = control_plane.scope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                catalog_audit = control_plane.sessions.list_retention_audit(
                    "tenant-a",
                    "workspace-a",
                )
                review_audit = control_plane.annotations.list_retention_audit(scope)
                ingestion_audit = control_plane.ingestion.list_retention_audits(
                    control_plane.import_scope(
                        "tenant-a",
                        "project-a",
                        "workspace-a",
                    )
                )
            finally:
                control_plane.close()
            self.assertEqual(catalog_audit[0].operation_id, "ci-retention-001:catalog")
            self.assertEqual(review_audit[0].operation_id, "ci-retention-001:review")
            self.assertEqual(catalog_audit[0].actor, "ci-maintenance")
            self.assertEqual(review_audit[0].actor, "ci-maintenance")
            self.assertEqual(len(ingestion_audit), 1)

    def test_missing_private_run_reference_store_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            self._create_scope(state_dir)
            (state_dir / "private-analysis-runs.sqlite3").unlink()
            policy_path = self._write_policy(root, enabled=True)

            with self.assertRaisesRegex(
                RetentionMaintenanceScopeError,
                "requested maintenance scope does not exist",
            ):
                run(self._configuration(state_dir, policy_path))

    def test_normal_reopen_cannot_replace_a_bound_private_run_store(self) -> None:
        for replacement in ("missing", "empty", "different"):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as directory,
            ):
                state_dir = Path(directory) / "state"
                self._create_scope(state_dir)
                database = state_dir / "private-analysis-runs.sqlite3"
                database.unlink()
                if replacement == "empty":
                    database.write_bytes(b"")
                elif replacement == "different":
                    replacement_store = SqlitePrivateAnalysisRunStore(
                        database,
                        admission_validator=lambda _request: None,
                    )
                    replacement_store.close()

                with self.assertRaisesRegex(
                    ControlPlaneError,
                    (
                        "does not match its binding"
                        if replacement == "different"
                        else "missing or truncated"
                    ),
                ):
                    ControlPlane(
                        state_dir,
                        registry=PluginRegistry((), require_executable_identity=True),
                    )
                self.assertEqual(database.exists(), replacement != "missing")
                if replacement == "empty":
                    self.assertEqual(database.stat().st_size, 0)

    def test_missing_scope_and_internal_failures_have_closed_cli_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = self._write_policy(root)
            args = [
                "--state-dir",
                str(root / "state"),
                "--tenant",
                "tenant-a",
                "--project",
                "project-a",
                "--workspace",
                "workspace-a",
                "--policy",
                str(policy_path),
            ]
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                main(args)
            self.assertEqual(raised.exception.code, 1)
            self.assertFalse((root / "state").exists())
            self.assertIn(
                "the requested maintenance scope does not exist",
                stderr.getvalue(),
            )

            secret = "PRIVATE-MAINTENANCE-ERROR-4cb3a"
            stderr = io.StringIO()
            with (
                patch(
                    "router_dump_analyzer.maintenance_cli.run",
                    side_effect=RuntimeError(secret),
                ),
                redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                main(args)
            self.assertEqual(raised.exception.code, 1)
            self.assertNotIn(secret, stderr.getvalue())
            self.assertIn("the maintenance operation failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
