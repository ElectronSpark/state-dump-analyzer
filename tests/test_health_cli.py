from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from router_dump_analyzer.health_cli import (
    EXIT_DEGRADED,
    EXIT_ERROR,
    EXIT_HEALTHY,
    run,
)
from router_dump_analyzer.ingestion_pipeline import inspect_durable_queue


def _queue_database(root: Path, rows: tuple[tuple[str, int], ...]) -> Path:
    database = root / "control-plane.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE ingestion_imports "
            "(state TEXT NOT NULL, updated_at_ns INTEGER NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO ingestion_imports (state, updated_at_ns) VALUES (?, ?)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()
    return database


class HealthCliTests(unittest.TestCase):
    def test_read_only_probe_distinguishes_pending_selection_and_stall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = _queue_database(
                root,
                (("queued", 0), ("awaiting_selection", 0)),
            )
            snapshot = inspect_durable_queue(
                database,
                stall_after_seconds=5,
                now_ns=10_000_000_000,
            )
            self.assertEqual(snapshot.pending_imports, 1)
            self.assertEqual(snapshot.awaiting_selection_imports, 1)
            self.assertEqual(snapshot.stalled_imports, 1)

            output = StringIO()
            errors = StringIO()
            exit_code = run(
                [
                    "--state-dir",
                    str(root),
                    "--stalled-after",
                    "5",
                    "--now-ns",
                    "10000000000",
                ],
                stdout=output,
                stderr=errors,
            )
            self.assertEqual(exit_code, EXIT_DEGRADED)
            self.assertEqual(errors.getvalue(), "")
            document = json.loads(output.getvalue())
            self.assertEqual(document["status"], "degraded")
            self.assertEqual(document["pending_imports"], 1)
            self.assertEqual(document["awaiting_selection_imports"], 1)
            self.assertEqual(document["stalled_imports"], 1)

    def test_empty_queue_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _queue_database(root, ())
            output = StringIO()
            exit_code = run(
                ["--state-dir", str(root), "--now-ns", "10000000000"],
                stdout=output,
                stderr=StringIO(),
            )
            self.assertEqual(exit_code, EXIT_HEALTHY)
            self.assertTrue(json.loads(output.getvalue())["healthy"])

    def test_terminal_history_is_excluded_from_queue_depth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = _queue_database(
                root,
                (
                    ("completed", 0),
                    ("failed", 0),
                    ("cancelled", 0),
                    ("queued", 9_000_000_000),
                ),
            )
            snapshot = inspect_durable_queue(
                database,
                stall_after_seconds=5,
                now_ns=10_000_000_000,
            )
            self.assertEqual(snapshot.pending_imports, 1)
            self.assertEqual(snapshot.stalled_imports, 0)
            self.assertEqual(snapshot.state_counts, (("queued", 1),))

    def test_unknown_state_is_fail_closed_without_echoing_private_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_state = "private-state-from-another-tenant"
            database = _queue_database(root, ((private_state, 0),))
            snapshot = inspect_durable_queue(
                database,
                stall_after_seconds=5,
                now_ns=10_000_000_000,
            )
            self.assertEqual(snapshot.observation_error, "unknown_import_state")
            self.assertEqual(snapshot.state_counts, ())

            output = StringIO()
            exit_code = run(
                [
                    "--state-dir",
                    str(root),
                    "--stalled-after",
                    "5",
                    "--now-ns",
                    "10000000000",
                ],
                stdout=output,
                stderr=StringIO(),
            )
            self.assertEqual(exit_code, EXIT_DEGRADED)
            self.assertNotIn(private_state, output.getvalue())
            self.assertEqual(
                json.loads(output.getvalue())["observation_error"],
                "unknown_import_state",
            )

    def test_malformed_queue_schema_is_a_bounded_cli_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "control-plane.sqlite3"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "CREATE TABLE ingestion_imports "
                    "(state TEXT, updated_at_ns INTEGER)"
                )
                connection.execute(
                    "INSERT INTO ingestion_imports VALUES ('queued', NULL)"
                )
                connection.commit()
            finally:
                connection.close()

            errors = StringIO()
            exit_code = run(
                [
                    "--state-dir",
                    str(root),
                    "--stalled-after",
                    "5",
                    "--now-ns",
                    "10000000000",
                ],
                stdout=StringIO(),
                stderr=errors,
            )
            self.assertEqual(exit_code, EXIT_ERROR)
            document = json.loads(errors.getvalue())
            self.assertEqual(document["status"], "error")
            self.assertEqual(document["error"], "TypeError")
            self.assertNotIn("queued", errors.getvalue())

    def test_missing_state_is_a_bounded_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_path = Path(directory) / "private-state-name"
            errors = StringIO()
            exit_code = run(
                ["--state-dir", str(private_path)],
                stdout=StringIO(),
                stderr=errors,
            )
            self.assertEqual(exit_code, EXIT_ERROR)
            document = json.loads(errors.getvalue())
            self.assertEqual(document["status"], "error")
            self.assertEqual(document["error"], "OperationalError")
            self.assertNotIn(str(private_path), errors.getvalue())


if __name__ == "__main__":
    unittest.main()
