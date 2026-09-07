from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from router_dump_analyzer.private_analysis.evidence import EvidenceScope
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisExecutionClosed,
    PrivateAnalysisExecutionCloseTimeout,
    PrivateAnalysisExecutionCoordinator,
    _PendingFactoryCleanup,
)
from router_dump_analyzer.private_analysis_factory_process import (
    PrivateAnalysisFactoryProcessCleanupError,
)
from router_dump_analyzer.private_analysis_run_store import SqlitePrivateAnalysisRunStore


class CleanupDeadlineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = SqlitePrivateAnalysisRunStore(
            Path(self.temporary.name) / "runs.sqlite3",
            admission_validator=lambda _request: None,
        )
        self.coordinator = PrivateAnalysisExecutionCoordinator(self.store)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def pending(self, close, run_id="run"):
        key = (EvidenceScope("tenant", "project", "workspace"), run_id)
        attempts = []
        pending = _PendingFactoryCleanup(
            owner=SimpleNamespace(close=close),
            attempt=SimpleNamespace(note_cleanup_attempt=attempts.append),
            cleanup_capability="retained-fence",
            retry_ready=True,
        )
        self.coordinator._pending_cleanup[key] = pending
        return key, pending, attempts

    def wait_for_cleanup(self) -> None:
        with self.coordinator._condition:
            self.assertTrue(self.coordinator._condition.wait_for(
                lambda: not self.coordinator._close_cleanup_active, timeout=2,
            ))

    def test_slow_reap_is_inside_deadline_and_stops_admission_first(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        admission = []

        def slow_close():
            try:
                self.coordinator._enter_execution()
            except PrivateAnalysisExecutionClosed:
                admission.append("closed")
            entered.set()
            if not release.wait(2):
                raise AssertionError("test did not release reaper")
            raise PrivateAnalysisFactoryProcessCleanupError("still owned")

        key, pending, attempts = self.pending(slow_close)
        try:
            started = time.monotonic()
            with self.assertRaises(PrivateAnalysisExecutionCloseTimeout):
                self.coordinator.close(timeout=0.05)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(entered.wait(1))
            self.assertEqual(admission, ["closed"])
            with self.assertRaises(PrivateAnalysisExecutionCloseTimeout):
                self.coordinator.close(timeout=0.01)
            self.assertEqual(attempts, ["retained-fence"])
            self.assertIs(self.coordinator._pending_cleanup[key], pending)
            self.assertFalse(self.coordinator._closed)
        finally:
            release.set()
            self.wait_for_cleanup()
        self.assertIs(self.coordinator._pending_cleanup[key], pending)
        self.assertEqual(pending.cleanup_capability, "retained-fence")
        self.assertFalse(pending.retry_lock.locked())

    def test_deadline_does_not_start_another_pending_reap(self) -> None:
        first = threading.Event()
        release = threading.Event()
        calls = []

        def slow_close():
            first.set()
            release.wait(2)
            raise PrivateAnalysisFactoryProcessCleanupError("still owned")

        self.pending(slow_close, "a")
        self.pending(lambda: calls.append("second"), "b")
        try:
            with self.assertRaises(PrivateAnalysisExecutionCloseTimeout):
                self.coordinator.close(timeout=0.05)
            self.assertTrue(first.wait(1))
        finally:
            release.set()
            self.wait_for_cleanup()
        self.assertEqual(calls, [])
        self.assertEqual(self.coordinator.locally_owned_cleanup_count, 2)

    def test_zero_timeout_retains_pending_without_starting_cleanup(self) -> None:
        calls = []
        self.pending(lambda: calls.append("reap"))
        with self.assertRaises(PrivateAnalysisExecutionCloseTimeout):
            self.coordinator.close(timeout=0)
        self.assertEqual(calls, [])
        with self.assertRaises(PrivateAnalysisExecutionClosed):
            self.coordinator._enter_execution()

    def test_cleanup_process_control_reaches_closing_caller(self) -> None:
        def interrupt():
            raise KeyboardInterrupt("cleanup interruption")

        self.pending(interrupt)
        with self.assertRaisesRegex(KeyboardInterrupt, "cleanup interruption"):
            self.coordinator.close(timeout=1)
        self.assertEqual(self.coordinator.locally_owned_cleanup_count, 1)
        self.assertFalse(self.coordinator._closed)

    def test_empty_close_is_idempotent(self) -> None:
        self.coordinator.close(timeout=0)
        self.coordinator.close(timeout=0)
        self.assertTrue(self.coordinator._closed)


if __name__ == "__main__":
    unittest.main()
