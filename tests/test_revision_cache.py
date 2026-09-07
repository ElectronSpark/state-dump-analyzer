from __future__ import annotations

import threading
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch

from router_dump_analyzer.control_plane import (
    ControlPlaneLimits,
    DatasetIntegrityError,
    _retained_revision_bytes,
)
from router_dump_analyzer.private_analysis_revision_evidence import (
    PrivateAnalysisRevisionEvidenceCancelled,
)
from tests import test_control_plane as control_fixtures


class RevisionCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = control_fixtures.ControlPlaneTests()
        self.addCleanup(fixture.doCleanups)
        self.control = fixture._control_plane(fixture._root())
        completed = fixture._ingest(self.control)
        self.revision = completed.revision_id
        self.scope = self.control.scope("tenant-a", "project-a", "workspace-a")

    def test_memory_budget_uses_decoded_size_and_evicts_lru(self) -> None:
        loaded = self.control._load_revision(self.scope, self.revision)
        weight = _retained_revision_bytes(loaded, 10**9)
        self.assertGreater(weight, 0)
        self.control._cache.clear()
        self.control._cache_weights.clear()
        self.control.limits = replace(
            self.control.limits, dataset_cache_entries=10,
            dataset_cache_bytes=weight * 2 + 1024,
        )
        with (
            patch.object(self.control, "_revision", return_value=loaded.descriptor),
            patch.object(self.control, "_read_revision", return_value=loaded),
        ):
            for revision in ("a", "b", "a", "c"):
                self.control._load_revision(self.scope, revision)
        self.assertEqual(list(self.control._cache), ["tenant-a\x1fa", "tenant-a\x1fc"])
        self.assertLessEqual(
            sum(self.control._cache_weights.values()),
            self.control.limits.dataset_cache_bytes,
        )

    def test_oversized_revision_is_readable_without_being_retained(self) -> None:
        self.control.limits = replace(self.control.limits, dataset_cache_bytes=1)
        first = self.control.load_revision_dataset(self.scope, self.revision)
        self.assertTrue(first["events"])
        self.assertFalse(self.control._cache)
        self.assertFalse(self.control._cache_weights)
        first["events"].clear()
        self.assertTrue(self.control.load_revision_dataset(self.scope, self.revision)["events"])

    def test_concurrent_cold_reads_decode_once(self) -> None:
        barrier = threading.Barrier(8)
        entered = threading.Event()
        release = threading.Event()
        read = self.control._read_revision

        def delayed(*args):
            entered.set()
            if not release.wait(3):
                raise AssertionError("reader was not released")
            return read(*args)

        def query():
            barrier.wait(3)
            return self.control._load_revision(self.scope, self.revision)

        with patch.object(self.control, "_read_revision", side_effect=delayed) as loader:
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(query) for _ in range(8)]
                try:
                    self.assertTrue(entered.wait(3))
                finally:
                    release.set()
                values = [future.result(timeout=5) for future in futures]
            self.assertEqual(loader.call_count, 1)
        self.assertTrue(all(value is values[0] for value in values))
        self.assertFalse(self.control._revision_loads)

    def test_failed_load_does_not_poison_future_attempts(self) -> None:
        with patch.object(
            self.control, "_read_revision", side_effect=DatasetIntegrityError("bad data"),
        ):
            with self.assertRaises(DatasetIntegrityError):
                self.control._load_revision(self.scope, self.revision)
        self.assertFalse(self.control._revision_loads)
        self.assertFalse(self.control._cache)
        self.assertTrue(self.control.load_revision_dataset(self.scope, self.revision)["events"])

    def test_completed_load_wins_a_timed_wait_completion_race(self) -> None:
        loaded = self.control._load_revision(self.scope, self.revision)
        self.control._cache.clear()
        self.control._cache_weights.clear()
        flight = Future()
        key = f"tenant-a\x1f{self.revision}"
        self.control._revision_loads[key] = flight
        real_result = flight.result

        def timed_result(timeout=None):
            if timeout is not None:
                # The wait expired, then the owner completed before done().
                flight.set_result(loaded)
                raise TimeoutError()
            return real_result()

        try:
            with patch.object(flight, "result", side_effect=timed_result):
                result = self.control._load_revision(self.scope, self.revision)
            self.assertIs(result, loaded)
        finally:
            self.control._revision_loads.pop(key)

    def test_waiter_can_cancel_without_cancelling_the_shared_load(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        cancelled = threading.Event()
        waiting = threading.Event()
        read = self.control._read_revision

        def delayed(*args):
            entered.set()
            release.wait(3)
            return read(*args)

        def probe():
            waiting.set()
            return cancelled.is_set()

        with patch.object(self.control, "_read_revision", side_effect=delayed) as loader:
            with ThreadPoolExecutor(max_workers=2) as pool:
                owner = pool.submit(self.control._load_revision, self.scope, self.revision)
                self.assertTrue(entered.wait(3))
                waiter = pool.submit(
                    self.control._load_revision, self.scope, self.revision,
                    cancellation_probe=probe,
                )
                try:
                    self.assertTrue(waiting.wait(2))
                    cancelled.set()
                    with self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled):
                        waiter.result(timeout=1)
                finally:
                    release.set()
                self.assertTrue(owner.result(timeout=3).dataset["events"])
            self.assertEqual(loader.call_count, 1)

    def test_invalid_cache_byte_limits_are_rejected(self) -> None:
        for value in (-1, True, 1.5, "100"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ControlPlaneLimits(dataset_cache_bytes=value)
        self.assertEqual(ControlPlaneLimits(dataset_cache_bytes=0).dataset_cache_bytes, 0)


if __name__ == "__main__":
    unittest.main()
