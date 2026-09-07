from __future__ import annotations

import errno
import multiprocessing
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import call, patch

from router_dump_analyzer import filesystem_lock
from router_dump_analyzer.filesystem_lock import (
    exclusive_file_lock,
    try_exclusive_file_lock,
    try_existing_exclusive_file_lock,
)


def _wait_for_file_lock(
    path_value: str, ready: Any, acquired: Any, results: Any
) -> None:
    path = Path(path_value)
    probes = []
    for lock in (try_exclusive_file_lock, try_existing_exclusive_file_lock):
        with lock(path) as result:
            probes.append(result)
    started = time.monotonic()
    ready.set()
    try:
        with exclusive_file_lock(path):
            elapsed = time.monotonic() - started
            acquired.set()
            results.put((probes, elapsed, None))
    except OSError as exc:
        results.put((probes, time.monotonic() - started, repr(exc)))


class FilesystemLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "store.lock"

    def assert_lock_state_released(self) -> None:
        _, key = filesystem_lock._normalized_lock_path(self.path)
        self.assertNotIn(key, filesystem_lock._held_lock_keys())
        self.assertNotIn(key, filesystem_lock._PROCESS_LOCKS)

    def test_uncontended_and_reentrant_contexts_release_the_lock(self) -> None:
        with exclusive_file_lock(self.path), exclusive_file_lock(self.path):
            with try_exclusive_file_lock(self.path) as acquired:
                self.assertTrue(acquired)
            with try_existing_exclusive_file_lock(self.path) as acquired:
                self.assertTrue(acquired)
        for lock in (try_exclusive_file_lock, try_existing_exclusive_file_lock):
            with lock(self.path) as acquired:
                self.assertTrue(acquired)
        self.assert_lock_state_released()

    def test_try_existing_lock_does_not_create_a_missing_path(self) -> None:
        with try_existing_exclusive_file_lock(self.path) as acquired:
            self.assertFalse(acquired)
        self.assertFalse(self.path.exists())
        self.assert_lock_state_released()

    def test_other_thread_try_locks_report_contention_without_waiting(self) -> None:
        def try_locks() -> list[bool]:
            results = []
            for lock in (try_exclusive_file_lock, try_existing_exclusive_file_lock):
                with lock(self.path) as acquired:
                    results.append(acquired)
            return results

        with ThreadPoolExecutor(max_workers=1) as pool:
            with exclusive_file_lock(self.path):
                self.assertEqual(pool.submit(try_locks).result(timeout=2), [False, False])
            self.assertEqual(pool.submit(try_locks).result(timeout=2), [True, True])
        self.assert_lock_state_released()

    @unittest.skipUnless(os.name == "nt", "Windows CRT locking regression")
    def test_windows_blocking_lock_waits_past_crt_retry_window(self) -> None:
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        acquired = context.Event()
        results = context.Queue()
        waiter = context.Process(
            target=_wait_for_file_lock,
            args=(str(self.path), ready, acquired, results),
        )
        try:
            with exclusive_file_lock(self.path):
                waiter.start()
                self.assertTrue(ready.wait(10), "contender did not start")
                self.assertFalse(acquired.wait(13), "contender bypassed the held lock")
            waiter.join(timeout=10)
            self.assertFalse(waiter.is_alive(), "contender did not acquire after release")
            self.assertEqual(waiter.exitcode, 0)
            probes, elapsed, error = results.get(timeout=2)
            self.assertEqual(probes, [False, False])
            self.assertIsNone(error, f"lock failed after {elapsed:.3f}s: {error}")
            self.assertGreaterEqual(elapsed, 13)
            self.assertTrue(acquired.is_set())
            with try_exclusive_file_lock(self.path) as reacquired:
                self.assertTrue(reacquired)
        finally:
            if waiter.pid is not None:
                if waiter.is_alive():
                    waiter.terminate()
                waiter.join(timeout=5)
                waiter.close()
            results.close()
            results.join_thread()
        self.assert_lock_state_released()

    @unittest.skipUnless(os.name == "nt", "Windows CRT error classification")
    def test_windows_blocking_lock_retries_only_contention(self) -> None:
        import msvcrt

        contention = PermissionError(errno.EACCES, "region is already locked")
        with (
            patch("msvcrt.locking", side_effect=[contention, contention, None, None]) as lock,
            patch("router_dump_analyzer.filesystem_lock.time.sleep") as sleep,
        ):
            with exclusive_file_lock(self.path):
                self.assertEqual(lock.call_count, 3)
            descriptor = lock.call_args_list[0].args[0]
            self.assertEqual(
                lock.call_args_list,
                [call(descriptor, msvcrt.LK_NBLCK, 1)] * 3
                + [call(descriptor, msvcrt.LK_UNLCK, 1)],
            )
            self.assertEqual(sleep.call_count, 2)
        self.assert_lock_state_released()

    @unittest.skipUnless(os.name == "nt", "Windows CRT error classification")
    def test_windows_acquisition_errors_propagate_and_release_local_state(self) -> None:
        self.path.write_bytes(b"\0")
        for context in (
            exclusive_file_lock,
            try_exclusive_file_lock,
            try_existing_exclusive_file_lock,
        ):
            for error_number in (errno.EBADF, errno.EINVAL, errno.EIO, errno.EDEADLK):
                with self.subTest(context=context.__name__, errno=error_number):
                    error = OSError(error_number, "injected acquisition error")
                    with (
                        patch("msvcrt.locking", side_effect=error) as lock,
                        patch("router_dump_analyzer.filesystem_lock.time.sleep") as sleep,
                        self.assertRaises(OSError) as raised,
                        context(self.path),
                    ):
                        self.fail("failed acquisition entered the context")
                    self.assertIs(raised.exception, error)
                    lock.assert_called_once()
                    sleep.assert_not_called()
                    with self.assertRaises(OSError):
                        os.fstat(lock.call_args.args[0])
                    self.assert_lock_state_released()
                    with try_exclusive_file_lock(self.path) as acquired:
                        self.assertTrue(acquired)

    @unittest.skipUnless(os.name == "nt", "Windows CRT unlock behavior")
    def test_windows_context_exceptions_unlock_and_release_local_state(self) -> None:
        import msvcrt

        self.path.write_bytes(b"\0")
        for context in (
            exclusive_file_lock,
            try_exclusive_file_lock,
            try_existing_exclusive_file_lock,
        ):
            with self.subTest(context=context.__name__):
                with patch("msvcrt.locking", wraps=msvcrt.locking) as lock:
                    with (
                        self.assertRaisesRegex(ValueError, "body failed"),
                        context(self.path),
                    ):
                        raise ValueError("body failed")
                    self.assertEqual(lock.call_count, 2)
                    self.assertEqual(lock.call_args.args[1:], (msvcrt.LK_UNLCK, 1))
                self.assert_lock_state_released()
                with try_existing_exclusive_file_lock(self.path) as acquired:
                    self.assertTrue(acquired)

    @unittest.skipUnless(os.name == "nt", "Windows CRT unlock error classification")
    def test_windows_unlock_errors_propagate_without_retry(self) -> None:
        self.path.write_bytes(b"\0")
        for context in (
            exclusive_file_lock,
            try_exclusive_file_lock,
            try_existing_exclusive_file_lock,
        ):
            with self.subTest(context=context.__name__):
                error = OSError(errno.EACCES, "injected unlock error")
                with (
                    patch("msvcrt.locking", side_effect=[None, error]) as lock,
                    patch("router_dump_analyzer.filesystem_lock.time.sleep") as sleep,
                    self.assertRaises(OSError) as raised,
                    context(self.path),
                ):
                    pass
                self.assertIs(raised.exception, error)
                self.assertEqual(lock.call_count, 2)
                sleep.assert_not_called()
                self.assert_lock_state_released()

    @unittest.skipUnless(os.name == "nt", "Windows CRT wait interruption")
    def test_windows_interrupted_retry_releases_local_state_without_unlock(self) -> None:
        with (
            patch(
                "msvcrt.locking",
                side_effect=PermissionError(errno.EACCES, "region is already locked"),
            ) as lock,
            patch(
                "router_dump_analyzer.filesystem_lock.time.sleep",
                side_effect=KeyboardInterrupt,
            ) as sleep,
            self.assertRaises(KeyboardInterrupt),
            exclusive_file_lock(self.path),
        ):
            self.fail("interrupted acquisition entered the context")
        lock.assert_called_once()
        sleep.assert_called_once()
        self.assert_lock_state_released()
        with try_exclusive_file_lock(self.path) as acquired:
            self.assertTrue(acquired)


if __name__ == "__main__":
    unittest.main()
