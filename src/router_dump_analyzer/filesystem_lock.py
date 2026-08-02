"""Small cross-process advisory-lock primitives for durable core stores.

The locks coordinate cooperating core processes on one host. They are not a
distributed lease and deliberately carry no network-filesystem guarantees.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class _ProcessLockEntry:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.users = 0


_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, _ProcessLockEntry] = {}
_THREAD_STATE = threading.local()


def _normalized_lock_path(path: Path) -> tuple[Path, str]:
    resolved = path.expanduser().resolve()
    return resolved, os.path.normcase(str(resolved))


@contextmanager
def _process_lock(key: str, *, blocking: bool) -> Iterator[bool]:
    """Coordinate threads before entering the operating-system lock."""

    with _PROCESS_LOCKS_GUARD:
        entry = _PROCESS_LOCKS.get(key)
        if entry is None:
            entry = _ProcessLockEntry()
            _PROCESS_LOCKS[key] = entry
        entry.users += 1
    acquired = entry.lock.acquire(blocking=blocking)
    try:
        yield acquired
    finally:
        if acquired:
            entry.lock.release()
        with _PROCESS_LOCKS_GUARD:
            entry.users -= 1
            if entry.users == 0 and _PROCESS_LOCKS.get(key) is entry:
                del _PROCESS_LOCKS[key]


def _held_lock_keys() -> set[str]:
    held = getattr(_THREAD_STATE, "held_lock_keys", None)
    if held is None:
        held = set()
        _THREAD_STATE.held_lock_keys = held
    return held


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold a blocking one-byte advisory lock until the context exits."""

    resolved, key = _normalized_lock_path(path)
    held = _held_lock_keys()
    if key in held:
        # Re-entrant acquisition in one thread already owns the OS lock.
        yield
        return
    with _process_lock(key, blocking=True) as acquired:
        assert acquired
        held.add(key)
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            with resolved.open("a+b") as stream:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0, os.SEEK_END)
                    if stream.tell() == 0:
                        stream.write(b"\0")
                        stream.flush()
                        os.fsync(stream.fileno())
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    return

                fcntl: Any = __import__("fcntl")
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            held.remove(key)


@contextmanager
def try_exclusive_file_lock(path: Path) -> Iterator[bool]:
    """Try a one-byte advisory lock without waiting behind another process."""

    resolved, key = _normalized_lock_path(path)
    held = _held_lock_keys()
    if key in held:
        yield True
        return
    with _process_lock(key, blocking=False) as process_acquired:
        if not process_acquired:
            yield False
            return
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with resolved.open("a+b") as stream:
            if os.name == "nt":
                import msvcrt

                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"\0")
                    stream.flush()
                    os.fsync(stream.fileno())
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    yield False
                    return
                held.add(key)
                try:
                    yield True
                finally:
                    held.remove(key)
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                return

            fcntl: Any = __import__("fcntl")
            try:
                fcntl.flock(
                    stream.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except OSError:
                yield False
                return
            held.add(key)
            try:
                yield True
            finally:
                held.remove(key)
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextmanager
def try_existing_exclusive_file_lock(path: Path) -> Iterator[bool]:
    """Try-lock an existing lock file without creating a new pathname.

    Callers that retire dynamic lock files must hold a separate stable
    namespace gate while using this helper.  That gate prevents a close/unlink
    cycle from splitting POSIX inode lock domains or racing a Windows opener.
    """

    resolved, key = _normalized_lock_path(path)
    held = _held_lock_keys()
    if key in held:
        yield True
        return
    with _process_lock(key, blocking=False) as process_acquired:
        if not process_acquired:
            yield False
            return
        try:
            stream = resolved.open("r+b")
        except FileNotFoundError:
            yield False
            return
        with stream:
            if os.name == "nt":
                import msvcrt

                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"\0")
                    stream.flush()
                    os.fsync(stream.fileno())
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    yield False
                    return
                held.add(key)
                try:
                    yield True
                finally:
                    held.remove(key)
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                return

            fcntl: Any = __import__("fcntl")
            try:
                fcntl.flock(
                    stream.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except OSError:
                yield False
                return
            held.add(key)
            try:
                yield True
            finally:
                held.remove(key)
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
