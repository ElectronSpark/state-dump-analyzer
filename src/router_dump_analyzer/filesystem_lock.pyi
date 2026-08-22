from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock as Lock

class _ProcessLockEntry:
    lock: Lock
    users: int
    def __init__(self) -> None: ...

@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]: ...
@contextmanager
def try_exclusive_file_lock(path: Path) -> Iterator[bool]: ...
@contextmanager
def try_existing_exclusive_file_lock(path: Path) -> Iterator[bool]: ...
