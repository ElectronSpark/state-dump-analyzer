"""Small scheduling windows for durable work beside CPU-heavy search builds."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from threading import Lock, get_ident
from time import sleep

_active_imports: dict[int, int] = {}
_active_imports_lock = Lock()
_IMPORT_COOPERATION_SECONDS = 0.0001


@contextmanager
def _processing_durable_import() -> Iterator[None]:
    """Count executing stages, including nested stages, until every exit path."""

    thread_id = get_ident()
    with _active_imports_lock:
        _active_imports[thread_id] = _active_imports.get(thread_id, 0) + 1
    try:
        yield
    finally:
        with _active_imports_lock:
            remaining = _active_imports[thread_id] - 1
            if remaining:
                _active_imports[thread_id] = remaining
            else:
                del _active_imports[thread_id]


def _cooperate_with_durable_import() -> None:
    """Let another import thread finish I/O and reacquire Python execution.

    On Windows, a CPU-bound builder can repeatedly win execution back from a
    thread performing many short source reads. A positive, bounded pause gives
    those reads a scheduling window. No window is needed for idle search or an
    import invoking search itself. Never hold the tracking lock while sleeping.
    """

    thread_id = get_ident()
    with _active_imports_lock:
        another_import = any(owner != thread_id for owner in _active_imports)
    if another_import:
        sleep(_IMPORT_COOPERATION_SECONDS)
