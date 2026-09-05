"""Shared transaction phases for the local SQLite stores.

Stores retain ownership of their locks, connections, cursor cleanup, recovery
strategy, and public exception vocabulary. This boundary only guarantees that
BEGIN, optional deadline checks, the body, and COMMIT share one recovery fence.
Read snapshots use the same lifecycle with a deferred BEGIN.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager


@contextmanager
def sqlite_transaction(
    *,
    begin: Callable[[], object],
    commit: Callable[[], object],
    recover: Callable[[], object],
    checkpoint: Callable[[], object] | None = None,
) -> Iterator[None]:
    """Recover any failed transaction phase, including ambiguous BEGIN."""

    try:
        begin()
        if checkpoint is not None:
            checkpoint()
        yield
        if checkpoint is not None:
            checkpoint()
        commit()
    except BaseException:
        recover()
        raise
