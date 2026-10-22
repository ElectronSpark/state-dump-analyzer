"""Strict cooperative-cancellation helpers for bounded core work."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextvars import ContextVar
from heapq import merge
from threading import Event
from typing import Final

from .process_control import PROCESS_CONTROL_EXCEPTIONS

type CancellationErrorFactory = Callable[[], BaseException]

_COOPERATIVE_SORT_CHUNK_ITEMS: Final = 8_192
_COOPERATIVE_SORT_CHECKPOINT_ITEMS: Final = 256

# One request owns this event. Context propagation into worker threads preserves
# cancellation without putting mutable request state on shared query services.
_QUERY_CANCELLED: ContextVar[Event | None] = ContextVar("query_cancelled", default=None)


def current_query_cancellation_probe() -> Callable[[], bool] | None:
    cancelled = _QUERY_CANCELLED.get()
    return cancelled.is_set if cancelled is not None else None


def query_cancellation_checkpoint() -> None:
    cancelled = _QUERY_CANCELLED.get()
    if cancelled is not None and cancelled.is_set():
        # Keep the established query error identity, without an import cycle
        # between normalized data and the query service that consumes it.
        from .revision_queries import RevisionQueryCancellationError

        raise RevisionQueryCancellationError("revision query was cancelled")


def query_checked[Value](values: Iterable[Value]) -> Iterable[Value]:
    """Check request cancellation while scanning, leaving non-HTTP calls alone."""
    if _QUERY_CANCELLED.get() is None:
        return values

    def checked() -> Iterable[Value]:
        for ordinal, value in enumerate(values):
            if ordinal % _COOPERATIVE_SORT_CHECKPOINT_ITEMS == 0:
                query_cancellation_checkpoint()
            yield value
        query_cancellation_checkpoint()

    return checked()


def check_cancellation_probe(
    cancellation_probe: Callable[[], bool] | None,
    *,
    cancelled_error: CancellationErrorFactory,
    unavailable_error: CancellationErrorFactory,
    invalid_result_error: CancellationErrorFactory,
) -> None:
    """Evaluate one strict cooperative probe with caller-owned error types."""

    if cancellation_probe is None:
        return
    try:
        cancelled = cancellation_probe()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise unavailable_error() from error
    if type(cancelled) is not bool:
        raise invalid_result_error()
    if cancelled:
        raise cancelled_error()


def cooperatively_sorted[Value](
    values: Iterable[Value],
    cancellation_checkpoint: Callable[[], None] | None,
) -> tuple[Value, ...]:
    """Return exact sorted membership with bounded cooperative checkpoints."""

    if cancellation_checkpoint is not None:
        cancellation_checkpoint()
    chunks: list[tuple[Value, ...]] = []
    pending: list[Value] = []
    for ordinal, value in enumerate(values):
        if (
            ordinal
            and ordinal % _COOPERATIVE_SORT_CHECKPOINT_ITEMS == 0
            and cancellation_checkpoint is not None
        ):
            cancellation_checkpoint()
        pending.append(value)
        if len(pending) == _COOPERATIVE_SORT_CHUNK_ITEMS:
            if cancellation_checkpoint is not None:
                cancellation_checkpoint()
            chunks.append(tuple(sorted(pending)))  # type: ignore[type-var]
            if cancellation_checkpoint is not None:
                cancellation_checkpoint()
            pending = []
    if pending:
        if cancellation_checkpoint is not None:
            cancellation_checkpoint()
        chunks.append(tuple(sorted(pending)))  # type: ignore[type-var]
        if cancellation_checkpoint is not None:
            cancellation_checkpoint()
    if not chunks:
        return ()
    if len(chunks) == 1:
        return chunks[0]
    result: list[Value] = []
    for ordinal, value in enumerate(merge(*chunks)):
        if (
            ordinal % _COOPERATIVE_SORT_CHECKPOINT_ITEMS == 0
            and cancellation_checkpoint is not None
        ):
            cancellation_checkpoint()
        result.append(value)
    if cancellation_checkpoint is not None:
        cancellation_checkpoint()
    return tuple(result)


__all__ = [
    "CancellationErrorFactory",
    "check_cancellation_probe",
    "cooperatively_sorted",
    "current_query_cancellation_probe",
    "query_cancellation_checkpoint",
    "query_checked",
]
