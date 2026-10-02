"""Connect a viewport request's disconnect to cooperative core query checks."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from contextvars import ContextVar
from threading import Event

from starlette.requests import Request


_QUERY_CANCELLED: ContextVar[Event | None] = ContextVar("viewport_query_cancelled", default=None)


def current_query_cancellation_probe() -> Callable[[], bool] | None:
    cancelled = _QUERY_CANCELLED.get()
    return cancelled.is_set if cancelled is not None else None


def query_cancellation_scope(request: Request) -> AbstractAsyncContextManager[None]:
    return asynccontextmanager(_query_cancellation_scope)(request)


async def _query_cancellation_scope(request: Request) -> AsyncIterator[None]:
    # Drain and cache the body before listening: competing receive consumers
    # could otherwise steal a JSON chunk from FastAPI's parser.
    await request.body()
    cancelled = Event()
    token = _QUERY_CANCELLED.set(cancelled)

    async def watch_disconnect() -> None:
        try:
            while True:
                message = await request.receive()
                if message["type"] == "http.disconnect":
                    cancelled.set()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            # Losing the transport cannot authorize continuing expensive work.
            cancelled.set()

    watcher = asyncio.create_task(watch_disconnect())
    try:
        yield
    finally:
        cancelled.set()
        watcher.cancel()
        try:
            with suppress(asyncio.CancelledError):
                await watcher
        finally:
            _QUERY_CANCELLED.reset(token)
