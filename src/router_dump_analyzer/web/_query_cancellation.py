"""Connect a read-only request's disconnect to cooperative core query checks."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from threading import Event

from starlette.requests import ClientDisconnect, Request

from router_dump_analyzer.cancellation import (
    _QUERY_CANCELLED,
    current_query_cancellation_probe as current_query_cancellation_probe,
    query_cancellation_checkpoint,
)
from router_dump_analyzer.revision_queries import RevisionQueryCancellationError

__all__ = ["current_query_cancellation_probe", "query_cancellation_scope"]


def query_cancellation_scope(request: Request) -> AbstractAsyncContextManager[None]:
    return asynccontextmanager(_query_cancellation_scope)(request)


async def _query_cancellation_scope(request: Request) -> AsyncIterator[None]:
    # Drain and cache the body before listening: competing receive consumers
    # could otherwise steal a JSON chunk from FastAPI's parser.
    try:
        await request.body()
    except ClientDisconnect as error:
        # An aborted upload is the same cancellation as a later disconnect;
        # no query work or watcher has started yet.
        raise RevisionQueryCancellationError("revision query was cancelled") from error
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
        # Observe an already queued disconnect before entering synchronous
        # dependency/provider acquisition, which may load a shared runtime.
        await asyncio.sleep(0)
        query_cancellation_checkpoint()
        yield
    finally:
        cancelled.set()
        watcher.cancel()
        try:
            with suppress(asyncio.CancelledError):
                await watcher
        finally:
            _QUERY_CANCELLED.reset(token)
