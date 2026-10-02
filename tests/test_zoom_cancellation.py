"""Disconnect and task cancellation propagate without racing JSON body reads."""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from starlette.requests import Request

from router_dump_analyzer.web._query_cancellation import (
    current_query_cancellation_probe,
    query_cancellation_scope,
)


class ZoomCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_body_drained_then_disconnect_reaches_thread(self):
        messages = asyncio.Queue()
        await messages.put({"type": "http.request", "body": b'{"x":', "more_body": True})
        await messages.put({"type": "http.request", "body": b'1}', "more_body": False})
        request = Request({"type": "http", "method": "POST", "headers": []}, messages.get)
        async with query_cancellation_scope(request):
            self.assertEqual(await request.json(), {"x": 1})
            probe = await asyncio.to_thread(current_query_cancellation_probe)
            self.assertFalse(probe())
            await messages.put({"type": "http.disconnect"})
            for _ in range(10):
                await asyncio.sleep(0)
                if probe():
                    break
            self.assertTrue(probe())
        self.assertIsNone(current_query_cancellation_probe())

    async def test_exit_and_external_cancellation_set_probe_and_restore_context(self):
        retained = []
        entered = asyncio.Event()

        async def receive():
            await asyncio.Future()

        request = Request({"type": "http", "headers": []}, receive)
        request._body = b"{}"

        async def work():
            async with query_cancellation_scope(request):
                retained.append(current_query_cancellation_probe())
                entered.set()
                await asyncio.Future()

        task = asyncio.create_task(work())
        await entered.wait()
        self.assertFalse(retained[0]())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(retained[0]())
        self.assertIsNone(current_query_cancellation_probe())

    async def test_http_disconnect_cancels_core_query_without_partial_response(self):
        from fastapi import FastAPI
        from types import SimpleNamespace
        from router_dump_analyzer.revision_store import RevisionDescriptor
        from router_dump_analyzer.runtime import CoreRuntimeSession
        from router_dump_analyzer.web.runtime_api import api_router
        from router_dump_analyzer.web.runtime_context import activate_runtime_session
        from tests.test_revision_queries import REVISION, query_fixture

        dataset, service, queries = query_fixture(indexed=True)
        descriptor = RevisionDescriptor("node", REVISION, "Node", 3, 3)
        store = SimpleNamespace(revision=lambda revision: {REVISION: descriptor}[revision])
        session = CoreRuntimeSession(SimpleNamespace(revision_store=store), service)
        app = FastAPI()
        app.include_router(api_router)
        messages = asyncio.Queue()
        body = json.dumps({"start_ns": "0", "end_ns": "100", "bin_count": 10}).encode()
        await messages.put({"type": "http.request", "body": body, "more_body": False})
        sent = []
        loop = asyncio.get_running_loop()
        worker_started = asyncio.Event()

        def wait_for_disconnect(query_service, query):
            self.assertIsNotNone(query_service.cancellation_probe)
            loop.call_soon_threadsafe(worker_started.set)
            # A timeout is only a test failure guard, not synchronization.
            import time
            until = time.monotonic() + 3
            while not query_service.cancellation_probe():
                if time.monotonic() > until:
                    raise AssertionError("disconnect did not reach worker")
                time.sleep(0.001)
            query_service._checkpoint()
            raise AssertionError("cancelled query returned partial work")

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "POST", "scheme": "http", "path": f"/v1/revisions/{REVISION}/events/density/query",
                 "raw_path": b"/", "query_string": b"", "root_path": "",
                 "headers": [(b"content-type", b"application/json")],
                 "server": ("localhost", 80), "client": ("test", 123)}
        with activate_runtime_session(session), patch.object(type(queries), "event_density", wait_for_disconnect):
            task = asyncio.create_task(app(scope, messages.get, send))
            await asyncio.wait_for(worker_started.wait(), 3)
            await messages.put({"type": "http.disconnect"})
            await asyncio.wait_for(task, 3)
        starts = [message for message in sent if message["type"] == "http.response.start"]
        self.assertEqual([message["status"] for message in starts], [499])
        self.assertNotIn(b'"bins"', b"".join(message.get("body", b"") for message in sent))
