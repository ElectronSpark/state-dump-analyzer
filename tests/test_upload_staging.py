"""Admission capacity is reserved before any upload body is consumed."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion_pipeline import (
    DurableIngestionPipeline,
    ImportConflictError,
    ImportQuotaExceededError,
    ImportScope,
    IngestionPipelineError,
    PipelineLimits,
    PluginRegistry,
    RetentionPolicy,
)
from router_dump_analyzer.web.control_plane_api import (
    TrustedHeaderIdentityResolver,
    control_plane_router,
)
from tests.test_ingestion_pipeline import _Publisher

_SCOPE = ImportScope("tenant-a", "project-a", "workspace-a")


def _pipeline(root: Path, **limits: Any) -> DurableIngestionPipeline:
    return DurableIngestionPipeline(
        root,
        registry=PluginRegistry(()),
        publisher=_Publisher(),
        limits=PipelineLimits(max_upload_bytes=16, **limits),
    )


def _hold_upload_process(root: str, started: Any, release: Any) -> None:
    pipeline = _pipeline(Path(root), max_concurrent_uploads=1, max_staging_bytes=8)

    def chunks():
        yield b"abcd"
        started.set()
        if not release.wait(15):
            raise TimeoutError("test upload was not released")
        yield b"efgh"

    pipeline.submit_chunks(_SCOPE, chunks(), original_name="a.bin", expected_bytes=8)


class UploadStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.pipeline = _pipeline(Path(self.temporary.name))

    def assert_released(self) -> None:
        self.assertEqual(tuple(self.pipeline.spool_root.iterdir()), ())
        with self.pipeline._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ingestion_upload_reservations"
                ).fetchone()[0],
                0,
            )

    def test_known_size_rejects_before_iterator_access(self) -> None:
        self.pipeline.limits = replace(self.pipeline.limits, max_staging_bytes=3)
        consumed = []

        def chunks():
            consumed.append(True)
            yield b"abcd"

        with self.assertRaises(ImportQuotaExceededError):
            self.pipeline.submit_chunks(
                _SCOPE, chunks(), original_name="a.bin", expected_bytes=4
            )
        self.assertEqual(consumed, [])
        self.assert_released()

    def test_row_and_byte_quotas_reject_before_reading_unknown_body(self) -> None:
        for policy in (
            RetentionPolicy(max_workspace_imports=1),
            RetentionPolicy(max_tenant_imports=1),
            RetentionPolicy(max_workspace_bytes=4),
            RetentionPolicy(max_tenant_bytes=4),
        ):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as root:
                pipeline = _pipeline(Path(root))
                pipeline.retention_policy = policy
                pipeline.submit_bytes(_SCOPE, b"abcd", original_name="a.bin")
                consumed = []

                def chunks(consumed=consumed):
                    consumed.append(True)
                    yield b"x"

                with self.assertRaises(ImportQuotaExceededError):
                    pipeline.submit_chunks(_SCOPE, chunks(), original_name="b.bin")
                self.assertEqual(consumed, [])

    def test_unknown_body_reserves_remaining_allowance_before_first_read(self) -> None:
        self.pipeline.retention_policy = RetentionPolicy(max_workspace_bytes=4)

        def chunks():
            with self.pipeline._connect() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT reserved_bytes FROM ingestion_upload_reservations"
                    ).fetchone()[0],
                    4,
                )
            yield b"abcd"

        result = self.pipeline.submit_chunks(_SCOPE, chunks(), original_name="a.bin")
        self.assertEqual(result.byte_count, 4)
        self.assert_released()

    def test_unknown_body_cannot_write_beyond_reserved_allowance(self) -> None:
        self.pipeline.limits = replace(self.pipeline.limits, max_staging_bytes=4)
        with self.assertRaises(ImportQuotaExceededError):
            self.pipeline.submit_chunks(_SCOPE, (b"abcd", b"e"), original_name="a.bin")
        self.assertEqual(self.pipeline.list_imports(_SCOPE), ())
        self.assert_released()

    def test_failed_and_length_mismatched_streams_release_capacity(self) -> None:
        def fails():
            yield b"ab"
            raise OSError("read failed")

        for chunks, expected, error in (
            (fails(), 4, OSError),
            ((b"ab",), 4, IngestionPipelineError),
            ((b"abcd",), 2, IngestionPipelineError),
        ):
            with self.subTest(expected=expected, error=error):
                with self.assertRaises(error):
                    self.pipeline.submit_chunks(
                        _SCOPE, chunks, original_name="a.bin", expected_bytes=expected
                    )
                self.assert_released()

    def test_concurrent_reservation_protects_slots_bytes_and_logical_quota(
        self,
    ) -> None:
        for constraints in ("slots", "bytes", "quota", "active"):
            with self.subTest(constraints=constraints):
                self.pipeline.limits = replace(
                    self.pipeline.limits,
                    max_concurrent_uploads=1 if constraints == "slots" else 2,
                    max_staging_bytes=4 if constraints == "bytes" else 32,
                    max_active_imports_per_workspace=1
                    if constraints == "active"
                    else 1000,
                )
                self.pipeline.retention_policy = RetentionPolicy(
                    max_workspace_bytes=4 if constraints == "quota" else None,
                )
                entered = threading.Event()
                release = threading.Event()
                consumed = []

                def holding(entered=entered, release=release):
                    entered.set()
                    if not release.wait(10):
                        raise TimeoutError("test upload was not released")
                    raise OSError("abort test upload")
                    yield b""  # pragma: no cover - generator contract

                def second(consumed=consumed):
                    consumed.append(True)
                    yield b"x"

                with ThreadPoolExecutor(max_workers=1) as executor:
                    first = executor.submit(
                        self.pipeline.submit_chunks,
                        _SCOPE,
                        holding(),
                        original_name="a.bin",
                        expected_bytes=4,
                    )
                    try:
                        self.assertTrue(entered.wait(5))
                        with self.assertRaises(ImportConflictError):
                            self.pipeline.submit_chunks(
                                _SCOPE,
                                second(),
                                original_name="b.bin",
                                expected_bytes=1,
                            )
                        self.assertEqual(consumed, [])
                    finally:
                        release.set()
                    with self.assertRaises(OSError):
                        first.result(timeout=5)
                self.assert_released()

    def test_idempotent_replay_uses_staging_but_not_another_logical_quota(self) -> None:
        self.pipeline.retention_policy = RetentionPolicy(
            max_workspace_imports=1, max_workspace_bytes=4
        )
        original = self.pipeline.submit_bytes(
            _SCOPE, b"abcd", original_name="a.bin", idempotency_key="same"
        )
        replay = self.pipeline.submit_bytes(
            _SCOPE, b"abcd", original_name="a.bin", idempotency_key="same"
        )
        self.assertEqual(original.import_id, replay.import_id)
        with self.assertRaises(ImportConflictError):
            self.pipeline.submit_bytes(
                _SCOPE, b"abce", original_name="a.bin", idempotency_key="same"
            )
        self.assert_released()

    def test_same_thread_nested_upload_does_not_reclaim_outer_spool(self) -> None:
        self.pipeline.limits = replace(self.pipeline.limits, max_concurrent_uploads=1)

        def chunks():
            with self.assertRaises(ImportQuotaExceededError):
                self.pipeline.submit_bytes(_SCOPE, b"x", original_name="inner.bin")
            self.assertEqual(len(tuple(self.pipeline.spool_root.glob("*.partial"))), 1)
            yield b"abcd"

        self.pipeline.submit_chunks(
            _SCOPE, chunks(), original_name="a.bin", expected_bytes=4
        )
        self.assert_released()

    def test_pending_idempotent_retries_share_one_logical_quota(self) -> None:
        self.pipeline.retention_policy = RetentionPolicy(
            max_workspace_imports=1, max_workspace_bytes=4
        )
        nested = []

        def chunks():
            nested.append(
                self.pipeline.submit_bytes(
                    _SCOPE, b"abcd", original_name="a.bin", idempotency_key="same"
                )
            )
            yield b"abcd"

        original = self.pipeline.submit_chunks(
            _SCOPE,
            chunks(),
            original_name="a.bin",
            idempotency_key="same",
            expected_bytes=4,
        )
        self.assertEqual(original.import_id, nested[0].import_id)
        self.assert_released()

    def test_admitted_reservation_does_not_double_charge_before_spool_cleanup(
        self,
    ) -> None:
        self.pipeline.retention_policy = RetentionPolicy(
            max_workspace_imports=2, max_workspace_bytes=8
        )
        discard = self.pipeline._discard_prepared_fixture_view
        nested = []

        def after_admission(prepared):
            discard(prepared)
            if not nested:
                nested.append(True)
                self.pipeline.submit_bytes(_SCOPE, b"efgh", original_name="b.bin")

        with patch.object(
            self.pipeline, "_discard_prepared_fixture_view", after_admission
        ):
            self.pipeline.submit_bytes(_SCOPE, b"abcd", original_name="a.bin")
        self.assertEqual(len(self.pipeline.list_imports(_SCOPE)), 2)
        self.assert_released()

    def test_cleanup_failure_retains_reservation_until_spool_is_reclaimed(self) -> None:
        self.pipeline.limits = replace(self.pipeline.limits, max_concurrent_uploads=1)
        unlink = Path.unlink

        def fail_spool_unlink(path, *args, **kwargs):
            if path.parent == self.pipeline.spool_root and path.suffix == ".partial":
                raise PermissionError("spool is temporarily busy")
            return unlink(path, *args, **kwargs)

        with (
            patch.object(Path, "unlink", fail_spool_unlink),
            self.assertRaises(PermissionError),
        ):
            self.pipeline.submit_chunks(
                _SCOPE, (b"ab",), original_name="a.bin", expected_bytes=4
            )
        self.assertEqual(len(tuple(self.pipeline.spool_root.glob("*.partial"))), 1)
        with self.pipeline._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT reserved_bytes FROM ingestion_upload_reservations"
                ).fetchone()[0],
                4,
            )
        self.pipeline.submit_bytes(_SCOPE, b"abcd", original_name="a.bin")
        self.assert_released()

    def test_cross_process_live_owner_blocks_and_crash_releases_capacity(self) -> None:
        context = multiprocessing.get_context("spawn")
        started, release = context.Event(), context.Event()
        process = context.Process(
            target=_hold_upload_process,
            args=(self.temporary.name, started, release),
        )
        process.start()
        try:
            self.assertTrue(started.wait(10))
            self.pipeline.limits = replace(
                self.pipeline.limits, max_concurrent_uploads=1, max_staging_bytes=8
            )
            partial = tuple(self.pipeline.spool_root.glob("*.partial"))
            self.assertEqual(len(partial), 1)
            with self.assertRaises(ImportQuotaExceededError):
                self.pipeline.submit_bytes(_SCOPE, b"x", original_name="b.bin")
            self.assertTrue(partial[0].exists())
            process.terminate()
            process.join(5)
            self.assertFalse(process.is_alive())
            self.pipeline.submit_bytes(_SCOPE, b"x", original_name="b.bin")
            self.assertFalse(partial[0].exists())
            self.assert_released()
        finally:
            if process.is_alive():
                process.terminate()
            process.join(5)
            process.close()

    def test_limits_and_known_lengths_require_exact_integers(self) -> None:
        for field in ("max_concurrent_uploads", "max_staging_bytes"):
            for value in (True, 0, 1.5):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    PipelineLimits(**{field: value})
        for value in (True, -1, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pipeline.submit_chunks(
                    _SCOPE, (b"x",), original_name="a.bin", expected_bytes=value
                )


class UploadStagingHttpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.control_plane = ControlPlane(
            Path(self.temporary.name),
            registry=PluginRegistry(()),
            pipeline_limits=PipelineLimits(max_upload_bytes=16, max_staging_bytes=16),
        )
        self.addCleanup(self.control_plane.close)
        self.app = FastAPI()
        self.app.include_router(control_plane_router)
        self.app.state.control_plane = self.control_plane
        self.app.state.control_plane_identity_resolver = TrustedHeaderIdentityResolver(
            allowed_hosts=("testserver",), allowed_origins=("http://testserver",)
        )
        headers = {"X-Tenant-ID": "tenant-a", "X-Principal-ID": "author"}
        with TestClient(self.app) as client:
            result = client.post(
                "/v1/control-plane/projects",
                headers=headers,
                json={"project_id": "project-a", "label": "Project"},
            )
            self.assertEqual(result.status_code, 201, result.text)
            result = client.post(
                "/v1/control-plane/projects/project-a/workspaces",
                headers=headers,
                json={"workspace_id": "workspace-a", "label": "Workspace"},
            )
            self.assertEqual(result.status_code, 201, result.text)

    async def request(
        self, receive: Any, *, announced: str | None = "4", authorized: bool = True
    ) -> list[dict[str, Any]]:
        headers = [(b"host", b"testserver")]
        if authorized:
            headers.extend(
                ((b"x-tenant-id", b"tenant-a"), (b"x-principal-id", b"author"))
            )
        if announced is not None:
            headers.append((b"content-length", announced.encode()))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 123),
            "root_path": "",
            "path": "/v1/control-plane/projects/project-a/workspaces/workspace-a/imports",
            "query_string": b"original_name=a.bin",
            "headers": headers,
        }
        messages = []

        async def send(message):
            messages.append(message)

        await self.app(scope, receive, send)
        return messages

    def assert_released(self) -> None:
        pipeline = self.control_plane.ingestion
        self.assertEqual(tuple(pipeline.spool_root.iterdir()), ())
        with pipeline._connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ingestion_upload_reservations"
                ).fetchone()[0],
                0,
            )

    async def test_http_uses_one_owned_spool_with_on_demand_reads(self) -> None:
        seen = []

        async def receive():
            pipeline = self.control_plane.ingestion
            seen.append(tuple(pipeline.spool_root.glob("*.partial")))
            with pipeline._connect() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT reserved_bytes FROM ingestion_upload_reservations"
                    ).fetchone()[0],
                    4,
                )
            return {"type": "http.request", "body": b"abcd", "more_body": False}

        with patch(
            "tempfile.SpooledTemporaryFile", side_effect=AssertionError("second spool")
        ):
            messages = await self.request(receive)
        self.assertEqual(messages[0]["status"], 202)
        self.assertEqual(len(seen), 1)
        self.assertEqual(len(seen[0]), 1)
        body = json.loads(messages[1]["body"])
        self.assertEqual(body["byte_count"], 4)
        self.assert_released()

    async def test_http_quota_and_authorization_reject_without_receive(self) -> None:
        consumed = []

        async def receive():
            consumed.append(True)
            return {"type": "http.request", "body": b"abcd", "more_body": False}

        pipeline = self.control_plane.ingestion
        pipeline.limits = replace(pipeline.limits, max_staging_bytes=3)
        self.assertEqual((await self.request(receive))[0]["status"], 409)
        self.assertEqual(
            (await self.request(receive, authorized=False))[0]["status"], 401
        )
        self.assertEqual(consumed, [])
        self.assert_released()

    async def test_http_content_length_and_stream_limit_are_checked(self) -> None:
        for announced, body, status in (
            ("03", b"abc", 400),
            ("3", b"abcd", 400),
            ("5", b"abcd", 400),
            (None, b"x" * 17, 413),
        ):
            with self.subTest(announced=announced):

                async def receive(body=body):
                    return {"type": "http.request", "body": body, "more_body": False}

                self.assertEqual(
                    (await self.request(receive, announced=announced))[0]["status"],
                    status,
                )
                self.assert_released()

    async def test_cancellation_interrupts_pending_receive_and_cleans_spool(
        self,
    ) -> None:
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def receive():
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        task = asyncio.create_task(self.request(receive))
        await asyncio.wait_for(entered.wait(), 5)
        self.assertEqual(
            len(tuple(self.control_plane.ingestion.spool_root.glob("*.partial"))), 1
        )
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        await asyncio.wait_for(cancelled.wait(), 5)
        self.assert_released()

    async def test_repeated_cancellation_waits_for_worker_spool_cleanup(self) -> None:
        receiving = asyncio.Event()
        cleaning, release = threading.Event(), threading.Event()
        pipeline = self.control_plane.ingestion
        discard = pipeline._discard_prepared_fixture_view

        async def receive():
            receiving.set()
            await asyncio.Event().wait()

        def slow_cleanup(prepared):
            cleaning.set()
            if not release.wait(5):
                raise TimeoutError("test cleanup was not released")
            discard(prepared)

        with patch.object(pipeline, "_discard_prepared_fixture_view", slow_cleanup):
            task = asyncio.create_task(self.request(receive))
            try:
                await asyncio.wait_for(receiving.wait(), 5)
                task.cancel()
                self.assertTrue(await asyncio.to_thread(cleaning.wait, 5))
                task.cancel()
                await asyncio.sleep(0.02)
                self.assertFalse(task.done())
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 5)
        self.assert_released()
