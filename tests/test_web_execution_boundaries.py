from __future__ import annotations

import asyncio
import http.client
import json
import socket
import threading
import time
import unittest
from contextlib import nullcontext
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import uvicorn
from fastapi import APIRouter, FastAPI
from fastapi import HTTPException as FastAPIHTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS
from router_dump_analyzer.web import control_plane_api, runtime_api

_PRIVATE_DETAIL = r"failed at C:\Users\alice\secret\provider.py"


class _ProviderAbort(BaseException):
    pass


class _ExplosiveDetail:
    def __str__(self) -> str:
        raise _ProviderAbort(_PRIVATE_DETAIL)


class _ExplosiveHeadersHTTPException(StarletteHTTPException):
    def __getattribute__(self, name: str) -> Any:
        if name == "headers":
            raise _ProviderAbort(_PRIVATE_DETAIL)
        return super().__getattribute__(name)


@dataclass(frozen=True, slots=True)
class _ASGIResult:
    status: int | None
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes
    error: BaseException | None


async def _asgi_get(
    application: FastAPI,
    path: str,
    *,
    headers: tuple[tuple[bytes, bytes], ...] = (),
) -> _ASGIResult:
    messages: list[dict[str, Any]] = []
    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": list(headers),
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
        "app": application,
    }
    error: BaseException | None = None
    try:
        await application(scope, receive, send)
    except BaseException as caught:  # noqa: BLE001 - inspect the ASGI boundary.
        error = caught
    starts = [item for item in messages if item["type"] == "http.response.start"]
    bodies = [
        item.get("body", b"")
        for item in messages
        if item["type"] == "http.response.body"
    ]
    return _ASGIResult(
        status=starts[0]["status"] if starts else None,
        headers=tuple(starts[0].get("headers", ())) if starts else (),
        body=b"".join(bodies),
        error=error,
    )


def _request_scope(application: FastAPI) -> dict[str, Any]:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/v1/control-plane/projects",
        "raw_path": b"/v1/control-plane/projects",
        "query_string": b"",
        "headers": [(b"x-tenant-id", b"tenant-a")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
        "app": application,
    }


def _control_plane_application(
    resolver: Any,
) -> tuple[FastAPI, list[tuple[str, dict[str, object]]]]:
    application = FastAPI()
    application.include_router(control_plane_api.control_plane_router)
    application.state.control_plane = object()
    events: list[tuple[str, dict[str, object]]] = []
    application.state.control_plane_access_denial_reporter = (
        control_plane_api.ControlPlaneAccessDenialReporter(
            emitter=(
                lambda event, **fields: events.append((event, dict(fields))) or True
            ),
            minimum_interval_seconds=0.0,
            maximum_interval_seconds=0.0,
        )
    )
    application.state.control_plane_identity_resolver = resolver
    return application, events


def _runtime_boundary_application() -> FastAPI:
    application = FastAPI()
    router = APIRouter(route_class=runtime_api._BoundedRuntimeApiRoute)

    @router.get("/runtime/operation")
    def runtime_operation() -> object:
        return runtime_api._runtime_api_call(
            lambda: (_ for _ in ()).throw(_ProviderAbort(_PRIVATE_DETAIL))
        )

    @router.get("/runtime/temporal-provider")
    def temporal_provider() -> object:
        return runtime_api._temporal_topology("revision-a")

    @router.get("/runtime/topology-provider")
    def topology_provider() -> object:
        return runtime_api._multi_node_topology()

    @router.get("/runtime/route-provider")
    def route_provider() -> object:
        return runtime_api._multi_node_route()

    @router.get("/runtime/process-control")
    async def process_control(request: Request) -> object:
        raise request.app.state.process_control

    application.include_router(router)
    return application


class WebExecutionBoundaryTests(unittest.TestCase):
    def assert_bounded_json(
        self,
        result: _ASGIResult,
        *,
        status: int,
        detail: str,
    ) -> None:
        self.assertIsNone(result.error)
        self.assertEqual(result.status, status)
        self.assertEqual(json.loads(result.body), {"detail": detail})
        self.assertNotIn(_PRIVATE_DETAIL.encode(), result.body)

    def test_identity_resolver_custom_baseexceptions_become_typed_denials(
        self,
    ) -> None:
        def direct_abort(_request: Request) -> object:
            raise _ProviderAbort(_PRIVATE_DETAIL)

        def explosive_detail(_request: Request) -> object:
            raise StarletteHTTPException(
                status_code=401,
                detail=_ExplosiveDetail(),
                headers={"WWW-Authenticate": "Bearer"},
            )

        def explosive_headers(_request: Request) -> object:
            raise _ExplosiveHeadersHTTPException(
                status_code=403,
                detail="deployment credential was rejected",
                headers={"X-Private": _PRIVATE_DETAIL},
            )

        for label, resolver in (
            ("direct", direct_abort),
            ("detail-descriptor", explosive_detail),
            ("header-descriptor", explosive_headers),
        ):
            with self.subTest(label=label):
                application, events = _control_plane_application(resolver)
                header_rejections = 0

                def observe_header_rejection() -> bool:
                    nonlocal header_rejections
                    header_rejections += 1
                    return True

                with patch.object(
                    control_plane_api,
                    "emit_resolver_response_headers_rejected",
                    side_effect=observe_header_rejection,
                ):
                    result = asyncio.run(
                        _asgi_get(
                            application,
                            "/v1/control-plane/projects",
                            headers=((b"x-tenant-id", b"tenant-a"),),
                        )
                    )
                self.assert_bounded_json(
                    result,
                    status=401,
                    detail="control-plane identity could not be verified",
                )
                self.assertEqual(header_rejections, 0)
                self.assertEqual(len(events), 1)
                event, fields = events[0]
                self.assertEqual(event, "control_plane.access.denied")
                self.assertEqual(fields["phase"], "identity_verification")
                self.assertEqual(fields["reason"], "identity_verification_failed")
                self.assertEqual(fields["response_status"], 401)
                self.assertNotIn(_PRIVATE_DETAIL, repr(events))
                reporter = application.state.control_plane_access_denial_reporter
                self.assertEqual(reporter.snapshot().observed_denials, 1)

    def test_identity_resolver_preserves_every_process_control(self) -> None:
        for exception_type in PROCESS_CONTROL_EXCEPTIONS:
            interruption = exception_type("stop")

            def resolver(
                _request: Request,
                failure: BaseException = interruption,
            ) -> object:
                raise failure

            application, events = _control_plane_application(resolver)
            with self.subTest(exception_type=exception_type.__name__):
                request = Request(_request_scope(application))
                with self.assertRaises(exception_type):
                    control_plane_api._resolved_identity(request)
                self.assertEqual(events, [])
                self.assertEqual(
                    application.state.control_plane_access_denial_reporter.snapshot().observed_denials,
                    0,
                )

    def test_runtime_operation_contains_custom_baseexception_but_not_controls(
        self,
    ) -> None:
        with self.assertRaises(FastAPIHTTPException) as contained:
            runtime_api._runtime_api_call(
                lambda: (_ for _ in ()).throw(_ProviderAbort(_PRIVATE_DETAIL))
            )
        self.assertEqual(contained.exception.status_code, 500)
        self.assertEqual(
            contained.exception.detail,
            "internal analysis operation failed",
        )

        for exception_type in PROCESS_CONTROL_EXCEPTIONS:
            interruption = exception_type("stop")
            with (
                self.subTest(exception_type=exception_type.__name__),
                self.assertRaises(exception_type),
            ):
                runtime_api._runtime_api_call(
                    lambda failure=interruption: (_ for _ in ()).throw(failure)
                )

    def test_runtime_route_contains_operation_and_provider_acquisition_aborts(
        self,
    ) -> None:
        application = _runtime_boundary_application()

        class DescriptorSession:
            @property
            def temporal_provider(self) -> object:
                raise _ProviderAbort(_PRIVATE_DETAIL)

        class Provider:
            def for_revision(self, *_args: object) -> object:
                raise _ProviderAbort(_PRIVATE_DETAIL)

            def get(self) -> object:
                raise _ProviderAbort(_PRIVATE_DETAIL)

        class Session:
            def __init__(self, provider_name: str) -> None:
                self.temporal_provider = (
                    Provider() if provider_name == "temporal" else None
                )
                self.topology_provider = (
                    Provider() if provider_name == "topology" else None
                )
                self.route_provider = Provider() if provider_name == "route" else None

        cases = (
            ("operation", "/runtime/operation", None),
            ("descriptor", "/runtime/temporal-provider", DescriptorSession()),
            ("temporal-call", "/runtime/temporal-provider", Session("temporal")),
            ("topology-call", "/runtime/topology-provider", Session("topology")),
            ("route-call", "/runtime/route-provider", Session("route")),
        )
        for label, path, session in cases:
            with self.subTest(label=label):
                patches = (
                    patch.object(
                        runtime_api,
                        "current_runtime_session",
                        return_value=session,
                    ),
                    patch.object(
                        runtime_api,
                        "_data_service",
                        return_value=SimpleNamespace(
                            _loading_operation=lambda *_args: nullcontext()
                        ),
                    ),
                )
                with patches[0], patches[1]:
                    result = asyncio.run(_asgi_get(application, path))
                self.assert_bounded_json(
                    result,
                    status=500,
                    detail="internal analysis operation failed",
                )

    def test_runtime_route_preserves_every_process_control(self) -> None:
        application = _runtime_boundary_application()
        for exception_type in PROCESS_CONTROL_EXCEPTIONS:
            application.state.process_control = exception_type("stop")
            with self.subTest(exception_type=exception_type.__name__):
                result = asyncio.run(_asgi_get(application, "/runtime/process-control"))
                self.assertIsInstance(result.error, exception_type)
                self.assertIsNone(result.status)
                self.assertEqual(result.body, b"")

    def test_real_wire_returns_bounded_json_and_keeps_connection_usable(self) -> None:
        def resolver(_request: Request) -> object:
            raise _ProviderAbort(_PRIVATE_DETAIL)

        application, _events = _control_plane_application(resolver)
        runtime_router = APIRouter(route_class=runtime_api._BoundedRuntimeApiRoute)

        @runtime_router.get("/runtime-wire-boom")
        def runtime_wire_boom() -> object:
            raise _ProviderAbort(_PRIVATE_DETAIL)

        @runtime_router.get("/boundary-health")
        def boundary_health() -> dict[str, str]:
            return {"status": "ok"}

        application.include_router(runtime_router)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        host, port = listener.getsockname()
        server = uvicorn.Server(
            uvicorn.Config(
                application,
                host=host,
                port=port,
                http="h11",
                lifespan="off",
                access_log=False,
                log_level="critical",
            )
        )
        server.install_signal_handlers = lambda: None
        failures: list[BaseException] = []

        def serve() -> None:
            try:
                server.run(sockets=[listener])
            except BaseException as error:  # noqa: BLE001 - capture server failure.
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        connection: http.client.HTTPConnection | None = None
        thread.start()
        try:
            deadline = time.monotonic() + 5.0
            while not server.started and thread.is_alive():
                if time.monotonic() >= deadline:
                    self.fail("uvicorn did not start within five seconds")
                time.sleep(0.01)
            self.assertTrue(thread.is_alive(), failures)
            connection = http.client.HTTPConnection(host, port, timeout=3.0)

            connection.request(
                "GET",
                "/v1/control-plane/projects",
                headers={"X-Tenant-ID": "tenant-a"},
            )
            denied = connection.getresponse()
            denied_body = denied.read()
            self.assertEqual(denied.status, 401, denied_body)
            self.assertEqual(
                json.loads(denied_body),
                {"detail": "control-plane identity could not be verified"},
            )
            first_socket = connection.sock
            self.assertIsNotNone(first_socket)

            connection.request("GET", "/runtime-wire-boom")
            runtime_failure = connection.getresponse()
            runtime_body = runtime_failure.read()
            self.assertEqual(runtime_failure.status, 500, runtime_body)
            self.assertEqual(
                json.loads(runtime_body),
                {"detail": "internal analysis operation failed"},
            )
            self.assertIs(connection.sock, first_socket)

            connection.request("GET", "/boundary-health")
            health = connection.getresponse()
            self.assertEqual(health.status, 200, health.read())
            self.assertIs(connection.sock, first_socket)
        finally:
            if connection is not None:
                connection.close()
            server.should_exit = True
            thread.join(5.0)
            if thread.is_alive():
                server.force_exit = True
                listener.close()
                thread.join(2.0)
            else:
                listener.close()
        self.assertFalse(thread.is_alive(), "uvicorn did not stop within seven seconds")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
