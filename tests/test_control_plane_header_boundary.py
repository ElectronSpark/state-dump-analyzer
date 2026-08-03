from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import unittest
from collections.abc import Iterator, Mapping
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_dump_analyzer.control_plane_server import (
    ControlPlaneApplicationRequest,
    create_control_plane_application,
)
from router_dump_analyzer.ingestion_pipeline import WorkerHealthSnapshot
from router_dump_analyzer.operational_logging import (
    RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT,
    flush_operational_events,
    operational_event_class_health_snapshot,
)
from router_dump_analyzer.web.control_plane_api import (
    CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
    ControlPlaneAccessDenialReporter,
    ControlPlaneAccessPhase,
    ControlPlaneAccessReason,
    ControlPlaneIdentity,
    _control_plane_access_denial,
    control_plane_router,
)

_PRIVATE_HEADER_MARKER = "private-resolver-header-6f1ce7"


class _HostileItemsMapping(Mapping[str, str]):
    """Expose duplicate entries that ``dict(mapping)`` would silently erase."""

    def __init__(self, pairs: tuple[tuple[str, str], ...]) -> None:
        self._pairs = pairs

    def __getitem__(self, key: str) -> str:
        for candidate, value in self._pairs:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(dict(self._pairs))

    def __len__(self) -> int:
        return len(dict(self._pairs))

    def items(self) -> tuple[tuple[str, str], ...]:
        return self._pairs


class _RaisingItemsMapping(Mapping[str, str]):
    """A deployment-owned mapping whose descriptor-like access is hostile."""

    def __getitem__(self, key: str) -> str:
        if key == "X-Resolver":
            return _PRIVATE_HEADER_MARKER
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("X-Resolver",))

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        raise RuntimeError("private response-header mapping failure")


class _WireControlPlane:
    """Small lifecycle-compatible host used by the real-wire regression."""

    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.ingestion = SimpleNamespace(
            limits=SimpleNamespace(
                max_workers=1,
                stalled_import_seconds=900.0,
            ),
            worker_health=self._worker_health,
        )

    def _worker_health(self) -> WorkerHealthSnapshot:
        live = self.started and not self.closed
        return WorkerHealthSnapshot(
            started=live,
            live_workers=1 if live else 0,
            total_claim_errors=0,
            consecutive_claim_errors=0,
            last_claim_error_at_ns=None,
            last_claim_error=None,
            total_iteration_errors=0,
            consecutive_iteration_errors=0,
            last_iteration_error_at_ns=None,
            last_iteration_error=None,
        )

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True


class ControlPlaneHeaderBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        application = FastAPI()
        application.include_router(control_plane_router)
        application.state.control_plane = object()
        self.application = application
        self.client_context = TestClient(
            application,
            raise_server_exceptions=False,
        )
        self.client = self.client_context.__enter__()
        self.last_resolver_header_rejection_calls = 0

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)

    def _install_reporter(self) -> list[tuple[str, dict[str, object]]]:
        events: list[tuple[str, dict[str, object]]] = []

        def capture(event: str, **fields: object) -> bool:
            events.append((event, dict(fields)))
            return True

        self.application.state.control_plane_access_denial_reporter = (
            ControlPlaneAccessDenialReporter(
                emitter=capture,
                minimum_interval_seconds=0.0,
                maximum_interval_seconds=0.0,
            )
        )
        return events

    def _request_resolver_denial(
        self,
        headers: object,
        *,
        status_code: int = 401,
        error_type: type[StarletteHTTPException] = StarletteHTTPException,
    ) -> tuple[Any, list[tuple[str, dict[str, object]]]]:
        events = self._install_reporter()

        def resolver(_request: object) -> object:
            raise error_type(
                status_code=status_code,
                detail="deployment credential was rejected",
                headers=headers,  # type: ignore[arg-type]
            )

        self.application.state.control_plane_identity_resolver = resolver
        self.last_resolver_header_rejection_calls = 0

        def observe_header_rejection() -> bool:
            self.last_resolver_header_rejection_calls += 1
            return True

        with patch(
            "router_dump_analyzer.web.control_plane_api."
            "emit_resolver_response_headers_rejected",
            side_effect=observe_header_rejection,
        ):
            response = self.client.get(
                "/v1/control-plane/projects",
                headers={"X-Tenant-ID": "tenant-a"},
            )
        return response, events

    def assert_bounded_header_failure(
        self,
        response: Any,
        events: list[tuple[str, dict[str, object]]],
    ) -> None:
        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(response.headers.get("x-resolver"), None)
        payload = response.json()
        self.assertEqual(set(payload), {"detail"})
        self.assertIs(type(payload["detail"]), str)
        self.assertTrue(1 <= len(payload["detail"]) <= 256)
        rendered = response.text + json.dumps(dict(response.headers))
        self.assertNotIn(_PRIVATE_HEADER_MARKER, rendered)
        self.assertNotIn("private response-header mapping failure", rendered)
        self.assertEqual(self.last_resolver_header_rejection_calls, 1)
        self.assertEqual(len(events), 1)
        reporter = self.application.state.control_plane_access_denial_reporter
        self.assertEqual(reporter.snapshot().observed_denials, 1)
        event, fields = events[0]
        self.assertEqual(event, "control_plane.access.denied")
        self.assertEqual(fields["phase"], "identity_verification")
        self.assertEqual(fields["reason"], "identity_verification_failed")
        self.assertEqual(fields["response_status"], 500)
        serialized_event = json.dumps(fields, sort_keys=True)
        self.assertNotIn(_PRIVATE_HEADER_MARKER, serialized_event)
        self.assertNotIn("private response-header mapping failure", serialized_event)

    def test_safe_authentication_headers_survive_for_both_framework_types(
        self,
    ) -> None:
        safe_headers = {
            "WWW-Authenticate": 'Bearer realm="router-dump"',
            "Retry-After": "30",
            # ``Cookie`` is a request-side field and cannot mutate the user
            # agent when seen on a response. It remains generically bounded;
            # the state-changing Set-Cookie families are rejected below.
            "Cookie": "resolver-metadata=nonmutating",
            "X-Resolver": "deployment-auth",
        }
        for error_type in (HTTPException, StarletteHTTPException):
            for status_code in (401, 403):
                with self.subTest(
                    error_type=error_type.__module__,
                    status_code=status_code,
                ):
                    response, events = self._request_resolver_denial(
                        safe_headers,
                        status_code=status_code,
                        error_type=error_type,
                    )
                    self.assertEqual(response.status_code, status_code, response.text)
                    self.assertEqual(
                        response.json(),
                        {"detail": "deployment credential was rejected"},
                    )
                    for header, value in safe_headers.items():
                        self.assertEqual(response.headers[header], value)
                    self.assertEqual(len(events), 1)
                    self.assertEqual(
                        events[0][1]["reason"],
                        "identity_verification_failed",
                    )
                    self.assertEqual(self.last_resolver_header_rejection_calls, 0)

    def test_invalid_response_header_maps_fail_closed_with_dual_telemetry(
        self,
    ) -> None:
        invalid_cases: list[tuple[str, object]] = [
            (
                "carriage-return",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\rb"},
            ),
            (
                "line-feed",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\nb"},
            ),
            (
                "crlf-injection",
                {
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    "X-Bad": "a\r\nInjected: yes",
                },
            ),
            (
                "nul",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\x00b"},
            ),
            (
                "c0-control",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\x1fb"},
            ),
            (
                "del-control",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\x7fb"},
            ),
            (
                "c1-control",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "a\x85b"},
            ),
            (
                "leading-whitespace",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": " private"},
            ),
            (
                "trailing-whitespace",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "private\t"},
            ),
            (
                "empty-name",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "": "private"},
            ),
            (
                "malformed-name",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "Bad Name": "private"},
            ),
            (
                "non-ascii-name",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Résolver": "private"},
            ),
            (
                "oversized-name",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X" * 129: "private"},
            ),
            (
                "non-latin1-value",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": "snowman ☃"},
            ),
            (
                "non-string-name",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, 7: "private"},
            ),
            (
                "non-string-value",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Bad": 7},
            ),
            (
                "case-insensitive-duplicate",
                _HostileItemsMapping(
                    (
                        ("X-Resolver", _PRIVATE_HEADER_MARKER),
                        ("X-Duplicate", "one"),
                        ("x-duplicate", "two"),
                    )
                ),
            ),
            (
                "too-many-headers",
                {
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    **{f"X-Limit-{index:02d}": "v" for index in range(32)},
                },
            ),
            (
                "oversized-value",
                {"X-Resolver": _PRIVATE_HEADER_MARKER, "X-Large": "v" * 4097},
            ),
            (
                "oversized-aggregate",
                {
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    **{f"X-Block-{index}": "v" * 3500 for index in range(5)},
                },
            ),
            ("raising-items", _RaisingItemsMapping()),
        ]
        reserved_headers = (
            "Connection",
            "Keep-Alive",
            "Proxy-Connection",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Content-Length",
            "Content-Type",
            "Content-Encoding",
            "Set-Cookie",
            "set-cookie",
            "SET-COOKIE",
            "Set-Cookie2",
            "set-cookie2",
            "SET-COOKIE2",
        )
        invalid_cases.extend(
            (
                f"reserved-{header.lower()}",
                {
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    header: "9" if header == "Content-Length" else "private",
                },
            )
            for header in reserved_headers
        )

        for label, headers in invalid_cases:
            with self.subTest(case=label):
                response, events = self._request_resolver_denial(headers)
                self.assert_bounded_header_failure(response, events)

    def test_final_private_denial_guard_revalidates_headers_before_telemetry(
        self,
    ) -> None:
        events = self._install_reporter()

        def forged_denial(_request: object) -> object:
            raise _control_plane_access_denial(
                status_code=403,
                public_detail="request was rejected",
                phase=ControlPlaneAccessPhase.IDENTITY_VERIFICATION,
                reason=ControlPlaneAccessReason.IDENTITY_VERIFICATION_FAILED,
                headers={
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    "X-Bad": "private\r\nInjected: yes",
                },
            )

        self.application.state.control_plane_identity_resolver = forged_denial
        self.last_resolver_header_rejection_calls = 0

        def observe_header_rejection() -> bool:
            self.last_resolver_header_rejection_calls += 1
            return True

        with patch(
            "router_dump_analyzer.web.control_plane_api."
            "emit_resolver_response_headers_rejected",
            side_effect=observe_header_rejection,
        ):
            response = self.client.get(
                "/v1/control-plane/projects",
                headers={"X-Tenant-ID": "tenant-a"},
            )
        self.assert_bounded_header_failure(response, events)

    def test_invalid_header_telemetry_failure_cannot_change_the_bounded_500(
        self,
    ) -> None:
        invalid_headers = {
            "X-Resolver": _PRIVATE_HEADER_MARKER,
            "X-Bad": "private\r\nInjected: yes",
        }
        baseline, _events = self._request_resolver_denial(invalid_headers)

        class _ThrowingReporter(ControlPlaneAccessDenialReporter):
            def report(self, **_values: object) -> bool:
                raise RuntimeError(r"failed at C:\private\telemetry.log")

        def resolver(_request: object) -> object:
            raise StarletteHTTPException(
                status_code=401,
                detail="deployment credential was rejected",
                headers=invalid_headers,
            )

        self.application.state.control_plane_access_denial_reporter = (
            _ThrowingReporter()
        )
        self.application.state.control_plane_identity_resolver = resolver
        with patch(
            "router_dump_analyzer.web.control_plane_api."
            "emit_resolver_response_headers_rejected",
            side_effect=RuntimeError("operational channel failed"),
        ):
            failed_telemetry = self.client.get(
                "/v1/control-plane/projects",
                headers={"X-Tenant-ID": "tenant-a"},
            )

        self.assertEqual(failed_telemetry.status_code, baseline.status_code)
        self.assertEqual(failed_telemetry.content, baseline.content)
        self.assertEqual(dict(failed_telemetry.headers), dict(baseline.headers))

    def test_header_rejection_is_counted_and_visible_to_instance_operator(
        self,
    ) -> None:
        before = operational_event_class_health_snapshot(
            RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT
        )

        def invalid_resolver(_request: object) -> object:
            raise StarletteHTTPException(
                status_code=403,
                detail="deployment credential was rejected",
                headers={"Set-Cookie": "session=attacker"},
            )

        self.application.state.control_plane_identity_resolver = invalid_resolver
        rejected = self.client.get(
            "/v1/control-plane/projects",
            headers={"X-Tenant-ID": "tenant-a"},
        )
        self.assertEqual(rejected.status_code, 500, rejected.text)
        self.assertTrue(flush_operational_events(timeout=2.0))
        after = operational_event_class_health_snapshot(
            RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT
        )
        self.assertEqual(after.accepted_events, before.accepted_events + 1)

        def instance_operator(_request: object) -> ControlPlaneIdentity:
            return ControlPlaneIdentity(
                tenant_id="tenant-a",
                principal_id="operator",
                roles=frozenset({CONTROL_PLANE_INSTANCE_OPERATOR_ROLE}),
            )

        self.application.state.control_plane_identity_resolver = instance_operator
        diagnostics = self.client.get(
            "/v1/control-plane/diagnostics/operational-events",
            headers={"X-Tenant-ID": "tenant-a"},
        )
        self.assertEqual(diagnostics.status_code, 200, diagnostics.text)
        event_classes = {
            item["event"]: item
            for item in diagnostics.json()["operational_events"]["event_classes"]
        }
        self.assertIn(RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT, event_classes)
        self.assertEqual(
            event_classes[RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT]["accepted_events"],
            after.accepted_events,
        )

    def test_crlf_resolver_header_is_rejected_on_wire_without_closing_keepalive(
        self,
    ) -> None:
        def resolver(_request: object) -> object:
            raise HTTPException(
                status_code=401,
                detail="deployment credential was rejected",
                headers={
                    "X-Resolver": _PRIVATE_HEADER_MARKER,
                    "X-Bad": "private\r\nInjected: yes",
                },
            )

        control_plane = _WireControlPlane()
        application = create_control_plane_application(
            ControlPlaneApplicationRequest(
                control_plane=control_plane,
                identity_resolver=resolver,
            )
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        host, port = listener.getsockname()
        config = uvicorn.Config(
            application,
            host=host,
            port=port,
            http="h11",
            lifespan="on",
            access_log=False,
            log_level="critical",
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        failures: list[BaseException] = []

        def serve() -> None:
            try:
                server.run(sockets=[listener])
            except BaseException as error:  # noqa: BLE001 - capture thread failures
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        connection: http.client.HTTPConnection | None = None
        thread.start()
        try:
            startup_deadline = time.monotonic() + 5.0
            while not server.started and thread.is_alive():
                if time.monotonic() >= startup_deadline:
                    self.fail("uvicorn did not start within five seconds")
                time.sleep(0.01)
            self.assertTrue(thread.is_alive(), failures)

            connection = http.client.HTTPConnection(host, port, timeout=3.0)
            connection.request(
                "GET",
                "/v1/control-plane/projects",
                headers={"X-Tenant-ID": "tenant-a"},
            )
            first = connection.getresponse()
            first_body = first.read()
            self.assertEqual(first.status, 500, first_body)
            self.assertEqual(first.getheader("X-Resolver"), None)
            self.assertEqual(first.getheader("Injected"), None)
            first_payload = json.loads(first_body)
            self.assertEqual(set(first_payload), {"detail"})
            self.assertTrue(1 <= len(first_payload["detail"]) <= 256)
            first_socket = connection.sock
            self.assertIsNotNone(first_socket)

            connection.request("GET", "/health")
            second = connection.getresponse()
            second_body = second.read()
            self.assertEqual(second.status, 200, second_body)
            self.assertIs(connection.sock, first_socket)
            self.assertIsInstance(json.loads(second_body), dict)
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
        self.assertTrue(control_plane.closed)


if __name__ == "__main__":
    unittest.main()
