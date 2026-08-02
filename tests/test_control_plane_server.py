from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from router_dump_analyzer.control_plane_server import (
    ControlPlaneApplicationRequest,
    create_control_plane_application,
)
from router_dump_analyzer.ingestion_pipeline import WorkerHealthSnapshot
from router_dump_analyzer.web.control_plane_api import (
    ControlPlaneAccessDenialReporter,
)


class _LifecycleControlPlane:
    def __init__(self) -> None:
        self.start_count = 0
        self.close_count = 0
        self.ingestion = SimpleNamespace(
            limits=SimpleNamespace(
                max_workers=1,
                stalled_import_seconds=900.0,
            ),
            worker_health=self._worker_health,
        )

    def _worker_health(self) -> WorkerHealthSnapshot:
        return WorkerHealthSnapshot(
            started=self.start_count == 1 and self.close_count == 0,
            live_workers=1 if self.start_count == 1 and self.close_count == 0 else 0,
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
        self.start_count += 1

    def close(self) -> None:
        self.close_count += 1


class _PartialStartControlPlane(_LifecycleControlPlane):
    def start(self) -> None:
        self.start_count += 1
        raise RuntimeError("partial start failed")


class ControlPlaneServerTests(unittest.TestCase):
    def test_headless_application_owns_lifecycle_and_only_mounts_service_apis(
        self,
    ) -> None:
        control_plane = _LifecycleControlPlane()
        resolver_calls: list[object] = []

        def resolver(request: object) -> object:
            resolver_calls.append(request)
            return object()

        application = create_control_plane_application(
            ControlPlaneApplicationRequest(
                control_plane=control_plane,
                identity_resolver=resolver,
            )
        )

        def route_paths(routes: Any) -> set[str]:
            paths: set[str] = set()
            for route in routes:
                path = getattr(route, "path", None)
                if isinstance(path, str):
                    paths.add(path)
                nested = getattr(route, "routes", None)
                if nested is not None:
                    paths.update(route_paths(nested))
                original_router = getattr(route, "original_router", None)
                if original_router is not None:
                    paths.update(route_paths(original_router.routes))
            return paths

        mounted_paths = route_paths(application.routes)
        self.assertIn("/health", mounted_paths)
        self.assertIn("/v1/control-plane/health", mounted_paths)
        self.assertNotIn("/openapi.json", mounted_paths)
        self.assertNotIn("/docs", mounted_paths)
        self.assertNotIn("/redoc", mounted_paths)
        self.assertNotIn("/v1/workspace", mounted_paths)
        self.assertNotIn("/assets", mounted_paths)
        self.assertNotIn("/", mounted_paths)
        self.assertIs(application.state.control_plane, control_plane)
        self.assertIs(application.state.control_plane_identity_resolver, resolver)
        self.assertIsInstance(
            application.state.control_plane_access_denial_reporter,
            ControlPlaneAccessDenialReporter,
        )
        self.assertIsNone(application.state.runtime_session)

        self.assertEqual(control_plane.start_count, 0)
        self.assertEqual(control_plane.close_count, 0)
        with TestClient(application) as client:
            self.assertEqual(control_plane.start_count, 1)
            self.assertEqual(control_plane.close_count, 0)

            root_health = client.get("/health")
            self.assertEqual(root_health.status_code, 200, root_health.text)
            self.assertEqual(root_health.headers["cache-control"], "no-store")
            root_payload = root_health.json()
            self.assertEqual(root_payload["status"], "ok")
            self.assertFalse(root_payload["analysis_ready"])
            self.assertEqual(root_payload["mode"], "control-plane")

            durable_health = client.get("/v1/control-plane/health")
            self.assertEqual(
                durable_health.status_code,
                200,
                durable_health.text,
            )
            self.assertTrue(durable_health.json()["healthy"])
            self.assertEqual(
                resolver_calls,
                [],
                "aggregate health is intentionally unauthenticated",
            )

            self.assertEqual(client.get("/").status_code, 404)
            self.assertEqual(client.get("/v1/workspace").status_code, 404)
            self.assertEqual(client.get("/assets/app.js").status_code, 404)
            self.assertEqual(client.get("/openapi.json").status_code, 404)
            self.assertEqual(client.get("/docs").status_code, 404)
            self.assertEqual(client.get("/redoc").status_code, 404)

        self.assertEqual(control_plane.start_count, 1)
        self.assertEqual(control_plane.close_count, 1)

    def test_api_docs_require_explicit_application_opt_in(self) -> None:
        control_plane = _LifecycleControlPlane()
        application = create_control_plane_application(
            ControlPlaneApplicationRequest(
                control_plane=control_plane,
                identity_resolver=lambda _request: object(),
                expose_api_docs=True,
            )
        )

        with TestClient(application) as client:
            schema = client.get("/openapi.json")
            docs = client.get("/docs")
            redoc = client.get("/redoc")

        self.assertEqual(schema.status_code, 200, schema.text)
        self.assertEqual(docs.status_code, 200, docs.text)
        self.assertEqual(redoc.status_code, 200, redoc.text)
        self.assertNotIn("/v1/workspace", schema.text)

    def test_request_rejects_missing_lifecycle_or_identity_contracts(self) -> None:
        with self.assertRaisesRegex(TypeError, r"start\(\) and close\(\)"):
            ControlPlaneApplicationRequest(
                control_plane=object(),
                identity_resolver=lambda _request: object(),
            )
        with self.assertRaisesRegex(TypeError, "identity_resolver"):
            ControlPlaneApplicationRequest(
                control_plane=_LifecycleControlPlane(),
                identity_resolver=None,  # type: ignore[arg-type]
            )

        async def async_resolver(_request: object) -> object:
            return object()

        with self.assertRaisesRegex(TypeError, "must be synchronous"):
            ControlPlaneApplicationRequest(
                control_plane=_LifecycleControlPlane(),
                identity_resolver=async_resolver,
            )
        with self.assertRaisesRegex(TypeError, "expose_api_docs"):
            ControlPlaneApplicationRequest(
                control_plane=_LifecycleControlPlane(),
                identity_resolver=lambda _request: object(),
                expose_api_docs=1,  # type: ignore[arg-type]
            )

    def test_lifespan_closes_once_when_start_partially_fails(self) -> None:
        control_plane = _PartialStartControlPlane()
        application = create_control_plane_application(
            ControlPlaneApplicationRequest(
                control_plane=control_plane,
                identity_resolver=lambda _request: object(),
            )
        )

        with (
            self.assertRaisesRegex(
                RuntimeError,
                "partial start failed",
            ),
            TestClient(application),
        ):
            self.fail("startup failure must prevent request serving")

        self.assertEqual(control_plane.start_count, 1)
        self.assertEqual(control_plane.close_count, 1)


if __name__ == "__main__":
    unittest.main()
