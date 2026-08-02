from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.operational_logging import OperationalEventHealthSnapshot
from router_dump_analyzer.web.control_plane_api import control_plane_router
from router_dump_analyzer.web.health import (
    analysis_service_health,
    durable_control_plane_health,
    ingestion_worker_health,
    operational_event_channel_health,
)
from router_dump_analyzer.web.service_api import service_router

PRIVATE_HEALTH_MARKER = "private-health-path-and-dump-content"


class _ExplodingLimits:
    @property
    def max_workers(self) -> int:
        raise RuntimeError(PRIVATE_HEALTH_MARKER)


class _ExplodingControlPlane:
    @property
    def ingestion(self) -> object:
        raise RuntimeError(PRIVATE_HEALTH_MARKER)


class _ExplodingItems:
    def items(self) -> object:
        raise RuntimeError(PRIVATE_HEALTH_MARKER)


def _snapshot(**changes: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "started": True,
        "live_workers": 2,
        "pending_imports": 3,
        "awaiting_selection_imports": 1,
        "stalled_imports": 0,
        "oldest_pending_updated_at_ns": 9_007_199_254_740_993,
        "stall_after_seconds": 900.0,
        "state_counts": (("queued", 3), ("awaiting_selection", 1)),
        "queue_observation_error": None,
        "unexpected_worker_exits": 0,
        "last_worker_exit_at_ns": None,
        "last_worker_exit": None,
        "total_claim_errors": 0,
        "consecutive_claim_errors": 0,
        "last_claim_error_at_ns": None,
        "last_claim_error": None,
        "total_iteration_errors": 0,
        "consecutive_iteration_errors": 0,
        "last_iteration_error_at_ns": None,
        "last_iteration_error": None,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class WebHealthProjectionTests(unittest.TestCase):
    def test_queue_counts_preserve_large_timestamps_and_healthy_state(self) -> None:
        ingestion = SimpleNamespace(
            limits=SimpleNamespace(max_workers=2, stalled_import_seconds=900.0),
            worker_health=lambda: _snapshot(),
        )
        projected = ingestion_worker_health(ingestion)
        self.assertTrue(projected["healthy"])
        self.assertEqual(projected["pending_imports"], 3)
        self.assertEqual(
            projected["oldest_pending_updated_at_ns"],
            "9007199254740993",
        )
        self.assertEqual(
            projected["state_counts"],
            {"awaiting_selection": 1, "queued": 3},
        )

    def test_stalled_queue_and_worker_exit_degrade_health(self) -> None:
        ingestion = SimpleNamespace(
            limits=SimpleNamespace(max_workers=2, stalled_import_seconds=900.0),
            worker_health=lambda: _snapshot(
                stalled_imports=2,
                unexpected_worker_exits=1,
                last_worker_exit_at_ns=12,
                last_worker_exit="SystemExit",
            ),
        )
        projected = ingestion_worker_health(ingestion)
        self.assertFalse(projected["healthy"])
        self.assertEqual(projected["stalled_imports"], 2)
        self.assertEqual(projected["last_worker_exit_at_ns"], "12")
        self.assertEqual(projected["last_worker_exit"], "SystemExit")

    def test_observation_failure_is_bounded_and_never_leaks_text(self) -> None:
        private = "private queue path and dump content"

        def fail() -> object:
            raise RuntimeError(private)

        ingestion = SimpleNamespace(
            limits=SimpleNamespace(max_workers=1),
            worker_health=fail,
        )
        projected = ingestion_worker_health(ingestion)
        self.assertFalse(projected["healthy"])
        self.assertEqual(projected["queue_observation_error"], "RuntimeError")
        self.assertNotIn(private, repr(projected))

    def test_control_plane_projection_is_session_independent(self) -> None:
        self.assertEqual(
            durable_control_plane_health(None),
            {
                "configured": False,
                "healthy": False,
                "observation_error": None,
                "ingestion_workers": None,
            },
        )
        control_plane = SimpleNamespace(
            ingestion=SimpleNamespace(
                limits=SimpleNamespace(
                    max_workers=2,
                    stalled_import_seconds=900.0,
                ),
                worker_health=lambda: _snapshot(),
            )
        )
        self.assertTrue(durable_control_plane_health(control_plane)["healthy"])

    def test_every_worker_acquisition_and_conversion_failure_is_total(self) -> None:
        cases = (
            SimpleNamespace(
                limits=_ExplodingLimits(),
                worker_health=lambda: _snapshot(),
            ),
            SimpleNamespace(
                limits=SimpleNamespace(max_workers=2, stalled_import_seconds=1.0),
                worker_health=lambda: _snapshot(live_workers=object()),
            ),
            SimpleNamespace(
                limits=SimpleNamespace(max_workers=2, stalled_import_seconds=1.0),
                worker_health=lambda: _snapshot(state_counts=_ExplodingItems()),
            ),
        )
        expected_keys = set(ingestion_worker_health(cases[0]))
        for ingestion in cases:
            with self.subTest(ingestion=type(ingestion.limits).__name__):
                projected = ingestion_worker_health(ingestion)
                self.assertEqual(set(projected), expected_keys)
                self.assertFalse(projected["healthy"])
                self.assertIsNotNone(projected["queue_observation_error"])
                self.assertNotIn(PRIVATE_HEALTH_MARKER, repr(projected))

    def test_control_plane_and_analysis_projection_fail_closed(self) -> None:
        control_plane = durable_control_plane_health(_ExplodingControlPlane())
        self.assertTrue(control_plane["configured"])
        self.assertFalse(control_plane["healthy"])
        self.assertEqual(control_plane["observation_error"], "RuntimeError")
        self.assertNotIn(PRIVATE_HEALTH_MARKER, repr(control_plane))

        def fail_analysis() -> object:
            raise RuntimeError(PRIVATE_HEALTH_MARKER)

        analysis = analysis_service_health(fail_analysis)
        self.assertFalse(analysis["analysis_ready"])
        self.assertEqual(analysis["analysis_observation_error"], "RuntimeError")
        self.assertNotIn(PRIVATE_HEALTH_MARKER, repr(analysis))

        malformed = analysis_service_health(
            lambda: {
                "analysis_ready": True,
                "revision_id": "revision-1",
                "event_count": float("nan"),
            }
        )
        self.assertFalse(malformed["analysis_ready"])
        self.assertEqual(
            malformed["analysis_observation_error"],
            "HealthProjectionError",
        )

    def test_operational_event_loss_is_bounded_and_degrades_health(self) -> None:
        snapshot = OperationalEventHealthSnapshot(
            accepted_events=9,
            dropped_events=3,
            delivery_failures=2,
            queue_depth=1,
            queue_capacity=16,
            worker_alive=True,
        )
        with patch(
            "router_dump_analyzer.web.health.operational_event_health_snapshot",
            return_value=snapshot,
        ):
            projected = operational_event_channel_health()

        self.assertEqual(
            projected,
            {
                "healthy": False,
                "observation_error": None,
                "accepted_events": 9,
                "dropped_events": 3,
                "delivery_failures": 2,
                "queue_depth": 1,
                "queue_capacity": 16,
                "worker_alive": True,
            },
        )

    def test_operational_event_observation_is_total_and_redacted(self) -> None:
        with patch(
            "router_dump_analyzer.web.health.operational_event_health_snapshot",
            side_effect=RuntimeError(PRIVATE_HEALTH_MARKER),
        ):
            projected = operational_event_channel_health()

        self.assertFalse(projected["healthy"])
        self.assertEqual(projected["observation_error"], "RuntimeError")
        self.assertEqual(projected["dropped_events"], 0)
        self.assertEqual(projected["delivery_failures"], 0)
        self.assertNotIn(PRIVATE_HEALTH_MARKER, repr(projected))

    def test_operational_loss_is_visible_on_both_unauthenticated_health_routes(
        self,
    ) -> None:
        application = FastAPI()
        application.include_router(service_router)
        application.include_router(control_plane_router)
        application.state.control_plane = SimpleNamespace(
            ingestion=SimpleNamespace(
                limits=SimpleNamespace(
                    max_workers=2,
                    stalled_import_seconds=900.0,
                ),
                worker_health=lambda: _snapshot(),
            )
        )
        snapshot = OperationalEventHealthSnapshot(
            accepted_events=10,
            dropped_events=1,
            delivery_failures=0,
            queue_depth=0,
            queue_capacity=16,
            worker_alive=True,
        )
        with (
            patch(
                "router_dump_analyzer.web.health.operational_event_health_snapshot",
                return_value=snapshot,
            ),
            TestClient(application) as client,
        ):
            root = client.get("/health")
            durable = client.get("/v1/control-plane/health")

        for response in (root, durable):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], "degraded")
            operational = (
                response.json()["control_plane"]["operational_events"]
                if response is root
                else response.json()["operational_events"]
            )
            self.assertEqual(operational["dropped_events"], 1)
            self.assertEqual(operational["delivery_failures"], 0)
            self.assertEqual(
                set(operational),
                {
                    "healthy",
                    "observation_error",
                    "accepted_events",
                    "dropped_events",
                    "delivery_failures",
                    "queue_depth",
                    "queue_capacity",
                    "worker_alive",
                },
            )

    def test_both_http_health_routes_remain_200_under_hostile_providers(self) -> None:
        application = FastAPI()
        application.include_router(service_router)
        application.include_router(control_plane_router)
        application.state.control_plane = _ExplodingControlPlane()

        def fail_analysis() -> object:
            raise RuntimeError(PRIVATE_HEALTH_MARKER)

        application.state.analysis_health_projector = fail_analysis
        with TestClient(application, raise_server_exceptions=False) as client:
            root = client.get("/health")
            durable = client.get("/v1/control-plane/health")

        for response in (root, durable):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.json()["status"], "degraded")
            self.assertNotIn(PRIVATE_HEALTH_MARKER, response.text)


if __name__ == "__main__":
    unittest.main()
