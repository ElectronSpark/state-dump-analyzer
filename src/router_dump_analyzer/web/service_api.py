"""Analysis-independent service routes shared by every deployment mode."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request, Response

from .health import (
    analysis_service_health,
    durable_control_plane_health,
    operational_event_channel_health,
)

service_router: APIRouter = APIRouter()


class _FailedControlPlaneObservation:
    def __init__(self, error: Exception) -> None:
        self._error = error

    @property
    def ingestion(self) -> Any:
        raise self._error


def control_plane_service_health(application_state: Any) -> dict[str, Any]:
    try:
        control_plane = getattr(application_state, "control_plane", None)
    except Exception as error:  # noqa: BLE001 - health is deliberately total.
        control_plane = _FailedControlPlaneObservation(error)
    status = durable_control_plane_health(control_plane)
    operational_events = operational_event_channel_health()
    return {
        **status,
        "healthy": bool(status["healthy"]) and operational_events["healthy"],
        "operational_events": operational_events,
    }


def _analysis_health(application_state: Any) -> dict[str, Any]:
    try:
        projector = getattr(application_state, "analysis_health_projector", None)
    except Exception as error:  # noqa: BLE001 - health is deliberately total.

        def failed_projector(observation_error: Exception = error) -> Any:
            raise observation_error

        projector = failed_projector
    return analysis_service_health(projector)


def service_health_payload(application_state: Any) -> dict[str, Any]:
    """Build one total root-health response from bounded projections."""

    try:
        control_plane_status = control_plane_service_health(application_state)
        analysis_status = _analysis_health(application_state)
        analysis_ready = bool(analysis_status["analysis_ready"])
        control_plane_configured = bool(control_plane_status["configured"])
        control_plane_healthy = bool(control_plane_status["healthy"])
        operational_status = control_plane_status["operational_events"]
        operational_healthy = bool(operational_status["healthy"])
        observation_failed = (
            analysis_status["analysis_observation_error"] is not None
            or control_plane_status["observation_error"] is not None
            or operational_status["observation_error"] is not None
        )
        available = analysis_ready or control_plane_healthy
        healthy = (
            available
            and not observation_failed
            and (not control_plane_configured or control_plane_healthy)
            and operational_healthy
        )
        if not analysis_ready:
            analysis_status["mode"] = (
                "control-plane" if control_plane_configured else "unavailable"
            )
        payload: dict[str, Any] = {
            "status": "ok" if healthy else "degraded",
            **analysis_status,
            "control_plane": control_plane_status,
        }
        ingestion_workers = control_plane_status["ingestion_workers"]
        if ingestion_workers is not None:
            payload["ingestion_workers"] = ingestion_workers
        return payload
    except Exception:  # noqa: BLE001 - last-resort stable health envelope.
        # The component projectors are already total. This final literal keeps
        # the route available even if a future refactor breaks their contract.
        return {
            "status": "degraded",
            "analysis_ready": False,
            "analysis_observation_error": "HealthProjectionError",
            "revision_id": None,
            "mode": "unavailable",
            "event_count": 0,
            "matched_event_count": 0,
            "resource_count": 0,
            "source_record_count": 0,
            "history_search_ready": False,
            "history_search_document_count": 0,
            "history_search_storage": "unavailable",
            "history_search_backend": "unavailable",
            "control_plane": {
                "configured": False,
                "healthy": False,
                "observation_error": "HealthProjectionError",
                "ingestion_workers": None,
                "operational_events": {
                    "healthy": False,
                    "observation_error": "HealthProjectionError",
                    "accepted_events": 0,
                    "dropped_events": 0,
                    "delivery_failures": 0,
                    "queue_depth": 0,
                    "queue_capacity": 0,
                    "worker_alive": False,
                },
            },
        }


@service_router.get("/health")
def service_health(request: Request, response: Response) -> dict[str, Any]:
    """Return HTTP 200 with a stable degraded body on observation failure."""

    response.headers["Cache-Control"] = "no-store"
    return service_health_payload(request.app.state)


__all__ = [
    "control_plane_service_health",
    "service_health",
    "service_health_payload",
    "service_router",
]
