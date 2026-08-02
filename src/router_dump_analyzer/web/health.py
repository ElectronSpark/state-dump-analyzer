"""Total, bounded health projections for durable analyzer services."""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from typing import Any

from router_dump_analyzer.operational_logging import (
    operational_event_health_snapshot,
)
from router_dump_analyzer.public_text import contains_unsafe_invisible_text

MAX_HEALTH_COUNT = 2**63 - 1
MAX_HEALTH_STATE_COUNTS = 128
MAX_HEALTH_TEXT_CHARACTERS = 256
MAX_HEALTH_REVISION_IDS = 10_000
_ERROR_LABEL = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")


class HealthProjectionError(ValueError):
    """Internal marker for malformed health-provider values."""


def _exception_label(error: BaseException) -> str:
    """Return a bounded ASCII class label without inspecting exception text."""

    try:
        name = type(error).__name__
    except BaseException:  # noqa: BLE001  # pragma: no cover - hostile metaclass.
        return "Exception"
    return (
        name if isinstance(name, str) and _ERROR_LABEL.fullmatch(name) else "Exception"
    )


def _integer(value: Any, name: str, *, maximum: int = MAX_HEALTH_COUNT) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise HealthProjectionError(f"{name} is invalid")
    return value


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise HealthProjectionError(f"{name} is invalid")
    return value


def _finite_non_negative(value: Any, name: str) -> float:
    if type(value) not in {int, float}:
        raise HealthProjectionError(f"{name} is invalid")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= float(MAX_HEALTH_COUNT):
        raise HealthProjectionError(f"{name} is invalid")
    return result


def _optional_decimal(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return str(_integer(value, name))


def _bounded_text(
    value: Any,
    name: str,
    *,
    maximum: int = MAX_HEALTH_TEXT_CHARACTERS,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or contains_unsafe_invisible_text(value)
    ):
        raise HealthProjectionError(f"{name} is invalid")
    return value


def _optional_error_label(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _ERROR_LABEL.fullmatch(value) is None:
        raise HealthProjectionError(f"{name} is invalid")
    return value


def _worker_fallback(
    *,
    observation_error: str,
    configured_workers: int = 0,
    stall_after_seconds: float = 0.0,
) -> dict[str, Any]:
    return {
        "healthy": False,
        "started": False,
        "configured_workers": configured_workers,
        "live_workers": 0,
        "pending_imports": 0,
        "awaiting_selection_imports": 0,
        "stalled_imports": 0,
        "oldest_pending_updated_at_ns": None,
        "stall_after_seconds": stall_after_seconds,
        "queue_evaluated_at_ns": None,
        "queue_observation_error": observation_error,
        "state_counts": {},
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
        "catalog_attention_imports": 0,
    }


def _operational_event_fallback(observation_error: str) -> dict[str, Any]:
    return {
        "healthy": False,
        "observation_error": observation_error,
        "accepted_events": 0,
        "dropped_events": 0,
        "delivery_failures": 0,
        "queue_depth": 0,
        "queue_capacity": 0,
        "worker_alive": False,
    }


def operational_event_channel_health() -> dict[str, Any]:
    """Project aggregate telemetry loss without exposing event payloads."""

    try:
        snapshot = operational_event_health_snapshot()
        accepted_events = _integer(
            snapshot.accepted_events,
            "accepted_events",
        )
        dropped_events = _integer(snapshot.dropped_events, "dropped_events")
        delivery_failures = _integer(
            snapshot.delivery_failures,
            "delivery_failures",
        )
        queue_capacity = _integer(snapshot.queue_capacity, "queue_capacity")
        if queue_capacity < 1:
            raise HealthProjectionError("queue_capacity is invalid")
        queue_depth = _integer(
            snapshot.queue_depth,
            "queue_depth",
            maximum=queue_capacity,
        )
        worker_alive = _boolean(snapshot.worker_alive, "worker_alive")
    except Exception as error:  # noqa: BLE001 - health is deliberately total.
        return _operational_event_fallback(_exception_label(error))
    return {
        "healthy": dropped_events == 0 and delivery_failures == 0,
        "observation_error": None,
        "accepted_events": accepted_events,
        "dropped_events": dropped_events,
        "delivery_failures": delivery_failures,
        "queue_depth": queue_depth,
        "queue_capacity": queue_capacity,
        "worker_alive": worker_alive,
    }


def _state_counts(value: Any) -> dict[str, int]:
    items_method = getattr(value, "items", None)
    pairs = items_method() if callable(items_method) else value
    iterator = iter(pairs)
    result: dict[str, int] = {}
    for index, pair in enumerate(iterator):
        if index >= MAX_HEALTH_STATE_COUNTS:
            raise HealthProjectionError("state_counts is too large")
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise HealthProjectionError("state_counts contains an invalid item")
        key = _bounded_text(pair[0], "state_counts key", maximum=64)
        if key in result:
            raise HealthProjectionError("state_counts contains a duplicate key")
        result[key] = _integer(pair[1], "state_counts value")
    return {key: result[key] for key in sorted(result)}


def ingestion_worker_health(ingestion: Any) -> dict[str, Any]:
    """Project worker/queue health as a total, JSON-safe operation.

    Any provider acquisition, property, conversion, or iteration failure
    produces the same stable degraded shape. Only the bounded exception-class
    label is exposed; exception messages and provider values never cross this
    boundary on failure.
    """

    configured_workers = 0
    stall_after_seconds = 0.0
    try:
        limits = ingestion.limits
        configured_workers = _integer(
            limits.max_workers,
            "configured_workers",
            maximum=1_000_000,
        )
        stall_after_seconds = _finite_non_negative(
            getattr(limits, "stalled_import_seconds", 0.0),
            "stall_after_seconds",
        )
        snapshot = ingestion.worker_health()
        started = _boolean(snapshot.started, "started")
        live_workers = _integer(
            snapshot.live_workers,
            "live_workers",
            maximum=1_000_000,
        )
        pending_imports = _integer(
            getattr(snapshot, "pending_imports", 0),
            "pending_imports",
        )
        awaiting_selection_imports = _integer(
            getattr(snapshot, "awaiting_selection_imports", 0),
            "awaiting_selection_imports",
        )
        stalled_imports = _integer(
            getattr(snapshot, "stalled_imports", 0),
            "stalled_imports",
        )
        oldest_pending_updated_at_ns = _optional_decimal(
            getattr(snapshot, "oldest_pending_updated_at_ns", None),
            "oldest_pending_updated_at_ns",
        )
        snapshot_stall_after_seconds = _finite_non_negative(
            getattr(snapshot, "stall_after_seconds", stall_after_seconds),
            "stall_after_seconds",
        )
        queue_evaluated_at_ns = _optional_decimal(
            getattr(snapshot, "queue_evaluated_at_ns", None),
            "queue_evaluated_at_ns",
        )
        queue_observation_error = _optional_error_label(
            getattr(snapshot, "queue_observation_error", None),
            "queue_observation_error",
        )
        state_counts = _state_counts(getattr(snapshot, "state_counts", ()))
        unexpected_worker_exits = _integer(
            getattr(snapshot, "unexpected_worker_exits", 0),
            "unexpected_worker_exits",
        )
        last_worker_exit_at_ns = _optional_decimal(
            getattr(snapshot, "last_worker_exit_at_ns", None),
            "last_worker_exit_at_ns",
        )
        last_worker_exit = _optional_error_label(
            getattr(snapshot, "last_worker_exit", None),
            "last_worker_exit",
        )
        total_claim_errors = _integer(
            snapshot.total_claim_errors,
            "total_claim_errors",
        )
        consecutive_claim_errors = _integer(
            snapshot.consecutive_claim_errors,
            "consecutive_claim_errors",
        )
        last_claim_error_at_ns = _optional_decimal(
            snapshot.last_claim_error_at_ns,
            "last_claim_error_at_ns",
        )
        last_claim_error = _optional_error_label(
            snapshot.last_claim_error,
            "last_claim_error",
        )
        total_iteration_errors = _integer(
            snapshot.total_iteration_errors,
            "total_iteration_errors",
        )
        consecutive_iteration_errors = _integer(
            snapshot.consecutive_iteration_errors,
            "consecutive_iteration_errors",
        )
        last_iteration_error_at_ns = _optional_decimal(
            snapshot.last_iteration_error_at_ns,
            "last_iteration_error_at_ns",
        )
        last_iteration_error = _optional_error_label(
            snapshot.last_iteration_error,
            "last_iteration_error",
        )
        catalog_attention_imports = _integer(
            getattr(snapshot, "catalog_attention_imports", 0),
            "catalog_attention_imports",
        )
    except Exception as error:  # noqa: BLE001 - health is deliberately total.
        return _worker_fallback(
            observation_error=_exception_label(error),
            configured_workers=configured_workers,
            stall_after_seconds=stall_after_seconds,
        )

    healthy = (
        started
        and live_workers == configured_workers
        and consecutive_claim_errors == 0
        and consecutive_iteration_errors == 0
        and unexpected_worker_exits == 0
        and queue_observation_error is None
        and stalled_imports == 0
        and catalog_attention_imports == 0
    )
    return {
        "healthy": healthy,
        "started": started,
        "configured_workers": configured_workers,
        "live_workers": live_workers,
        "pending_imports": pending_imports,
        "awaiting_selection_imports": awaiting_selection_imports,
        "stalled_imports": stalled_imports,
        "oldest_pending_updated_at_ns": oldest_pending_updated_at_ns,
        "stall_after_seconds": snapshot_stall_after_seconds,
        "queue_evaluated_at_ns": queue_evaluated_at_ns,
        "queue_observation_error": queue_observation_error,
        "state_counts": state_counts,
        "unexpected_worker_exits": unexpected_worker_exits,
        "last_worker_exit_at_ns": last_worker_exit_at_ns,
        "last_worker_exit": last_worker_exit,
        "total_claim_errors": total_claim_errors,
        "consecutive_claim_errors": consecutive_claim_errors,
        "last_claim_error_at_ns": last_claim_error_at_ns,
        "last_claim_error": last_claim_error,
        "total_iteration_errors": total_iteration_errors,
        "consecutive_iteration_errors": consecutive_iteration_errors,
        "last_iteration_error_at_ns": last_iteration_error_at_ns,
        "last_iteration_error": last_iteration_error,
        "catalog_attention_imports": catalog_attention_imports,
    }


def durable_control_plane_health(control_plane: Any | None) -> dict[str, Any]:
    """Return a total projection independent of an opened analysis input."""

    if control_plane is None:
        return {
            "configured": False,
            "healthy": False,
            "observation_error": None,
            "ingestion_workers": None,
        }
    try:
        ingestion = control_plane.ingestion
        if ingestion is None:
            raise HealthProjectionError("control plane has no ingestion service")
        workers = ingestion_worker_health(ingestion)
        return {
            "configured": True,
            "healthy": bool(workers["healthy"]),
            "observation_error": None,
            "ingestion_workers": workers,
        }
    except Exception as error:  # noqa: BLE001 - health is deliberately total.
        return {
            "configured": True,
            "healthy": False,
            "observation_error": _exception_label(error),
            "ingestion_workers": None,
        }


def empty_analysis_health() -> dict[str, Any]:
    """Return the stable shape for a deployment with no analysis session."""

    return {
        "analysis_ready": False,
        "analysis_observation_error": None,
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
    }


def _analysis_health(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HealthProjectionError("analysis health must be an object")
    ready = _boolean(value.get("analysis_ready", True), "analysis_ready")
    result = empty_analysis_health()
    result.update(
        {
            "analysis_ready": ready,
            "revision_id": (
                _bounded_text(value.get("revision_id"), "revision_id", maximum=512)
                if ready
                else None
            ),
            "mode": _bounded_text(value.get("mode", "analysis"), "mode"),
            "event_count": _integer(value.get("event_count", 0), "event_count"),
            "matched_event_count": _integer(
                value.get("matched_event_count", value.get("event_count", 0)),
                "matched_event_count",
            ),
            "resource_count": _integer(
                value.get("resource_count", 0),
                "resource_count",
            ),
            "source_record_count": _integer(
                value.get("source_record_count", 0),
                "source_record_count",
            ),
            "history_search_ready": _boolean(
                value.get("history_search_ready", False),
                "history_search_ready",
            ),
            "history_search_document_count": _integer(
                value.get("history_search_document_count", 0),
                "history_search_document_count",
            ),
            "history_search_storage": _bounded_text(
                value.get("history_search_storage", "unavailable"),
                "history_search_storage",
            ),
            "history_search_backend": _bounded_text(
                value.get("history_search_backend", "unavailable"),
                "history_search_backend",
            ),
        }
    )
    assembly = value.get("assembly")
    if assembly is not None:
        if not isinstance(assembly, Mapping):
            raise HealthProjectionError("assembly is invalid")
        raw_revision_ids = assembly.get("loaded_revision_ids", ())
        if (
            not isinstance(raw_revision_ids, (tuple, list))
            or len(raw_revision_ids) > MAX_HEALTH_REVISION_IDS
        ):
            raise HealthProjectionError("loaded_revision_ids is invalid")
        revision_ids = [
            _bounded_text(item, "loaded_revision_id", maximum=512)
            for item in raw_revision_ids
        ]
        result["assembly"] = {
            "assembly_id": _bounded_text(
                assembly.get("assembly_id"),
                "assembly_id",
                maximum=512,
            ),
            "node_count": _integer(assembly.get("node_count", 0), "node_count"),
            "coverage_case_count": _integer(
                assembly.get("coverage_case_count", 0),
                "coverage_case_count",
            ),
            "events_per_node_min": _integer(
                assembly.get("events_per_node_min", 0),
                "events_per_node_min",
            ),
            "resources_per_node_min": _integer(
                assembly.get("resources_per_node_min", 0),
                "resources_per_node_min",
            ),
            "resources_per_node_max": _integer(
                assembly.get("resources_per_node_max", 0),
                "resources_per_node_max",
            ),
            "loaded_revision_ids": revision_ids,
        }
    return result


def analysis_service_health(
    projector: Callable[[], Any] | None,
) -> dict[str, Any]:
    """Execute and validate one optional analysis-health projector."""

    if projector is None:
        return empty_analysis_health()
    try:
        if not callable(projector):
            raise HealthProjectionError("analysis projector is not callable")
        return _analysis_health(projector())
    except Exception as error:  # noqa: BLE001 - health is deliberately total.
        result = empty_analysis_health()
        result["analysis_observation_error"] = _exception_label(error)
        return result


__all__ = [
    "HealthProjectionError",
    "analysis_service_health",
    "durable_control_plane_health",
    "empty_analysis_health",
    "ingestion_worker_health",
    "operational_event_channel_health",
]
