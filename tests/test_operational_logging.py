from __future__ import annotations

import io
import logging
import queue
import threading
import time
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from router_dump_analyzer.operational_logging import (
    MAX_OPERATIONAL_COUNTER,
    MAX_OPERATIONAL_FIELD_TEXT,
    OPERATIONAL_EVENT_CONTRACT,
    OPERATIONAL_LOG_SCHEMA,
    OPERATIONAL_LOGGER_NAME,
    OperationalEventEmitter,
    operational_event_diagnostics_snapshot,
)

_BOOLEAN_FIELDS = frozenset(
    {
        "ambiguous_external_outcome",
        "concealed",
        "idempotent",
        "mutating",
        "mutation_started",
        "policy_enabled",
        "remote_acknowledged",
        "resumed",
        "retryable",
        "truncated",
    }
)
_INTEGER_FIELDS = frozenset(
    {
        "attempt",
        "attempted_items",
        "batch_index",
        "checkpointed_items",
        "completed_items",
        "consecutive",
        "content_blobs",
        "deleted_bytes",
        "deleted_files",
        "deleted_imports",
        "deleted_items",
        "deletion_failures",
        "duration_ms",
        "enqueue_failures_since_last",
        "eligible_imports",
        "event_count",
        "failed_items",
        "limit",
        "max_delete_batch",
        "max_scan_entries",
        "observed_at_least",
        "pending_items",
        "remaining_items",
        "response_status",
        "resource_count",
        "revision_datasets",
        "skipped_items",
        "source_record_count",
        "occurrences",
        "stale_partials",
        "suppressed_since_last",
        "timeout_ms",
        "total_items",
        "unexpected_worker_exits",
        "work_items",
    }
)


def _field_value(name: str) -> bool | int | str:
    if name == "phase":
        return "identity_binding"
    if name == "reason":
        return "tenant_binding_mismatch"
    if name == "response_status":
        return 403
    if name == "sampling_scope":
        return "exact"
    if name in _BOOLEAN_FIELDS:
        return True
    if name in _INTEGER_FIELDS:
        return 1
    return f"safe_{name}"


class _CapturingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[int, str, dict[str, object]]] = []
        self.called = threading.Event()

    def log(self, level: int, message: str, *, extra: dict[str, object]) -> None:
        self.records.append((level, message, extra))
        self.called.set()


class _BlockingLogger:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def log(self, level: int, message: str, *, extra: dict[str, object]) -> None:
        del level, message, extra
        self.calls += 1
        self.entered.set()
        if not self.release.wait(timeout=5.0):
            raise TimeoutError("test logger was not released")


class _ThrowingLogger:
    def log(self, level: int, message: str, *, extra: dict[str, object]) -> None:
        del level, message, extra
        raise RuntimeError("private C:\\tenant\\dump.sqlite3")


class _InterruptingLogger:
    def __init__(self) -> None:
        self.calls = 0
        self.delivered = threading.Event()

    def log(self, level: int, message: str, *, extra: dict[str, object]) -> None:
        del level, message, extra
        self.calls += 1
        if self.calls == 1:
            raise KeyboardInterrupt()
        self.delivered.set()


class _AcceptanceObservingLogger:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.emitter: OperationalEventEmitter | None = None
        self.accepted_when_delivery_started: list[int] = []

    def log(self, level: int, message: str, *, extra: dict[str, object]) -> None:
        del level, message, extra
        self.entered.set()
        assert self.emitter is not None
        snapshot = self.emitter.event_class_health_snapshot(
            "control_plane.access.denied"
        )
        self.accepted_when_delivery_started.append(snapshot.accepted_events)
        raise RuntimeError("controlled delivery failure")


class _DeliveryCoordinatingQueue(queue.Queue):
    def __init__(self, entered: threading.Event) -> None:
        super().__init__(maxsize=4)
        self._delivery_entered = entered

    def put_nowait(self, item: object) -> None:
        super().put_nowait(item)
        if not self._delivery_entered.wait(timeout=2.0):
            raise TimeoutError("operational worker did not start delivery")


class _ExplosiveValue:
    def __init__(self) -> None:
        self.str_calls = 0
        self.repr_calls = 0

    def __str__(self) -> str:
        self.str_calls += 1
        raise AssertionError("operational validation stringified a caller value")

    def __repr__(self) -> str:
        self.repr_calls += 1
        raise AssertionError("operational validation repr'd a caller value")


class OperationalLoggingTests(unittest.TestCase):
    def test_default_logger_suppresses_last_resort_but_preserves_propagation(
        self,
    ) -> None:
        root_logger = logging.getLogger()
        prior_handlers = tuple(root_logger.handlers)
        prior_level = root_logger.level
        records: list[logging.LogRecord] = []

        class _RecordHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        try:
            for handler in prior_handlers:
                root_logger.removeHandler(handler)
            unconfigured = OperationalEventEmitter()
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertTrue(
                    unconfigured.emit(
                        "ingestion.worker.exited",
                        error_family="exception",
                        unexpected_worker_exits=1,
                    )
                )
                self.assertTrue(unconfigured.flush(timeout=2.0))
            self.assertEqual(stderr.getvalue(), "")

            handler = _RecordHandler()
            root_logger.addHandler(handler)
            root_logger.setLevel(logging.DEBUG)
            configured = OperationalEventEmitter()
            self.assertTrue(
                configured.emit(
                    "ingestion.worker.exited",
                    error_family="exception",
                    unexpected_worker_exits=2,
                )
            )
            self.assertTrue(configured.flush(timeout=2.0))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].name, OPERATIONAL_LOGGER_NAME)
            self.assertEqual(records[0].rda_event, "ingestion.worker.exited")
        finally:
            for handler in tuple(root_logger.handlers):
                root_logger.removeHandler(handler)
            for handler in prior_handlers:
                root_logger.addHandler(handler)
            root_logger.setLevel(prior_level)

    def test_every_declared_event_uses_its_closed_schema_and_level(self) -> None:
        logger = _CapturingLogger()
        emitter = OperationalEventEmitter(logger=logger)

        for event, spec in OPERATIONAL_EVENT_CONTRACT.items():
            fields = {name: _field_value(name) for name in spec.required}
            with self.subTest(event=event):
                self.assertTrue(emitter.emit(event, **fields))

        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertEqual(len(logger.records), len(OPERATIONAL_EVENT_CONTRACT))
        records_by_event = {
            message: (level, extra) for level, message, extra in logger.records
        }
        self.assertEqual(set(records_by_event), set(OPERATIONAL_EVENT_CONTRACT))
        for event, spec in OPERATIONAL_EVENT_CONTRACT.items():
            with self.subTest(delivered_event=event):
                level, extra = records_by_event[event]
                self.assertEqual(level, spec.level)
                self.assertEqual(
                    extra,
                    {
                        "rda_schema": OPERATIONAL_LOG_SCHEMA,
                        "rda_event": event,
                        "rda_fields": {
                            name: _field_value(name) for name in spec.required
                        },
                    },
                )
        self.assertEqual(emitter.dropped_events, 0)
        self.assertEqual(emitter.delivery_failures, 0)
        snapshot = emitter.health_snapshot()
        self.assertEqual(snapshot.accepted_events, len(OPERATIONAL_EVENT_CONTRACT))
        self.assertEqual(snapshot.dropped_events, 0)
        self.assertEqual(snapshot.delivery_failures, 0)
        self.assertEqual(snapshot.queue_depth, 0)
        self.assertGreaterEqual(snapshot.queue_capacity, 1)
        self.assertTrue(snapshot.worker_alive)

    def test_contract_is_immutable_and_unknown_missing_or_extra_fields_fail_closed(
        self,
    ) -> None:
        with self.assertRaises(TypeError):
            OPERATIONAL_EVENT_CONTRACT["undeclared"] = object()  # type: ignore[index]

        logger = _CapturingLogger()
        emitter = OperationalEventEmitter(logger=logger)
        valid = {
            "import_id": "import_1",
            "stage": "admission",
            "operation_id": "operation_1",
            "attempt": 1,
            "timeout_ms": 100,
        }
        invalid_payloads: tuple[tuple[str, dict[str, object]], ...] = (
            ("undeclared.event", {}),
            (
                "ingestion.catalog_call.started",
                {key: value for key, value in valid.items() if key != "stage"},
            ),
            (
                "ingestion.catalog_call.started",
                {**valid, "undeclared_field": "value"},
            ),
        )
        for event, fields in invalid_payloads:
            with self.subTest(event=event, fields=tuple(fields)):
                self.assertFalse(emitter.emit(event, **fields))

        self.assertTrue(emitter.flush(timeout=0.1))
        self.assertEqual(logger.records, [])
        self.assertEqual(emitter.dropped_events, len(invalid_payloads))

    def test_access_denial_closed_vocabulary_is_enforced_at_emit_boundary(
        self,
    ) -> None:
        logger = _CapturingLogger()
        emitter = OperationalEventEmitter(logger=logger)
        valid: dict[str, object] = {
            "phase": "identity_binding",
            "reason": "tenant_binding_mismatch",
            "response_status": 403,
            "request_method": "GET",
            "route_name": "list_projects",
            "mutating": False,
            "concealed": False,
            "occurrences": 1,
            "suppressed_since_last": 0,
            "enqueue_failures_since_last": 0,
            "sampling_scope": "exact",
            "required_role": "control-plane:read",
            "tenant_correlation": "a5" * 16,
        }
        invalid_overrides: tuple[tuple[str, object], ...] = (
            ("phase", "plug_in_phase"),
            ("reason", "host_rejected"),
            ("sampling_scope", "unbounded"),
            ("response_status", 500),
            ("required_role", "plug-in:admin"),
            ("tenant_correlation", "A5" * 16),
            ("tenant_correlation", "a5" * 15),
        )
        for field, value in invalid_overrides:
            with self.subTest(field=field, value=value):
                self.assertFalse(
                    emitter.emit(
                        "control_plane.access.denied",
                        **{**valid, field: value},
                    )
                )

        self.assertTrue(emitter.emit("control_plane.access.denied", **valid))
        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertEqual(len(logger.records), 1)
        self.assertEqual(emitter.dropped_events, len(invalid_overrides))

    def test_field_types_text_safety_integer_bounds_and_event_size_are_bounded(
        self,
    ) -> None:
        logger = _CapturingLogger()
        emitter = OperationalEventEmitter(logger=logger)
        valid = {
            "import_id": "import_1",
            "stage": "admission",
            "operation_id": "operation_1",
            "attempt": 1,
            "timeout_ms": 100,
        }
        invalid_overrides: tuple[tuple[str, object], ...] = (
            ("attempt", -1),
            ("attempt", 2**63),
            ("attempt", 1.5),
            ("attempt", [1]),
            ("stage", ""),
            ("stage", "x" * (MAX_OPERATIONAL_FIELD_TEXT + 1)),
            ("stage", "unsafe\u202evalue"),
            ("stage", r"C:\private\tenant\dump.sqlite3"),
            ("stage", "/srv/private/tenant/dump.sqlite3"),
        )
        for key, value in invalid_overrides:
            with self.subTest(key=key, value_type=type(value).__name__):
                self.assertFalse(
                    emitter.emit(
                        "ingestion.catalog_call.started",
                        **{**valid, key: value},
                    )
                )

        # Each value is within the character limit, but JSON's ASCII escaping
        # makes the complete record exceed the independent 4 KiB event budget.
        oversized = "\u00e9" * MAX_OPERATIONAL_FIELD_TEXT
        self.assertFalse(
            emitter.emit(
                "retention.run.failed",
                run_id=oversized,
                phase=oversized,
                error_family=oversized,
                mutation_started=False,
            )
        )
        self.assertTrue(emitter.flush(timeout=0.1))
        self.assertEqual(logger.records, [])
        self.assertEqual(emitter.dropped_events, len(invalid_overrides) + 1)

    def test_invalid_caller_values_are_never_stringified_or_reprd(self) -> None:
        explosive = _ExplosiveValue()
        emitter = OperationalEventEmitter(logger=_CapturingLogger())

        self.assertFalse(
            emitter.emit(
                "ingestion.catalog_call.started",
                import_id="import_1",
                stage=explosive,
                operation_id="operation_1",
                attempt=1,
                timeout_ms=100,
            )
        )
        self.assertEqual(explosive.str_calls, 0)
        self.assertEqual(explosive.repr_calls, 0)
        self.assertEqual(emitter.dropped_events, 1)

    def test_full_queue_drops_immediately_and_flush_is_bounded(self) -> None:
        logger = _BlockingLogger()
        emitter = OperationalEventEmitter(logger=logger, max_queue_size=1)
        fields = {
            "error_family": "exception",
            "unexpected_worker_exits": 1,
        }

        try:
            self.assertTrue(emitter.emit("ingestion.worker.exited", **fields))
            self.assertTrue(logger.entered.wait(timeout=1.0))
            self.assertTrue(emitter.emit("ingestion.worker.exited", **fields))
            started = time.monotonic()
            self.assertFalse(emitter.emit("ingestion.worker.exited", **fields))
            self.assertLess(time.monotonic() - started, 0.25)
            self.assertFalse(emitter.flush(timeout=0.01))
            self.assertEqual(emitter.dropped_events, 1)
            event_health = emitter.event_class_health_snapshot(
                "ingestion.worker.exited"
            )
            self.assertEqual(event_health.accepted_events, 2)
            self.assertEqual(event_health.queue_full_drops, 1)
            self.assertEqual(event_health.rejected_events, 0)
            self.assertEqual(event_health.delivery_failures, 0)
        finally:
            logger.release.set()

        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertEqual(logger.calls, 2)
        self.assertEqual(emitter.delivery_failures, 0)

    def test_per_event_counters_separate_validation_and_queue_capacity_loss(
        self,
    ) -> None:
        logger = _BlockingLogger()
        emitter = OperationalEventEmitter(logger=logger, max_queue_size=1)
        event = "control_plane.access.denied"
        valid = {
            "phase": "identity_binding",
            "reason": "tenant_binding_mismatch",
            "response_status": 403,
            "request_method": "GET",
            "route_name": "list_projects",
            "mutating": False,
            "concealed": False,
            "occurrences": 1,
            "suppressed_since_last": 0,
            "enqueue_failures_since_last": 0,
            "sampling_scope": "exact",
        }
        try:
            self.assertFalse(emitter.emit(event, **{**valid, "extra": "no"}))
            rejected = emitter.event_class_health_snapshot(event)
            self.assertEqual(rejected.rejected_events, 1)
            self.assertEqual(rejected.queue_full_drops, 0)
            self.assertEqual(rejected.delivery_failures, 0)

            self.assertTrue(emitter.emit(event, **valid))
            self.assertTrue(logger.entered.wait(timeout=1.0))
            self.assertTrue(emitter.emit(event, **valid))
            self.assertFalse(emitter.emit(event, **valid))
            saturated = emitter.event_class_health_snapshot(event)
            self.assertEqual(saturated.accepted_events, 2)
            self.assertEqual(saturated.rejected_events, 1)
            self.assertEqual(saturated.queue_full_drops, 1)
            self.assertEqual(saturated.delivery_failures, 0)
            self.assertEqual(emitter.dropped_events, 2)
        finally:
            logger.release.set()
        self.assertTrue(emitter.flush(timeout=2.0))

        with self.assertRaisesRegex(ValueError, "not declared"):
            emitter.event_class_health_snapshot("undeclared.event")

    def test_acceptance_is_committed_before_delivery_failure_is_observable(
        self,
    ) -> None:
        logger = _AcceptanceObservingLogger()
        emitter = OperationalEventEmitter(logger=logger, max_queue_size=4)
        logger.emitter = emitter
        emitter._queue = _DeliveryCoordinatingQueue(logger.entered)
        event = "control_plane.access.denied"
        valid = {
            "phase": "identity_binding",
            "reason": "tenant_binding_mismatch",
            "response_status": 403,
            "request_method": "GET",
            "route_name": "list_projects",
            "mutating": False,
            "concealed": False,
            "occurrences": 1,
            "suppressed_since_last": 0,
            "enqueue_failures_since_last": 0,
            "sampling_scope": "exact",
        }
        self.assertTrue(emitter.emit(event, **valid))
        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertEqual(logger.accepted_when_delivery_started, [1])
        snapshot = emitter.event_class_health_snapshot(event)
        self.assertEqual(snapshot.accepted_events, 1)
        self.assertEqual(snapshot.delivery_failures, 1)

    def test_throwing_logger_is_isolated_and_counted_as_delivery_failure(self) -> None:
        emitter = OperationalEventEmitter(logger=_ThrowingLogger())
        self.assertTrue(
            emitter.emit(
                "ingestion.worker.exited",
                error_family="exception",
                unexpected_worker_exits=1,
            )
        )
        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertEqual(emitter.dropped_events, 0)
        self.assertEqual(emitter.delivery_failures, 1)
        snapshot = emitter.health_snapshot()
        self.assertEqual(snapshot.accepted_events, 1)
        self.assertEqual(snapshot.delivery_failures, 1)
        event_snapshot = emitter.event_class_health_snapshot("ingestion.worker.exited")
        self.assertEqual(event_snapshot.accepted_events, 1)
        self.assertEqual(event_snapshot.delivery_failures, 1)
        self.assertEqual(
            emitter.diagnostics_snapshot()
            .event_classes["ingestion.worker.exited"]
            .delivery_failures,
            1,
        )

    def test_diagnostics_snapshot_is_complete_immutable_and_payload_free(self) -> None:
        emitter = OperationalEventEmitter(logger=_CapturingLogger())
        private_correlation = "a5" * 16
        self.assertTrue(
            emitter.emit(
                "control_plane.access.denied",
                phase="identity_binding",
                reason="tenant_binding_mismatch",
                response_status=403,
                request_method="GET",
                route_name="list_projects",
                mutating=False,
                concealed=False,
                occurrences=1,
                suppressed_since_last=0,
                enqueue_failures_since_last=0,
                sampling_scope="exact",
                tenant_correlation=private_correlation,
            )
        )
        self.assertTrue(emitter.flush(timeout=2.0))

        snapshot = emitter.diagnostics_snapshot()
        self.assertEqual(
            set(snapshot.event_classes),
            set(OPERATIONAL_EVENT_CONTRACT),
        )
        self.assertEqual(
            snapshot.event_classes["control_plane.access.denied"].accepted_events,
            1,
        )
        for event, counters in snapshot.event_classes.items():
            with self.subTest(event=event):
                self.assertGreaterEqual(counters.accepted_events, 0)
                self.assertGreaterEqual(counters.queue_full_drops, 0)
                self.assertGreaterEqual(counters.rejected_events, 0)
                self.assertGreaterEqual(counters.delivery_failures, 0)
        self.assertNotIn(private_correlation, repr(snapshot))
        with self.assertRaises(TypeError):
            snapshot.event_classes["undeclared.event"] = snapshot.event_classes[
                "control_plane.access.denied"
            ]  # type: ignore[index]

        process_snapshot = operational_event_diagnostics_snapshot()
        self.assertEqual(
            set(process_snapshot.event_classes),
            set(OPERATIONAL_EVENT_CONTRACT),
        )

    def test_per_event_diagnostic_counters_saturate_at_the_shared_bound(self) -> None:
        event = "ingestion.worker.exited"
        fields = {
            "error_family": "exception",
            "unexpected_worker_exits": 1,
        }
        emitter = OperationalEventEmitter(logger=_CapturingLogger())
        with emitter._lock:
            emitter._accepted_events = MAX_OPERATIONAL_COUNTER
            emitter._dropped_events = MAX_OPERATIONAL_COUNTER
            emitter._accepted_by_event[event] = MAX_OPERATIONAL_COUNTER
            emitter._queue_full_drops_by_event[event] = MAX_OPERATIONAL_COUNTER
            emitter._rejected_by_event[event] = MAX_OPERATIONAL_COUNTER
        self.assertTrue(emitter.emit(event, **fields))
        self.assertFalse(emitter.emit(event, **{**fields, "extra": "invalid"}))
        emitter._record_drop(event, queue_full=True)
        self.assertTrue(emitter.flush(timeout=2.0))
        counters = emitter.diagnostics_snapshot().event_classes[event]
        self.assertEqual(counters.accepted_events, MAX_OPERATIONAL_COUNTER)
        self.assertEqual(counters.queue_full_drops, MAX_OPERATIONAL_COUNTER)
        self.assertEqual(counters.rejected_events, MAX_OPERATIONAL_COUNTER)

        failing = OperationalEventEmitter(logger=_ThrowingLogger())
        with failing._lock:
            failing._delivery_failures = MAX_OPERATIONAL_COUNTER
            failing._delivery_failures_by_event[event] = MAX_OPERATIONAL_COUNTER
        self.assertTrue(failing.emit(event, **fields))
        self.assertTrue(failing.flush(timeout=2.0))
        self.assertEqual(
            failing.diagnostics_snapshot().event_classes[event].delivery_failures,
            MAX_OPERATIONAL_COUNTER,
        )

    def test_diagnostics_snapshot_is_atomic_while_counters_change(self) -> None:
        emitter = OperationalEventEmitter(logger=_CapturingLogger())
        event = "ingestion.worker.exited"
        mutation_entered = threading.Event()
        release_mutation = threading.Event()
        snapshot_started = threading.Event()
        snapshot_completed = threading.Event()
        snapshots = []

        def mutate_under_one_lock() -> None:
            with emitter._lock:
                emitter._accepted_by_event[event] = 1
                mutation_entered.set()
                if not release_mutation.wait(timeout=2.0):
                    raise TimeoutError(
                        "diagnostic snapshot test did not release mutation"
                    )
                emitter._delivery_failures_by_event[event] = 1

        def capture_snapshot() -> None:
            snapshot_started.set()
            snapshots.append(emitter.diagnostics_snapshot())
            snapshot_completed.set()

        mutation_thread = threading.Thread(target=mutate_under_one_lock)
        snapshot_thread = threading.Thread(target=capture_snapshot)
        mutation_thread.start()
        self.assertTrue(mutation_entered.wait(timeout=1.0))
        snapshot_thread.start()
        self.assertTrue(snapshot_started.wait(timeout=1.0))
        self.assertFalse(snapshot_completed.wait(timeout=0.05))
        release_mutation.set()
        mutation_thread.join(timeout=2.0)
        snapshot_thread.join(timeout=2.0)
        self.assertFalse(mutation_thread.is_alive())
        self.assertFalse(snapshot_thread.is_alive())
        self.assertTrue(snapshot_completed.is_set())
        counters = snapshots[0].event_classes[event]
        self.assertEqual(counters.accepted_events, 1)
        self.assertEqual(counters.delivery_failures, 1)

    def test_emit_never_swallows_process_control_base_exceptions(self) -> None:
        emitter = OperationalEventEmitter(logger=_CapturingLogger())
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch(
                    "router_dump_analyzer.operational_logging._validated_fields",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)),
            ):
                emitter.emit("ingestion.worker.exited")
        self.assertEqual(emitter.dropped_events, 0)
        self.assertEqual(emitter.accepted_events, 0)

    def test_worker_isolates_handler_base_exception_and_keeps_draining(self) -> None:
        logger = _InterruptingLogger()
        emitter = OperationalEventEmitter(logger=logger)
        fields = {
            "error_family": "exception",
            "unexpected_worker_exits": 1,
        }
        self.assertTrue(emitter.emit("ingestion.worker.exited", **fields))
        self.assertTrue(emitter.emit("ingestion.worker.exited", **fields))
        self.assertTrue(emitter.flush(timeout=2.0))
        self.assertTrue(logger.delivered.is_set())
        self.assertEqual(logger.calls, 2)
        self.assertEqual(emitter.delivery_failures, 1)

    def test_flush_rejects_invalid_timeouts(self) -> None:
        emitter = OperationalEventEmitter(logger=_CapturingLogger())
        for timeout in (True, -0.1, 60.1, "1"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                emitter.flush(timeout=timeout)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
