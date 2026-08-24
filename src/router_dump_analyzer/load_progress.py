"""Thread-safe, path-free progress for opening and loading analysis inputs.

The tracker is owned by the core application.  Plug-ins may only report into
the operation that the core has bound around an existing execution boundary;
outside that boundary :func:`report_analysis_load` is deliberately a no-op.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from uuid import uuid4

from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .value_core import MAX_JSON_SAFE_INTEGER

_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class AnalysisLoadState(StrEnum):
    """Closed lifecycle exposed to the browser progress indicator."""

    WAITING = "waiting"
    RUNNING = "running"
    READY = "ready"
    FAILED = "failed"


class AnalysisLoadStage(StrEnum):
    """Generic core stages; plug-in-specific vocabulary never crosses the API."""

    STARTING = "starting"
    OPENING_RUNTIME = "opening_runtime"
    INVENTORYING = "inventorying"
    PROBING = "probing"
    LOCATING_INPUTS = "locating_inputs"
    PARSING = "parsing"
    NORMALIZING = "normalizing"
    LOADING_REVISION = "loading_revision"
    INDEXING = "indexing"


@dataclass(frozen=True, slots=True)
class AnalysisLoadSnapshot:
    """One immutable, JSON-safe observation of aggregate analysis loading."""

    state: AnalysisLoadState
    stage: AnalysisLoadStage | None
    operation_id: str | None
    sequence: int
    active_operations: int
    completed: int | None
    total: int | None
    records_processed: int
    started_at_ns: int | None
    updated_at_ns: int
    error_code: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "stage": self.stage.value if self.stage is not None else None,
            "operation_id": self.operation_id,
            "sequence": self.sequence,
            "active_operations": self.active_operations,
            "completed": self.completed,
            "total": self.total,
            "determinate": self.total is not None,
            "records_processed": self.records_processed,
            "started_at_ns": (
                str(self.started_at_ns) if self.started_at_ns is not None else None
            ),
            "updated_at_ns": str(self.updated_at_ns),
            "error_code": self.error_code,
        }


@dataclass(slots=True)
class _OperationState:
    operation_id: str
    order: int
    stage: AnalysisLoadStage
    completed: int | None
    total: int | None
    records_processed: int
    started_at_ns: int
    updated_at_ns: int


class AnalysisLoadOperation:
    """Opaque mutation capability returned only by the core-owned tracker."""

    __slots__ = ("_closed", "_operation_id", "_tracker")

    def __init__(self, tracker: AnalysisLoadTracker, operation_id: str) -> None:
        self._tracker = tracker
        self._operation_id = operation_id
        self._closed = False

    @property
    def operation_id(self) -> str:
        return self._operation_id

    def update(
        self,
        stage: AnalysisLoadStage,
        *,
        completed: int | None = None,
        total: int | None = None,
        records_processed: int | None = None,
    ) -> None:
        if self._closed:
            return
        self._tracker._update(
            self._operation_id,
            stage,
            completed=completed,
            total=total,
            records_processed=records_processed,
        )

    def complete(self) -> None:
        if self._closed:
            return
        self._tracker._finish(self._operation_id, error_code=None)
        self._closed = True

    def fail(self, error_code: str = "analysis_load_failed") -> None:
        if self._closed:
            return
        self._tracker._finish(self._operation_id, error_code=error_code)
        self._closed = True

    @contextmanager
    def bind(self) -> Iterator[AnalysisLoadOperation]:
        token = _active_operation.set(self)
        try:
            yield self
        finally:
            _active_operation.reset(token)


_active_operation: ContextVar[AnalysisLoadOperation | None] = ContextVar(
    "router_dump_analyzer_analysis_load_operation",
    default=None,
)


class AnalysisLoadTracker:
    """Aggregate concurrent load operations behind one bounded snapshot."""

    def __init__(self) -> None:
        now = time.time_ns()
        self._lock = RLock()
        self._operations: dict[str, _OperationState] = {}
        self._sequence = 0
        self._last_state = AnalysisLoadState.WAITING
        self._last_stage: AnalysisLoadStage | None = AnalysisLoadStage.STARTING
        self._last_operation_id: str | None = None
        self._last_started_at_ns: int | None = None
        self._last_updated_at_ns = now
        self._last_records_processed = 0
        self._last_error_code: str | None = None
        self._batch_failure: tuple[_OperationState, str] | None = None

    def begin(
        self,
        stage: AnalysisLoadStage,
        *,
        completed: int | None = None,
        total: int | None = None,
        records_processed: int = 0,
    ) -> AnalysisLoadOperation:
        selected_stage = _stage(stage)
        selected_completed, selected_total = _progress(completed, total)
        selected_records = _count(records_processed, "records_processed")
        now = time.time_ns()
        operation_id = uuid4().hex
        with self._lock:
            if not self._operations:
                # No operation overlaps this one, so it begins a new batch.
                # A failure retained from the preceding batch must not poison
                # this independent load attempt.
                self._batch_failure = None
            self._sequence = min(self._sequence + 1, MAX_JSON_SAFE_INTEGER)
            self._operations[operation_id] = _OperationState(
                operation_id=operation_id,
                order=self._sequence,
                stage=selected_stage,
                completed=selected_completed,
                total=selected_total,
                records_processed=selected_records,
                started_at_ns=now,
                updated_at_ns=now,
            )
            self._last_state = AnalysisLoadState.RUNNING
            self._last_stage = selected_stage
            self._last_operation_id = operation_id
            self._last_started_at_ns = now
            self._last_updated_at_ns = now
            self._last_records_processed = selected_records
            self._last_error_code = None
        return AnalysisLoadOperation(self, operation_id)

    def _update(
        self,
        operation_id: str,
        stage: AnalysisLoadStage,
        *,
        completed: int | None,
        total: int | None,
        records_processed: int | None,
    ) -> None:
        selected_stage = _stage(stage)
        selected_completed, selected_total = _progress(completed, total)
        now = time.time_ns()
        with self._lock:
            operation = self._operations.get(operation_id)
            if operation is None:
                return
            selected_records = (
                operation.records_processed
                if records_processed is None
                else _count(records_processed, "records_processed")
            )
            if selected_records < operation.records_processed:
                raise ValueError("records_processed must not decrease")
            operation.stage = selected_stage
            operation.completed = selected_completed
            operation.total = selected_total
            operation.records_processed = selected_records
            operation.updated_at_ns = now
            self._sequence = min(self._sequence + 1, MAX_JSON_SAFE_INTEGER)
            self._last_state = AnalysisLoadState.RUNNING
            self._last_stage = selected_stage
            self._last_operation_id = operation_id
            self._last_started_at_ns = operation.started_at_ns
            self._last_updated_at_ns = now
            self._last_records_processed = selected_records
            self._last_error_code = None

    def _finish(self, operation_id: str, *, error_code: str | None) -> None:
        if error_code is not None and _ERROR_CODE.fullmatch(error_code) is None:
            raise ValueError("error_code is invalid")
        now = time.time_ns()
        with self._lock:
            operation = self._operations.pop(operation_id, None)
            if operation is None:
                return
            self._sequence = min(self._sequence + 1, MAX_JSON_SAFE_INTEGER)
            if error_code is not None and self._batch_failure is None:
                self._batch_failure = (operation, error_code)
            if self._operations:
                self._last_state = AnalysisLoadState.RUNNING
                self._last_error_code = None
                return
            if self._batch_failure is not None:
                failed_operation, failed_error_code = self._batch_failure
                self._last_state = AnalysisLoadState.FAILED
                self._last_stage = failed_operation.stage
                self._last_operation_id = failed_operation.operation_id
                self._last_started_at_ns = failed_operation.started_at_ns
                self._last_records_processed = failed_operation.records_processed
                self._last_error_code = failed_error_code
            else:
                self._last_state = AnalysisLoadState.READY
                self._last_stage = operation.stage
                self._last_operation_id = operation_id
                self._last_started_at_ns = operation.started_at_ns
                self._last_records_processed = operation.records_processed
                self._last_error_code = None
            self._last_updated_at_ns = now

    def snapshot(self) -> AnalysisLoadSnapshot:
        with self._lock:
            active = min(
                self._operations.values(),
                key=lambda item: item.order,
                default=None,
            )
            if active is not None:
                return AnalysisLoadSnapshot(
                    state=AnalysisLoadState.RUNNING,
                    stage=active.stage,
                    operation_id=active.operation_id,
                    sequence=self._sequence,
                    active_operations=min(
                        len(self._operations),
                        MAX_JSON_SAFE_INTEGER,
                    ),
                    completed=active.completed,
                    total=active.total,
                    records_processed=active.records_processed,
                    started_at_ns=active.started_at_ns,
                    updated_at_ns=active.updated_at_ns,
                    error_code=None,
                )
            return AnalysisLoadSnapshot(
                state=self._last_state,
                stage=self._last_stage,
                operation_id=self._last_operation_id,
                sequence=self._sequence,
                active_operations=0,
                completed=None,
                total=None,
                records_processed=self._last_records_processed,
                started_at_ns=self._last_started_at_ns,
                updated_at_ns=self._last_updated_at_ns,
                error_code=self._last_error_code,
            )


def report_analysis_load(
    stage: AnalysisLoadStage,
    *,
    completed: int | None = None,
    total: int | None = None,
    records_processed: int | None = None,
) -> None:
    """Update the active core operation, or do nothing outside one."""

    operation = _active_operation.get()
    if operation is None:
        return
    try:
        operation.update(
            stage,
            completed=completed,
            total=total,
            records_processed=records_processed,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - optional telemetry is fail-open.
        # Reporting is advisory. A malformed or stale optional progress update
        # must never turn otherwise-valid plug-in parsing into an analysis
        # failure. Direct AnalysisLoadOperation.update() remains strict so the
        # core tracker and its tests still expose contract mistakes.
        return


def _stage(value: AnalysisLoadStage) -> AnalysisLoadStage:
    if type(value) is not AnalysisLoadStage:
        raise TypeError("stage must be an exact AnalysisLoadStage")
    return value


def _count(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_SAFE_INTEGER:
        raise ValueError(f"{name} must be a JSON-safe non-negative integer")
    return value


def _progress(
    completed: int | None,
    total: int | None,
) -> tuple[int | None, int | None]:
    if completed is not None:
        completed = _count(completed, "completed")
    if total is not None:
        total = _count(total, "total")
        if total < 1:
            raise ValueError("total must be positive")
        if completed is None:
            raise ValueError("completed is required when total is provided")
        if completed > total:
            raise ValueError("completed must not exceed total")
    elif completed is not None:
        raise ValueError("total is required when completed is provided")
    return completed, total


__all__ = [
    "AnalysisLoadOperation",
    "AnalysisLoadSnapshot",
    "AnalysisLoadStage",
    "AnalysisLoadState",
    "AnalysisLoadTracker",
    "report_analysis_load",
]
