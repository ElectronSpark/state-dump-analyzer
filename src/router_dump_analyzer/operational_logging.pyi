import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

__all__ = ['OPERATIONAL_LOG_SCHEMA', 'OPERATIONAL_LOGGER_NAME', 'MAX_OPERATIONAL_EVENT_BYTES', 'MAX_OPERATIONAL_COUNTER', 'RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT', 'OperationalEventHealthSnapshot', 'OperationalEventClassHealthSnapshot', 'OperationalEventDiagnosticsSnapshot', 'OPERATIONAL_EVENT_CONTRACT', 'OperationalEventEmitter', 'emit_operational_event', 'emit_resolver_response_headers_rejected', 'flush_operational_events', 'operational_event_health_snapshot', 'operational_event_class_health_snapshot', 'operational_event_diagnostics_snapshot']

OPERATIONAL_LOG_SCHEMA: Final[str]
OPERATIONAL_LOGGER_NAME: Final[str]
MAX_OPERATIONAL_EVENT_BYTES: Final[int]
MAX_OPERATIONAL_COUNTER: Final[int]
RESOLVER_RESPONSE_HEADERS_REJECTED_EVENT: Final[str]

@dataclass(frozen=True, slots=True)
class _EventSpec:
    level: int
    required: frozenset[str]
    optional: frozenset[str] = ...

@dataclass(frozen=True, slots=True)
class OperationalEventHealthSnapshot:
    accepted_events: int
    dropped_events: int
    delivery_failures: int
    queue_depth: int
    queue_capacity: int
    worker_alive: bool

@dataclass(frozen=True, slots=True)
class OperationalEventClassHealthSnapshot:
    accepted_events: int
    queue_full_drops: int
    rejected_events: int
    delivery_failures: int

@dataclass(frozen=True, slots=True)
class OperationalEventDiagnosticsSnapshot:
    channel: OperationalEventHealthSnapshot
    event_classes: Mapping[str, OperationalEventClassHealthSnapshot]

OPERATIONAL_EVENT_CONTRACT: Mapping[str, _EventSpec]

class OperationalEventEmitter:
    def __init__(self, *, logger: logging.Logger | None = None, max_queue_size: int = ...) -> None: ...
    @property
    def accepted_events(self) -> int: ...
    @property
    def dropped_events(self) -> int: ...
    @property
    def delivery_failures(self) -> int: ...
    def event_class_health_snapshot(self, event: str) -> OperationalEventClassHealthSnapshot: ...
    def diagnostics_snapshot(self) -> OperationalEventDiagnosticsSnapshot: ...
    def health_snapshot(self) -> OperationalEventHealthSnapshot: ...
    def emit(self, event: str, /, **fields: Any) -> bool: ...
    def flush(self, *, timeout: float = 1.0) -> bool: ...

def emit_operational_event(event: str, /, **fields: Any) -> bool: ...
def emit_resolver_response_headers_rejected() -> bool: ...
def flush_operational_events(*, timeout: float = 1.0) -> bool: ...
def operational_event_health_snapshot() -> OperationalEventHealthSnapshot: ...
def operational_event_class_health_snapshot(event: str) -> OperationalEventClassHealthSnapshot: ...
def operational_event_diagnostics_snapshot() -> OperationalEventDiagnosticsSnapshot: ...
