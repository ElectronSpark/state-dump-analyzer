from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum

__all__ = ['AnalysisLoadState', 'AnalysisLoadStage', 'AnalysisLoadSnapshot', 'AnalysisLoadOperation', 'AnalysisLoadTracker', 'report_analysis_load']

class AnalysisLoadState(StrEnum):
    WAITING = 'waiting'
    RUNNING = 'running'
    READY = 'ready'
    FAILED = 'failed'

class AnalysisLoadStage(StrEnum):
    STARTING = 'starting'
    OPENING_RUNTIME = 'opening_runtime'
    INVENTORYING = 'inventorying'
    PROBING = 'probing'
    LOCATING_INPUTS = 'locating_inputs'
    PARSING = 'parsing'
    NORMALIZING = 'normalizing'
    LOADING_REVISION = 'loading_revision'
    INDEXING = 'indexing'
    READING_ARCHIVE = 'reading_archive'
    VALIDATING_PROVIDERS = 'validating_providers'
    RECONSTRUCTING_TOPOLOGY = 'reconstructing_topology'
    QUERYING_ROUTE_TABLES = 'querying_route_tables'
    TRACING_ROUTES = 'tracing_routes'

@dataclass(frozen=True, slots=True)
class AnalysisLoadSnapshot:
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
    def as_dict(self) -> dict[str, object]: ...

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
    def __init__(self, tracker: AnalysisLoadTracker, operation_id: str) -> None: ...
    @property
    def operation_id(self) -> str: ...
    def update(self, stage: AnalysisLoadStage, *, completed: int | None = None, total: int | None = None, records_processed: int | None = None) -> None: ...
    def complete(self) -> None: ...
    def fail(self, error_code: str = 'analysis_load_failed') -> None: ...
    @contextmanager
    def bind(self) -> Iterator[AnalysisLoadOperation]: ...

class AnalysisLoadTracker:
    def __init__(self) -> None: ...
    def begin(self, stage: AnalysisLoadStage, *, completed: int | None = None, total: int | None = None, records_processed: int = 0) -> AnalysisLoadOperation: ...
    def snapshot(self) -> AnalysisLoadSnapshot: ...

def report_analysis_load(stage: AnalysisLoadStage, *, completed: int | None = None, total: int | None = None, records_processed: int | None = None) -> None: ...
