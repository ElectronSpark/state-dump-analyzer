from _typeshed import Incomplete
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

@dataclass(frozen=True)
class DensitySummary:
    count: int
    failure_count: int
    type_counts: Mapping[str, int]

class DensityIndex:
    event_times: Incomplete
    failure_event_times: Incomplete
    event_times_by_type: Incomplete
    max_cache_units: Incomplete
    def __init__(self, event_times: Sequence[int], failure_event_times: Sequence[int], event_times_by_type: Mapping[str, Sequence[int]], *, max_cache_units: int = 32768) -> None: ...
    @property
    def cache_units(self) -> int: ...
    @property
    def stats(self) -> Counter[str]: ...
    @property
    def cache_entries(self) -> int: ...
    def page(self, *, start_ns: int, integer_span: int, bin_count: int, bin_start_index: int, bin_end_index: int, checkpoint: Callable[[], None] | None = None) -> dict[int, DensitySummary]: ...

def adaptive_type_counts(event_times_by_type: Mapping[str, Sequence[int]], *, start_ns: int, integer_span: int, bin_count: int, bin_start_index: int, bin_end_index: int, checkpoint: Callable[[], None] | None = None, operation_counts: Counter[str] | None = None) -> dict[int, Counter[str]]: ...
