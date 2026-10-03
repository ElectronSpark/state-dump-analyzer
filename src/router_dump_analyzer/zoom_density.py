"""Exact bounded density summaries over immutable sorted timestamp indexes.

An instance belongs to one immutable history/revision. Aligned dyadic cells
reuse work across pans and zoom levels; all type counts are retained so merged
top types remain exact. Cache limits count entries plus their type counters.
"""
from __future__ import annotations

from bisect import bisect_left
from collections import Counter, OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from threading import Lock
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class DensitySummary:
    count: int
    failure_count: int
    type_counts: Mapping[str, int]


class DensityIndex:
    def __init__(self, event_times: Sequence[int], failure_event_times: Sequence[int],
                 event_times_by_type: Mapping[str, Sequence[int]], *,
                 max_cache_units: int = 32768) -> None:
        self.event_times: Sequence[int] = event_times
        self.failure_event_times: Sequence[int] = failure_event_times
        self.event_times_by_type: Mapping[str, Sequence[int]] = event_times_by_type
        self.max_cache_units: int = max(0, max_cache_units)
        self._cache: OrderedDict[tuple[int, int], DensitySummary] = OrderedDict()
        self._cache_units = 0
        self._stats: Counter[str] = Counter()
        self._lock = Lock()

    @property
    def cache_units(self) -> int:
        with self._lock:
            return self._cache_units

    @property
    def stats(self) -> Counter[str]:
        with self._lock:
            return self._stats.copy()

    @property
    def cache_entries(self) -> int:
        with self._lock:
            return len(self._cache)

    def page(self, *, start_ns: int, integer_span: int, bin_count: int,
             bin_start_index: int, bin_end_index: int,
             checkpoint: Callable[[], None] | None = None) -> dict[int, DensitySummary]:
        check = checkpoint or (lambda: None)
        check()
        pending: OrderedDict[tuple[int, int], DensitySummary] = OrderedDict()
        pending_units = 0
        stats: Counter[str] = Counter()
        touched: dict[tuple[int, int], None] = {}

        def cached_cell(key: tuple[int, int]) -> DensitySummary | None:
            cached = pending.get(key)
            if cached is None:
                with self._lock:
                    cached = self._cache.get(key)
                if cached is not None:
                    touched[key] = None
            return cached

        def count(times: Sequence[int], lo: int, hi: int) -> int:
            stats['bisections'] += 2
            return bisect_left(times, hi) - bisect_left(times, lo)

        def exact(lo: int, hi: int) -> DensitySummary:
            types = dict(adaptive_type_counts(
                self.event_times_by_type, start_ns=lo, integer_span=hi - lo,
                bin_count=1, bin_start_index=0, bin_end_index=1,
                checkpoint=check, operation_counts=stats).get(0, {}))
            return DensitySummary(count(self.event_times, lo, hi),
                                  count(self.failure_event_times, lo, hi), MappingProxyType(types))

        def stage(key: tuple[int, int], summary: DensitySummary) -> None:
            nonlocal pending_units
            units = 1 + len(summary.type_counts)
            if units <= self.max_cache_units:
                while pending and pending_units + units > self.max_cache_units:
                    _, old = pending.popitem(last=False)
                    pending_units -= 1 + len(old.type_counts)
                pending[key] = summary
                pending_units += units

        def cell(lo: int, width: int) -> DensitySummary:
            key = (lo, width)
            cached = cached_cell(key)
            if cached is not None:
                stats['cache_hits'] += 1
                return cached
            check()
            half = width // 2
            children = []
            if width > 1 and width & (width - 1) == 0:
                children = [cached_cell((position, half))
                            for position in (lo, lo + half)]
            if children and all(child is not None for child in children):
                present_children = [child for child in children if child is not None]
                merged: Counter[str] = Counter()
                for child in present_children:
                    merged.update(child.type_counts)
                summary = DensitySummary(sum(child.count for child in present_children),
                                         sum(child.failure_count for child in present_children),
                                         MappingProxyType(dict(merged)))
                stats['cells_merged'] += 1
            else:
                summary = exact(lo, lo + width)
            stats['cells_built'] += 1
            stage(key, summary)
            return summary

        # Many short type lists make per-cell dictionary scans expensive. Sweep
        # the requested page once, then retain exact bin summaries in the same
        # bounded cache. Dense low-cardinality pages keep dyadic reuse below.
        sparse_page = (len(self.event_times_by_type) > 32 and
                       len(self.event_times) <= 64 * len(self.event_times_by_type))
        sparse_cached: dict[int, DensitySummary] = {}
        sparse_types: dict[int, Counter[str]] = {}
        if sparse_page:
            missing = False
            for index in range(bin_start_index, bin_end_index):
                check()
                lo = start_ns + integer_span * index // bin_count
                hi = start_ns + integer_span * (index + 1) // bin_count
                if hi <= lo:
                    continue
                cached = cached_cell((lo, hi - lo))
                if cached is None:
                    missing = True
                else:
                    sparse_cached[index] = cached
                    stats['cache_hits'] += 1
            if missing:
                sparse_types = adaptive_type_counts(
                    self.event_times_by_type, start_ns=start_ns,
                    integer_span=integer_span, bin_count=bin_count,
                    bin_start_index=bin_start_index, bin_end_index=bin_end_index,
                    checkpoint=check, operation_counts=stats)

        result = {}
        for index in range(bin_start_index, bin_end_index):
            check()
            lo = start_ns + integer_span * index // bin_count
            hi = start_ns + integer_span * (index + 1) // bin_count
            if hi <= lo:
                continue
            if sparse_page:
                summary = sparse_cached.get(index)
                if summary is None:
                    summary = DensitySummary(
                        count(self.event_times, lo, hi),
                        count(self.failure_event_times, lo, hi),
                        MappingProxyType(dict(sparse_types.get(index, {}))))
                    stage((lo, hi - lo), summary)
                    stats['cells_built'] += 1
                if summary.count:
                    result[index] = summary
                continue
            width = 1 << ((hi - lo).bit_length() - 1)
            # At most two unaligned edges and one or two reusable cells.
            aligned_lo = -(-lo // width) * width
            aligned_hi = hi // width * width
            parts = []
            if aligned_lo >= aligned_hi:
                # Exact unaligned ranges still reuse a summary when requested again.
                parts.append(cell(lo, hi - lo))
            else:
                if lo < aligned_lo:
                    parts.append(cell(lo, aligned_lo - lo))
                for position in range(aligned_lo, aligned_hi, width):
                    parts.append(cell(position, width))
                if aligned_hi < hi:
                    parts.append(cell(aligned_hi, hi - aligned_hi))
            types: Counter[str] = Counter()
            for part in parts:
                types.update(part.type_counts)
            total = sum(part.count for part in parts)
            if total:
                result[index] = DensitySummary(total, sum(p.failure_count for p in parts), MappingProxyType(dict(types)))
        # Publish only after the whole request completed, including cancellation.
        check()
        with self._lock:
            for key in touched:
                if key in self._cache:
                    self._cache.move_to_end(key)
            for key, summary in pending.items():
                if key in self._cache:
                    self._cache.move_to_end(key)
                    continue
                units = 1 + len(summary.type_counts)
                while self._cache and self._cache_units + units > self.max_cache_units:
                    _, old = self._cache.popitem(last=False)
                    self._cache_units -= 1 + len(old.type_counts)
                self._cache[key] = summary
                self._cache_units += units
            self._stats.update(stats)
        return result


def adaptive_type_counts(event_times_by_type: Mapping[str, Sequence[int]], *,
                         start_ns: int, integer_span: int, bin_count: int,
                         bin_start_index: int, bin_end_index: int,
                         checkpoint: Callable[[], None] | None = None,
                         operation_counts: Counter[str] | None = None) -> dict[int, Counter[str]]:
    """Choose a sparse sweep or dense per-bin bisection independently per type."""
    check = checkpoint or (lambda: None)
    counts: dict[int, Counter[str]] = {}
    page_lo = start_ns + integer_span * bin_start_index // bin_count
    page_hi = start_ns + integer_span * bin_end_index // bin_count
    for name, times in event_times_by_type.items():
        check()
        left, right = bisect_left(times, page_lo), bisect_left(times, page_hi)
        if operation_counts is not None:
            operation_counts['bisections'] += 2
        bins = bin_end_index - bin_start_index
        if right - left <= bins * max(1, len(times).bit_length()):
            for position in range(left, right):
                if (position - left) % 256 == 0:
                    check()
                index = min(bin_count - 1, ((times[position] - start_ns + 1) * bin_count - 1) // integer_span)
                if operation_counts is not None:
                    operation_counts['swept_points'] += 1
                counts.setdefault(index, Counter())[str(name)] += 1
        else:
            for index in range(bin_start_index, bin_end_index):
                check()
                lo = start_ns + integer_span * index // bin_count
                hi = start_ns + integer_span * (index + 1) // bin_count
                amount = bisect_left(times, hi, left, right) - bisect_left(times, lo, left, right)
                if operation_counts is not None:
                    operation_counts['bisections'] += 2
                if amount:
                    counts.setdefault(index, Counter())[str(name)] += amount
    return counts
