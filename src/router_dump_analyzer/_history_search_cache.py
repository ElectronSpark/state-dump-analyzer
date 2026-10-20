"""Process-local bounded postings reuse; no runtime or trust decisions retained."""

import sys
from collections import OrderedDict
from threading import RLock

from .history_search_matches import MatchSet


class _SearchResultCache:
    def __init__(
        self, max_entries: int = 128, max_bytes: int = 16 * 1024 * 1024
    ) -> None:
        if max_entries <= 0 or max_bytes <= 0:
            raise ValueError("shared search cache bounds must be positive")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._entries: OrderedDict[tuple[str, str], tuple[MatchSet, int]] = OrderedDict()
        self._bytes = 0
        self._lock = RLock()

    def get(self, corpus: str, needle: str) -> MatchSet | None:
        if type(corpus) is not str or type(needle) is not str:
            return None
        key = (corpus, needle)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry[0]

    def put(self, corpus: str, needle: str, matches: MatchSet) -> None:
        # Subclasses may override conversion, hashing or equality and retain
        # runtime owners. Keep sharing restricted to exact built-in strings.
        if type(corpus) is not str or type(needle) is not str:
            return
        key = (corpus, needle)
        # Include key objects and a conservative allowance for LRU bookkeeping.
        size = (matches.nbytes + sys.getsizeof(corpus) + sys.getsizeof(needle)
                + sys.getsizeof(key) + 256)
        if size > self._max_bytes:
            return
        with self._lock:
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._bytes -= previous[1]
            self._entries[key] = matches, size
            self._bytes += size
            while (len(self._entries) > self._max_entries
                   or self._bytes > self._max_bytes):
                _, (_, evicted_bytes) = self._entries.popitem(last=False)
                self._bytes -= evicted_bytes


_shared_results = _SearchResultCache()
