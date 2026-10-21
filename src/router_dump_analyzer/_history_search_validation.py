"""Bounded process-local facts about completely validated compressed bytes.

Keys are freshly computed content fingerprints, never file stamps or unchecked
metadata digests. Values contain no serving objects or executable trust state.
"""

import sys
from collections import OrderedDict
from threading import RLock


class _ValidationCache:
    def __init__(self, max_entries: int = 128, max_bytes: int = 256 * 1024) -> None:
        if max_entries <= 0 or max_bytes <= 0:
            raise ValueError("validation cache bounds must be positive")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._entries: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._bytes = 0
        self._lock = RLock()

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._entries)

    def get(self, fingerprint: str) -> int | None:
        if type(fingerprint) is not str:
            return None
        with self._lock:
            entry = self._entries.get(fingerprint)
            if entry is None:
                return None
            self._entries.move_to_end(fingerprint)
            return entry[0]

    def put(self, fingerprint: str, maximum_document_bytes: int) -> None:
        if type(fingerprint) is not str or type(maximum_document_bytes) is not int:
            return
        if maximum_document_bytes < 0:
            return
        size = sys.getsizeof(fingerprint) + sys.getsizeof(maximum_document_bytes) + 256
        if size > self._max_bytes:
            return
        with self._lock:
            previous = self._entries.pop(fingerprint, None)
            if previous is not None:
                self._bytes -= previous[1]
            self._entries[fingerprint] = maximum_document_bytes, size
            self._bytes += size
            while len(self._entries) > self._max_entries or self._bytes > self._max_bytes:
                _, (_, evicted_bytes) = self._entries.popitem(last=False)
                self._bytes -= evicted_bytes


_validated_compressed = _ValidationCache()
