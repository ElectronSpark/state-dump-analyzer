"""Derived query state belongs to the history generation, not its host service."""
from __future__ import annotations

from threading import RLock
from typing import Any, Callable
from weakref import ref

_LOCK = RLock()


class GenerationQueries:
    def __init__(self, source: Any) -> None:
        self._source: Callable[[], Any]
        try:
            self._source = ref(source)
        except TypeError:
            # Attribute-bearing providers without weak-reference support form a
            # collectible generation-local cycle, never a service-owned root.
            self._source = lambda: source

    def belongs_to(self, source: Any) -> bool:
        return self._source() is source


def generation_queries(source: Any) -> GenerationQueries:
    """Reuse only the exact generation; immutable adapters get request-local state."""
    with _LOCK:
        cached = getattr(source, "_revision_query_cache", None)
        if isinstance(cached, GenerationQueries) and cached.belongs_to(source):
            return cached
        cached = GenerationQueries(source)
        try:
            source._revision_query_cache = cached
        except (AttributeError, TypeError):
            pass
        return cached
