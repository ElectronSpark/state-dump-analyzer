"""Request-local access to the core-owned runtime session.

The plug-in opens a non-web session.  The core lifespan enters it and the
core middleware makes that session available to generic HTTP handlers for the
duration of each request.  This keeps runtime state out of module globals and
allows more than one application instance to coexist in tests.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from router_dump_analyzer.runtime import CoreRuntimeSession


_active_runtime_session: ContextVar[CoreRuntimeSession | None] = ContextVar(
    "router_dump_analyzer_active_runtime_session",
    default=None,
)


def current_runtime_session() -> CoreRuntimeSession:
    """Return the request's opened runtime session or fail closed."""

    session = _active_runtime_session.get()
    if session is None:
        raise RuntimeError("no analyzer runtime session is active")
    return session


@contextmanager
def activate_runtime_session(
    session: CoreRuntimeSession,
) -> Iterator[None]:
    """Bind one opened session to the current request/task context."""

    token = _active_runtime_session.set(session)
    try:
        yield
    finally:
        _active_runtime_session.reset(token)


__all__ = [
    "activate_runtime_session",
    "current_runtime_session",
]
