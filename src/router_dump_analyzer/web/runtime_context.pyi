from contextlib import contextmanager
from router_dump_analyzer.runtime import CoreRuntimeSession
from typing import Iterator

__all__ = ['current_runtime_session', 'activate_runtime_session']

def current_runtime_session() -> CoreRuntimeSession: ...
@contextmanager
def activate_runtime_session(session: CoreRuntimeSession) -> Iterator[None]: ...
