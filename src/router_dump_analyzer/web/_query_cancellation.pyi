from contextlib import AbstractAsyncContextManager
from router_dump_analyzer.cancellation import current_query_cancellation_probe as current_query_cancellation_probe
from starlette.requests import Request

__all__ = ['current_query_cancellation_probe', 'query_cancellation_scope']

def query_cancellation_scope(request: Request) -> AbstractAsyncContextManager[None]: ...
