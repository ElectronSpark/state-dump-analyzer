from collections.abc import Callable
from dataclasses import dataclass
from fastapi import APIRouter, HTTPException as FastAPIHTTPException, Request
from fastapi.routing import APIRoute
from typing import Any

__all__ = ['api_router', 'analysis_health_projection', 'reset_runtime_api_caches', 'start_runtime_warmup']

class _RuntimeHTTPResponse(FastAPIHTTPException):
    def __init__(self, status_code: int, detail: Any = None, headers: dict[str, str] | None = None) -> None: ...

@dataclass(frozen=True, slots=True)
class _RuntimeApiErrorPolicy:
    status_code: int
    public_detail: str
    expose_message: bool = ...

class _BoundedRuntimeApiRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Any]: ...

api_router: APIRouter

def analysis_health_projection() -> dict[str, Any]: ...
def reset_runtime_api_caches() -> None: ...
def start_runtime_warmup() -> None: ...
