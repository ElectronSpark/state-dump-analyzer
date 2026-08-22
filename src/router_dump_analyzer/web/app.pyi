from .frontend_host import FrontendHost
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from fastapi import APIRouter, FastAPI
from typing import Any

__all__ = ['create_web_app']

Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[Any]]

def create_web_app(*, api_router: APIRouter, lifespan: Lifespan | None = None, title: str = 'Router Dump Analyzer API', version: str = '0.1.0', description: str = 'Generic temporal router-state query API supplied by installed runtime and plug-in providers.', host: FrontendHost, mount_frontend: bool = True, expose_api_docs: bool = False) -> FastAPI: ...
