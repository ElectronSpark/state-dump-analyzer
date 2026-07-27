"""Generic FastAPI shell for the core-owned web client.

The core contributes the API router, application construction, compression,
cache behavior, and browser bundle.  A loaded plug-in supplies data and
declarative policy through the runtime contracts; it never supplies routes or
an application.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from starlette.middleware.gzip import GZipMiddleware

from .frontend_host import FrontendHost


Lifespan = Callable[[FastAPI], AbstractAsyncContextManager[Any]]


def create_web_app(
    *,
    api_router: APIRouter,
    lifespan: Lifespan | None = None,
    title: str = "Router Dump Analyzer API",
    version: str = "0.1.0",
    description: str = (
        "Generic temporal router-state query API supplied by installed "
        "runtime and plug-in providers."
    ),
    host: FrontendHost,
) -> FastAPI:
    """Build a web application without importing a concrete plug-in/runtime."""

    application = FastAPI(
        title=title,
        version=version,
        description=description,
        lifespan=lifespan,
    )
    application.add_middleware(
        GZipMiddleware,
        minimum_size=1024,
        compresslevel=5,
    )

    @application.middleware("http")
    async def disable_core_asset_cache(request: Request, call_next):
        response = await call_next(request)
        if host.owns_request_path(request.url.path):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    application.mount("/assets", host, name="frontend-assets")

    def frontend_page(request: Request):
        return host.page_response(request.url.path)

    for frontend_route in host.page_routes:
        application.add_api_route(
            frontend_route,
            frontend_page,
            methods=["GET"],
            include_in_schema=False,
            name=f"frontend-page-{frontend_route.strip('/') or 'index'}",
        )
    application.include_router(api_router)
    return application


__all__ = ["create_web_app"]
