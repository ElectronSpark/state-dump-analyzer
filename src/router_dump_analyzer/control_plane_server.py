"""Core-owned, analysis-independent HTTP host for the durable control plane."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ControlPlaneApplicationRequest:
    """Dependencies for one headless durable-control-plane application.

    The caller constructs the single-host control plane and supplies a
    resolver backed by its authentication boundary.  The ASGI lifespan owns
    worker startup and shutdown.  No analysis input or plug-in runtime is
    opened by this application.
    """

    control_plane: Any
    identity_resolver: Callable[[Any], Any]
    expose_api_docs: bool = False

    def __post_init__(self) -> None:
        for operation in ("start", "close"):
            if not callable(getattr(self.control_plane, operation, None)):
                raise TypeError(
                    "control_plane must expose callable start() and close()"
                )
        if not callable(self.identity_resolver):
            raise TypeError("identity_resolver must be callable")
        if inspect.iscoroutinefunction(
            self.identity_resolver
        ) or inspect.iscoroutinefunction(type(self.identity_resolver).__call__):
            raise TypeError("identity_resolver must be synchronous")
        if type(self.expose_api_docs) is not bool:
            raise TypeError("expose_api_docs must be a boolean")


class ControlPlaneApplicationFactory(Protocol):
    """Build a headless ASGI application around one durable control plane."""

    def __call__(self, request: ControlPlaneApplicationRequest) -> Any: ...


def create_control_plane_application(
    request: ControlPlaneApplicationRequest,
) -> Any:
    """Create an API-only application with no analysis-runtime dependency."""

    try:
        from fastapi import FastAPI
    except ImportError as error:
        raise RuntimeError(
            "the control-plane server requires the "
            "'router-dump-analyzer-core[web]' extra"
        ) from error

    import asyncio
    from contextlib import asynccontextmanager

    from .web.app import create_web_app
    from .web.control_plane_api import (
        ControlPlaneAccessDenialReporter,
        control_plane_router,
    )
    from .web.frontend_host import FrontendHost
    from .web.service_api import service_router

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        try:
            request.control_plane.start()
            yield
        finally:
            await asyncio.to_thread(request.control_plane.close)

    application = create_web_app(
        api_router=service_router,
        host=FrontendHost(enabled=False),
        mount_frontend=False,
        title="Router Dump Analyzer Control Plane API",
        version="0.1.0",
        description=(
            "Core-owned, analysis-independent durable ingestion, catalog, "
            "session, review, and report API."
        ),
        lifespan=lifespan,
        expose_api_docs=request.expose_api_docs,
    )
    application.include_router(control_plane_router)
    application.state.control_plane = request.control_plane
    application.state.control_plane_identity_resolver = request.identity_resolver
    application.state.control_plane_access_denial_reporter = (
        ControlPlaneAccessDenialReporter()
    )
    application.state.runtime_session = None
    return application


__all__ = [
    "ControlPlaneApplicationFactory",
    "ControlPlaneApplicationRequest",
    "create_control_plane_application",
]
