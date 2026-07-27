"""Contracts that connect one loaded plug-in to the core web runtime.

The plug-in opens data and supplies non-web query providers.  The core owns
the ASGI application, HTTP routes, frontend hosting, and the lifetime in which
the returned session is entered and closed.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Protocol, TypeVar, runtime_checkable

from .normalized_data import (
    NormalizedDataPolicy,
    NormalizedDataService,
    NormalizedDatasetSource,
)
from .multi_node_route import MultiNodeRouteService
from .multi_node_topology import MultiNodeTopologyService
from .revision_store import RevisionStore
from .temporal_topology import TemporalTopologyService


PLUGIN_RUNTIME_CAPABILITY_ID = "router_dump_analyzer.runtime.v1"
_CachedValue = TypeVar("_CachedValue")


class PluginRuntimeCapabilityError(TypeError):
    """Raised when a loaded analyzer plug-in cannot host an input."""


@runtime_checkable
class RuntimeTemporalProvider(Protocol):
    """Plug-in-injected temporal policy/query surface."""

    def for_revision(
        self,
        revision_id: str | None,
        data_service: NormalizedDataService,
    ) -> TemporalTopologyService: ...


@runtime_checkable
class RuntimeTopologyProvider(Protocol):
    """Plug-in-injected topology policy/query surface."""

    @property
    def topology_id(self) -> str: ...

    def get(self) -> MultiNodeTopologyService: ...


@runtime_checkable
class RuntimeRouteProvider(Protocol):
    """Plug-in-injected route policy/query surface."""

    def get(self) -> MultiNodeRouteService: ...


@runtime_checkable
class PluginRuntimeSession(Protocol):
    """One opened analysis input, containing no HTTP or ASGI objects.

    The core application lifespan owns the surrounding context manager.
    The plug-in supplies only data loading and device/input policy. The core
    constructs :class:`NormalizedDataService` and owns generic queries.
    """

    revision_store: RevisionStore
    data_source: NormalizedDatasetSource
    data_policy: NormalizedDataPolicy
    temporal_provider: RuntimeTemporalProvider | None
    topology_provider: RuntimeTopologyProvider | None
    route_provider: RuntimeRouteProvider | None


@dataclass(frozen=True, slots=True)
class CoreRuntimeSession:
    """Core-bound view of one opened plug-in session."""

    plugin_session: PluginRuntimeSession
    data_service: NormalizedDataService
    _cache: dict[object, Any] = field(
        default_factory=dict,
        init=False,
        repr=False,
        compare=False,
    )
    _cache_lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def revision_store(self) -> RevisionStore:
        return self.plugin_session.revision_store

    @property
    def temporal_provider(self) -> RuntimeTemporalProvider | None:
        return self.plugin_session.temporal_provider

    @property
    def topology_provider(self) -> RuntimeTopologyProvider | None:
        return self.plugin_session.topology_provider

    @property
    def route_provider(self) -> RuntimeRouteProvider | None:
        return self.plugin_session.route_provider

    def cached(
        self,
        key: object,
        factory: Callable[[], _CachedValue],
    ) -> _CachedValue:
        """Return one projection cached only for this opened application."""

        with self._cache_lock:
            if key not in self._cache:
                self._cache[key] = factory()
            return self._cache[key]

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()


@runtime_checkable
class PluginRuntimeCapability(Protocol):
    """Plug-in-owned input adapter consumed by the core application.

    The adapter owns the dump/fixture format and returns a context-managed,
    non-web session. The core owns the server, APIs, generic services, and
    application lifetime.
    """

    capability_id: str

    def open(
        self,
        input_path: Path,
    ) -> AbstractContextManager[PluginRuntimeSession]:
        """Open one input without transferring format semantics to core."""


def validate_runtime_session(session: Any) -> PluginRuntimeSession:
    """Validate every provider surface before the core serves a request."""

    if not isinstance(session, PluginRuntimeSession):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime open() must yield a PluginRuntimeSession"
        )
    if not isinstance(session.revision_store, RevisionStore):
        raise PluginRuntimeCapabilityError(
            "runtime session revision_store does not implement RevisionStore"
        )
    if not isinstance(session.data_source, NormalizedDatasetSource):
        raise PluginRuntimeCapabilityError(
            "runtime session data_source does not implement the normalized "
            "dataset source contract"
        )
    if not isinstance(session.data_policy, NormalizedDataPolicy):
        raise PluginRuntimeCapabilityError(
            "runtime session data_policy does not implement the normalized "
            "data policy contract"
        )
    optional_providers = (
        (
            "temporal_provider",
            session.temporal_provider,
            RuntimeTemporalProvider,
        ),
        (
            "topology_provider",
            session.topology_provider,
            RuntimeTopologyProvider,
        ),
        (
            "route_provider",
            session.route_provider,
            RuntimeRouteProvider,
        ),
    )
    for name, provider, contract in optional_providers:
        if provider is not None and not isinstance(provider, contract):
            raise PluginRuntimeCapabilityError(
                f"runtime session {name} does not implement its provider "
                "contract"
            )
    return session


def require_plugin_runtime(plugin: Any) -> PluginRuntimeCapability:
    """Return one explicit runtime capability or fail with a clear contract error."""

    runtime = getattr(plugin, "runtime", None)
    if runtime is None:
        raise PluginRuntimeCapabilityError(
            "loaded plug-in does not expose a 'runtime' capability"
        )
    if not isinstance(runtime, PluginRuntimeCapability):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime must expose capability_id and "
            "open(input_path)"
        )
    if runtime.capability_id != PLUGIN_RUNTIME_CAPABILITY_ID:
        raise PluginRuntimeCapabilityError(
            "unsupported plug-in runtime capability "
            f"{runtime.capability_id!r}; expected "
            f"{PLUGIN_RUNTIME_CAPABILITY_ID!r}"
        )
    return runtime


@dataclass(frozen=True, slots=True)
class RuntimeApplicationRequest:
    """Inputs supplied to the core-owned application factory."""

    runtime: PluginRuntimeCapability
    input_path: Path
    frontend_root: Path | None = None
    serve_frontend: bool = True


class RuntimeApplicationFactory(Protocol):
    """Build the generic ASGI application around one plug-in runtime."""

    def __call__(self, request: RuntimeApplicationRequest) -> Any: ...


def create_runtime_application(
    request: RuntimeApplicationRequest,
) -> Any:
    """Build the core FastAPI application around one opened plug-in session.

    Importing the web stack is deliberately lazy so contract-only users do not
    need FastAPI installed. The plug-in contributes data and policy providers;
    it cannot replace routes, middleware, frontend hosting, or application
    lifetime.
    """

    try:
        from fastapi import FastAPI, Request
    except ImportError as error:
        raise RuntimeError(
            "the analyzer application requires the "
            "'router-dump-analyzer-core[web]' extra"
        ) from error

    from contextlib import asynccontextmanager

    from .web.app import create_web_app
    from .web.frontend_host import FrontendHost
    from .web.runtime_api import (
        api_router,
        reset_runtime_api_caches,
        start_runtime_warmup,
    )
    from .web.runtime_context import activate_runtime_session

    frontend_host = FrontendHost(
        request.frontend_root,
        enabled=request.serve_frontend,
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        frontend_host.validate_if_enabled()
        with request.runtime.open(request.input_path) as session:
            plugin_session = validate_runtime_session(session)
            session = CoreRuntimeSession(
                plugin_session=plugin_session,
                data_service=NormalizedDataService(
                    plugin_session.data_source,
                    plugin_session.data_policy,
                ),
            )
            application.state.runtime_session = session
            reset_runtime_api_caches()
            with activate_runtime_session(session):
                warmup = start_runtime_warmup()
            try:
                yield
            finally:
                if warmup is not None:
                    import asyncio

                    await asyncio.to_thread(warmup.join)
                reset_runtime_api_caches()
                application.state.runtime_session = None

    application = create_web_app(
        api_router=api_router,
        host=frontend_host,
        title="Router Dump Analyzer API",
        version="0.1.0",
        description=(
            "Core-owned temporal router-state API over a dynamically loaded "
            "plug-in runtime."
        ),
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def bind_runtime_session(
        http_request: Request,
        call_next: Any,
    ) -> Any:
        session = getattr(application.state, "runtime_session", None)
        if session is None:
            return await call_next(http_request)
        with activate_runtime_session(session):
            # Revision selection is intentionally bound by an APIRouter
            # dependency after Starlette has parsed ``revision_id``.  Raw-path
            # middleware cannot disambiguate slash-containing revision IDs.
            return await call_next(http_request)

    return application


__all__ = [
    "CoreRuntimeSession",
    "PLUGIN_RUNTIME_CAPABILITY_ID",
    "PluginRuntimeCapability",
    "PluginRuntimeCapabilityError",
    "PluginRuntimeSession",
    "RuntimeApplicationFactory",
    "RuntimeApplicationRequest",
    "RuntimeRouteProvider",
    "RuntimeTemporalProvider",
    "RuntimeTopologyProvider",
    "create_runtime_application",
    "require_plugin_runtime",
    "validate_runtime_session",
]
