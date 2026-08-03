"""Contracts that connect one loaded plug-in to the core web runtime.

The plug-in opens data and supplies non-web query providers.  The core owns
the ASGI application, HTTP routes, frontend hosting, and the lifetime in which
the returned session is entered and closed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

from .multi_node_route import MultiNodeRouteService
from .multi_node_topology import MultiNodeTopologyService
from .normalized_data import (
    NormalizedDataPolicy,
    NormalizedDataService,
    NormalizedDatasetSource,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
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
    _provider_snapshot: _ValidatedRuntimeSession | None = field(
        default=None,
        repr=False,
        compare=False,
    )
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
        if self._provider_snapshot is not None:
            return self._provider_snapshot.revision_store
        return self.plugin_session.revision_store

    @property
    def temporal_provider(self) -> RuntimeTemporalProvider | None:
        if self._provider_snapshot is not None:
            return self._provider_snapshot.temporal_provider
        return self.plugin_session.temporal_provider

    @property
    def topology_provider(self) -> RuntimeTopologyProvider | None:
        if self._provider_snapshot is not None:
            return self._provider_snapshot.topology_provider
        return self.plugin_session.topology_provider

    @property
    def route_provider(self) -> RuntimeRouteProvider | None:
        if self._provider_snapshot is not None:
            return self._provider_snapshot.route_provider
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
            return cast(_CachedValue, self._cache[key])

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


@dataclass(frozen=True, slots=True)
class _ValidatedRuntimeCapability:
    """Core-owned snapshot of one plug-in runtime capability.

    ``source_runtime`` preserves the public runtime object carried by
    :class:`RuntimeApplicationRequest`; the executable descriptors below are
    the only values the core uses after validation.
    """

    source_runtime: Any = field(repr=False, compare=False)
    capability_id: str
    open: Callable[[Path], AbstractContextManager[PluginRuntimeSession]]


@dataclass(slots=True)
class _ValidatedRuntimeSession:
    """Core snapshot of plug-in session descriptors resolved exactly once."""

    revision_store: RevisionStore
    data_source: NormalizedDatasetSource
    data_policy: NormalizedDataPolicy
    temporal_provider: RuntimeTemporalProvider | None
    topology_provider: RuntimeTopologyProvider | None
    route_provider: RuntimeRouteProvider | None


def _runtime_member(
    owner: Any,
    name: str,
    *,
    failure: str,
    default: Any = ...,
) -> Any:
    """Resolve one hostile descriptor without rendering its failure."""

    try:
        if default is ...:
            return getattr(owner, name)
        return getattr(owner, name, default)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - plug-in descriptors are hostile.
        raise PluginRuntimeCapabilityError(failure) from None


def _implements_contract(value: Any, contract: Any, *, failure: str) -> bool:
    """Run a runtime-checkable protocol test behind the same boundary."""

    try:
        return isinstance(value, contract)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - nested provider descriptors are hostile.
        raise PluginRuntimeCapabilityError(failure) from None


def _snapshot_runtime_capability(
    runtime: Any,
    *,
    expected_capability_id: str | None = None,
) -> _ValidatedRuntimeCapability:
    """Resolve and validate executable runtime descriptors exactly once."""

    if type(runtime) is _ValidatedRuntimeCapability:
        return runtime
    capability_id = _runtime_member(
        runtime,
        "capability_id",
        failure="plug-in runtime capability_id descriptor could not be resolved",
    )
    open_hook = _runtime_member(
        runtime,
        "open",
        failure="plug-in runtime open(input_path) descriptor could not be resolved",
    )
    if type(capability_id) is not str or not callable(open_hook):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime must expose capability_id and open(input_path)"
        )
    if (
        expected_capability_id is not None
        and capability_id != expected_capability_id
    ):
        raise PluginRuntimeCapabilityError(
            "unsupported plug-in runtime capability; expected "
            f"{expected_capability_id!r}"
        )
    return _ValidatedRuntimeCapability(
        source_runtime=runtime,
        capability_id=capability_id,
        open=cast(
            Callable[[Path], AbstractContextManager[PluginRuntimeSession]],
            open_hook,
        ),
    )


def _snapshot_runtime_session(session: Any) -> _ValidatedRuntimeSession:
    """Resolve and validate all plug-in session fields once."""

    values = {
        name: _runtime_member(
            session,
            name,
            failure=f"runtime session {name} could not be resolved",
        )
        for name in (
            "revision_store",
            "data_source",
            "data_policy",
            "temporal_provider",
            "topology_provider",
            "route_provider",
        )
    }
    revision_store = values["revision_store"]
    data_source = values["data_source"]
    data_policy = values["data_policy"]
    if not _implements_contract(
        revision_store,
        RevisionStore,
        failure="runtime session revision_store validation failed",
    ):
        raise PluginRuntimeCapabilityError(
            "runtime session revision_store does not implement RevisionStore"
        )
    if not _implements_contract(
        data_source,
        NormalizedDatasetSource,
        failure="runtime session data_source validation failed",
    ):
        raise PluginRuntimeCapabilityError(
            "runtime session data_source does not implement the normalized "
            "dataset source contract"
        )
    if not _implements_contract(
        data_policy,
        NormalizedDataPolicy,
        failure="runtime session data_policy validation failed",
    ):
        raise PluginRuntimeCapabilityError(
            "runtime session data_policy does not implement the normalized "
            "data policy contract"
        )
    optional_providers = (
        (
            "temporal_provider",
            values["temporal_provider"],
            RuntimeTemporalProvider,
        ),
        (
            "topology_provider",
            values["topology_provider"],
            RuntimeTopologyProvider,
        ),
        (
            "route_provider",
            values["route_provider"],
            RuntimeRouteProvider,
        ),
    )
    for name, provider, contract in optional_providers:
        if provider is not None and not _implements_contract(
            provider,
            contract,
            failure=f"runtime session {name} validation failed",
        ):
            raise PluginRuntimeCapabilityError(
                f"runtime session {name} does not implement its provider contract"
            )
    return _ValidatedRuntimeSession(
        revision_store=revision_store,
        data_source=data_source,
        data_policy=data_policy,
        temporal_provider=values["temporal_provider"],
        topology_provider=values["topology_provider"],
        route_provider=values["route_provider"],
    )


def validate_runtime_session(session: Any) -> PluginRuntimeSession:
    """Validate every provider surface before the core serves a request."""

    _snapshot_runtime_session(session)
    return cast(PluginRuntimeSession, session)


def require_plugin_runtime(plugin: Any) -> PluginRuntimeCapability:
    """Return an executable runtime for either supported plug-in shape.

    ``runtime.v1`` is the compatibility surface for immutable/precomputed
    fixture adapters. Ordinary parser plug-ins need no path-opening hook: the
    core wraps their standard discovery/parser contract in its own
    ``runtime.v2`` ingestion adapter.
    """

    runtime = _runtime_member(
        plugin,
        "runtime",
        failure="plug-in runtime descriptor could not be resolved",
        default=None,
    )
    if runtime is None:
        from .ingestion import CoreIngestionRuntime, IngestionError

        try:
            return CoreIngestionRuntime(plugin)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except IngestionError as error:
            raise PluginRuntimeCapabilityError(
                "loaded plug-in does not expose runtime.v1 and does not "
                "implement the standard core-ingestion parser contract"
            ) from error
        except BaseException:  # noqa: BLE001 - parser descriptors are hostile.
            raise PluginRuntimeCapabilityError(
                "loaded plug-in does not expose runtime.v1 and does not "
                "implement the standard core-ingestion parser contract"
            ) from None
    return cast(
        PluginRuntimeCapability,
        _snapshot_runtime_capability(
            runtime,
            expected_capability_id=PLUGIN_RUNTIME_CAPABILITY_ID,
        ),
    )


@contextmanager
def _open_runtime_session(
    runtime: Any,
    input_path: Path,
) -> Iterator[Any]:
    """Open one plug-in session while containing its complete lifetime."""

    open_hook = _runtime_member(
        runtime,
        "open",
        failure="plug-in runtime session open descriptor could not be resolved",
    )
    if not callable(open_hook):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime session open descriptor must be callable"
        )
    try:
        manager = open_hook(input_path)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - plug-in open hooks are hostile.
        raise PluginRuntimeCapabilityError(
            "plug-in runtime session open failed"
        ) from None

    enter_hook = _runtime_member(
        manager,
        "__enter__",
        failure="plug-in runtime session enter descriptor could not be resolved",
    )
    exit_hook = _runtime_member(
        manager,
        "__exit__",
        failure="plug-in runtime session exit descriptor could not be resolved",
    )
    if not callable(enter_hook):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime session enter descriptor must be callable"
        )
    if not callable(exit_hook):
        raise PluginRuntimeCapabilityError(
            "plug-in runtime session exit descriptor must be callable"
        )
    try:
        opened_session = enter_hook()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - plug-in context entry is hostile.
        raise PluginRuntimeCapabilityError(
            "plug-in runtime session enter failed"
        ) from None

    try:
        yield opened_session
    except BaseException as body_error:
        # A plug-in must not suppress or replace a core/application failure.
        # If cleanup also fails, preserve the original object and attach only
        # a fixed, path-free note recording the secondary failure.
        exit_failed = False
        try:
            exit_hook(
                type(body_error),
                body_error,
                body_error.__traceback__,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - cleanup failure is secondary.
            exit_failed = True
        if exit_failed:
            BaseException.add_note(
                body_error,
                "plug-in runtime session cleanup also failed",
            )
        raise
    else:
        try:
            exit_hook(None, None, None)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - plug-in context exit is hostile.
            raise PluginRuntimeCapabilityError(
                "plug-in runtime session exit failed"
            ) from None


@dataclass(frozen=True, slots=True)
class RuntimeApplicationRequest:
    """Inputs supplied to the core-owned application factory."""

    runtime: PluginRuntimeCapability
    input_path: Path
    frontend_root: Path | None = None
    serve_frontend: bool = True
    control_plane: Any | None = None
    control_plane_identity_resolver: Any | None = None
    manage_control_plane_lifecycle: bool = False
    expose_api_docs: bool = False
    _runtime_snapshot: _ValidatedRuntimeCapability = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.expose_api_docs) is not bool:
            raise TypeError("expose_api_docs must be a boolean")
        runtime_snapshot = _snapshot_runtime_capability(self.runtime)
        object.__setattr__(self, "_runtime_snapshot", runtime_snapshot)
        object.__setattr__(self, "runtime", runtime_snapshot.source_runtime)


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
    from .web.control_plane_api import (
        ControlPlaneAccessDenialReporter,
        control_plane_router,
    )
    from .web.frontend_host import FrontendHost
    from .web.runtime_api import (
        analysis_health_projection,
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
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        frontend_host.validate_if_enabled()
        if request.control_plane is not None and request.manage_control_plane_lifecycle:
            request.control_plane.start()
        try:
            with _open_runtime_session(
                request._runtime_snapshot,
                request.input_path,
            ) as opened_session:
                plugin_session = _snapshot_runtime_session(opened_session)
                core_session = CoreRuntimeSession(
                    plugin_session=cast(PluginRuntimeSession, opened_session),
                    data_service=NormalizedDataService(
                        plugin_session.data_source,
                        plugin_session.data_policy,
                    ),
                    _provider_snapshot=plugin_session,
                )
                application.state.runtime_session = core_session
                reset_runtime_api_caches()
                with activate_runtime_session(core_session):
                    warmup = start_runtime_warmup()
                try:
                    yield
                finally:
                    if warmup is not None:
                        import asyncio

                        await asyncio.to_thread(warmup.join)
                    reset_runtime_api_caches()
                    application.state.runtime_session = None
        finally:
            if (
                request.control_plane is not None
                and request.manage_control_plane_lifecycle
            ):
                import asyncio

                await asyncio.to_thread(request.control_plane.close)

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
        expose_api_docs=request.expose_api_docs,
    )
    application.include_router(control_plane_router)
    application.state.control_plane = request.control_plane
    application.state.control_plane_identity_resolver = (
        request.control_plane_identity_resolver
    )
    application.state.control_plane_access_denial_reporter = (
        ControlPlaneAccessDenialReporter()
    )
    application.state.analysis_health_projector = analysis_health_projection

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
    "PLUGIN_RUNTIME_CAPABILITY_ID",
    "CoreRuntimeSession",
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
