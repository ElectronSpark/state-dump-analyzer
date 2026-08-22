from .multi_node_route import MultiNodeRouteService
from .multi_node_topology import MultiNodeTopologyService
from .normalized_data import NormalizedDataPolicy, NormalizedDataService, NormalizedDatasetSource
from .revision_store import RevisionStore
from .temporal_topology import TemporalTopologyService
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

__all__ = ['PLUGIN_RUNTIME_CAPABILITY_ID', 'PluginRuntimeCapabilityError', 'RuntimeTemporalProvider', 'RuntimeTopologyProvider', 'RuntimeRouteProvider', 'PluginRuntimeSession', 'CoreRuntimeSession', 'PluginRuntimeCapability', 'validate_runtime_session', 'require_plugin_runtime', 'RuntimeApplicationRequest', 'RuntimeApplicationFactory', 'create_runtime_application']

PLUGIN_RUNTIME_CAPABILITY_ID: str

class PluginRuntimeCapabilityError(TypeError): ...

class RuntimeTemporalProvider(Protocol):
    def for_revision(self, revision_id: str | None, data_service: NormalizedDataService) -> TemporalTopologyService: ...

class RuntimeTopologyProvider(Protocol):
    @property
    def topology_id(self) -> str: ...
    def get(self) -> MultiNodeTopologyService: ...

class RuntimeRouteProvider(Protocol):
    def get(self) -> MultiNodeRouteService: ...

class PluginRuntimeSession(Protocol):
    revision_store: RevisionStore
    data_source: NormalizedDatasetSource
    data_policy: NormalizedDataPolicy
    temporal_provider: RuntimeTemporalProvider | None
    topology_provider: RuntimeTopologyProvider | None
    route_provider: RuntimeRouteProvider | None

@dataclass(frozen=True, slots=True)
class CoreRuntimeSession:
    plugin_session: PluginRuntimeSession
    data_service: NormalizedDataService
    _provider_snapshot: _ValidatedRuntimeSession | None = ...
    @property
    def revision_store(self) -> RevisionStore: ...
    @property
    def temporal_provider(self) -> RuntimeTemporalProvider | None: ...
    @property
    def topology_provider(self) -> RuntimeTopologyProvider | None: ...
    @property
    def route_provider(self) -> RuntimeRouteProvider | None: ...
    def cached(self, key: object, factory: Callable[[], _CachedValue]) -> _CachedValue: ...
    def clear_cache(self) -> None: ...

class PluginRuntimeCapability(Protocol):
    capability_id: str
    def open(self, input_path: Path) -> AbstractContextManager[PluginRuntimeSession]: ...

@dataclass(frozen=True, slots=True)
class _ValidatedRuntimeCapability:
    source_runtime: Any = field(repr=False, compare=False)
    capability_id: str
    open: Callable[[Path], AbstractContextManager[PluginRuntimeSession]]

@dataclass(slots=True)
class _ValidatedRuntimeSession:
    revision_store: RevisionStore
    data_source: NormalizedDatasetSource
    data_policy: NormalizedDataPolicy
    temporal_provider: RuntimeTemporalProvider | None
    topology_provider: RuntimeTopologyProvider | None
    route_provider: RuntimeRouteProvider | None

def validate_runtime_session(session: Any) -> PluginRuntimeSession: ...
def require_plugin_runtime(plugin: Any) -> PluginRuntimeCapability: ...

@dataclass(frozen=True, slots=True)
class RuntimeApplicationRequest:
    runtime: PluginRuntimeCapability
    input_path: Path
    frontend_root: Path | None = ...
    serve_frontend: bool = ...
    control_plane: Any | None = ...
    control_plane_identity_resolver: Any | None = ...
    manage_control_plane_lifecycle: bool = ...
    expose_api_docs: bool = ...
    def __post_init__(self) -> None: ...

class RuntimeApplicationFactory(Protocol):
    def __call__(self, request: RuntimeApplicationRequest) -> Any: ...

def create_runtime_application(request: RuntimeApplicationRequest) -> Any: ...

# Private type variable used by a public generic method signature.
from typing import TypeVar
_CachedValue = TypeVar('_CachedValue')
