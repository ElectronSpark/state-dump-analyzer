"""Input-session adapter supplied by the example plug-in.

The core owns the executable, ASGI application, HTTP API, frontend, and
application lifetime.  This module only opens the example plug-in's generated
fixture format and exposes non-web providers consumed by those core services.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Self, TypeVar

from router_dump_analyzer.multi_node_route import MultiNodeRouteService
from router_dump_analyzer.multi_node_topology import MultiNodeTopologyService
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.plugin_api import StatusPerspectiveRef
from router_dump_analyzer.runtime import PLUGIN_RUNTIME_CAPABILITY_ID
from router_dump_analyzer.temporal_topology import TemporalTopologyService

from . import data
from .assembly_store import DemoAssemblyStore
from .route_policy import (
    DEMO_ROUTE_POLICY,
    build_route_projection_set,
)
from .scale_data import load_scale_dataset
from .source_records import lazy_demo_ctf_source_record
from .temporal_contract import (
    build_demo_plugin_contract,
    build_temporal_metadata,
)
from .topology_contract import (
    DEMO_TOPOLOGY_ID,
    build_topology_contract,
    build_topology_metadata,
    build_topology_profiles,
)

_Result = TypeVar("_Result")


def _load_generated_revision(
    archive_path: Path,
    revision_id: str,
) -> dict[str, Any]:
    """Load one node with the review metadata owned by this example plug-in."""

    return load_scale_dataset(
        archive_path,
        revision_id=revision_id,
        gaps=data.DEMO_GAPS,
        review_prompts=data.REVIEW_PROMPTS,
    )


class _LazyDemoAssemblyStore(DemoAssemblyStore):
    """Defer archive inventory/extraction until a tracked core request.

    Runtime-session validation needs a complete revision-store surface before
    the server is reachable, but constructing :class:`DemoAssemblyStore`
    eagerly would extract every nested node archive during lifespan startup.
    This proxy keeps ``open()`` lightweight and performs that work on the first
    data/topology access, where the core has bound an analysis-load operation.
    """

    def __init__(
        self,
        archive_path: Path,
        *,
        cache_size: int = 2,
        dataset_loader: Callable[[Path, str], dict[str, Any]] | None = None,
    ) -> None:
        # Deliberately do not call the eager parent constructor.
        self.archive_path = Path(archive_path)
        self.cache_size = cache_size
        self._lazy_dataset_loader = dataset_loader
        self._lazy_lock = RLock()
        self._lazy_store: DemoAssemblyStore | None = None
        self._lazy_closed = False

    def _materialized(self) -> DemoAssemblyStore:
        with self._lazy_lock:
            if self._lazy_closed:
                raise RuntimeError("demo assembly store is closed")
            if self._lazy_store is None:
                self._lazy_store = DemoAssemblyStore(
                    self.archive_path,
                    cache_size=self.cache_size,
                    dataset_loader=self._lazy_dataset_loader,
                )
            return self._lazy_store

    @property
    def assembly(self) -> Any:
        return self._materialized().assembly

    @property
    def default_node_id(self) -> str:
        return self._materialized().default_node_id

    @property
    def default_revision_id(self) -> str:
        return self._materialized().default_revision_id

    @property
    def manifest(self) -> dict[str, Any]:
        return self._materialized().manifest

    @manifest.setter
    def manifest(self, value: dict[str, Any]) -> None:
        self._materialized().manifest = value

    @property
    def coverage(self) -> dict[str, Any]:
        return self._materialized().coverage

    @coverage.setter
    def coverage(self, value: dict[str, Any]) -> None:
        self._materialized().coverage = value

    def revision(self, revision_id: str) -> Any:
        return self._materialized().revision(revision_id)

    def revision_for_node(self, node_id: str) -> Any:
        return self._materialized().revision_for_node(node_id)

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        return self._materialized().dataset_for_node(node_id)

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        return self._materialized().dataset_for_revision(revision_id)

    def projection_for_node(self, node_id: str) -> Mapping[str, Any]:
        return self._materialized().projection_for_node(node_id)

    def loaded_revision_ids(self) -> tuple[str, ...]:
        with self._lazy_lock:
            if self._lazy_store is None:
                return ()
            return self._lazy_store.loaded_revision_ids()

    def close(self) -> None:
        with self._lazy_lock:
            if self._lazy_closed:
                return
            self._lazy_closed = True
            store = self._lazy_store
        if store is not None:
            store.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


class DemoDatasetSource:
    """Load generated revisions and expose their optional generic index."""

    def __init__(self, revision_store: DemoAssemblyStore) -> None:
        self.revision_store: DemoAssemblyStore = revision_store

    def _call(
        self,
        operation: Callable[..., _Result],
        *args: Any,
        **kwargs: Any,
    ) -> _Result:
        # The store scope is request-local; the data facade never discovers or
        # owns an archive through process-global configuration.
        with data.revision_store_scope(self.revision_store):
            return operation(*args, **kwargs)

    @contextmanager
    def revision_scope(self, revision_id: str) -> Iterator[None]:
        """Select an exact revision for one core request/task."""

        self.revision_store.revision(revision_id)
        with (
            data.revision_store_scope(self.revision_store),
            data.demo_revision_scope(revision_id),
        ):
            yield

    def load_dataset(
        self,
        revision_id: str | None = None,
        *,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        return self._call(
            data.load_demo_dataset,
            revision_id,
            node_id=node_id,
        )

    def revision_id(self, dataset: Mapping[str, Any]) -> str:
        return data.dataset_revision_id(dataset)

    def indexed_history(self, dataset: Mapping[str, Any]) -> Any | None:
        return data.scale_runtime(dataset)

    def reset(self) -> None:
        """Release source-local state.

        Dataset and history caches are owned and closed by the revision store.
        This adapter deliberately retains no cross-session cache.
        """


class DemoDataPolicy:
    """Example-only presentation, route, and source-evidence policy."""

    def __init__(self, source: DemoDatasetSource) -> None:
        self._source = source

    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return data.analysis_metadata(dataset)

    def workspace_metadata(
        self,
        dataset: Mapping[str, Any],
        *,
        revision_id: str,
        history_mode: str,
    ) -> Mapping[str, Any]:
        return data.workspace_metadata(
            dataset,
            revision_id=revision_id,
            history_mode=history_mode,
        )

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self._source._call(
            data.route_resolution_capability,
            dataset,
        )

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self._source._call(
            data.generated_route_row,
            route_id,
            dataset,
        )

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return lazy_demo_ctf_source_record(dict(event))


class DemoTemporalProvider:
    """Construct request-owned revision-scoped temporal query services.

    A service retains its dataset generation and optional history index.
    Keeping services in a second provider cache would therefore defeat the
    revision store's memory bound and could retain a generation after LRU
    eviction. The returned service lives only as long as its core query.
    """

    def __init__(self, data_source: DemoDatasetSource) -> None:
        self._data_source = data_source

    def for_revision(
        self,
        revision_id: str | None,
        data_service: NormalizedDataService,
    ) -> Any:
        selected_revision_id = (
            revision_id
            or self._data_source.revision_store.default_revision_id
        )
        dataset = self._data_source.load_dataset(selected_revision_id)

        def state_reader(
            resource_identifier: str,
            timestamp_ns: int,
        ) -> dict[str, Any]:
            with data_service.revision_scope(selected_revision_id):
                return data_service.resource_state_at(
                    resource_identifier,
                    timestamp_ns,
                )

        def relationship_reader(
            timestamp_ns: int,
        ) -> list[dict[str, Any]]:
            with data_service.revision_scope(selected_revision_id):
                return data_service.relationships_at(timestamp_ns)

        def perspective_state_reader(
            resource_identifier: str,
            timestamp_ns: int,
            perspective_ref: StatusPerspectiveRef,
        ) -> dict[str, Any]:
            with data_service.revision_scope(selected_revision_id):
                return data_service.resource_state_at(
                    resource_identifier, timestamp_ns, perspective_ref=perspective_ref,
                )

        return TemporalTopologyService(
            dataset,
            state_reader,
            relationship_reader,
            contract=build_demo_plugin_contract(dataset),
            temporal_metadata=build_temporal_metadata(dataset),
            perspective_state_reader=perspective_state_reader,
            indexed_history=data_service.history_runtime(dataset),
        )

    def reset(self) -> None:
        """Compatibility hook; request-owned services require no reset."""


class DemoTopologyProvider:
    """Supply the plug-in's multi-node topology projection to the core."""

    def __init__(
        self,
        revision_store: DemoAssemblyStore,
        data_source: DemoDatasetSource,
    ) -> None:
        self._revision_store = revision_store
        self._data_source = data_source
        self._service: Any | None = None
        self._lock = RLock()

    @property
    def topology_id(self) -> str:
        return DEMO_TOPOLOGY_ID

    def get(self) -> Any:
        with self._lock:
            if self._service is None:
                # Keep the optional topology-capability implementation out of
                # the primary parser's import-time executable identity.  The
                # provider has its own strict module target and is attested
                # when this request-owned topology service is constructed.
                from .typed_topology import (
                    build_demo_topology_federation,
                    build_demo_topology_projection_state_provider,
                )

                dataset = self._data_source.load_dataset(
                    self._revision_store.default_revision_id
                )
                contract = build_topology_contract(self._revision_store)
                topology_federation = build_demo_topology_federation(
                    contract,
                )
                self._service = MultiNodeTopologyService(
                    contract=contract,
                    topology_profiles=build_topology_profiles(contract),
                    topology_metadata=build_topology_metadata(
                        dataset,
                        self._revision_store,
                    ),
                    topology_federation=topology_federation,
                    topology_projection_state_provider=(
                        build_demo_topology_projection_state_provider(
                            contract,
                            self._revision_store,
                        )
                    ),
                )
            return self._service

    def reset(self) -> None:
        with self._lock:
            self._service = None


class DemoRouteProvider:
    """Supply route policy/orchestration without owning any web endpoint."""

    def __init__(
        self,
        topology_provider: DemoTopologyProvider,
        revision_store: DemoAssemblyStore,
    ) -> None:
        self._topology_provider = topology_provider
        self._revision_store = revision_store
        self._service: Any | None = None
        self._lock = RLock()

    def get(self) -> Any:
        with self._lock:
            if self._service is None:
                self._service = MultiNodeRouteService(
                    self._topology_provider.get(),
                    projections=build_route_projection_set(
                        self._revision_store
                    ),
                    policy=DEMO_ROUTE_POLICY,
                )
            return self._service

    def reset(self) -> None:
        with self._lock:
            self._service = None


@dataclass(slots=True)
class DemoRuntimeSession:
    """One opened example fixture and its non-web provider set."""

    revision_store: DemoAssemblyStore
    data_source: DemoDatasetSource
    data_policy: DemoDataPolicy
    temporal_provider: DemoTemporalProvider
    topology_provider: DemoTopologyProvider
    route_provider: DemoRouteProvider
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        """Drop all derived services, then release extracted fixture state."""

        if self._closed:
            return
        self._closed = True
        self.route_provider.reset()
        self.topology_provider.reset()
        self.temporal_provider.reset()
        self.data_source.reset()
        self.revision_store.close()


class DemoRuntimeCapability:
    """Open the generated example fixture for the core-owned application."""

    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    @contextmanager
    def open(self, input_path: Path) -> Iterator[DemoRuntimeSession]:
        store = _LazyDemoAssemblyStore(
            Path(input_path),
            # A million-event revision is intentionally large.  Keep only one
            # materialized node so normal cross-node navigation cannot retain
            # two multi-gigabyte histories at once; topology projections stay
            # independently lazy and do not require this dataset cache.
            cache_size=1,
            dataset_loader=_load_generated_revision,
        )
        data_source = DemoDatasetSource(store)
        data_policy = DemoDataPolicy(data_source)
        temporal_provider = DemoTemporalProvider(data_source)
        topology_provider = DemoTopologyProvider(store, data_source)
        route_provider = DemoRouteProvider(topology_provider, store)
        session = DemoRuntimeSession(
            revision_store=store,
            data_source=data_source,
            data_policy=data_policy,
            temporal_provider=temporal_provider,
            topology_provider=topology_provider,
            route_provider=route_provider,
        )
        try:
            yield session
        finally:
            session.close()


runtime: DemoRuntimeCapability = DemoRuntimeCapability()


__all__ = [
    "DemoDataPolicy",
    "DemoDatasetSource",
    "DemoRouteProvider",
    "DemoRuntimeCapability",
    "DemoRuntimeSession",
    "DemoTemporalProvider",
    "DemoTopologyProvider",
    "runtime",
]
