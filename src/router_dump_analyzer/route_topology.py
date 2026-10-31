"""Core topology access required by route coordination.

This interface describes already validated core services. It does not replace
the plug-in provider registry, exact provider identity, or execution boundary.
Topology owns context retention, node contracts, and selector normalization.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .value_core import snapshot_json_value


class MultiNodeTopologyRequestError(ValueError):
    """A multi-node request cannot be executed by the advertised providers."""


@dataclass(frozen=True, slots=True)
class TopologyProjectionQuery:
    """Resolved, immutable scope for one query-time normalized projection.

    A provider returns only resources, local_links, connector_claims and/or
    network_segment_claims. Omitted arrays retain the static declaration.
    The core retains identity, status policy, bounded rendering and joining.
    """

    node_id: str
    member_id: str
    revision_id: str
    plugin_set_id: str
    plugin_id: str
    projection_id: str
    status_perspective_id: str
    context_id: str
    resolved_time: Mapping[str, Any]
    requested_basis: Mapping[str, Any]
    max_records: int = 10_000

    def __post_init__(self) -> None:
        for name in (
            "node_id",
            "member_id",
            "revision_id",
            "plugin_set_id",
            "plugin_id",
            "projection_id",
            "status_perspective_id",
            "context_id",
        ):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 512:
                raise ValueError(f"{name} must be a non-empty bounded string")
        if type(self.max_records) is not int or not 1 <= self.max_records <= 100_000:
            raise ValueError("max_records must be between 1 and 100000")
        for name in ("resolved_time", "requested_basis"):
            if not isinstance(getattr(self, name), Mapping):
                raise TypeError(f"{name} must be a mapping")
            object.__setattr__(self, name, snapshot_json_value(getattr(self, name)))


class TopologyProjectionProvider(Protocol):
    """Callable extension; no service subclass or access to private stores."""

    def __call__(self, query: TopologyProjectionQuery) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class RouteProjectionSelection:
    """Ordered canonical projection identities selected by topology."""

    plugin_set_id: str
    projection_ids: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        if type(self.plugin_set_id) is not str or not self.plugin_set_id:
            raise ValueError("plugin_set_id must be a non-empty string")
        if type(self.projection_ids) is not tuple or any(
            type(identity) is not tuple
            or len(identity) != 3
            or any(type(value) is not str or not value for value in identity)
            for identity in self.projection_ids
        ):
            raise ValueError("projection_ids must contain immutable identity triples")


class RouteTopologyAccess(Protocol):
    """Narrow topology contract consumed by the core route coordinator.

    Context and catalog results are detached, recursively immutable snapshots.
    They use ``snapshot_json_value``'s mapping-proxy/tuple representation;
    normalization inputs use that representation or ordinary JSON containers.
    Repeated context lookup must reuse the retained snapshot without copying
    the full reconstruction. A missing or evicted context returns ``None``.
    Catalog and node metadata describe the service's retained revision and are
    reused across lookups; a new catalog revision requires a new service.
    ``query`` and ``capabilities`` return independent mutable wire values.
    Unsupported or invalid requests raise ``MultiNodeTopologyRequestError``
    from the normalization and query methods; lookup misses return ``None``.
    """

    @property
    def assembly_id(self) -> str: ...

    @property
    def topology_id(self) -> str: ...

    @property
    def start_ns(self) -> int: ...

    def context_snapshot(self, context_id: str) -> Mapping[str, Any] | None: ...

    def route_catalog(self) -> Mapping[str, Any]:
        """Return nodes, network_segment_matchers and federation_plugin metadata."""
        ...

    def node_contract(self, node_id: str) -> Mapping[str, Any] | None: ...

    def normalize_node_queries(
        self, body: Mapping[str, Any]
    ) -> tuple[Mapping[str, Any], ...]: ...

    def normalize_projection_selection(
        self, node_id: str, request: Mapping[str, Any]
    ) -> RouteProjectionSelection: ...

    def normalize_basis(self, basis: Any, field: str = "basis") -> dict[str, Any]: ...

    def capabilities(self) -> dict[str, Any]: ...

    def query(self, body: dict[str, Any]) -> dict[str, Any]: ...


__all__ = [
    "MultiNodeTopologyRequestError",
    "RouteProjectionSelection",
    "RouteTopologyAccess",
    "TopologyProjectionProvider",
    "TopologyProjectionQuery",
]
