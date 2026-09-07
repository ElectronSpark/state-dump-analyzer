"""Core topology access required by route coordination.

This interface describes already validated core services. It does not replace
the plug-in provider registry, exact provider identity, or execution boundary.
Topology owns context retention, node contracts, and selector normalization.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


class MultiNodeTopologyRequestError(ValueError):
    """A multi-node request cannot be executed by the advertised providers."""


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
]
