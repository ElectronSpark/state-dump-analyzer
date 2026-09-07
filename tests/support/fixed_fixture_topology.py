"""Reuse retained topology results inside one immutable fixture traversal test.

This adapter deliberately does not exercise repeated live-provider execution.
It must stay scoped to an exhaustive core traversal test over one fixed fixture;
provider attestation and ordinary HTTP integration tests use the live service.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any

from router_dump_analyzer.route_topology import (
    RouteProjectionSelection,
    RouteTopologyAccess,
)
from router_dump_analyzer.value_core import mutable_json_value


class FixedFixtureTopologyMemoizer:
    """Memoize complete query values while their exact contexts remain retained."""

    MAX_QUERIES = 8
    MAX_KEY_BYTES = 65_536

    def __init__(self, delegate: RouteTopologyAccess) -> None:
        self._delegate = delegate
        self._queries: OrderedDict[str, Mapping[str, Any]] = OrderedDict()
        self.query_hits = 0
        self.query_misses = 0

    @property
    def assembly_id(self) -> str:
        return self._delegate.assembly_id

    @property
    def topology_id(self) -> str:
        return self._delegate.topology_id

    @property
    def start_ns(self) -> int:
        return self._delegate.start_ns

    def context_snapshot(self, context_id: str) -> Mapping[str, Any] | None:
        return self._delegate.context_snapshot(context_id)

    def route_catalog(self) -> Mapping[str, Any]:
        return self._delegate.route_catalog()

    def node_contract(self, node_id: str) -> Mapping[str, Any] | None:
        return self._delegate.node_contract(node_id)

    def normalize_node_queries(
        self, body: Mapping[str, Any]
    ) -> tuple[Mapping[str, Any], ...]:
        return self._delegate.normalize_node_queries(body)

    def normalize_projection_selection(
        self, node_id: str, request: Mapping[str, Any]
    ) -> RouteProjectionSelection:
        return self._delegate.normalize_projection_selection(node_id, request)

    def normalize_basis(self, basis: Any, field: str = "basis") -> dict[str, Any]:
        return self._delegate.normalize_basis(basis, field)

    def capabilities(self) -> dict[str, Any]:
        return self._delegate.capabilities()

    def query(self, body: dict[str, Any]) -> dict[str, Any]:
        # Include every field, including future selectors. Only mapping key order
        # is ignored; ordered node/projection arrays and scalar types stay distinct.
        key = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(key.encode("utf-8")) > self.MAX_KEY_BYTES:
            raise AssertionError("fixed-fixture query exceeds its test key budget")
        snapshot = self._queries.get(key)
        if (
            snapshot is not None
            and self._delegate.context_snapshot(snapshot["context_id"]) is snapshot
        ):
            self.query_hits += 1
            return mutable_json_value(snapshot)

        response = self._delegate.query(body)
        snapshot = self._delegate.context_snapshot(response["context_id"])
        if snapshot is None or mutable_json_value(snapshot) != response:
            raise AssertionError("topology query did not retain its exact wire result")
        self._queries[key] = snapshot
        self._queries.move_to_end(key)
        while len(self._queries) > self.MAX_QUERIES:
            self._queries.popitem(last=False)
        self.query_misses += 1
        return mutable_json_value(snapshot)
