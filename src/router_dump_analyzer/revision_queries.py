"""Reusable bounded queries over one explicitly selected normalized revision.

HTTP adapters parse wire values and resolve access before constructing these
query values. Execution owns no web framework, request context or active
workspace: the caller supplies the dataset, optional history index and core
normalized-data service used for safe resource/event projections.
"""

from __future__ import annotations

import json
import heapq
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, cast
from threading import Lock

from .zoom_density import DensityIndex, adaptive_type_counts

from .cancellation import check_cancellation_probe
from .history_search_core import HistorySearchCapacityError
from .load_progress import AnalysisLoadStage
from .normalized_data import (
    IndexedHistory,
    NormalizedDataCancellationError,
    NormalizedDataService,
    event_redaction_policy,
    redact_event_for_client,
    redact_resource_view,
    resource_id,
)
from .plugin_api import MAX_TIMESTAMP_NS, MIN_TIMESTAMP_NS, ConditionClass
from .source_record_core import (
    project_source_record_for_log,
    record_lanes_for_window,
    source_record_haystack,
)
from .temporal_core import (
    TEMPORAL_ORDER_VERSION,
    possible_relationship_presence,
    relationship_presence,
    temporal_integer,
    temporal_order_key,
)
from .temporal_core import (
    contains_time as _contains_time,
)
from .temporal_core import (
    overlaps_range as _overlaps_window,
)
from .value_core import (
    MAX_JSON_SAFE_INTEGER,
    mutable_json_value,
    snapshot_json_value,
)

_DENSITY_CACHE_LOCK = Lock()


def _density_index(
    owner: Any, revision: str, runtime: Any, checkpoint: Callable[[], None]
) -> DensityIndex:
    # Keep two histories at most; identity prevents reuse across reloads.
    key = (revision, id(runtime))
    with _DENSITY_CACHE_LOCK:
        cache = getattr(owner, "_density_query_indexes", None)
        if cache is None:
            cache = OrderedDict()
            owner._density_query_indexes = cache
        entry = cache.get(key)
        if entry is not None and entry[0] is runtime:
            cache.move_to_end(key)
            return cast(DensityIndex, entry[1])
    failures, types = density_secondary_indexes(runtime, checkpoint=checkpoint)
    index = DensityIndex(runtime.event_times, failures, types)
    checkpoint()
    with _DENSITY_CACHE_LOCK:
        entry = cache.get(key)
        if entry is not None and entry[0] is runtime:
            return cast(DensityIndex, entry[1])
        cache[key] = (runtime, index)
        while len(cache) > 2:
            cache.popitem(last=False)
    return index


MAX_CORRELATION_NODES = 500
MAX_TIMELINE_RESOURCE_LANES = 100
MAX_TIMELINE_GLYPHS = 10_000
MAX_TIMELINE_VIEWPORT_PIXELS = 100_000
MAX_TIMELINE_CLUSTER_DETAIL = 50
MAX_TIMELINE_INTERVAL_DETAILS = 2_000
MAX_TIMELINE_INDEX_UNITS = 8_000_000


_TIMELINE_CACHE_LOCK = Lock()


def _cooperative_sorted(
    items: Iterable[Any], key: Callable[[Any], Any], checkpoint: Callable[[], None]
) -> list[Any]:
    """Bound uninterrupted sorting to small chunks and merge cooperatively."""
    chunks = []
    chunk = []
    for position, item in enumerate(items):
        if position % 256 == 0:
            checkpoint()
        chunk.append(item)
        if len(chunk) == 4096:
            chunks.append(sorted(chunk, key=key))
            chunk = []
            checkpoint()
    if chunk:
        chunks.append(sorted(chunk, key=key))
    result = []
    for position, item in enumerate(heapq.merge(*chunks, key=key)):
        if position % 256 == 0:
            checkpoint()
        result.append(item)
    checkpoint()
    return result


def _timeline_cache(owner: Any, name: str) -> Any:
    # Called only under the cache lock; expensive builds happen outside it.
    cache = getattr(owner, name, None)
    if cache is None:
        cache = OrderedDict()
        setattr(owner, name, cache)
    return cache


def _timeline_index(
    owner: Any,
    revision: Any,
    identifier: str,
    events: Any,
    states: Any,
    checkpoint: Callable[[], None],
    *,
    retain: bool = True,
) -> Any:
    key = (revision, identifier)
    if retain:
        with _TIMELINE_CACHE_LOCK:
            cache = _timeline_cache(owner, "_timeline_query_indexes")
            cached = cache.get(key)
            if cached is not None and cached[0] is events and cached[1] is states:
                cache.move_to_end(key)
                return cached[2]
    ordered = _cooperative_sorted(
        events,
        lambda event: temporal_order_key(
            event, time_field="timestamp_ns", identifier_fields=("event_uid",)
        ),
        checkpoint,
    )
    times: list[int] = []
    uids: dict[str, int] = {}
    failures = [0]
    for position, event in enumerate(ordered):
        if position % 256 == 0:
            checkpoint()
        times.append(int(event["timestamp_ns"]))
        uids[str(event["event_uid"])] = position
        failures.append(failures[-1] + (event.get("outcome") == "failure"))
    changes = _cooperative_sorted(
        (
            int(item["valid_from_ns"])
            for item in states
            if item.get("valid_from_ns") is not None
        ),
        lambda time: time,
        checkpoint,
    )
    value = (ordered, times, failures, changes, uids)
    checkpoint()
    units = len(ordered) * 4 + len(changes)
    if retain and units <= MAX_TIMELINE_INDEX_UNITS:
        with _TIMELINE_CACHE_LOCK:
            cache[key] = (events, states, value, units)
            while (
                len(cache) > MAX_TIMELINE_RESOURCE_LANES * 2
                or sum(item[3] for item in cache.values()) > MAX_TIMELINE_INDEX_UNITS
            ):
                cache.popitem(last=False)
    return value


MAX_DENSITY_BINS = 4_096
MAX_EVENT_LOG_LIMIT = 500
MAX_EVENT_LOG_OFFSET = 10_000_000
MAX_EVENT_LOG_FILTER_VALUES = 64
MAX_EVENT_LOG_FILTER_LENGTH = 128
MAX_EVENT_LOG_SEARCH_LENGTH = 256
MAX_EVENT_LOG_UID_LENGTH = 256


class RevisionQueryRequestError(ValueError):
    """A query value or revision-dependent selection is invalid."""


class RevisionQueryCancellationError(RuntimeError):
    """A query was cancelled or its cancellation probe became unavailable."""


def _integer(value: int, name: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RevisionQueryRequestError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )


def _range(start_ns: int, end_ns: int) -> None:
    _integer(start_ns, "start_ns", MIN_TIMESTAMP_NS, MAX_TIMESTAMP_NS)
    _integer(end_ns, "end_ns", MIN_TIMESTAMP_NS, MAX_TIMESTAMP_NS)
    if end_ns < start_ns:
        raise RevisionQueryRequestError("end_ns must be >= start_ns")


def _names(value: tuple[str, ...], name: str, *, bounded: bool = False) -> None:
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise RevisionQueryRequestError(f"{name} must be a tuple of strings")
    if bounded and (
        len(value) > MAX_EVENT_LOG_FILTER_VALUES
        or any(len(item) > MAX_EVENT_LOG_FILTER_LENGTH for item in value)
    ):
        raise RevisionQueryRequestError(f"{name} exceeds the bounded filter limits")


@dataclass(frozen=True, slots=True)
class CorrelationQuery:
    time_ns: int
    resource_ids: tuple[str, ...] = ()
    relation_types: tuple[str, ...] = ()
    direction: str = "both"
    depth: int = 3
    max_nodes: int = MAX_CORRELATION_NODES

    def __post_init__(self) -> None:
        _integer(self.time_ns, "time_ns", MIN_TIMESTAMP_NS, MAX_TIMESTAMP_NS)
        _names(self.resource_ids, "resource_ids")
        _names(self.relation_types, "relation_types")
        if self.direction not in {"incoming", "outgoing", "both"}:
            raise RevisionQueryRequestError(
                "direction must be incoming, outgoing or both"
            )
        _integer(self.depth, "depth", 0, 20)
        _integer(self.max_nodes, "max_nodes", 1, MAX_CORRELATION_NODES)


@dataclass(frozen=True, slots=True)
class EventDensityQuery:
    """One bounded page in an already normalized global bin partition."""

    start_ns: int
    end_ns: int
    requested_bin_count: int
    bin_count: int
    bin_start_index: int
    bin_end_index: int

    def __post_init__(self) -> None:
        _range(self.start_ns, self.end_ns)
        _integer(
            self.requested_bin_count, "requested_bin_count", 1, MAX_JSON_SAFE_INTEGER
        )
        _integer(
            self.bin_count,
            "bin_count",
            1,
            min(self.requested_bin_count, self.end_ns - self.start_ns + 1),
        )
        _integer(self.bin_start_index, "bin_start_index", 0, self.bin_count - 1)
        _integer(
            self.bin_end_index,
            "bin_end_index",
            self.bin_start_index + 1,
            self.bin_count,
        )
        if self.bin_end_index - self.bin_start_index > MAX_DENSITY_BINS:
            raise RevisionQueryRequestError(
                f"density page must contain at most {MAX_DENSITY_BINS} bins"
            )


@dataclass(frozen=True, slots=True)
class EventLogQuery:
    include_normalized: bool = True
    source_types: tuple[str, ...] | None = None
    layers: tuple[str, ...] = ()
    search: str = ""
    selected_range: tuple[int, int] | None = None
    offset: int = 0
    limit: int = 100
    locate: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        if type(self.include_normalized) is not bool:
            raise RevisionQueryRequestError("include_normalized must be a boolean")
        if self.source_types is not None:
            _names(self.source_types, "source_types", bounded=True)
        _names(self.layers, "layers", bounded=True)
        if (
            type(self.search) is not str
            or len(self.search) > MAX_EVENT_LOG_SEARCH_LENGTH
        ):
            raise RevisionQueryRequestError("search exceeds the bounded string limit")
        if self.selected_range is not None:
            if type(self.selected_range) is not tuple or len(self.selected_range) != 2:
                raise RevisionQueryRequestError(
                    "selected_range must be a pair of timestamps"
                )
            _range(*self.selected_range)
        _integer(self.offset, "offset", 0, MAX_EVENT_LOG_OFFSET)
        _integer(self.limit, "limit", 1, MAX_EVENT_LOG_LIMIT)
        if self.locate is not None and (
            type(self.locate) is not tuple
            or len(self.locate) != 2
            or self.locate[0] not in {"event", "source"}
            or type(self.locate[1]) is not str
            or not 1 <= len(self.locate[1]) <= MAX_EVENT_LOG_UID_LENGTH
        ):
            raise RevisionQueryRequestError("locate must identify one event or source")


@dataclass(frozen=True, slots=True)
class TimelineQuery:
    start_ns: int
    end_ns: int
    resource_ids: tuple[str, ...] = ()
    layers: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    allow_empty: bool = False
    only_with_activity: bool = False
    relationship_history_roots: tuple[str, ...] = ()
    search: str = ""
    cluster_window_ns: int = 20_000_000
    max_glyphs: int = MAX_TIMELINE_GLYPHS
    viewport_pixels: int = MAX_TIMELINE_VIEWPORT_PIXELS
    selected_event_uid: str | None = None
    cursor_time_ns: int | None = None
    selected_range: Mapping[str, Any] | None = None
    record_lane_rules: tuple[Mapping[str, Any], ...] = ()
    max_record_marks: int = 5_000

    def __post_init__(self) -> None:
        _range(self.start_ns, self.end_ns)
        for name in ("resource_ids", "layers", "kinds", "relationship_history_roots"):
            _names(getattr(self, name), name)
        for name in ("allow_empty", "only_with_activity"):
            if type(getattr(self, name)) is not bool:
                raise RevisionQueryRequestError(f"{name} must be a boolean")
        if type(self.search) is not str:
            raise RevisionQueryRequestError("search must be a string")
        _integer(self.cluster_window_ns, "cluster_window_ns", 0, MAX_TIMESTAMP_NS)
        _integer(self.max_glyphs, "max_glyphs", 1, MAX_TIMELINE_GLYPHS)
        _integer(
            self.viewport_pixels, "viewport_pixels", 1, MAX_TIMELINE_VIEWPORT_PIXELS
        )
        _integer(self.max_record_marks, "max_record_marks", 0, 5_000)
        if (
            self.selected_event_uid is not None
            and type(self.selected_event_uid) is not str
        ):
            raise RevisionQueryRequestError(
                "selected_event_uid must be a string or null"
            )
        if self.cursor_time_ns is not None:
            _integer(
                self.cursor_time_ns,
                "cursor_time_ns",
                MIN_TIMESTAMP_NS,
                MAX_TIMESTAMP_NS,
            )
        try:
            if self.selected_range is not None:
                object.__setattr__(
                    self,
                    "selected_range",
                    snapshot_json_value(dict(self.selected_range)),
                )
            object.__setattr__(
                self,
                "record_lane_rules",
                tuple(
                    snapshot_json_value(dict(item)) for item in self.record_lane_rules
                ),
            )
        except (TypeError, ValueError) as error:
            raise RevisionQueryRequestError(str(error)) from error


class RevisionQueryService:
    """Execute transport-independent queries for an explicitly supplied revision.

    The data service supplies existing safe projections and the source's
    revision scope. An explicit index is optional; no private dataset key is
    consulted here. Omit it to use ordinary normalized arrays. The caller must
    supply a dataset and optional index belonging to this revision in the data
    service; this service does not independently attest their correspondence.
    """

    def __init__(
        self,
        data_service: NormalizedDataService,
        *,
        revision_id: str,
        dataset: Mapping[str, Any],
        indexed_history: IndexedHistory | None = None,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> None:
        if not isinstance(revision_id, str) or not revision_id:
            raise ValueError("revision_id must be a non-empty string")
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")
        self.data_service: NormalizedDataService = data_service
        self.revision_id: str = revision_id
        self.dataset: Mapping[str, Any] = dataset
        self.indexed_history: IndexedHistory | None = indexed_history
        self.cancellation_probe: Callable[[], bool] | None = cancellation_probe

    def _checkpoint(self) -> None:
        check_cancellation_probe(
            self.cancellation_probe,
            cancelled_error=lambda: RevisionQueryCancellationError(
                "revision query was cancelled"
            ),
            unavailable_error=lambda: RevisionQueryCancellationError(
                "revision query cancellation state is unavailable"
            ),
            invalid_result_error=lambda: RevisionQueryCancellationError(
                "revision query cancellation probe must return a boolean"
            ),
        )

    def _checked(self, values: Iterable[Any]) -> Iterable[Any]:
        if self.cancellation_probe is None:
            return values

        def checked() -> Iterator[Any]:
            for ordinal, value in enumerate(values):
                if ordinal % 256 == 0:
                    self._checkpoint()
                yield value

        return checked()

    @contextmanager
    def _scope(self) -> Iterator[None]:
        self._checkpoint()
        with self.data_service.revision_scope(self.revision_id):
            yield
        self._checkpoint()

    def graph(self, timestamp_ns: int) -> dict[str, Any]:
        _integer(timestamp_ns, "time_ns", MIN_TIMESTAMP_NS, MAX_TIMESTAMP_NS)
        with self._scope():
            return self._graph_payload(timestamp_ns)

    def correlation(self, query: CorrelationQuery) -> dict[str, Any]:
        with self._scope():
            return self._correlation_payload(query)

    def event_density(self, query: EventDensityQuery) -> dict[str, Any]:
        with self._scope():
            return self._event_density(query)

    def event_log(self, query: EventLogQuery) -> dict[str, Any]:
        with self._scope():
            return self._event_log(query)

    def timeline(self, query: TimelineQuery) -> dict[str, Any]:
        with self._scope():
            return self._timeline(query)

    def warm_event_search(self) -> None:
        """Build the client-safe corpus while reporting core indexing progress."""
        with self._scope():
            self._warm_event_search(self.dataset)

    def search_events(self, search: str) -> Any:
        """Return exact event-index matches from the safe, tracked corpus."""
        query = EventLogQuery(search=search)
        if self.indexed_history is None:
            raise RevisionQueryRequestError("event search requires a history index")
        with self._scope():
            policy = self._event_redaction_policy(self.dataset)
            return self._query_event_search(
                self.dataset, self.indexed_history, policy, query.search.casefold()
            )

    def _event_redaction_policy(self, dataset: Mapping[str, Any]) -> Any:
        try:
            return event_redaction_policy(
                dataset,
                self.indexed_history,
                cancellation_probe=self.cancellation_probe,
            )
        except NormalizedDataCancellationError as error:
            raise RevisionQueryCancellationError(str(error)) from error

    def _redact_event_for_client(
        self,
        event: Mapping[str, Any],
        dataset: Mapping[str, Any],
        *,
        policy: Any = None,
    ) -> dict[str, Any]:
        return redact_event_for_client(
            event, dataset, runtime=self.indexed_history, policy=policy
        )

    def _graph_payload(self, timestamp_ns: int) -> dict[str, Any]:
        dataset = self.dataset
        complete = {
            resource_id(item): item for item in self._checked(dataset["resources"])
        }
        descriptor_index = {
            item["kind"]: item for item in self._checked(dataset["kind_descriptors"])
        }
        active_views = {
            identifier: view
            for identifier in self._checked(complete)
            if (view := self.data_service.resource_state_at(identifier, timestamp_ns))[
                "exists"
            ]
            is not False
        }
        relationships = [
            item
            for item in self._checked(self.data_service.relationships_at(timestamp_ns))
            if item["source"] in active_views and item["target"] in active_views
        ]

        nodes: list[dict[str, Any]] = []
        for identifier in self._checked(sorted(active_views)):
            record = complete.get(identifier)
            view = active_views[identifier]
            nodes.append(
                {
                    "id": identifier,
                    "label": view["label"],
                    "layer": view["layer"],
                    "kind": view["kind"],
                    "exists": view["exists"],
                    "status": view["status_class"],
                    "status_value": view["status"],
                    "state": view["state"],
                    "quality": view["quality"],
                    "state_basis": "selected from temporal resource intervals",
                    "complete_record": record is not None,
                    "presentation_tags": record.get("presentation_tags", [])
                    if record
                    else [],
                    "icon": descriptor_index.get(view["kind"], {}).get("icon"),
                }
            )

        edges = [
            graph_edge_payload(item, item.get("relationship_id", f"edge-{index}"))
            for index, item in self._checked(enumerate(relationships))
        ]
        return {
            "revision_id": self.revision_id,
            "time_ns": str(timestamp_ns),
            "nodes": nodes,
            "edges": edges,
            "incomplete_node_count": sum(
                not node["complete_record"] for node in self._checked(nodes)
            ),
            "note": (
                "Nodes require an active resource lifecycle; edges additionally require "
                "an active relationship interval and two active endpoints. Explicitly "
                "absent relationships are excluded; unknown presence remains ambiguous."
            ),
        }

    def _correlation_payload(self, query: CorrelationQuery) -> dict[str, Any]:
        dataset = self.dataset
        if self.indexed_history is not None:
            return self._indexed_correlation_payload(dataset, query)
        timestamp_ns = query.time_ns
        payload = self._graph_payload(timestamp_ns)
        relation_types = set(query.relation_types)
        edges = [
            edge
            for edge in self._checked(payload["edges"])
            if not relation_types or edge["type"] in relation_types
        ]
        requested_roots = list(query.resource_ids)
        direction, depth, max_nodes = query.direction, query.depth, query.max_nodes
        active_node_ids = {str(node["id"]) for node in self._checked(payload["nodes"])}
        known_node_ids = {
            resource_id(record)
            for record in self._checked(dataset.get("resources", []))
        }
        unknown_roots = [
            identifier
            for identifier in self._checked(requested_roots)
            if identifier not in known_node_ids
        ]
        inactive_roots = [
            identifier
            for identifier in self._checked(requested_roots)
            if identifier in known_node_ids and identifier not in active_node_ids
        ]
        active_roots = [
            identifier
            for identifier in self._checked(requested_roots)
            if identifier in active_node_ids
        ]
        dropped_roots = active_roots[max_nodes:]
        roots = active_roots[:max_nodes]

        if not requested_roots:
            accepted_ids = sorted(active_node_ids)[:max_nodes]
            accepted_set = set(accepted_ids)
            payload["nodes"] = [
                node
                for node in self._checked(payload["nodes"])
                if node["id"] in accepted_set
            ]
            payload["edges"] = [
                edge
                for edge in self._checked(edges)
                if edge["source"] in accepted_set and edge["target"] in accepted_set
            ]
            payload["truncated"] = len(active_node_ids) > max_nodes
            payload["max_nodes"] = max_nodes
            payload["query"] = {
                "resource_ids": [],
                "requested_resource_ids": [],
                "accepted_resource_ids": [],
                "unknown_resource_ids": [],
                "inactive_resource_ids": [],
                "dropped_resource_ids": [],
                "roots_truncated": False,
                "depth": None,
                "direction": direction,
                "relation_types": sorted(relation_types),
            }
            return payload

        reached = set(roots)
        frontier = set(roots)
        truncated = bool(dropped_roots)
        for _ in self._checked(range(depth)):
            following: set[str] = set()
            for edge in self._checked(edges):
                if direction in {"outgoing", "both"} and edge["source"] in frontier:
                    following.add(edge["target"])
                if direction in {"incoming", "both"} and edge["target"] in frontier:
                    following.add(edge["source"])
            following -= reached
            if not following:
                break
            remaining = max_nodes - len(reached)
            if len(following) > remaining:
                following = set(sorted(following)[: max(0, remaining)])
                truncated = True
            if not following:
                break
            reached.update(following)
            frontier = following
        payload["nodes"] = [
            node for node in self._checked(payload["nodes"]) if node["id"] in reached
        ]
        payload["edges"] = [
            edge
            for edge in self._checked(edges)
            if edge["source"] in reached and edge["target"] in reached
        ]
        payload["truncated"] = truncated
        payload["max_nodes"] = max_nodes
        payload["query"] = {
            "resource_ids": roots,
            "requested_resource_ids": requested_roots,
            "accepted_resource_ids": roots,
            "unknown_resource_ids": unknown_roots,
            "inactive_resource_ids": inactive_roots,
            "dropped_resource_ids": dropped_roots,
            "roots_truncated": bool(dropped_roots),
            "depth": depth,
            "direction": direction,
            "relation_types": sorted(relation_types),
        }
        return payload

    def _indexed_correlation_payload(
        self,
        dataset: Mapping[str, Any],
        query: CorrelationQuery,
    ) -> dict[str, Any]:
        """Return a bounded, time-valid neighborhood from the scale indexes."""

        runtime = self.indexed_history
        if runtime is None:
            raise RuntimeError("history indexes are unavailable")
        timestamp_ns = query.time_ns
        direction, depth, max_nodes = query.direction, query.depth, query.max_nodes
        relation_types = set(query.relation_types)
        requested_roots = list(query.resource_ids)
        defaulted = not requested_roots
        if defaulted:
            requested_roots = runtime.initial_resource_ids[:4]
        known_roots = [
            identifier
            for identifier in self._checked(requested_roots)
            if identifier in runtime.resource_by_id
        ]
        unknown_roots = [
            identifier
            for identifier in self._checked(requested_roots)
            if identifier not in runtime.resource_by_id
        ]
        active_roots = [
            identifier
            for identifier in self._checked(known_roots)
            if indexed_resource_exists(runtime, identifier, timestamp_ns)
        ]
        active_root_set = set(active_roots)
        inactive_roots = [
            identifier
            for identifier in self._checked(known_roots)
            if identifier not in active_root_set
        ]
        roots = active_roots[:max_nodes]
        dropped_roots = active_roots[max_nodes:]
        reached = set(roots)
        frontier = set(roots)
        truncated = bool(dropped_roots)
        for _ in self._checked(range(depth)):
            following: set[str] = set()
            for identifier in self._checked(frontier):
                for relationship in self._checked(
                    runtime.relationships_by_endpoint.get(identifier, [])
                ):
                    if relationship_presence(relationship) is False:
                        continue
                    relation_type = relationship.get(
                        "relation_type",
                        relationship.get("type", "related_to"),
                    )
                    if relation_types and relation_type not in relation_types:
                        continue
                    if not _contains_time(
                        timestamp_ns,
                        relationship.get("valid_from_ns"),
                        relationship.get("valid_to_ns"),
                    ):
                        continue
                    source = relationship["source"]
                    target = relationship["target"]
                    other: str | None = None
                    if direction in {"outgoing", "both"} and source == identifier:
                        other = target
                    elif direction in {"incoming", "both"} and target == identifier:
                        other = source
                    if (
                        other
                        and other not in reached
                        and indexed_resource_exists(runtime, other, timestamp_ns)
                    ):
                        following.add(other)
            following -= reached
            remaining = max_nodes - len(reached)
            if len(following) > remaining:
                following = set(sorted(following)[: max(0, remaining)])
                truncated = True
            if not following:
                break
            reached.update(following)
            frontier = following

        edge_records: dict[str, dict[str, Any]] = {}
        for identifier in self._checked(reached):
            for relationship in self._checked(
                runtime.relationships_by_endpoint.get(identifier, [])
            ):
                if relationship_presence(relationship) is False:
                    continue
                source = relationship["source"]
                target = relationship["target"]
                relation_type = relationship.get(
                    "relation_type",
                    relationship.get("type", "related_to"),
                )
                if source not in reached or target not in reached:
                    continue
                if relation_types and relation_type not in relation_types:
                    continue
                if not _contains_time(
                    timestamp_ns,
                    relationship.get("valid_from_ns"),
                    relationship.get("valid_to_ns"),
                ):
                    continue
                key = str(
                    relationship.get(
                        "relationship_id",
                        f"{source}|{relation_type}|{target}|{relationship.get('valid_from_ns')}",
                    )
                )
                edge_records[key] = relationship

        descriptor_index = {
            item["kind"]: item for item in self._checked(dataset["kind_descriptors"])
        }
        nodes: list[dict[str, Any]] = []
        for identifier in self._checked(sorted(reached)):
            view = self.data_service.resource_state_at(identifier, timestamp_ns)
            if view["exists"] is False:
                continue
            record = runtime.resource_by_id[identifier]
            nodes.append(
                {
                    "id": identifier,
                    "label": view["label"],
                    "layer": view["layer"],
                    "kind": view["kind"],
                    "exists": view["exists"],
                    "status": view["status_class"],
                    "status_value": view["status"],
                    "state": view["state"],
                    "quality": view["quality"],
                    "state_basis": "selected from full-scale temporal indexes",
                    "complete_record": True,
                    "presentation_tags": record.get("presentation_tags", []),
                    "icon": descriptor_index.get(view["kind"], {}).get("icon"),
                }
            )
        node_ids = {node["id"] for node in self._checked(nodes)}
        edges = [
            graph_edge_payload(
                item, key, temporal_note="selected from full-scale validity interval"
            )
            for key, item in self._checked(sorted(edge_records.items()))
            if item["source"] in node_ids and item["target"] in node_ids
        ]
        return {
            "revision_id": self.revision_id,
            "time_ns": str(timestamp_ns),
            "nodes": nodes,
            "edges": edges,
            "incomplete_node_count": 0,
            "truncated": truncated,
            "max_nodes": max_nodes,
            "query": {
                "resource_ids": roots,
                "requested_resource_ids": requested_roots,
                "accepted_resource_ids": roots,
                "unknown_resource_ids": unknown_roots,
                "inactive_resource_ids": inactive_roots,
                "dropped_resource_ids": dropped_roots,
                "roots_truncated": bool(dropped_roots),
                "depth": depth,
                "direction": direction,
                "relation_types": sorted(relation_types),
                "defaulted_to_representative_roots": defaulted,
            },
            "note": (
                "Time-valid full-scale neighborhood; the response is capped at "
                f"{max_nodes} nodes for browser layout safety."
            ),
        }

    def _indexed_event_search_documents(
        self,
        dataset: Mapping[str, Any],
        runtime: Any,
        policy: Any,
    ) -> Iterator[str]:
        """Yield the exact case-folded, client-safe event search projection."""

        for event in self._checked(runtime.events):
            projected = self._redact_event_for_client(event, dataset, policy=policy)
            yield json.dumps(
                projected,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).casefold()

    def _warm_event_search(self, dataset: Mapping[str, Any]) -> None:
        """Build one immutable revision's safe corpus under tracked indexing."""

        runtime = self.indexed_history
        if runtime is None:
            return
        policy = self._event_redaction_policy(dataset)
        with getattr(self.data_service, "_loading_operation")(
            AnalysisLoadStage.INDEXING
        ):
            try:
                runtime.event_search.ensure(
                    lambda: self._indexed_event_search_documents(
                        dataset, runtime, policy
                    )
                )
            except HistorySearchCapacityError:
                # Exact queries retain the compatible streaming fallback when a
                # future input exceeds the bounded serving corpus.  Capacity is a
                # supported outcome, so the progress operation completes rather
                # than presenting it as a dump-load failure.
                return

    def _query_event_search(
        self,
        dataset: Mapping[str, Any],
        runtime: Any,
        policy: Any,
        search: str,
    ) -> Any:
        """Run a first-use corpus build and query as one visible core operation."""

        capacity_error: HistorySearchCapacityError | None = None
        matches = None
        with getattr(self.data_service, "_loading_operation")(
            AnalysisLoadStage.INDEXING
        ):
            try:
                matches = runtime.event_search.query(
                    search,
                    lambda: self._indexed_event_search_documents(
                        dataset, runtime, policy
                    ),
                )
            except HistorySearchCapacityError as error:
                # Raise only after the operation has completed successfully so
                # the caller can select its exact streaming fallback without a
                # stale FAILED progress banner.
                capacity_error = error
        if capacity_error is not None:
            raise capacity_error
        return matches

    def _indexed_event_search_log_page(
        self,
        *,
        revision_id: str,
        dataset: Mapping[str, Any],
        runtime: Any,
        search: str,
        layers: set[str],
        selected_range: tuple[int, int] | None,
        offset: int,
        limit: int,
        locate: tuple[str, str] | None,
        policy: Any,
    ) -> dict[str, Any]:
        """Page one exact indexed scale search without rebuilding a full merge."""

        matches = self._query_event_search(dataset, runtime, policy, search)
        if layers:
            filtered_matches = [
                index
                for index in self._checked(matches)
                if event_layer_values(runtime.events[index]) & layers
            ]
        else:
            filtered_matches = matches

        event_times = runtime.event_times
        total_count = len(filtered_matches)
        if selected_range is None:
            event_left = 0
            event_right = len(runtime.events)
            match_left = 0
            match_right = total_count
            inside_count = 0
        else:
            event_left = bisect_left(event_times, selected_range[0])
            event_right = bisect_right(event_times, selected_range[1])
            match_left = bisect_left(filtered_matches, event_left)
            match_right = bisect_left(filtered_matches, event_right)
            inside_count = match_right - match_left
        outside_count = total_count - inside_count

        def event_index(display_index: int) -> int:
            if selected_range is None:
                return int(filtered_matches[display_index])
            if display_index < inside_count:
                return int(filtered_matches[match_left + display_index])
            before_index = display_index - inside_count
            if before_index < match_left:
                return int(filtered_matches[before_index])
            return int(filtered_matches[match_right + before_index - match_left])

        located_display_index = None
        if locate is not None and locate[0] == "event":
            target_index = runtime.event_index_by_uid.get(locate[1])
            if target_index is None:
                target = runtime.event_by_uid.get(locate[1])
                if target is not None:
                    target_time = int(target.get("timestamp_ns", 0))
                    same_time_start = bisect_left(event_times, target_time)
                    same_time_end = bisect_right(event_times, target_time)
                    target_index = next(
                        (
                            index
                            for index in self._checked(
                                range(same_time_start, same_time_end)
                            )
                            if str(
                                runtime.events[index].get("event_uid")
                                or runtime.events[index].get("event_id")
                            )
                            == locate[1]
                        ),
                        None,
                    )
            if target_index is not None:
                position = bisect_left(filtered_matches, target_index)
                if (
                    position < total_count
                    and int(filtered_matches[position]) == target_index
                ):
                    if selected_range is None:
                        located_display_index = position
                    elif match_left <= position < match_right:
                        located_display_index = position - match_left
                    elif position < match_left:
                        located_display_index = inside_count + position
                    else:
                        located_display_index = (
                            inside_count + match_left + position - match_right
                        )

        page_end = min(total_count, offset + limit)
        items: list[dict[str, Any]] = []
        for display_index in self._checked(range(offset, page_end)):
            event = runtime.events[event_index(display_index)]
            timestamp_ns = int(event.get("timestamp_ns", 0))
            if selected_range is None:
                membership = "all"
            else:
                membership = (
                    "inside"
                    if selected_range[0] <= timestamp_ns <= selected_range[1]
                    else "outside"
                )
            uid = str(event.get("event_uid") or event.get("event_id"))
            items.append(
                {
                    "display_index": display_index,
                    "stream_kind": "event",
                    "uid": uid,
                    "timestamp_ns": str(timestamp_ns),
                    "membership": membership,
                    "in_selected_range": (
                        None if selected_range is None else membership == "inside"
                    ),
                    "entry": self._redact_event_for_client(
                        event, dataset, policy=policy
                    ),
                }
            )

        next_offset = offset + len(items)
        return {
            "revision_id": revision_id,
            "selected_range": (
                None
                if selected_range is None
                else {
                    "start_ns": str(selected_range[0]),
                    "end_ns": str(selected_range[1]),
                }
            ),
            "include_normalized": True,
            "source_types": [],
            "layers": sorted(layers),
            "total_count": total_count,
            "inside_count": inside_count,
            "outside_count": outside_count,
            "returned_count": len(items),
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset if next_offset < total_count else None,
            "located_display_index": located_display_index,
            "items": items,
            "indexed_fast_path": True,
            "indexed_search": True,
        }

    def _indexed_event_only_log_page(
        self,
        *,
        revision_id: str,
        dataset: Mapping[str, Any],
        runtime: Any,
        selected_range: tuple[int, int] | None,
        offset: int,
        limit: int,
        locate: tuple[str, str] | None,
        policy: Any,
    ) -> dict[str, Any]:
        """Page the common event-only scale query without materializing 125K tuples.

        The normalized scale stream and its timestamp index are already ordered.
        Range-first display order is therefore three contiguous slices (inside,
        before, after), so both paging and exact counts stay O(page size + log N).
        Plug-in event payloads are still redacted only for the bounded return page.
        """

        events = runtime.events
        event_times = runtime.event_times
        total_count = len(events)
        if selected_range is None:
            left = 0
            right = total_count
            inside_count = 0
        else:
            left = bisect_left(event_times, selected_range[0])
            right = bisect_right(event_times, selected_range[1])
            inside_count = right - left
        outside_count = total_count - inside_count

        def original_index(display_index: int) -> int:
            if selected_range is None:
                return display_index
            if display_index < inside_count:
                return left + display_index
            before_index = display_index - inside_count
            if before_index < left:
                return before_index
            return right + before_index - left

        located_display_index = None
        if locate is not None and locate[0] == "event":
            target = runtime.event_by_uid.get(locate[1])
            if target is not None:
                target_time = int(target.get("timestamp_ns", 0))
                same_time_start = bisect_left(event_times, target_time)
                same_time_end = bisect_right(event_times, target_time)
                target_index = next(
                    (
                        index
                        for index in self._checked(
                            range(same_time_start, same_time_end)
                        )
                        if str(
                            events[index].get("event_uid")
                            or events[index].get("event_id")
                        )
                        == locate[1]
                    ),
                    None,
                )
                if target_index is not None:
                    if selected_range is None:
                        located_display_index = target_index
                    elif left <= target_index < right:
                        located_display_index = target_index - left
                    elif target_index < left:
                        located_display_index = inside_count + target_index
                    else:
                        located_display_index = (
                            inside_count + left + target_index - right
                        )

        page_end = min(total_count, offset + limit)
        items: list[dict[str, Any]] = []
        for display_index in self._checked(range(offset, page_end)):
            event = events[original_index(display_index)]
            timestamp_ns = int(event.get("timestamp_ns", 0))
            if selected_range is None:
                membership = "all"
            else:
                membership = (
                    "inside"
                    if selected_range[0] <= timestamp_ns <= selected_range[1]
                    else "outside"
                )
            uid = str(event.get("event_uid") or event.get("event_id"))
            items.append(
                {
                    "display_index": display_index,
                    "stream_kind": "event",
                    "uid": uid,
                    "timestamp_ns": str(timestamp_ns),
                    "membership": membership,
                    "in_selected_range": (
                        None if selected_range is None else membership == "inside"
                    ),
                    "entry": self._redact_event_for_client(
                        event, dataset, policy=policy
                    ),
                }
            )
        next_offset = offset + len(items)
        return {
            "revision_id": revision_id,
            "selected_range": (
                None
                if selected_range is None
                else {
                    "start_ns": str(selected_range[0]),
                    "end_ns": str(selected_range[1]),
                }
            ),
            "include_normalized": True,
            "source_types": [],
            "layers": [],
            "total_count": total_count,
            "inside_count": inside_count,
            "outside_count": outside_count,
            "returned_count": len(items),
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset if next_offset < total_count else None,
            "located_display_index": located_display_index,
            "items": items,
            "indexed_fast_path": True,
        }

    def _effective_relationship_intervals(
        self,
        dataset: Mapping[str, Any],
        lane_ids: set[str],
        query_start_ns: int,
        query_end_ns: int,
    ) -> list[dict[str, Any]]:
        """Project relationships onto the overlapping lifecycles of both endpoints."""

        runtime = self.indexed_history
        if runtime is not None:
            lifecycle_by_resource = cast(
                dict[str, list[dict[str, Any]]], runtime.lifecycle_by_resource
            )
            candidate_map: dict[str, dict[str, Any]] = {}
            for identifier in self._checked(lane_ids):
                for relationship in self._checked(
                    runtime.relationships_by_endpoint.get(identifier, [])
                ):
                    if (
                        relationship["source"] not in lane_ids
                        or relationship["target"] not in lane_ids
                    ):
                        continue
                    key = str(
                        relationship.get(
                            "relationship_id",
                            f"{relationship['source']}|{relationship['relation_type']}|"
                            f"{relationship['target']}|{relationship.get('valid_from_ns')}",
                        )
                    )
                    candidate_map[key] = relationship
            relationship_candidates = list(candidate_map.values())
        else:
            lifecycle_by_resource = {}
            for lifecycle in self._checked(dataset["lifecycle_intervals"]):
                if lifecycle["resource"] not in lifecycle_by_resource:
                    lifecycle_by_resource[lifecycle["resource"]] = []
                lifecycle_by_resource[lifecycle["resource"]].append(lifecycle)
            relationship_candidates = dataset["relationship_intervals"]
        descriptors = {
            item["relation_type"]: item
            for item in self._checked(dataset["relationship_descriptors"])
        }
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str | None, str | None]] = set()
        for relationship in self._checked(relationship_candidates):
            source = relationship["source"]
            target = relationship["target"]
            if source not in lane_ids or target not in lane_ids:
                continue
            source_lifecycles = lifecycle_by_resource.get(source, [])
            target_lifecycles = lifecycle_by_resource.get(target, [])
            for source_lifecycle in self._checked(source_lifecycles):
                for target_lifecycle in self._checked(target_lifecycles):
                    start_candidates = [
                        (
                            relationship.get("valid_from_ns"),
                            relationship.get("start_event_uid"),
                            "relationship",
                        ),
                        (
                            source_lifecycle.get("valid_from_ns"),
                            source_lifecycle.get("start_event_uid"),
                            "source_lifecycle",
                        ),
                        (
                            target_lifecycle.get("valid_from_ns"),
                            target_lifecycle.get("start_event_uid"),
                            "target_lifecycle",
                        ),
                    ]
                    finite_starts = [
                        item
                        for item in self._checked(start_candidates)
                        if item[0] is not None
                    ]
                    effective_start = (
                        max(finite_starts, key=lambda item: int(item[0]))
                        if finite_starts
                        else (None, None, "open")
                    )
                    end_candidates = [
                        (
                            relationship.get("valid_to_ns"),
                            relationship.get("end_event_uid"),
                            "relationship",
                        ),
                        (
                            source_lifecycle.get("valid_to_ns"),
                            source_lifecycle.get("end_event_uid"),
                            "source_lifecycle",
                        ),
                        (
                            target_lifecycle.get("valid_to_ns"),
                            target_lifecycle.get("end_event_uid"),
                            "target_lifecycle",
                        ),
                    ]
                    finite_ends = [
                        item
                        for item in self._checked(end_candidates)
                        if item[0] is not None
                    ]
                    effective_end = (
                        min(finite_ends, key=lambda item: int(item[0]))
                        if finite_ends
                        else (None, None, "open")
                    )
                    start_ns = effective_start[0]
                    end_ns = effective_end[0]
                    if (
                        start_ns is not None
                        and end_ns is not None
                        and int(start_ns) >= int(end_ns)
                    ):
                        continue
                    if not _overlaps_window(
                        start_ns,
                        end_ns,
                        query_start_ns,
                        query_end_ns,
                    ):
                        continue
                    segment_key = (
                        str(relationship.get("relationship_id", "")),
                        str(start_ns) if start_ns is not None else None,
                        str(end_ns) if end_ns is not None else None,
                    )
                    if segment_key in seen:
                        continue
                    seen.add(segment_key)
                    relation_type = relationship["relation_type"]
                    result.append(
                        {
                            **relationship,
                            "relationship_valid_from_ns": relationship.get(
                                "valid_from_ns"
                            ),
                            "relationship_valid_to_ns": relationship.get("valid_to_ns"),
                            "relationship_start_event_uid": relationship.get(
                                "start_event_uid"
                            ),
                            "relationship_end_event_uid": relationship.get(
                                "end_event_uid"
                            ),
                            "valid_from_ns": start_ns,
                            "valid_to_ns": end_ns,
                            "start_ns": start_ns,
                            "end_ns": end_ns,
                            "start_event_uid": effective_start[1],
                            "end_event_uid": effective_end[1],
                            "effective_start_source": effective_start[2],
                            "effective_end_source": effective_end[2],
                            "duration_ns": interval_duration(start_ns, end_ns),
                            "descriptor": descriptors.get(relation_type),
                        }
                    )
        result.sort(
            key=lambda item: (
                item["relation_type"],
                item["source"],
                item["target"],
                int(item.get("valid_from_ns") or -1),
            )
        )
        return result

    def _relationship_mutations_in_window(
        self,
        dataset: Mapping[str, Any],
        lane_ids: set[str],
        query_start_ns: int,
        query_end_ns: int,
    ) -> list[dict[str, Any]]:
        descriptors = {
            item["relation_type"]: item
            for item in self._checked(dataset["relationship_descriptors"])
        }
        runtime = self.indexed_history
        if runtime is not None:
            candidate_map: dict[str, dict[str, Any]] = {}
            for identifier in self._checked(lane_ids):
                for mutation in self._checked(
                    runtime.mutations_by_endpoint.get(identifier, [])
                ):
                    key = str(
                        mutation.get(
                            "mutation_id",
                            f"{mutation['source']}|{mutation['relation_type']}|"
                            f"{mutation['target']}|{mutation['effective_time_ns']}|"
                            f"{mutation['operation']}",
                        )
                    )
                    candidate_map[key] = mutation
            mutation_candidates = candidate_map.values()
        else:
            mutation_candidates = dataset["relationship_mutations"]
        result = [
            {
                **item,
                "descriptor": descriptors.get(item["relation_type"]),
                "event_uid": item.get("cause_event_uid"),
            }
            for item in self._checked(mutation_candidates)
            if item["source"] in lane_ids
            and item["target"] in lane_ids
            and query_start_ns <= int(item["effective_time_ns"]) <= query_end_ns
        ]
        result.sort(
            key=lambda item: (
                int(item["effective_time_ns"]),
                item["relation_type"],
                item["source"],
                item["target"],
                item["operation"],
            )
        )
        return result

    def _event_density(self, query: EventDensityQuery) -> dict[str, Any]:
        revision_id = self.revision_id
        start_ns, end_ns = query.start_ns, query.end_ns
        integer_span = end_ns - start_ns + 1
        requested_bin_count, bin_count = query.requested_bin_count, query.bin_count
        bin_start_index, bin_end_index = query.bin_start_index, query.bin_end_index
        dataset = self.dataset
        runtime = self.indexed_history
        if runtime is not None:
            density = _density_index(
                self.data_service, revision_id, runtime, self._checkpoint
            )
            total_count = bisect_right(runtime.event_times, end_ns) - bisect_left(
                runtime.event_times, start_ns
            )
            summaries = density.page(
                start_ns=start_ns,
                integer_span=integer_span,
                bin_count=bin_count,
                bin_start_index=bin_start_index,
                bin_end_index=bin_end_index,
                checkpoint=self._checkpoint,
            )
            response_bins: list[dict[str, Any]] = []
            for index, summary in self._checked(summaries.items()):
                bin_start_ns, bin_end_ns = density_bin_bounds(
                    start_ns, integer_span, bin_count, index
                )
                response_bins.append(
                    {
                        "index": index,
                        "start_ns": str(bin_start_ns),
                        "end_ns": str(bin_end_ns),
                        "count": summary.count,
                        "failure_count": summary.failure_count,
                        "top_types": [
                            {"event_type": name, "count": amount}
                            for name, amount in sorted(
                                summary.type_counts.items(),
                                key=lambda item: (-item[1], item[0]),
                            )[:4]
                        ],
                    }
                )
        else:
            selected_events = [
                event
                for event in self._checked(dataset.get("events", []))
                if start_ns <= int(event.get("timestamp_ns", 0)) <= end_ns
            ]
            total_count = len(selected_events)

            # The sparse map keeps response and aggregation memory proportional to
            # populated bins, never to the requested timeline resolution.
            bins: dict[int, dict[str, Any]] = {}
            for event in self._checked(selected_events):
                timestamp_ns = int(event.get("timestamp_ns", 0))
                index = density_bin_index(
                    timestamp_ns,
                    start_ns,
                    integer_span,
                    bin_count,
                )
                if index < bin_start_index or index >= bin_end_index:
                    continue
                aggregate = bins.setdefault(
                    index,
                    {
                        "count": 0,
                        "failure_count": 0,
                        "types": Counter(),
                    },
                )
                aggregate["count"] += 1
                if str(event.get("outcome", "")) == "failure":
                    aggregate["failure_count"] += 1
                event_type = str(
                    event.get("event_type") or event.get("event_name") or "unknown"
                )
                aggregate["types"][event_type] += 1

            response_bins = []
            for index, aggregate in self._checked(sorted(bins.items())):
                bin_start_ns, bin_end_ns = density_bin_bounds(
                    start_ns,
                    integer_span,
                    bin_count,
                    index,
                )
                response_bins.append(
                    {
                        "index": index,
                        "start_ns": str(bin_start_ns),
                        "end_ns": str(bin_end_ns),
                        "count": aggregate["count"],
                        "failure_count": aggregate["failure_count"],
                        "top_types": [
                            {"event_type": event_type, "count": count}
                            for event_type, count in self._checked(
                                sorted(
                                    aggregate["types"].items(),
                                    key=lambda item: (-item[1], item[0]),
                                )[:4]
                            )
                        ],
                    }
                )
        return {
            "revision_id": revision_id,
            "start_ns": str(start_ns),
            "end_ns": str(end_ns),
            "requested_bin_count": requested_bin_count,
            "bin_count": bin_count,
            "bin_start_index": bin_start_index,
            "bin_end_index": bin_end_index,
            "total_count": total_count,
            "indexed": runtime is not None,
            "bins": response_bins,
        }

    def _event_log(self, query: EventLogQuery) -> dict[str, Any]:
        dataset, revision_id = self.dataset, self.revision_id
        include_normalized = query.include_normalized
        source_types_supplied = query.source_types is not None
        source_types = list(query.source_types or ())
        layers = set(query.layers)
        search = query.search.casefold()
        selected_range, offset, limit, locate = (
            query.selected_range,
            query.offset,
            query.limit,
            query.locate,
        )
        source_records = dataset.get("source_records", [])
        known_source_types = {
            str(item["source_type"])
            for item in self._checked(dataset.get("source_record_descriptors", []))
            if isinstance(item, dict) and item.get("source_type")
        }
        known_source_types.update(
            str(item["source_type"])
            for item in self._checked(source_records)
            if isinstance(item, dict) and item.get("source_type")
        )
        if source_types_supplied:
            unknown_source_types = set(source_types) - known_source_types
            if unknown_source_types:
                raise RevisionQueryRequestError(
                    "event-log query references unknown source types: "
                    + ", ".join(sorted(unknown_source_types))
                )
        selected_source_types = set(source_types)
        policy = self._event_redaction_policy(dataset)
        runtime = self.indexed_history
        if (
            runtime is not None
            and include_normalized
            and source_types_supplied
            and not selected_source_types
        ):
            if search:
                try:
                    return self._indexed_event_search_log_page(
                        revision_id=revision_id,
                        dataset=dataset,
                        runtime=runtime,
                        search=search,
                        layers=layers,
                        selected_range=selected_range,
                        offset=offset,
                        limit=limit,
                        locate=locate,
                        policy=policy,
                    )
                except HistorySearchCapacityError:
                    pass
            elif not layers:
                return self._indexed_event_only_log_page(
                    revision_id=revision_id,
                    dataset=dataset,
                    runtime=runtime,
                    selected_range=selected_range,
                    offset=offset,
                    limit=limit,
                    locate=locate,
                    policy=policy,
                )

        # Candidate tuple: group rank, timestamp, source sequence, stable prefixed
        # id, stream kind, raw uid, membership, raw entry. Event projections are
        # deliberately not retained for all 100K+ rows; they are redacted before
        # search and again only for the bounded return page.
        candidates: list[
            tuple[int, int | None, int, str, str, str, str, dict[str, Any]]
        ] = []
        inside_count = 0

        def optional_timestamp(entry: Mapping[str, Any]) -> int | None:
            value = entry.get("timestamp_ns")
            return None if value is None else temporal_integer(value, "timestamp_ns")

        def append_candidate(
            *,
            stream_kind: str,
            uid: str,
            timestamp_ns: int | None,
            entry: dict[str, Any],
        ) -> None:
            nonlocal inside_count
            if selected_range is None:
                membership = "all"
                group_rank = 0
            else:
                in_range = (
                    timestamp_ns is not None
                    and selected_range[0] <= timestamp_ns <= selected_range[1]
                )
                membership = "inside" if in_range else "outside"
                group_rank = 0 if in_range else 1
                if in_range:
                    inside_count += 1
            stable_id = f"{stream_kind}:{uid}"
            source_sequence = temporal_integer(
                entry.get("source_sequence", 0),
                "source_sequence",
            )
            candidates.append(
                (
                    group_rank,
                    timestamp_ns,
                    source_sequence,
                    stable_id,
                    stream_kind,
                    uid,
                    membership,
                    entry,
                )
            )

        if include_normalized:
            event_source = (
                runtime.events if runtime is not None else dataset.get("events", [])
            )
            indexed_event_search = False
            if runtime is not None and search:
                try:
                    event_indices = self._query_event_search(
                        dataset,
                        runtime,
                        policy,
                        search,
                    )
                    indexed_event_search = True
                except HistorySearchCapacityError:
                    event_indices = range(len(event_source))
            else:
                event_indices = range(len(event_source))
            for index in self._checked(event_indices):
                event = event_source[index]
                if layers and not (event_layer_values(event) & layers):
                    continue
                projected = None
                if search and not indexed_event_search:
                    projected = self._redact_event_for_client(
                        event, dataset, policy=policy
                    )
                    search_text = json.dumps(
                        projected,
                        sort_keys=True,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).casefold()
                    if search not in search_text:
                        continue
                uid = str(
                    event.get("event_uid") or event.get("event_id") or f"event-{index}"
                )
                append_candidate(
                    stream_kind="event",
                    uid=uid,
                    timestamp_ns=optional_timestamp(event),
                    entry=event,
                )

        if not source_types_supplied or selected_source_types:
            for index, record in self._checked(enumerate(source_records)):
                if (
                    source_types_supplied
                    and str(record.get("source_type")) not in selected_source_types
                ):
                    continue
                if layers and str(record.get("layer", "unknown")) not in layers:
                    continue
                if search and search not in source_record_haystack(record).casefold():
                    continue
                uid = str(
                    record.get("source_record_uid")
                    or record.get("record_uid")
                    or f"source-{index}"
                )
                append_candidate(
                    stream_kind="source",
                    uid=uid,
                    timestamp_ns=optional_timestamp(record),
                    entry=record,
                )

        # Untimed rows remain selectable after all timed rows in their group.
        # The sort-only zero is never exposed as a timestamp or used for range
        # membership; negative revision-relative instants retain their order.
        candidates.sort(
            key=lambda item: (
                item[0],
                item[1] is None,
                item[1] if item[1] is not None else 0,
                item[2],
                item[3],
            )
        )
        total_count = len(candidates)
        outside_count = total_count - inside_count
        located_display_index = None
        if locate is not None:
            located_display_index = next(
                (
                    index
                    for index, candidate in self._checked(enumerate(candidates))
                    if candidate[4] == locate[0] and candidate[5] == locate[1]
                ),
                None,
            )

        selected = candidates[offset : offset + limit]
        items: list[dict[str, Any]] = []
        for display_index, candidate in self._checked(
            enumerate(selected, start=offset)
        ):
            (
                _,
                timestamp_ns,
                _,
                _,
                stream_kind,
                uid,
                membership,
                entry,
            ) = candidate
            safe_entry = (
                self._redact_event_for_client(entry, dataset, policy=policy)
                if stream_kind == "event"
                else project_source_record_for_log(entry)
            )
            items.append(
                {
                    "display_index": display_index,
                    "stream_kind": stream_kind,
                    "uid": uid,
                    "timestamp_ns": str(timestamp_ns)
                    if timestamp_ns is not None
                    else None,
                    "membership": membership,
                    "in_selected_range": (
                        None if selected_range is None else membership == "inside"
                    ),
                    "entry": safe_entry,
                }
            )
        next_offset = offset + len(items)
        return {
            "revision_id": revision_id,
            "selected_range": (
                None
                if selected_range is None
                else {
                    "start_ns": str(selected_range[0]),
                    "end_ns": str(selected_range[1]),
                }
            ),
            "include_normalized": include_normalized,
            "source_types": source_types if source_types_supplied else None,
            "layers": sorted(layers),
            "total_count": total_count,
            "inside_count": inside_count,
            "outside_count": outside_count,
            "returned_count": len(items),
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset if next_offset < total_count else None,
            "located_display_index": located_display_index,
            "items": items,
        }

    def _timeline(self, query: TimelineQuery) -> dict[str, Any]:
        dataset, revision_id = self.dataset, self.revision_id
        start_ns, end_ns = query.start_ns, query.end_ns
        layers, kinds = set(query.layers), set(query.kinds)
        requested_id_values = list(query.resource_ids)
        originally_requested_ids = list(requested_id_values)
        allow_empty, only_with_activity = query.allow_empty, query.only_with_activity
        runtime = self.indexed_history
        if runtime is not None and not requested_id_values and not allow_empty:
            requested_id_values = list(dict.fromkeys(runtime.initial_resource_ids))
        history_roots = list(query.relationship_history_roots)
        history_candidate_ids: list[str] = []
        history_expanded_ids: list[str] = []
        history_dropped_ids: list[str] = []
        history_accepted_roots: list[str] = []
        history_dropped_roots: list[str] = []
        history_unknown_roots: list[str] = []
        accepted_base_ids = list(requested_id_values)
        dropped_base_ids: list[str] = []
        if runtime is not None and history_roots:
            history_unknown_roots = [
                identifier
                for identifier in self._checked(history_roots)
                if identifier not in runtime.resource_by_id
            ]
            valid_history_roots = [
                identifier
                for identifier in self._checked(history_roots)
                if identifier in runtime.resource_by_id
            ]
            expanded: set[str] = set()
            for identifier in self._checked(valid_history_roots):
                for relationship in self._checked(
                    runtime.relationships_by_endpoint.get(identifier, [])
                ):
                    if not _overlaps_window(
                        relationship.get("valid_from_ns"),
                        relationship.get("valid_to_ns"),
                        start_ns,
                        end_ns,
                    ):
                        continue
                    for endpoint in self._checked(
                        (
                            str(relationship["source"]),
                            str(relationship["target"]),
                        )
                    ):
                        if (
                            endpoint != identifier
                            and endpoint in runtime.resource_by_id
                        ):
                            expanded.add(endpoint)
            base_ids = list(
                dict.fromkeys(
                    identifier
                    for identifier in self._checked(
                        [*requested_id_values, *valid_history_roots]
                    )
                    if identifier in runtime.resource_by_id
                )
            )
            history_candidate_ids = sorted(expanded.difference(base_ids))
            # Expansion is useful only if at least one dependency lane survives the
            # global safety cap. Split the capacity deterministically between the
            # requested/root lanes and discovered endpoints, and disclose every
            # omitted identity instead of claiming that it was rendered.
            reserve = min(
                len(history_candidate_ids),
                max(1, MAX_TIMELINE_RESOURCE_LANES // 2),
            )
            base_capacity = MAX_TIMELINE_RESOURCE_LANES - reserve
            accepted_base = base_ids[:base_capacity]
            accepted_base_ids = accepted_base
            dropped_base_ids = base_ids[base_capacity:]
            history_accepted_roots = [
                identifier
                for identifier in self._checked(valid_history_roots)
                if identifier in accepted_base
            ]
            history_dropped_roots = [
                identifier
                for identifier in self._checked(valid_history_roots)
                if identifier not in accepted_base
            ]
            expansion_capacity = MAX_TIMELINE_RESOURCE_LANES - len(accepted_base)
            history_expanded_ids = history_candidate_ids[:expansion_capacity]
            history_dropped_ids = history_candidate_ids[expansion_capacity:]
            requested_id_values = [*accepted_base, *history_expanded_ids]
        if (
            runtime is not None
            and len(requested_id_values) > MAX_TIMELINE_RESOURCE_LANES
        ):
            raise RevisionQueryRequestError(
                "full-scale timeline queries are limited to "
                f"{MAX_TIMELINE_RESOURCE_LANES} resource lanes"
            )
        requested_ids = set(requested_id_values)
        search = query.search.casefold()
        if runtime is not None:
            filtered: list[dict[str, Any]] = []
            lifecycle_by_resource = cast(
                dict[str, list[dict[str, Any]]], runtime.lifecycle_by_resource
            )
            state_by_resource = cast(
                dict[str, list[dict[str, Any]]], runtime.state_by_resource
            )
            resource_candidates = [
                runtime.resource_by_id[identifier]
                for identifier in self._checked(requested_id_values)
                if identifier in runtime.resource_by_id
            ]
        else:
            filtered = self.data_service.events_in_range(start_ns, end_ns)
            lifecycle_by_resource = {}
            state_by_resource = {}
            for item in self._checked(dataset["lifecycle_intervals"]):
                lifecycle_by_resource.setdefault(item["resource"], []).append(item)
            for item in self._checked(dataset["state_intervals"]):
                state_by_resource.setdefault(item["resource"], []).append(item)
            resource_candidates = dataset["resources"]

        descriptor_by_kind = {
            str(item.get("kind")): item
            for item in self._checked(dataset.get("kind_descriptors", []))
            if isinstance(item, dict) and item.get("kind")
        }
        lanes: list[dict[str, Any]] = []
        event_windows = []
        index_scope = (self.revision_id, id(dataset), id(runtime))
        interval_budget = max(
            1, MAX_TIMELINE_INTERVAL_DETAILS // max(1, len(resource_candidates))
        )
        glyph_budget = min(query.max_glyphs, max(1, query.viewport_pixels * 4))
        for order, resource in self._checked(enumerate(resource_candidates)):
            identifier = resource["resource_id"]
            descriptor = descriptor_by_kind.get(str(resource.get("kind", "UNKNOWN")))
            safe_projection = redact_resource_view(
                {
                    "state": dict(resource.get("state", {})),
                    "key": dict(resource.get("key", {})),
                    "resource": resource,
                },
                descriptor,
            )
            safe_resource = dict(safe_projection.get("resource") or resource)
            safe_resource["state"] = safe_projection.get("state", {})
            safe_resource["key"] = safe_projection.get("key", {})
            if layers and resource.get("layer") not in layers:
                continue
            if kinds and resource.get("kind") not in kinds:
                continue
            if requested_ids and identifier not in requested_ids:
                continue
            if search and search not in str(safe_resource).casefold():
                continue
            lifecycles = _timeline_intervals(
                self.data_service,
                index_scope,
                identifier + "::lifecycle",
                lifecycle_by_resource.get(identifier, []),
                start_ns,
                end_ns,
                self._checkpoint,
            )
            statuses = _timeline_intervals(
                self.data_service,
                index_scope,
                identifier + "::state",
                state_by_resource.get(identifier, []),
                start_ns,
                end_ns,
                self._checkpoint,
            )
            # The unindexed fallback scans the revision once for its window,
            # then checks only those matches per lane; transient windows are uncached.
            event_source = (
                runtime.events_by_resource.get(identifier, [])
                if runtime is not None
                else [
                    item
                    for item in self._checked(filtered)
                    if identifier in event_resource_ids(item)
                ]
            )
            (
                indexed_events,
                event_times,
                failure_prefix,
                change_times,
                event_positions,
            ) = _timeline_index(
                self.data_service,
                index_scope,
                identifier,
                event_source,
                state_by_resource.get(identifier, ()),
                self._checkpoint,
                retain=runtime is not None,
            )
            left = bisect_left(event_times, start_ns)
            right = bisect_right(event_times, end_ns)
            if only_with_activity and not (lifecycles or statuses or right > left):
                continue
            event_windows.append((indexed_events, left, right))

            def project(
                position: int,
                indexed_events: Any = indexed_events,
                change_times: Any = change_times,
                identifier: str = identifier,
            ) -> dict[str, Any]:
                self._checkpoint()
                event = self._redact_event_for_client(indexed_events[position], dataset)
                next_position = bisect_right(change_times, int(event["timestamp_ns"]))
                next_change = (
                    change_times[next_position]
                    if next_position < len(change_times)
                    else None
                )
                return timeline_mark(event, identifier, next_change)

            # Keep raw indexes until the global lane budget is allocated.
            marks: list[dict[str, Any]] = []
            resource_events: list[dict[str, Any]] = []
            raw_window = (
                indexed_events,
                event_times,
                failure_prefix,
                left,
                right,
                project,
                event_positions,
            )
            status_count = len(statuses)
            condition_visible = (
                redact_resource_view(
                    {"state": {}, "status": "timeline-condition"}, descriptor
                ).get("status")
                == "timeline-condition"
            )
            status_counts = Counter(
                str(item.get("status", "unknown")) if condition_visible else "unknown"
                for item in self._checked(statuses)
            )
            class_counts = Counter(
                str(item.get("status_class", "unknown")).casefold()
                if str(item.get("status_class", "unknown")).casefold()
                in {member.value for member in ConditionClass}
                else "unknown"
                for item in self._checked(statuses)
            )
            returned_status_counts = dict(status_counts.most_common(32))
            status_summary = {
                "interval_count": status_count,
                "properties_omitted": status_count > interval_budget,
                "start_ns": str(start_ns),
                "end_ns": str(end_ns),
                "status_counts": returned_status_counts,
                "status_counts_truncated": len(status_counts)
                > len(returned_status_counts),
                "omitted_status_interval_count": sum(status_counts.values())
                - sum(returned_status_counts.values()),
                "status_class_counts": dict(class_counts),
            }
            statuses = statuses[:interval_budget]
            lifecycle_count = len(lifecycles)
            lifecycles = lifecycles[:interval_budget]
            lifecycle_payload = [
                {
                    **item,
                    "start_ns": item.get("valid_from_ns"),
                    "end_ns": item.get("valid_to_ns"),
                    "duration_ns": interval_duration(
                        item.get("valid_from_ns"), item.get("valid_to_ns")
                    ),
                    "open_start": item.get("valid_from_ns") is None,
                    "open_end": item.get("valid_to_ns") is None,
                }
                for item in self._checked(lifecycles)
            ]
            status_payload = [
                {
                    **self.data_service.redact_state_interval_for_client(
                        identifier, item, dataset
                    ),
                    "properties": redact_resource_view(
                        {"state": dict(item.get("properties", {}))},
                        descriptor,
                    ).get("state", {}),
                    "start_ns": item.get("valid_from_ns"),
                    "end_ns": item.get("valid_to_ns"),
                    "duration_ns": interval_duration(
                        item.get("valid_from_ns"), item.get("valid_to_ns")
                    ),
                    "start_event_uid": item.get(
                        "start_event_uid", item.get("cause_event_uid")
                    ),
                }
                for item in self._checked(statuses)
            ]
            lanes.append(
                {
                    "lane_id": identifier,
                    "resource_id": identifier,
                    "order": order,
                    "layer": resource.get("layer", "unknown"),
                    "kind": resource.get("kind", "UNKNOWN"),
                    # Resource identifiers are opaque core handles.  A plug-in may
                    # provide a human label; otherwise display the handle verbatim
                    # instead of parsing vendor/domain meaning out of its shape.
                    "label": resource.get("label") or identifier,
                    "resource": safe_resource,
                    "has_lifecycle_history": bool(
                        lifecycle_by_resource.get(identifier)
                    ),
                    "lifecycle_interval_count": lifecycle_count,
                    "lifecycle_intervals_truncated": lifecycle_count > len(lifecycles),
                    "lifecycle_intervals": lifecycle_payload,
                    "status_intervals": status_payload,
                    "_raw_window": raw_window,
                    "status_interval_summary": status_summary,
                    "status_interval_count": status_count,
                    "status_intervals_truncated": status_count > len(statuses),
                    "status_interval_mode": "summary-with-bounded-details"
                    if status_count > len(statuses)
                    else "detail",
                    "event_marks": marks,
                    "events": resource_events,
                }
            )

        if len(event_windows) == 1:
            event_count = event_windows[0][2] - event_windows[0][1]
        elif runtime is None:
            event_count = len(
                {
                    str(events[position]["event_uid"])
                    for events, left, right in event_windows
                    for position in self._checked(range(left, right))
                }
            )
        else:
            event_count = _timeline_unique_count(
                self.data_service,
                index_scope,
                [events for events, _, _ in event_windows],
                start_ns,
                end_ns,
                self._checkpoint,
            )
        cluster_window_ns = query.cluster_window_ns
        requested_max_glyphs, viewport_pixels = query.max_glyphs, query.viewport_pixels
        glyph_budget = min(requested_max_glyphs, max(1, viewport_pixels * 4))
        selected_event_uid = query.selected_event_uid
        clusters, glyph_meta = indexed_timeline_clusters(
            lanes,
            start_ns=start_ns,
            end_ns=end_ns,
            glyph_budget=glyph_budget,
            cluster_window_ns=cluster_window_ns,
            selected_event_uid=selected_event_uid,
        )
        glyph_meta.update(
            {
                "requested_max_glyphs": requested_max_glyphs,
                "effective_max_glyphs": glyph_budget,
                "viewport_pixels": viewport_pixels,
            }
        )
        lane_ids = {lane["resource_id"] for lane in self._checked(lanes)}
        relationship_intervals = self._effective_relationship_intervals(
            dataset,
            lane_ids,
            start_ns,
            end_ns,
        )
        relationship_mutations = self._relationship_mutations_in_window(
            dataset,
            lane_ids,
            start_ns,
            end_ns,
        )
        cursor_time_ns = (
            str(query.cursor_time_ns) if query.cursor_time_ns is not None else None
        )
        selected_range = (
            mutable_json_value(query.selected_range)
            if query.selected_range is not None
            else None
        )
        known_source_types = {
            str(item["source_type"])
            for item in self._checked(dataset.get("source_record_descriptors", []))
            if item.get("source_type")
        }
        record_lane_rules = [
            mutable_json_value(item) for item in self._checked(query.record_lane_rules)
        ]
        max_record_marks = query.max_record_marks
        record_lanes = record_lanes_for_window(
            self._checked(dataset.get("source_records", [])),
            record_lane_rules,
            start_ns=start_ns,
            end_ns=end_ns,
            known_source_types=known_source_types,
            max_marks=max_record_marks,
        )
        return {
            "revision_id": revision_id,
            "start_ns": str(start_ns),
            "end_ns": str(end_ns),
            "lanes": lanes,
            "clusters": clusters,
            "glyphs": glyph_meta,
            "record_lanes": record_lanes,
            "record_lane_count": len(record_lanes),
            "relationship_intervals": relationship_intervals,
            "relationship_interval_count": len(relationship_intervals),
            "relationship_mutations": relationship_mutations,
            "relationship_mutation_count": len(relationship_mutations),
            "relationship_type_descriptors": dataset["relationship_descriptors"],
            "relationship_descriptors": dataset["relationship_descriptors"],
            "event_count": event_count,
            "mark_count": glyph_meta["mark_count"],
            "returned_mark_detail_count": glyph_meta["returned_mark_detail_count"],
            "requested_resource_ids": originally_requested_ids,
            "relationship_history_roots": history_roots,
            "relationship_history_expanded_resource_ids": history_expanded_ids,
            "relationship_history_expansion": {
                "lane_limit": MAX_TIMELINE_RESOURCE_LANES,
                "requested_base_ids": list(
                    dict.fromkeys([*originally_requested_ids, *history_roots])
                ),
                "accepted_base_ids": accepted_base_ids,
                "dropped_base_ids": dropped_base_ids,
                "accepted_root_ids": history_accepted_roots,
                "dropped_root_ids": history_dropped_roots,
                "unknown_root_ids": history_unknown_roots,
                "candidate_resource_ids": history_candidate_ids,
                "accepted_resource_ids": history_expanded_ids,
                "dropped_resource_ids": history_dropped_ids,
                "truncated": bool(
                    dropped_base_ids or history_dropped_roots or history_dropped_ids
                ),
            },
            "aggregation": "resource-lanes-with-time-window-clusters",
            "selection": {
                "cursor_time_ns": cursor_time_ns,
                "selected_event_uid": selected_event_uid,
                "range": selected_range,
                "independent_controls": True,
            },
        }


def indexed_resource_exists(runtime: Any, identifier: str, timestamp_ns: int) -> bool:
    return any(
        _contains_time(
            timestamp_ns,
            interval.get("valid_from_ns"),
            interval.get("valid_to_ns"),
        )
        for interval in runtime.lifecycle_by_resource.get(identifier, [])
    )


def graph_edge_payload(
    item: Mapping[str, Any],
    identifier: str,
    *,
    temporal_note: str | None = None,
) -> dict[str, Any]:
    present = relationship_presence(item)
    return {
        "id": identifier,
        "source": item["source"],
        "target": item["target"],
        "type": item.get("relation_type", item.get("type", "related_to")),
        "present": present,
        "possible_presence": list(possible_relationship_presence(item)),
        "quality": item.get("quality", "unknown") if present is True else "ambiguous",
        "provenance": item.get("provenance", "unknown"),
        "temporal_note": temporal_note
        if temporal_note is not None
        else item.get("temporal_note"),
        "valid_from_ns": item.get("valid_from_ns"),
        "valid_to_ns": item.get("valid_to_ns"),
        "start_event_uid": item.get("start_event_uid"),
        "end_event_uid": item.get("end_event_uid"),
    }


def event_layer_values(event: dict[str, Any]) -> set[str]:
    """Return declared layer values without interpreting plug-in vocabulary."""

    values: set[str] = set()
    if event.get("layer") is not None:
        values.add(str(event["layer"]))
    subject = event.get("subject")
    if isinstance(subject, dict) and subject.get("layer") is not None:
        values.add(str(subject["layer"]))
    for field in ("subjects", "effects"):
        records = event.get(field)
        if not isinstance(records, list):
            continue
        values.update(
            str(item["layer"])
            for item in records
            if isinstance(item, dict) and item.get("layer") is not None
        )
    return values


def density_secondary_indexes(
    runtime: Any,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[list[int], Mapping[str, list[int]]]:
    """Resolve optional density indexes without extending IndexedHistory.

    ``failure_event_times`` and ``event_times_by_type`` are an optimization
    supplied by some history implementations, not part of the public
    ``IndexedHistory`` contract.  A conforming older implementation therefore
    falls back to one pass over its normalized events and is never mutated.
    """

    failure_event_times = getattr(runtime, "failure_event_times", None)
    event_times_by_type = getattr(runtime, "event_times_by_type", None)
    if (
        failure_event_times is not None
        and isinstance(event_times_by_type, Mapping)
        and (event_times_by_type or not runtime.events)
    ):
        return failure_event_times, event_times_by_type

    fallback_failure_times: list[int] = []
    fallback_times_by_type: dict[str, list[int]] = {}
    for position, event in enumerate(runtime.events):
        if checkpoint is not None and position % 256 == 0:
            checkpoint()
        timestamp_ns = int(event.get("timestamp_ns", 0))
        if str(event.get("outcome", "")) == "failure":
            fallback_failure_times.append(timestamp_ns)
        event_type = str(
            event.get("event_type") or event.get("event_name") or "unknown"
        )
        fallback_times_by_type.setdefault(event_type, []).append(timestamp_ns)
    # Sorting the derived secondary lists also keeps this compatibility path
    # safe for simple structural adapters that only guarantee event_times
    # ordering.
    fallback_failure_times.sort()
    for timestamps in fallback_times_by_type.values():
        timestamps.sort()
    return fallback_failure_times, fallback_times_by_type


def density_bin_bounds(
    start_ns: int,
    integer_span: int,
    bin_count: int,
    index: int,
) -> tuple[int, int]:
    """Return one bin's inclusive bounds in the canonical density partition."""

    bin_start_ns = start_ns + (integer_span * index) // bin_count
    bin_end_ns = start_ns + (integer_span * (index + 1)) // bin_count - 1
    return bin_start_ns, bin_end_ns


def density_bin_index(
    timestamp_ns: int,
    start_ns: int,
    integer_span: int,
    bin_count: int,
) -> int:
    """Invert ``density_bin_bounds`` exactly for a timestamp in the span."""

    offset = timestamp_ns - start_ns
    return min(
        bin_count - 1,
        (((offset + 1) * bin_count) - 1) // integer_span,
    )


def density_type_counts_by_bin(
    event_times_by_type: Mapping[str, list[int]],
    *,
    page_start_ns: int,
    page_end_exclusive: int,
    start_ns: int,
    integer_span: int,
    bin_count: int,
    bin_start_index: int,
    bin_end_index: int,
) -> dict[int, Counter[str]]:
    """Choose dense bisections or a sparse sweep independently for each type."""
    return adaptive_type_counts(
        event_times_by_type,
        start_ns=start_ns,
        integer_span=integer_span,
        bin_count=bin_count,
        bin_start_index=bin_start_index,
        bin_end_index=bin_end_index,
    )


def event_resource_ids(event: dict[str, Any]) -> list[str]:
    identifiers = [
        str(identifier)
        for identifier in event.get("affected_resources", [])
        if identifier
    ]
    for identifier in (
        event.get("resource_id"),
        event.get("resource_uid"),
        (event.get("subject") or {}).get("resource_id")
        if isinstance(event.get("subject"), dict)
        else None,
    ):
        if identifier:
            identifiers.append(str(identifier))
    identifiers.extend(
        effect["resource_id"]
        for effect in event.get("effects", [])
        if effect.get("resource_id")
    )
    identifiers.extend(
        subject["resource_id"]
        for subject in event.get("subjects", [])
        if subject.get("resource_id")
    )
    return list(dict.fromkeys(identifiers))


def interval_duration(start: Any, end: Any) -> str | None:
    if start is None or end is None:
        return None
    return str(int(end) - int(start))


def timeline_mark(
    event: dict[str, Any], resource_identifier: str, next_change_ns: int | None
) -> dict[str, Any]:
    effect: dict[str, Any] = next(
        (
            item
            for item in event.get("effects", [])
            if item.get("resource_id") == resource_identifier
        ),
        {},
    )
    failed = event.get("outcome") == "failure"
    result = event.get("attributes", {}).get("result", {})
    effect_type = effect.get("effect_type")
    if effect_type is None:
        # ``state_changed`` is a normalized plug-in declaration.  A declared
        # false value means "no mutation" regardless of outcome; it is not a
        # failure-status inference by the core.  Missing mutation metadata
        # remains unknown.
        effect_type = (
            "none"
            if "state_changed" in event and event.get("state_changed") is False
            else "unknown"
        )
    return {
        "event_uid": event["event_uid"],
        "time_ns": str(event["timestamp_ns"]),
        "timestamp_ns": str(event["timestamp_ns"]),
        "source_sequence": temporal_integer(
            event.get("source_sequence", 0),
            "source_sequence",
        ),
        "event_type": event.get("event_type"),
        "action": event.get("action", "unknown"),
        "operation": effect.get("effect_type", event.get("action", "unknown")),
        "outcome": event.get("outcome", "unknown"),
        "label": event.get("display_name", event.get("event_type", "event")),
        "failure": {"failed": failed, "status": result} if failed else None,
        "state_changed": bool(
            effect.get("state_changed", event.get("state_changed", False))
        ),
        "effect_type": effect_type,
        "duration_to_next_change_ns": (
            str(next_change_ns - int(event["timestamp_ns"]))
            if next_change_ns is not None
            and next_change_ns >= int(event["timestamp_ns"])
            else None
        ),
        "resource_id": resource_identifier,
        "event": event,
    }


def timeline_glyph_allocations(
    lanes: list[dict[str, Any]], glyph_budget: int
) -> list[int]:
    """Distribute a global glyph budget fairly and deterministically by lane."""

    counts = [len(lane["event_marks"]) for lane in lanes]
    if sum(counts) <= glyph_budget:
        return counts
    allocations = [0] * len(lanes)
    remaining = glyph_budget
    # Keep at least one glyph for as many non-empty lanes as the budget permits.
    for index, count in enumerate(counts):
        if remaining <= 0:
            break
        if count:
            allocations[index] = 1
            remaining -= 1
    # Balanced rounds prevent the first high-volume lane from starving later
    # lanes while remaining stable for an identical query.
    while remaining > 0:
        progressed = False
        for index, count in enumerate(counts):
            if allocations[index] >= count:
                continue
            allocations[index] += 1
            remaining -= 1
            progressed = True
            if remaining <= 0:
                break
        if not progressed:
            break
    return allocations


def timeline_cluster_preview(
    group: list[dict[str, Any]], selected_event_uid: str | None
) -> list[dict[str, Any]]:
    if len(group) <= MAX_TIMELINE_CLUSTER_DETAIL:
        return group
    preview = list(group[: MAX_TIMELINE_CLUSTER_DETAIL - 1])
    selected = next(
        (
            mark
            for mark in group
            if selected_event_uid and mark["event_uid"] == selected_event_uid
        ),
        None,
    )
    if selected is not None and selected not in preview:
        preview[-1] = selected
    if group[-1] not in preview:
        preview.append(group[-1])
    return preview[:MAX_TIMELINE_CLUSTER_DETAIL]


def bounded_timeline_clusters(
    lanes: list[dict[str, Any]],
    *,
    start_ns: int,
    end_ns: int,
    glyph_budget: int,
    cluster_window_ns: int,
    selected_event_uid: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return server clusters while ensuring rendered glyphs fit the budget."""

    mark_count = sum(len(lane["event_marks"]) for lane in lanes)
    forced = mark_count > glyph_budget
    allocations = timeline_glyph_allocations(lanes, glyph_budget)
    clusters: list[dict[str, Any]] = []
    returned_mark_count = 0
    glyph_count = 0
    span = max(1, end_ns - start_ns + 1)
    for lane, allocation in zip(lanes, allocations, strict=True):
        marks = sorted(
            lane["event_marks"],
            key=lambda item: temporal_order_key(
                item,
                time_field="time_ns",
                identifier_fields=("event_uid",),
            ),
        )
        lane["event_mark_count"] = len(marks)
        lane["event_marks_truncated"] = forced and allocation < len(marks)
        groups: list[list[dict[str, Any]]] = []
        if forced:
            if allocation > 0:
                for mark in marks:
                    bin_index = min(
                        allocation - 1,
                        max(
                            0,
                            ((int(mark["time_ns"]) - start_ns) * allocation) // span,
                        ),
                    )
                    while len(groups) <= bin_index:
                        groups.append([])
                    groups[bin_index].append(mark)
                groups = [group for group in groups if group]
        else:
            for mark in marks:
                if (
                    groups
                    and int(mark["time_ns"]) - int(groups[-1][-1]["time_ns"])
                    <= cluster_window_ns
                ):
                    groups[-1].append(mark)
                else:
                    groups.append([mark])

        visible_marks: list[dict[str, Any]] = []
        for index, group in enumerate(groups):
            if len(group) == 1:
                visible_marks.append(group[0])
                glyph_count += 1
                continue
            preview = timeline_cluster_preview(group, selected_event_uid)
            cluster_event_marks = preview if forced else group
            clusters.append(
                {
                    "cluster_id": (
                        f"{lane['lane_id']}::server-v{TEMPORAL_ORDER_VERSION}::"
                        f"{index}::"
                        f"{group[0]['time_ns']}::{group[-1]['time_ns']}"
                    ),
                    "lane_id": lane["lane_id"],
                    "start_ns": group[0]["time_ns"],
                    "end_ns": group[-1]["time_ns"],
                    "count": len(group),
                    "failure_count": sum(
                        item["outcome"] == "failure" for item in group
                    ),
                    # When lane marks are retained, publish every collapsed UID
                    # so a client cannot render the undisclosed tail twice. In
                    # forced mode the lane marks are removed, so the bounded
                    # preview is sufficient for interaction and source jumps.
                    "event_uids": [item["event_uid"] for item in cluster_event_marks],
                    "first_event_uid": group[0]["event_uid"],
                    "last_event_uid": group[-1]["event_uid"],
                    "items": preview,
                    "detail_count": len(preview),
                    "detail_truncated": len(preview) < len(group),
                    "scrollable": True,
                }
            )
            glyph_count += 1
        if forced:
            lane["event_marks"] = visible_marks
            lane["events"] = []
            returned_mark_count += len(visible_marks) + sum(
                int(cluster["detail_count"])
                for cluster in clusters
                if cluster["lane_id"] == lane["lane_id"]
            )
        else:
            returned_mark_count += len(marks)
        lane["glyph_count"] = len(visible_marks) + sum(
            1 for cluster in clusters if cluster["lane_id"] == lane["lane_id"]
        )
    detail_truncated = forced or any(
        bool(cluster["detail_truncated"]) for cluster in clusters
    )
    return clusters, {
        "requested_max_glyphs": glyph_budget,
        "glyph_count": glyph_count,
        "mark_count": mark_count,
        "returned_mark_detail_count": returned_mark_count,
        "cluster_count": len(clusters),
        "clustered": bool(clusters),
        "detail_truncated": detail_truncated,
        "omitted_mark_detail_count": max(0, mark_count - returned_mark_count),
    }


def indexed_timeline_clusters(
    lanes: list[dict[str, Any]],
    *,
    start_ns: int,
    end_ns: int,
    glyph_budget: int,
    cluster_window_ns: int,
    selected_event_uid: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    counts = [lane["_raw_window"][4] - lane["_raw_window"][3] for lane in lanes]
    if sum(counts) <= glyph_budget:
        for lane in lanes:
            events, times, failures, left, right, project, event_positions = lane.pop(
                "_raw_window"
            )
            lane["event_marks"] = [project(position) for position in range(left, right)]
            lane["events"] = [mark["event"] for mark in lane["event_marks"]]
        return bounded_timeline_clusters(
            lanes,
            start_ns=start_ns,
            end_ns=end_ns,
            glyph_budget=glyph_budget,
            cluster_window_ns=cluster_window_ns,
            selected_event_uid=selected_event_uid,
        )
    # Allocate on counts without constructing one mark per event.
    allocations = [0] * len(lanes)
    remaining = glyph_budget
    while remaining:
        progressed = False
        for index, count in enumerate(counts):
            if allocations[index] < count:
                allocations[index] += 1
                remaining -= 1
                progressed = True
                if not remaining:
                    break
        if not progressed:
            break
    if selected_event_uid:
        for index, lane in enumerate(lanes):
            position = lane["_raw_window"][6].get(selected_event_uid)
            if (
                position is not None
                and lane["_raw_window"][3] <= position < lane["_raw_window"][4]
                and allocations[index] == 0
            ):
                donor = next(
                    (other for other, value in enumerate(allocations) if value > 0),
                    None,
                )
                if donor is not None:
                    allocations[donor] -= 1
                    allocations[index] = 1
                break
    clusters = []
    details = glyphs = 0
    span = max(1, end_ns - start_ns + 1)
    for lane, allocation, count in zip(lanes, allocations, counts, strict=True):
        events, times, failures, left, right, project, event_positions = lane.pop(
            "_raw_window"
        )
        lane["event_mark_count"] = count
        lane["event_marks_truncated"] = allocation < count
        lane_glyphs = 0
        selected_position = event_positions.get(selected_event_uid)
        for index in range(allocation):
            low = start_ns + (span * index + allocation - 1) // allocation
            high = start_ns + (span * (index + 1) + allocation - 1) // allocation
            group_left = bisect_left(times, low, left, right)
            group_right = bisect_left(times, high, group_left, right)
            size = group_right - group_left
            if not size:
                continue
            lane_glyphs += 1
            if size == 1:
                lane["event_marks"].append(project(group_left))
                details += 1
                continue
            positions = list(
                range(
                    group_left,
                    min(group_right, group_left + MAX_TIMELINE_CLUSTER_DETAIL - 1),
                )
            )
            if (
                selected_position is not None
                and group_left <= selected_position < group_right
                and selected_position not in positions
            ):
                positions[-1] = selected_position
            if group_right - 1 not in positions:
                positions.append(group_right - 1)
            preview = [project(position) for position in positions]
            first, last = events[group_left], events[group_right - 1]
            clusters.append(
                {
                    "cluster_id": f"{lane['lane_id']}::server-v{TEMPORAL_ORDER_VERSION}::{index}::{times[group_left]}::{times[group_right - 1]}",
                    "lane_id": lane["lane_id"],
                    "start_ns": str(times[group_left]),
                    "end_ns": str(times[group_right - 1]),
                    "count": size,
                    "failure_count": failures[group_right] - failures[group_left],
                    "event_uids": [mark["event_uid"] for mark in preview],
                    "first_event_uid": first["event_uid"],
                    "last_event_uid": last["event_uid"],
                    "items": preview,
                    "detail_count": len(preview),
                    "detail_truncated": len(preview) < size,
                    "scrollable": True,
                }
            )
            details += len(preview)
        lane["glyph_count"] = lane_glyphs
        glyphs += lane_glyphs
    total = sum(counts)
    return clusters, {
        "requested_max_glyphs": glyph_budget,
        "glyph_count": glyphs,
        "mark_count": total,
        "returned_mark_detail_count": details,
        "cluster_count": len(clusters),
        "clustered": bool(clusters),
        "detail_truncated": True,
        "omitted_mark_detail_count": max(0, total - details),
    }


def _timeline_intervals(
    owner: Any,
    revision: Any,
    identifier: str,
    intervals: Any,
    start: int,
    end: int,
    checkpoint: Callable[[], None],
) -> list[Any]:
    key = (revision, identifier)
    with _TIMELINE_CACHE_LOCK:
        cache = _timeline_cache(owner, "_timeline_interval_indexes")
        entry = cache.get(key)
        if entry is not None and entry[0] is intervals:
            cache.move_to_end(key)
            indexed = entry[1]
        else:
            indexed = None
    if indexed is None:
        ordered = _cooperative_sorted(
            intervals,
            lambda item: (
                int(item["valid_from_ns"])
                if item.get("valid_from_ns") is not None
                else MIN_TIMESTAMP_NS - 1
            ),
            checkpoint,
        )
        starts: list[int] = []
        max_ends: list[int] = []
        running_end = MIN_TIMESTAMP_NS - 1
        for position, item in enumerate(ordered):
            if position % 256 == 0:
                checkpoint()
            starts.append(
                int(item["valid_from_ns"])
                if item.get("valid_from_ns") is not None
                else MIN_TIMESTAMP_NS - 1
            )
            running_end = max(
                running_end,
                int(item["valid_to_ns"])
                if item.get("valid_to_ns") is not None
                else MAX_TIMESTAMP_NS + 1,
            )
            max_ends.append(running_end)
        indexed = ordered, starts, max_ends
        checkpoint()
        units = len(ordered) * 3
        if units <= MAX_TIMELINE_INDEX_UNITS:
            with _TIMELINE_CACHE_LOCK:
                cache[key] = (intervals, indexed, units)
                while (
                    len(cache) > MAX_TIMELINE_RESOURCE_LANES * 2
                    or sum(item[2] for item in cache.values())
                    > MAX_TIMELINE_INDEX_UNITS
                ):
                    cache.popitem(last=False)
    ordered, starts, max_ends = indexed
    left = bisect_right(max_ends, start)
    right = bisect_left(starts, end)
    result = []
    for position in range(left, right):
        if position % 256 == 0:
            checkpoint()
        item = ordered[position]
        if item.get("valid_to_ns") is None or int(item["valid_to_ns"]) > start:
            result.append(item)
    return result


def _timeline_unique_count(
    owner: Any,
    revision: Any,
    sources: list[Any],
    start: int,
    end: int,
    checkpoint: Callable[[], None],
) -> int:
    """Index the exact event union once per immutable lane selection."""
    key = (revision, tuple(id(source) for source in sources))
    with _TIMELINE_CACHE_LOCK:
        cache = _timeline_cache(owner, "_timeline_union_indexes")
        entry = cache.get(key)
        if entry is not None and all(
            old is new for old, new in zip(entry[0], sources, strict=True)
        ):
            cache.move_to_end(key)
            times = entry[1]
        else:
            times = None
    if times is None:
        timestamp_by_uid = {}
        for source in sources:
            for position, event in enumerate(source):
                if position % 256 == 0:
                    checkpoint()
                timestamp_by_uid[str(event["event_uid"])] = int(event["timestamp_ns"])
        times = _cooperative_sorted(
            timestamp_by_uid.values(), lambda time: time, checkpoint
        )
        checkpoint()
        units = sum(len(source) * 4 for source in sources) + len(times)
        if units <= MAX_TIMELINE_INDEX_UNITS:
            with _TIMELINE_CACHE_LOCK:
                cache[key] = (tuple(sources), times, units)
                while (
                    len(cache) > 16
                    or sum(item[2] for item in cache.values())
                    > MAX_TIMELINE_INDEX_UNITS
                ):
                    cache.popitem(last=False)
    return bisect_right(times, end) - bisect_left(times, start)
