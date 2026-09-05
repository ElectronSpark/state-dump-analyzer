"""Bounded temporal-topology queries over plug-in supplied descriptors.

The query engine in this module is deliberately domain-neutral: it resolves a
time basis, asks injected readers for state/relationships, and applies the
plug-in's declarative selectors. The injected contract owns layer names,
usable status values, and which relationships may be projected as
connectivity.

Nanosecond values are serialized as strings because JavaScript cannot safely
represent the capture's epoch-sized integers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import hmac
import json
from bisect import bisect_left
from collections.abc import Callable
from typing import Any

from .contract_validation import strict_integer
from .normalized_data import active_interval, state_intervals_for_perspective
from .plugin_api import StatusPerspectiveRef
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .temporal_core import (
    MIN_TEMPORAL_NS,
    RESOURCE_CREATION_OPERATIONS,
    RESOURCE_DELETION_OPERATIONS,
    TEMPORAL_ORDER_VERSION,
    checked_temporal_add,
    checked_temporal_subtract,
    contains_time,
    distinct_temporal_states,
    possible_relationship_presence,
    relationship_presence,
    temporal_integer,
    temporal_order_key,
)
from .value_core import MAX_JSON_SAFE_INTEGER

StateReader = Callable[[str, int], dict[str, Any]]
PerspectiveStateReader = Callable[[str, int, StatusPerspectiveRef], dict[str, Any]]
RelationshipReader = Callable[[int], list[dict[str, Any]]]


class TemporalTopologyRequestError(ValueError):
    """A caller supplied an unsupported projection, perspective, or basis."""


def _invoke_provider_callback(
    callback: Callable[..., Any],
    operation: str,
    /,
    *args: Any,
) -> Any:
    try:
        return callback(*args)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - plug-in callback boundary.
        raise TemporalTopologyRequestError(
            f"temporal provider {operation} failed"
        ) from None


def _materialize_provider_items(value: Any, operation: str) -> list[Any]:
    """Contain lazy iteration and cleanup without hiding the primary failure."""

    try:
        iterator = iter(value)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - plug-in iterable boundary.
        raise TemporalTopologyRequestError(
            f"temporal provider {operation} returned an unreadable iterable"
        ) from None

    items: list[Any] = []
    failure: BaseException | None = None
    try:
        while True:
            try:
                items.append(next(iterator))
            except StopIteration:
                break
    except BaseException as error:  # noqa: BLE001 - preserve primary failure.
        failure = error
    finally:
        try:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except Exception:
            if failure is None:
                raise
            failure.add_note("plug-in provider iterator cleanup failed")
        except BaseException:  # noqa: BLE001 - plug-in cleanup boundary.
            if failure is None:
                raise TemporalTopologyRequestError(
                    f"temporal provider {operation} iterator cleanup failed"
                ) from None
            failure.add_note("plug-in provider iterator cleanup failed")

    if failure is not None:
        if isinstance(failure, PROCESS_CONTROL_EXCEPTIONS):
            raise failure
        if isinstance(failure, Exception):
            raise failure
        raise TemporalTopologyRequestError(
            f"temporal provider {operation} iteration failed"
        ) from None
    return items


def _page_count(value: object, field: str) -> int:
    """Keep cursor coordinates and published counts in the exact JSON domain."""

    try:
        return strict_integer(
            value, field, minimum=0, maximum=MAX_JSON_SAFE_INTEGER
        )
    except ValueError as error:
        raise TemporalTopologyRequestError(str(error)) from error


def _ns(value: Any, field: str) -> int:
    try:
        return temporal_integer(value, field)
    except ValueError as error:
        raise TemporalTopologyRequestError(
            f"{field} must be an integer nanosecond value"
        ) from error


def _ns_add(left: int, right: int, field: str) -> int:
    try:
        return checked_temporal_add(left, right, field)
    except ValueError as error:
        raise TemporalTopologyRequestError(
            f"{field} exceeds the signed 64-bit nanosecond range"
        ) from error


def _ns_subtract(left: int, right: int, field: str) -> int:
    try:
        return checked_temporal_subtract(left, right, field)
    except ValueError as error:
        raise TemporalTopologyRequestError(
            f"{field} exceeds the signed 64-bit nanosecond range"
        ) from error


def _resource_node(record: dict[str, Any], default_node: str) -> str:
    return str(record.get("node") or default_node)


def _event_layer(event: dict[str, Any]) -> str:
    if event.get("layer"):
        return str(event["layer"])
    subjects = event.get("subjects") or []
    return str(subjects[0].get("layer", "unknown")) if subjects else "unknown"


def _relationship_key(item: dict[str, Any]) -> str:
    explicit = item.get("relationship_id") or item.get("id")
    if explicit:
        return str(explicit)
    return "|".join(
        str(value)
        for value in (
            item.get("source"),
            item.get("relation_type", item.get("type", "related_to")),
            item.get("target"),
            item.get("valid_from_ns"),
        )
    )


class TemporalTopologyService:
    """Generic temporal orchestration over a plug-in-supplied descriptor."""

    def __init__(
        self,
        dataset: dict[str, Any],
        state_reader: StateReader | None,
        relationship_reader: RelationshipReader,
        *,
        contract: dict[str, Any],
        temporal_metadata: dict[str, Any],
        perspective_state_reader: PerspectiveStateReader | None = None,
    ) -> None:
        if not isinstance(contract, dict):
            raise TemporalTopologyRequestError(
                "the temporal provider must supply a normalized contract"
            )
        self.dataset: dict[str, Any] = dataset
        self.state_reader: StateReader | None = state_reader
        self.perspective_state_reader = perspective_state_reader
        self.relationship_reader: RelationshipReader = relationship_reader
        self.contract: dict[str, Any] = contract
        self.temporal_metadata: dict[str, Any] = dict(temporal_metadata)
        try:
            self.revision_id: str = str(temporal_metadata["revision_id"])
            self.timeline_start_ns: int = temporal_integer(
                temporal_metadata["timeline_start_ns"],
                "temporal_metadata.timeline_start_ns",
            )
            self.timeline_end_ns: int = temporal_integer(
                temporal_metadata["timeline_end_ns"],
                "temporal_metadata.timeline_end_ns",
            )
            self.capture_ns: int = temporal_integer(
                temporal_metadata["capture_ns"],
                "temporal_metadata.capture_ns",
            )
        except (KeyError, TypeError, ValueError) as error:
            raise TemporalTopologyRequestError(
                "temporal metadata must provide revision and integer "
                "capture/timeline bounds"
            ) from error
        default_node = temporal_metadata.get("default_node")
        if not isinstance(default_node, str) or not default_node:
            raise TemporalTopologyRequestError(
                "temporal metadata must provide a non-empty default_node"
            )
        self.default_node: str = default_node
        self.resource_by_id: dict[str, Any] = {
            str(item["resource_id"]): item for item in dataset.get("resources", [])
        }
        self._perspective_event_cache: dict[
            tuple[str, str, str | None, str | None], list[dict[str, Any]]
        ] = {}
        self.runtime: Any = dataset.get("_scale_runtime")
        self._resource_history_cache: dict[
            str, tuple[list[dict[str, Any]], list[dict[str, Any]]]
        ] = {}
        if self.runtime is not None:
            self._events = self.runtime.events
            self._event_times = self.runtime.event_times
            self._mutations = self.runtime.mutations
            self._mutation_times = self.runtime.mutation_times
        else:
            self._events = sorted(
                dataset.get("events", []),
                key=lambda item: temporal_order_key(
                    item,
                    time_field="timestamp_ns",
                    identifier_fields=("event_uid", "event_id"),
                ),
            )
            self._event_times = [
                temporal_integer(item["timestamp_ns"], "timestamp_ns")
                for item in self._events
            ]
            self._mutations = sorted(
                dataset.get("relationship_mutations", []),
                key=lambda item: temporal_order_key(
                    item,
                    time_field="effective_time_ns",
                    identifier_fields=("mutation_id",),
                ),
            )
            self._mutation_times = [
                temporal_integer(
                    item["effective_time_ns"],
                    "effective_time_ns",
                )
                for item in self._mutations
            ]

    def capabilities(self) -> dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "default_projection_id": self.contract["default_projection_id"],
            "default_status_perspective_id": self.contract[
                "default_status_perspective_id"
            ],
            "defaults": {
                "projection_id": self.contract["default_projection_id"],
                "status_perspective_id": self.contract[
                    "default_status_perspective_id"
                ],
                "clock_policy": "strict",
                "absolute_clock_domain": "utc",
            },
            "absolute_clock_domains": ["utc"],
            "time_bounds": {
                "start_ns": str(self.timeline_start_ns),
                "end_ns": str(self.timeline_end_ns),
                "capture_ns": str(self.capture_ns),
            },
            "topology_projections": [
                self._public_projection(item)
                for item in self.contract["topology_projections"]
            ],
            "status_perspectives": [
                self._public_perspective(item)
                for item in self.contract["status_perspectives"]
            ],
            "nodes": [self._public_node(item) for item in self.contract["nodes"]],
            "time_bases": [
                {
                    "kind": "absolute_time",
                    "required": ["time_ns", "clock_domain"],
                    "semantics": "One absolute instant mapped independently into each node clock.",
                },
                {
                    "kind": "relative_to_watermark",
                    "aliases": ["relative_to_scope_end"],
                    "required": ["offset_ns"],
                    "semantics": (
                        "One offset from each selected node/perspective watermark; "
                        "the result is a capture vector and does not imply simultaneity."
                    ),
                },
            ],
            "clock_policies": ["strict", "best_effort"],
            "limits": {
                "default_resources": 100,
                "max_resources": 500,
                "default_connectivity": 100,
                "max_connectivity": 500,
                "default_changes": 200,
                "max_changes": 1000,
            },
            "semantic_ownership": {
                "projection": "plugin",
                "status_mapping": "plugin",
                "temporal_query": "core",
                "core": [
                    "basis resolution and clock uncertainty",
                    "temporal interval selection",
                    "bounded resource and relationship queries",
                    "unknown/ambiguous result preservation",
                ],
                "plugin": [
                    "topology projection and connectivity rules",
                    "status perspectives and usability mapping",
                    "layer watermark scope",
                    "resource and relationship meaning",
                ],
            },
            "data_disclosure": str(
                self.temporal_metadata.get("data_disclosure") or ""
            ),
        }

    @staticmethod
    def _cursor_fingerprint(payload: dict[str, Any]) -> str:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()[:24]

    @staticmethod
    def _reject_generic_cursor(body: dict[str, Any]) -> None:
        if body.get("cursor") is not None:
            raise TemporalTopologyRequestError(
                "cursor is ambiguous; use resource_cursor for resources "
                "or change_cursor for changes"
            )

    def _encode_cursor(
        self,
        kind: str,
        fingerprint: str,
        *,
        position: int,
        offset: int | None = None,
        after: tuple[int, int, int, str] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "v": TEMPORAL_ORDER_VERSION,
            "kind": kind,
            "revision_id": self.revision_id,
            "fingerprint": fingerprint,
            "position": _page_count(position, f"{kind}_cursor position"),
        }
        if offset is not None:
            payload["offset"] = _page_count(offset, f"{kind}_cursor offset")
        if after is not None:
            payload["after"] = list(after)
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        checksum = hashlib.sha256(
            raw + b"\0" + self.revision_id.encode("utf-8")
        ).hexdigest()[:16]
        return f"tt{TEMPORAL_ORDER_VERSION}.{encoded}.{checksum}"

    def _decode_cursor(
        self,
        token: Any,
        kind: str,
        fingerprint: str,
    ) -> dict[str, Any]:
        if token is None or token == "":
            return {"position": 0}
        if not isinstance(token, str):
            raise TemporalTopologyRequestError(f"{kind}_cursor must be a string")
        try:
            prefix, encoded, supplied_checksum = token.split(".", 2)
            if prefix != f"tt{TEMPORAL_ORDER_VERSION}":
                raise ValueError("unsupported version")
            padding = "=" * (-len(encoded) % 4)
            raw = base64.urlsafe_b64decode(encoded + padding)
            expected_checksum = hashlib.sha256(
                raw
                + b"\0"
                + self.revision_id.encode("utf-8")
            ).hexdigest()[:16]
            if not hmac.compare_digest(supplied_checksum, expected_checksum):
                raise ValueError("checksum mismatch")
            payload = json.loads(raw.decode("utf-8"))
        except (
            binascii.Error,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise TemporalTopologyRequestError(
                f"invalid {kind}_cursor"
            ) from error
        if not isinstance(payload, dict):
            raise TemporalTopologyRequestError(f"invalid {kind}_cursor")
        if (
            payload.get("v") != TEMPORAL_ORDER_VERSION
            or payload.get("kind") != kind
            or payload.get("revision_id") != self.revision_id
        ):
            raise TemporalTopologyRequestError(
                f"{kind}_cursor belongs to a different query or revision"
            )
        if payload.get("fingerprint") != fingerprint:
            raise TemporalTopologyRequestError(
                f"{kind}_cursor does not match the current query"
            )
        payload["position"] = _page_count(
            payload.get("position"), f"{kind}_cursor position"
        )
        if kind == "resource":
            payload["offset"] = _page_count(
                payload.get("offset", 0), "resource_cursor offset"
            )
        return payload

    @staticmethod
    def _change_after(
        cursor: dict[str, Any],
    ) -> tuple[int, int, int, str] | None:
        after = cursor.get("after")
        if after is None:
            return None
        if not isinstance(after, list) or len(after) != 4:
            raise TemporalTopologyRequestError("invalid change_cursor boundary")
        timestamp_ns, source_rank, source_sequence, identifier = after
        numeric = (timestamp_ns, source_rank, source_sequence)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in numeric):
            raise TemporalTopologyRequestError("invalid change_cursor boundary")
        if not isinstance(identifier, str):
            raise TemporalTopologyRequestError("invalid change_cursor boundary")
        return timestamp_ns, source_rank, source_sequence, identifier

    @staticmethod
    def _basis_cursor_shape(node_times: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "node_id": item["node_id"],
                "query_time_ns": item.get("query_time_ns"),
                "resolved_at_min_ns": item.get("resolved_at_min_ns"),
                "resolved_at_max_ns": item.get("resolved_at_max_ns"),
                "resolution": item.get("resolution"),
            }
            for item in node_times
        ]

    def query(self, body: dict[str, Any]) -> dict[str, Any]:
        self._reject_generic_cursor(body)
        projection, perspective = self._selection(
            body.get("projection_id", body.get("topology_projection_id")),
            body.get("status_perspective_id"),
        )
        requested_relation_types = None
        if "relation_types" in body:
            raw_relation_types = body["relation_types"]
            if not isinstance(raw_relation_types, list) or any(
                not isinstance(item, str) or not item for item in raw_relation_types
            ):
                raise TemporalTopologyRequestError(
                    "relation_types must be an array of non-empty strings"
                )
            requested_relation_types = set(raw_relation_types)
        requested_basis = body.get("basis") or {}
        clock_policy = str(
            body.get("clock_policy", requested_basis.get("clock_policy", "strict"))
        )
        if clock_policy not in {"strict", "best_effort"}:
            raise TemporalTopologyRequestError(
                "clock_policy must be strict or best_effort"
            )
        node_ids = self._selected_node_ids(body, requested_basis)
        resolved_basis, node_times = self._resolve_basis(
            requested_basis, projection, perspective, node_ids, clock_policy
        )
        include = body.get("include")
        if include is None:
            include = ["inferred_connectivity"]
            if body.get("include_resources", True):
                include.append("resources")
            if body.get("include_relationships", True):
                include.append("relationships")
        if isinstance(include, dict):
            include_names = {key for key, value in include.items() if value}
        elif isinstance(include, list):
            include_names = {str(item) for item in include}
        else:
            raise TemporalTopologyRequestError("include must be an array or object")
        allowed_include = {
            "resources",
            "relationships",
            "inferred_connectivity",
            "changes",
        }
        if unknown := include_names - allowed_include:
            raise TemporalTopologyRequestError(
                "unsupported include values: " + ", ".join(sorted(unknown))
            )

        legacy_limit = body.get("limit", body.get("page_size", 100))
        resource_limit = max(
            1,
            min(
                _ns(body.get("resource_limit", legacy_limit), "resource_limit"),
                500,
            ),
        )
        connectivity_limit = max(
            1,
            min(
                _ns(
                    body.get("connectivity_limit", legacy_limit),
                    "connectivity_limit",
                ),
                500,
            ),
        )
        relationship_limit = max(
            1,
            min(
                _ns(
                    body.get("relationship_limit", connectivity_limit),
                    "relationship_limit",
                ),
                1000,
            ),
        )
        resource_ids = [str(item) for item in body.get("resource_ids") or []]
        kinds = {str(item) for item in body.get("kinds") or []}
        resource_fingerprint = self._cursor_fingerprint(
            {
                "projection_id": projection["projection_id"],
                "status_perspective_id": perspective["perspective_id"],
                "node_times": self._basis_cursor_shape(node_times),
                "resource_ids": sorted(resource_ids),
                "kinds": sorted(kinds),
            }
        )
        resource_cursor = self._decode_cursor(
            body.get("resource_cursor"), "resource", resource_fingerprint
        )
        resource_offset = resource_cursor.get("offset", 0)
        resources, resource_meta = self._resource_views(
            projection,
            perspective,
            node_times,
            resource_ids=resource_ids,
            kinds=kinds,
            offset=resource_offset,
            limit=resource_limit,
        )
        next_resource_cursor = None
        if resource_meta["next_offset"] is not None:
            next_resource_cursor = self._encode_cursor(
                "resource",
                resource_fingerprint,
                position=resource_meta["next_offset"],
                offset=resource_meta["next_offset"],
            )
        resource_meta["next_cursor"] = next_resource_cursor
        relationships: list[dict[str, Any]] = []
        connectivity_relationships: list[dict[str, Any]] = []
        relationship_meta = {
            "total_count": 0,
            "returned_count": 0,
            "truncated": False,
            "connectivity_candidate_count": 0,
        }
        if "relationships" in include_names or "inferred_connectivity" in include_names:
            (
                relationships,
                connectivity_relationships,
                relationship_meta,
            ) = self._relationship_views(
                projection,
                node_times,
                {item["resource_id"] for item in resources},
                relationship_limit=relationship_limit,
                connectivity_limit=connectivity_limit,
                requested_relation_types=requested_relation_types,
            )
        inferred: list[dict[str, Any]] = []
        connectivity_meta = {
            "total_count": 0,
            "returned_count": 0,
            "truncated": False,
        }
        if "inferred_connectivity" in include_names:
            inferred_candidates = self._inferred_connectivity(
                projection,
                perspective,
                node_times,
                connectivity_relationships,
            )
            connectivity_total = len(projection.get("static_connectivity", [])) + int(
                relationship_meta.get("connectivity_candidate_count", 0)
            )
            inferred = inferred_candidates[:connectivity_limit]
            connectivity_meta = {
                "total_count": connectivity_total,
                "returned_count": len(inferred),
                "truncated": connectivity_total > len(inferred),
            }

        changes: list[dict[str, Any]] = []
        change_meta = {
            "total_count": 0,
            "total_count_is_exact": True,
            "minimum_total_count": 0,
            "returned_count": 0,
            "truncated": False,
            "next_cursor": None,
        }
        if "changes" in include_names:
            end_time = self._primary_query_time(node_times)
            start_time = _ns(
                body.get(
                    "change_start_ns",
                    self.timeline_start_ns,
                ),
                "change_start_ns",
            )
            change_limit = max(
                1, min(_ns(body.get("change_limit", 200), "change_limit"), 1000)
            )
            change_resource_ids = (
                set(resource_ids)
                if resource_ids
                else set()
            )
            change_fingerprint = self._cursor_fingerprint(
                {
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": perspective["perspective_id"],
                    "start_ns": start_time,
                    "end_ns": end_time,
                    "resource_ids": sorted(change_resource_ids),
                }
            )
            change_cursor = self._decode_cursor(
                body.get("change_cursor"), "change", change_fingerprint
            )
            changes, change_meta = self._changes(
                projection,
                perspective,
                start_time,
                end_time,
                change_resource_ids,
                change_limit,
                after=self._change_after(change_cursor),
                position=change_cursor["position"],
            )
            change_meta["next_cursor"] = None
            if change_meta["next_after"] is not None:
                change_meta["next_cursor"] = self._encode_cursor(
                    "change",
                    change_fingerprint,
                    position=change_meta["next_position"],
                    after=change_meta["next_after"],
                )
            change_meta.pop("next_after", None)
            change_meta.pop("next_position", None)

        incomplete_nodes = [
            item["node_id"]
            for item in node_times
            if item["resolution"] not in {"exact", "bounded", "local_exact"}
            or not item.get("resources_available", False)
        ]
        complete = (
            not incomplete_nodes
            and not resource_meta["truncated"]
            and not relationship_meta["truncated"]
            and not connectivity_meta["truncated"]
            and not change_meta["truncated"]
        )
        pagination_truncated = (
            resource_meta["truncated"]
            or relationship_meta["truncated"]
            or connectivity_meta["truncated"]
            or change_meta["truncated"]
        )
        projection_records = [
            {
                "projection_id": projection["projection_id"],
                "status_perspective_id": perspective["perspective_id"],
                "payload": {
                    "kind": "link",
                    "link_id": item["connectivity_id"],
                    "source": item["endpoint_a"],
                    "target": item["endpoint_b"],
                    "directed": item["directed"],
                },
                "usability": (
                    item["operational"]["status"]
                    if item["operational"]["status"]
                    in {"usable", "unusable", "degraded"}
                    else "unknown"
                ),
                "exists": item.get("exists", True),
                "source_resource_ids": [
                    source["resource_id"] for source in item["status_sources"]
                ],
                "properties": {"operational": item["operational"]},
                "unknown_fields": [
                    *item.get("unknown_fields", []),
                    *(
                        []
                        if item["operational"]["usable"] is not None
                        else [
                            {
                                "name": "usability",
                                "reason_code": item["operational"]["reason"],
                            }
                        ]
                    ),
                ],
                "provenance": "plugin_projection",
                "quality": item["quality"],
            }
            for item in inferred
        ]
        response: dict[str, Any] = {
            "revision_id": self.revision_id,
            "projection_id": projection["projection_id"],
            "topology_projection_id": projection["projection_id"],
            "status_perspective_id": perspective["perspective_id"],
            "resolved_basis": resolved_basis,
            "basis": resolved_basis,
            "node_times": node_times,
            "resources": resources if "resources" in include_names else [],
            "relationships": relationships if "relationships" in include_names else [],
            "inferred_connectivity": inferred,
            "projection_records": projection_records,
            "changes": changes,
            "complete": complete,
            "truncated": pagination_truncated,
            "next_cursor": change_meta["next_cursor"] or next_resource_cursor,
            "next_resource_cursor": next_resource_cursor,
            "next_change_cursor": change_meta["next_cursor"],
            "counts": {
                "resources": resource_meta,
                "relationships": relationship_meta,
                "inferred_connectivity": connectivity_meta,
                "changes": change_meta,
            },
            "completeness": {
                "complete": complete,
                "incomplete_nodes": incomplete_nodes,
                "resources": resource_meta,
                "relationships": relationship_meta,
                "inferred_connectivity": connectivity_meta,
                "changes": change_meta,
                "changes_truncated": change_meta["truncated"],
                "remote_status_note": (
                    "Some selected nodes supply clock/topology observations "
                    "without a status-bearing analysis revision: "
                    + ", ".join(incomplete_nodes)
                    if incomplete_nodes
                    else None
                ),
            },
            "semantic_ownership": {
                "projection": "plugin",
                "status_mapping": "plugin",
                "temporal_query": "core",
            },
        }
        return response

    def query_changes(self, body: dict[str, Any]) -> dict[str, Any]:
        self._reject_generic_cursor(body)
        """Return a bounded ordered replay slice between two temporal bases."""

        projection, perspective = self._selection(
            body.get("projection_id", body.get("topology_projection_id")),
            body.get("status_perspective_id"),
        )
        start_basis = body.get("start_basis")
        end_basis = body.get("end_basis")
        if not isinstance(start_basis, dict) or not isinstance(end_basis, dict):
            raise TemporalTopologyRequestError(
                "topology change queries require start_basis and end_basis"
            )
        clock_policy = str(
            body.get(
                "clock_policy",
                end_basis.get(
                    "clock_policy", start_basis.get("clock_policy", "strict")
                ),
            )
        )
        if clock_policy not in {"strict", "best_effort"}:
            raise TemporalTopologyRequestError(
                "clock_policy must be strict or best_effort"
            )
        node_ids = self._selected_node_ids(body, end_basis)
        start_resolved, start_nodes = self._resolve_basis(
            start_basis, projection, perspective, node_ids, clock_policy
        )
        end_resolved, end_nodes = self._resolve_basis(
            end_basis, projection, perspective, node_ids, clock_policy
        )
        start_ns = self._primary_query_time(start_nodes)
        end_ns = self._primary_query_time(end_nodes)
        if end_ns < start_ns:
            raise TemporalTopologyRequestError(
                "end_basis resolves before start_basis for the local revision"
            )
        limit = max(
            1,
            min(
                _ns(
                    body.get("change_limit", body.get("page_size", 200)),
                    "change_limit",
                ),
                1000,
            ),
        )
        resource_limit = max(
            1,
            min(_ns(body.get("resource_limit", 100), "resource_limit"), 500),
        )
        requested_resource_ids = [
            str(item) for item in body.get("resource_ids") or []
        ]
        kinds = {str(item) for item in body.get("kinds") or []}
        if requested_resource_ids or kinds:
            resources, resource_meta = self._resource_views(
                projection,
                perspective,
                end_nodes,
                resource_ids=requested_resource_ids,
                kinds=kinds,
                offset=0,
                limit=resource_limit,
            )
        else:
            resources = []
            resource_meta = {
                "total_count": 0,
                "returned_count": 0,
                "offset": 0,
                "truncated": False,
                "next_offset": None,
            }
        resource_meta["next_cursor"] = None
        change_resource_ids = (
            set(requested_resource_ids)
            if requested_resource_ids
            else {item["resource_id"] for item in resources}
            if kinds
            else set()
        )
        change_fingerprint = self._cursor_fingerprint(
            {
                "projection_id": projection["projection_id"],
                "status_perspective_id": perspective["perspective_id"],
                "start_ns": start_ns,
                "end_ns": end_ns,
                "resource_ids": sorted(change_resource_ids),
                "kinds": sorted(kinds),
            }
        )
        change_cursor = self._decode_cursor(
            body.get("change_cursor"),
            "change",
            change_fingerprint,
        )
        changes, change_meta = self._changes(
            projection,
            perspective,
            start_ns,
            end_ns,
            change_resource_ids,
            limit,
            after=self._change_after(change_cursor),
            position=change_cursor["position"],
        )
        next_change_cursor = None
        if change_meta["next_after"] is not None:
            next_change_cursor = self._encode_cursor(
                "change",
                change_fingerprint,
                position=change_meta["next_position"],
                after=change_meta["next_after"],
            )
        change_meta["next_cursor"] = next_change_cursor
        change_meta.pop("next_after", None)
        change_meta.pop("next_position", None)
        start_by_node = {item["node_id"]: item for item in start_nodes}
        end_by_node = {item["node_id"]: item for item in end_nodes}
        node_ranges = [
            {
                "node_id": node_id,
                "start": start_by_node.get(node_id),
                "end": end_by_node.get(node_id),
                "simultaneity": "not_implied"
                if (
                    start_resolved["kind"] == "relative_capture_vector"
                    or end_resolved["kind"] == "relative_capture_vector"
                )
                else "absolute_interval",
            }
            for node_id in node_ids
        ]
        incomplete_nodes = [
            item["node_id"]
            for item in end_nodes
            if item["resolution"] not in {"exact", "bounded", "local_exact"}
            or not item.get("resources_available", False)
        ]
        return {
            "revision_id": self.revision_id,
            "projection_id": projection["projection_id"],
            "topology_projection_id": projection["projection_id"],
            "status_perspective_id": perspective["perspective_id"],
            "start_basis": start_resolved,
            "end_basis": end_resolved,
            "node_ranges": node_ranges,
            "changes": changes,
            "returned_count": len(changes),
            "total_count": change_meta["total_count"],
            "total_count_is_exact": change_meta["total_count_is_exact"],
            "minimum_total_count": change_meta["minimum_total_count"],
            "truncated": change_meta["truncated"],
            "next_cursor": next_change_cursor,
            "next_change_cursor": next_change_cursor,
            "counts": {"changes": change_meta},
            "complete": (
                not change_meta["truncated"]
                and not resource_meta["truncated"]
                and not incomplete_nodes
            ),
            "completeness": {
                "complete": (
                    not change_meta["truncated"]
                    and not resource_meta["truncated"]
                    and not incomplete_nodes
                ),
                "incomplete_nodes": incomplete_nodes,
                "resources": resource_meta,
                "changes": change_meta,
                "changes_truncated": change_meta["truncated"],
            },
            "replay_note": (
                "Resource and relationship changes are generic core records; the "
                "selected plug-in projection recomputes inferred connectivity from them."
            ),
        }

    def _projection(self, identifier: Any) -> dict[str, Any]:
        requested = str(identifier or self.contract["default_projection_id"])
        for item in self.contract["topology_projections"]:
            if item["projection_id"] == requested:
                return item
        raise TemporalTopologyRequestError(f"unknown topology projection: {requested}")

    def _perspective(self, identifier: Any) -> dict[str, Any]:
        requested = str(identifier or self.contract["default_status_perspective_id"])
        for item in self.contract["status_perspectives"]:
            if item["perspective_id"] == requested:
                return item
        raise TemporalTopologyRequestError(f"unknown status perspective: {requested}")

    def _selection(
        self, projection_id: Any, perspective_id: Any
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        projection = self._projection(projection_id)
        requested_perspective = (
            perspective_id
            or projection.get("default_status_perspective_id")
            or self.contract["default_status_perspective_id"]
        )
        perspective = self._perspective(requested_perspective)
        supported = set(projection.get("supported_status_perspective_ids") or [])
        if supported and perspective["perspective_id"] not in supported:
            raise TemporalTopologyRequestError(
                f"status perspective {perspective['perspective_id']} is not supported "
                f"by topology projection {projection['projection_id']}"
            )
        return projection, perspective

    def _selected_node_ids(
        self, body: dict[str, Any], basis: dict[str, Any]
    ) -> list[str]:
        values = body.get("node_ids") or body.get("nodes") or []
        if not values:
            values = [item.get("node_id") for item in basis.get("scopes") or []]
        if not values and isinstance(basis.get("scope"), dict):
            values = [basis["scope"].get("node_id")]
        if not values:
            values = [item["node_id"] for item in self.contract["nodes"]]
        known = {item["node_id"] for item in self.contract["nodes"]}
        result = list(dict.fromkeys(str(value) for value in values))
        if unknown := set(result) - known:
            raise TemporalTopologyRequestError(
                "unknown topology nodes: " + ", ".join(sorted(unknown))
            )
        return result

    def _resolve_basis(
        self,
        basis: dict[str, Any],
        projection: dict[str, Any],
        perspective: dict[str, Any],
        node_ids: list[str],
        clock_policy: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        kind = str(basis.get("kind", "relative_to_watermark"))
        if kind == "relative_to_scope_end":
            kind = "relative_to_watermark"
        if kind not in {"absolute_time", "relative_to_watermark"}:
            raise TemporalTopologyRequestError(
                "basis.kind must be absolute_time or relative_to_watermark"
            )
        node_by_id = {item["node_id"]: item for item in self.contract["nodes"]}
        scopes = list(basis.get("scopes") or [])
        if isinstance(basis.get("scope"), dict):
            scopes.append(basis["scope"])
        scope_by_node = {
            str(item.get("node_id")): item for item in basis.get("scopes") or []
        }
        scope_by_node.update(
            {str(item.get("node_id")): item for item in scopes if item.get("node_id")}
        )
        node_times: list[dict[str, Any]] = []
        if kind == "absolute_time":
            clock_domain = str(basis.get("clock_domain", "utc"))
            if clock_domain not in self.contract.get("absolute_clock_domains", {"utc"}):
                raise TemporalTopologyRequestError(
                    f"unsupported absolute clock domain: {clock_domain}"
                )
            timestamp_ns = _ns(
                basis.get("time_ns", basis.get("timestamp_ns")), "basis.time_ns"
            )
            for node_id in node_ids:
                node_times.append(
                    self._absolute_node_time(
                        node_by_id[node_id], perspective, timestamp_ns, clock_policy
                    )
                )
            resolved_kind = "absolute_time"
            anchor = None
        else:
            default_offset = _ns(basis.get("offset_ns", 0), "basis.offset_ns")
            if default_offset > 0:
                raise TemporalTopologyRequestError(
                    "basis.offset_ns must be zero or negative"
                )
            for node_id in node_ids:
                scope = scope_by_node.get(node_id, {})
                offset = _ns(scope.get("offset_ns", default_offset), "scope.offset_ns")
                if offset > 0:
                    raise TemporalTopologyRequestError(
                        "scope.offset_ns must be zero or negative"
                    )
                watermark = self._watermark(
                    node_by_id[node_id], projection, perspective, scope
                )
                node_times.append(
                    self._relative_node_time(
                        node_by_id[node_id], perspective, watermark, offset, clock_policy
                    )
                )
            resolved_kind = "relative_capture_vector"
            anchor = {
                "kind": "layer_watermark",
                "status_perspective_id": perspective["perspective_id"],
                "topology_projection_id": projection["projection_id"],
            }
        return (
            {
                "requested": basis,
                "kind": resolved_kind,
                "clock_policy": clock_policy,
                "anchor": anchor,
                "simultaneity": (
                    "same_absolute_instant"
                    if resolved_kind == "absolute_time"
                    else "not_implied"
                ),
                "node_count": len(node_times),
                "clock_domain": (
                    str(basis.get("clock_domain", "utc"))
                    if resolved_kind == "absolute_time"
                    else None
                ),
            },
            node_times,
        )

    def _clock(self, node: dict[str, Any], perspective: dict[str, Any]) -> dict[str, Any] | None:
        clocks = node.get("clocks", {})
        return clocks.get(perspective["perspective_id"]) or clocks.get("default")

    def _absolute_node_time(
        self,
        node: dict[str, Any],
        perspective: dict[str, Any],
        timestamp_ns: int,
        clock_policy: str,
    ) -> dict[str, Any]:
        clock = self._clock(node, perspective)
        if not clock:
            return self._unaligned_node_time(node, perspective, clock_policy)
        uncertainty = _ns(
            clock["uncertainty_ns"],
            "clock.uncertainty_ns",
        )
        if uncertainty < 0:
            raise TemporalTopologyRequestError(
                "clock.uncertainty_ns must be zero or positive"
            )
        local_offset = _ns(
            clock["local_minus_absolute_ns"],
            "clock.local_minus_absolute_ns",
        )
        local_time = _ns_add(
            timestamp_ns,
            local_offset,
            "resolved local time",
        )
        local_min = _ns_subtract(
            local_time,
            uncertainty,
            "resolved local minimum",
        )
        local_max = _ns_add(
            local_time,
            uncertainty,
            "resolved local maximum",
        )
        absolute_min = _ns_subtract(
            timestamp_ns,
            uncertainty,
            "resolved absolute minimum",
        )
        absolute_max = _ns_add(
            timestamp_ns,
            uncertainty,
            "resolved absolute maximum",
        )
        return {
            "node_id": node["node_id"],
            "status_perspective_id": perspective["perspective_id"],
            "clock_domain": clock["clock_domain"],
            "local_clock_domain": clock["clock_domain"],
            "query_time_ns": str(timestamp_ns),
            "local_time_ns": str(local_time),
            "local_min_ns": str(local_min),
            "local_max_ns": str(local_max),
            "resolved_at_min_ns": str(absolute_min),
            "resolved_at_max_ns": str(absolute_max),
            "absolute_min_ns": str(absolute_min),
            "absolute_max_ns": str(absolute_max),
            "uncertainty_ns": str(uncertainty),
            "resolution": "exact" if uncertainty == 0 else "bounded",
            "mapping_method": clock["method"],
            "mapping_quality": clock["quality"],
            "quality": clock["quality"],
            "reason_code": None,
            "resources_available": bool(node.get("resources_available")),
        }

    def _relative_node_time(
        self,
        node: dict[str, Any],
        perspective: dict[str, Any],
        watermark: dict[str, Any] | None,
        offset_ns: int,
        clock_policy: str,
    ) -> dict[str, Any]:
        if watermark is None:
            return self._unaligned_node_time(node, perspective, clock_policy)
        query_time_ns = _ns_add(
            _ns(
                watermark["query_time_ns"],
                "watermark.query_time_ns",
            ),
            offset_ns,
            "resolved relative query time",
        )
        local_time_ns = _ns_add(
            _ns(
                watermark["local_time_ns"],
                "watermark.local_time_ns",
            ),
            offset_ns,
            "resolved relative local time",
        )
        absolute_min = watermark.get("absolute_min_ns")
        absolute_max = watermark.get("absolute_max_ns")
        if absolute_min is not None:
            absolute_min = _ns_add(
                _ns(
                    absolute_min,
                    "watermark.absolute_min_ns",
                ),
                offset_ns,
                "resolved relative absolute minimum",
            )
            absolute_max = _ns_add(
                _ns(
                    absolute_max,
                    "watermark.absolute_max_ns",
                ),
                offset_ns,
                "resolved relative absolute maximum",
            )
        uncertainty = (
            None
            if absolute_min is None
            else _ns(
                max(0, (int(absolute_max) - int(absolute_min)) // 2),
                "resolved relative uncertainty",
            )
        )
        return {
            "node_id": node["node_id"],
            "status_perspective_id": perspective["perspective_id"],
            "clock_domain": watermark["clock_domain"],
            "local_clock_domain": watermark["clock_domain"],
            "query_time_ns": str(query_time_ns),
            "local_time_ns": str(local_time_ns),
            "local_min_ns": str(local_time_ns),
            "local_max_ns": str(local_time_ns),
            "resolved_at_min_ns": str(
                query_time_ns if absolute_min is None else absolute_min
            ),
            "resolved_at_max_ns": str(
                query_time_ns if absolute_max is None else absolute_max
            ),
            "absolute_min_ns": None if absolute_min is None else str(absolute_min),
            "absolute_max_ns": None if absolute_max is None else str(absolute_max),
            "uncertainty_ns": None if uncertainty is None else str(uncertainty),
            "resolution": "local_exact" if absolute_min is None else "bounded",
            "mapping_method": watermark.get("mapping_method"),
            "mapping_quality": watermark["quality"],
            "quality": watermark["quality"],
            "reason_code": None,
            "resources_available": bool(node.get("resources_available")),
            "watermark_ns": str(watermark["local_time_ns"]),
            "watermark_query_time_ns": str(watermark["query_time_ns"]),
            "watermark_quality": watermark["quality"],
            "relative_offset_ns": str(offset_ns),
        }

    @staticmethod
    def _unaligned_node_time(
        node: dict[str, Any],
        perspective: dict[str, Any],
        clock_policy: str,
    ) -> dict[str, Any]:
        return {
            "node_id": node["node_id"],
            "status_perspective_id": perspective["perspective_id"],
            "local_clock_domain": None,
            "query_time_ns": None,
            "local_time_ns": None,
            "local_min_ns": None,
            "local_max_ns": None,
            "resolved_at_min_ns": None,
            "resolved_at_max_ns": None,
            "absolute_min_ns": None,
            "absolute_max_ns": None,
            "uncertainty_ns": None,
            "resolution": "clock_unaligned",
            "mapping_method": None,
            "mapping_quality": "unknown",
            "quality": "unknown",
            "reason_code": "clock_unaligned",
            "clock_policy": clock_policy,
            "resources_available": bool(node.get("resources_available")),
        }

    def _watermark(
        self,
        node: dict[str, Any],
        projection: dict[str, Any],
        perspective: dict[str, Any],
        scope: Any,
    ) -> dict[str, Any] | None:
        if scope and isinstance(scope, dict):
            anchor = scope.get("anchor") or scope
            anchor_kind = anchor.get("kind", "layer_watermark")
            if anchor_kind != "layer_watermark":
                raise TemporalTopologyRequestError(
                    "only layer_watermark anchors are supported by this provider"
                )
            selected_perspective = anchor.get("status_perspective_id")
            if selected_perspective and selected_perspective != perspective["perspective_id"]:
                raise TemporalTopologyRequestError(
                    "watermark scope status_perspective_id does not match the query"
                )
            selected_projection = anchor.get("topology_projection_id")
            if selected_projection and selected_projection != projection["projection_id"]:
                raise TemporalTopologyRequestError(
                    "watermark scope topology_projection_id does not match the query"
                )
        watermark = (
            node.get("watermarks", {})
            .get(perspective["perspective_id"], {})
            .get(projection["projection_id"])
        )
        if not watermark:
            return None
        return dict(watermark)

    def _catalog_for_perspective(
        self,
        perspective: dict[str, Any],
        resource_ids: list[str],
        kinds: set[str],
        projection_kinds: set[str],
    ) -> list[dict[str, Any]]:
        if resource_ids:
            candidates = [
                self.resource_by_id[item]
                for item in resource_ids
                if item in self.resource_by_id
            ]
        else:
            # Canonical identity belongs to the projection, not to the selected
            # status perspective. Switching control/programmed/observed status
            # therefore keeps this ordered catalog stable.
            candidates = list(self.resource_by_id.values())
        if kinds:
            candidates = [item for item in candidates if item.get("kind") in kinds]
        if projection_kinds:
            candidates = [
                item for item in candidates if item.get("kind") in projection_kinds
            ]
        candidates.sort(
            key=lambda item: (
                str(item.get("kind", "")),
                str(item.get("label", "")),
                str(item["resource_id"]),
            )
        )
        if not resource_ids and self.runtime is not None:
            representative = [
                self.resource_by_id[item]
                for item in getattr(self.runtime, "initial_resource_ids", [])
                if item in self.resource_by_id
                and (not kinds or self.resource_by_id[item].get("kind") in kinds)
                and (
                    not projection_kinds
                    or self.resource_by_id[item].get("kind") in projection_kinds
                )
            ]
            seen = {item["resource_id"] for item in representative}
            representative.extend(
                item for item in candidates if item["resource_id"] not in seen
            )
            candidates = representative
        return candidates

    def _resource_views(
        self,
        projection: dict[str, Any],
        perspective: dict[str, Any],
        node_times: list[dict[str, Any]],
        *,
        resource_ids: list[str],
        kinds: set[str],
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        projection_kinds = set(projection.get("resource_kinds") or [])
        candidates = self._catalog_for_perspective(
            perspective,
            resource_ids,
            kinds,
            projection_kinds,
        )
        total = _page_count(len(candidates), "resource page count")
        offset = _page_count(offset, "resource_cursor offset")
        if offset > total:
            raise TemporalTopologyRequestError(
                "resource_cursor is beyond the end of this query"
            )
        page = candidates[offset : offset + limit]
        time_by_node = {item["node_id"]: item for item in node_times}
        result: list[dict[str, Any]] = []
        for record in page:
            node_id = _resource_node(record, self.default_node)
            node_time = time_by_node.get(node_id)
            if not node_time or node_time.get("query_time_ns") is None:
                result.append(
                    self._unknown_resource(
                        record, node_id, "clock_unaligned", perspective
                    )
                )
                continue
            result.append(
                self._state_with_uncertainty(
                    record, node_id, node_time, perspective
                )
            )
        next_offset = _page_count(offset + len(result), "resource page count")
        has_more = next_offset < total
        return result, {
            "total_count": total,
            "returned_count": len(result),
            "offset": offset,
            "truncated": has_more,
            "next_offset": next_offset if has_more else None,
        }

    def _state_with_uncertainty(
        self,
        record: dict[str, Any],
        node_id: str,
        node_time: dict[str, Any],
        perspective: dict[str, Any],
    ) -> dict[str, Any]:
        center_ns = int(node_time["query_time_ns"])
        min_ns = int(node_time["resolved_at_min_ns"])
        max_ns = int(node_time["resolved_at_max_ns"])
        status_events = self._perspective_status_events(
            str(record["resource_id"]), perspective
        )
        sample_times = {min_ns, center_ns, max_ns}
        states, lifecycle = self._resource_history(str(record["resource_id"]))
        if self._has_named_history(states) or not self._allows_unqualified_perspective(perspective):
            states = state_intervals_for_perspective(
                states, self._perspective_ref(perspective)
            )
        elif str(record.get("layer", "unknown")) != perspective["layer"]:
            states = []
        for interval in (*states, *lifecycle):
            for field in ("valid_from_ns", "valid_to_ns"):
                bound = interval.get(field)
                if bound is not None:
                    timestamp = temporal_integer(bound, field)
                    if min_ns <= timestamp <= max_ns:
                        sample_times.add(timestamp)
                        if timestamp > min_ns:
                            sample_times.add(timestamp - 1)
        for item in status_events:
            timestamp = int(item["timestamp_ns"])
            if min_ns <= timestamp <= max_ns:
                sample_times.add(timestamp)
                if timestamp > min_ns:
                    sample_times.add(timestamp - 1)
        samples = [
            (
                timestamp,
                self._perspective_state_at(
                    record, perspective, timestamp, status_events
                ),
            )
            for timestamp in sorted(sample_times)
        ]
        unique, comparison_complete = distinct_temporal_states(samples)
        center = self._perspective_state_at(
            record, perspective, center_ns, status_events
        )
        common = {
            "resource_id": str(record["resource_id"]),
            "node_id": node_id,
            "layer": perspective["layer"],
            "status_layer": perspective["layer"],
            "status_perspective_id": perspective["perspective_id"],
            "native_layer": str(record.get("layer", "unknown")),
            "kind": str(record.get("kind", "UNKNOWN")),
            "label": str(record.get("label", record["resource_id"])),
            "key": record.get("key", {}),
            "basis_time_ns": str(center_ns),
            "time_uncertainty_ns": node_time.get("uncertainty_ns"),
            "plugin_defined": bool(record.get("plugin_defined", True)),
        }
        if not comparison_complete:
            return {
                **common,
                "exists": None,
                "status": "unknown",
                "status_class": "unknown",
                "state": None,
                "properties": None,
                "valid_from_ns": None,
                "valid_to_ns": None,
                "quality": "unknown",
                "temporal_resolution": "unknown",
                "possible_states": [],
                "unknown_fields": [
                    {
                        "name": "*",
                        "reason_code": "state_comparison_unavailable",
                        "message": (
                            "The state could not be compared safely inside "
                            "the mapped clock interval."
                        ),
                    }
                ],
            }
        if len(unique) > 1:
            return {
                **common,
                "exists": None,
                "status": "ambiguous",
                "status_class": "unknown",
                "state": None,
                "properties": None,
                "valid_from_ns": None,
                "valid_to_ns": None,
                "quality": "ambiguous",
                "temporal_resolution": "ambiguous",
                "possible_states": [
                    {
                        "sampled_at_ns": str(sampled_at),
                        "exists": view.get("exists"),
                        "status": view.get("status"),
                        "state": view.get("state"),
                        "valid_from_ns": view.get("valid_from_ns"),
                        "valid_to_ns": view.get("valid_to_ns"),
                    }
                    for sampled_at, view in sorted(unique)
                ],
                "unknown_fields": [
                    {
                        "name": "*",
                        "reason_code": "clock_window_crosses_state_transition",
                        "message": "More than one state is possible inside the mapped clock interval.",
                    }
                ],
            }
        return {
            **common,
            "exists": center.get("exists"),
            "status": center.get("status", "unknown"),
            "status_class": center.get("status_class", "unknown"),
            "state": center.get("state", {}),
            "properties": center.get("state", {}),
            "valid_from_ns": center.get("valid_from_ns"),
            "valid_to_ns": center.get("valid_to_ns"),
            "source_event_uid": center.get("source_event_uid"),
            "quality": (
                "best_effort"
                if min_ns != max_ns and center.get("quality") == "exact"
                else center.get("quality", "unknown")
            ),
            "temporal_resolution": "stable_within_clock_window",
            "possible_states": [],
            "unknown_fields": center.get("unknown_fields", []),
        }

    def _resource_history(
        self, resource_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        cached = self._resource_history_cache.get(resource_id)
        if cached is None:
            if self.runtime is not None:
                states = list(self.runtime.state_by_resource.get(resource_id, ()))
                lifecycle = list(self.runtime.lifecycle_by_resource.get(resource_id, ()))
            else:
                states = [
                    item for item in self.dataset.get("state_intervals", [])
                    if item.get("resource") == resource_id
                ]
                lifecycle = [
                    item for item in self.dataset.get("lifecycle_intervals", [])
                    if item.get("resource") == resource_id
                ]
            cached = states, lifecycle
            self._resource_history_cache[resource_id] = cached
        return cached

    @staticmethod
    def _has_named_history(states: list[dict[str, Any]]) -> bool:
        return any(item.get("perspective_ref") is not None for item in states)

    @staticmethod
    def _perspective_ref(perspective: dict[str, Any]) -> StatusPerspectiveRef:
        return StatusPerspectiveRef(
            perspective["perspective_id"],
            perspective.get("plugin_instance_id"),
            perspective.get("schema_digest"),
        )

    def _allows_unqualified_perspective(self, perspective: dict[str, Any]) -> bool:
        if perspective.get("plugin_instance_id") or perspective.get("schema_digest"):
            return False
        return sum(
            item.get("layer") == perspective["layer"]
            for item in self.contract.get("status_perspectives", [])
        ) <= 1

    def _perspective_status_events(
        self, resource_id: str, perspective: dict[str, Any]
    ) -> list[dict[str, Any]]:
        requested = self._perspective_ref(perspective)
        cache_key = (
            resource_id, requested.perspective_id,
            requested.plugin_instance_id, requested.schema_digest,
        )
        cached = self._perspective_event_cache.get(cache_key)
        if cached is not None:
            return cached
        if self.runtime is not None:
            candidates = self.runtime.events_by_resource.get(resource_id, [])
        else:
            candidates = [
                event
                for event in self._events
                if resource_id in event.get("affected_resources", [])
                or event.get("resource_id") == resource_id
                or any(
                    effect.get("resource_id") == resource_id
                    for effect in event.get("effects", [])
                )
            ]
        entries: list[dict[str, Any]] = []
        named = (
            self._has_named_history(self._resource_history(resource_id)[0])
            or not self._allows_unqualified_perspective(perspective)
        )
        for event in candidates:
            if _event_layer(event) != perspective["layer"]:
                continue
            effects = [
                effect
                for effect in event.get("effects", [])
                if effect.get("resource_id") == resource_id
                and effect.get("state_changed", event.get("state_changed", True))
            ]
            if not effects and event.get("resource_id") == resource_id and event.get(
                "state_changed", False
            ):
                effects = [
                    {
                        "resource_id": resource_id,
                        "effect_type": event.get("action", "modify"),
                        "after": event.get("properties", {}),
                        "state_changed": True,
                    }
            ]
            for effect_index, effect in enumerate(effects):
                explicit = effect.get("perspective_ref", event.get("perspective_ref"))
                if named and explicit is None:
                    continue
                if explicit is not None and not state_intervals_for_perspective(
                    [{"perspective_ref": explicit}], requested
                ):
                    continue
                timestamp_ns, source_sequence, event_uid = temporal_order_key(
                    event,
                    time_field="timestamp_ns",
                    identifier_fields=("event_uid", "event_id"),
                )
                entries.append(
                    {
                        "timestamp_ns": timestamp_ns,
                        "source_sequence": source_sequence,
                        "event_uid": event_uid,
                        "effect_index": effect_index,
                        "order_key": (
                            timestamp_ns,
                            source_sequence,
                            event_uid,
                            effect_index,
                        ),
                        "operation": str(
                            effect.get("effect_type", event.get("action", "modify"))
                        ).casefold(),
                        "after": dict(effect.get("after") or {}),
                    }
                )
        entries.sort(key=lambda item: item["order_key"])
        self._perspective_event_cache[cache_key] = entries
        return entries

    def _perspective_state_at(
        self,
        record: dict[str, Any],
        perspective: dict[str, Any],
        timestamp_ns: int,
        entries: list[dict[str, Any]],
        *,
        through_order: tuple[int, int, str, int] | None = None,
    ) -> dict[str, Any]:
        resource_id = str(record["resource_id"])
        native = str(record.get("layer", "unknown")) == perspective["layer"]
        states, lifecycle = self._resource_history(resource_id)
        named = self._has_named_history(states) or not self._allows_unqualified_perspective(perspective)
        selected_states = (
            state_intervals_for_perspective(states, self._perspective_ref(perspective))
            if named else states if native else []
        )
        read_time = timestamp_ns
        if through_order is not None and timestamp_ns > MIN_TEMPORAL_NS:
            read_time = checked_temporal_subtract(timestamp_ns, 1, "event before time")
        initial = None
        if through_order is None or timestamp_ns > MIN_TEMPORAL_NS:
            if named and self.perspective_state_reader is not None:
                initial = _invoke_provider_callback(
                    self.perspective_state_reader, "perspective state read",
                    resource_id, read_time, self._perspective_ref(perspective),
                )
            elif native and not named and self.state_reader is not None:
                initial = _invoke_provider_callback(
                    self.state_reader, "state read", resource_id, read_time,
                )
        initial_available = isinstance(initial, dict)
        initial_observed = (
            initial_available
            and isinstance(initial.get("exists"), bool)
        )
        state = (
            dict(initial.get("state") or {})
            if initial_observed and isinstance(initial, dict)
            else {}
        )
        exists: bool | None = (
            initial.get("exists")
            if initial_observed and isinstance(initial, dict)
            else None
        )
        if (
            not initial_available
            and
            entries
            and entries[0]["operation"] in RESOURCE_CREATION_OPERATIONS
        ):
            state = {}
            exists = False
        valid_from = (
            initial.get("valid_from_ns")
            if initial_observed and isinstance(initial, dict)
            else None
        )
        valid_to = initial.get("valid_to_ns") if initial_available else None
        source_event_uid = (
            initial.get("source_event_uid")
            if initial_observed and isinstance(initial, dict)
            else None
        )
        observed = initial_available
        applied_entries = 0
        anchor_ns = (
            temporal_integer(valid_from, "valid_from_ns")
            if valid_from is not None else None
        )
        anchor_order = next(
            (tuple(entry["order_key"]) for entry in entries
             if source_event_uid is not None and entry.get("event_uid") == source_event_uid),
            None,
        )
        snapshot_times = {
            temporal_integer(item["valid_from_ns"], "valid_from_ns")
            for item in selected_states
            if item.get("valid_from_ns") is not None
            and item.get("start_event_uid", item.get("source_event_uid")) is None
        }
        unresolved_order = any(
            int(entry["timestamp_ns"]) in snapshot_times
            and int(entry["timestamp_ns"]) == (
                timestamp_ns if through_order is not None else anchor_ns
            )
            for entry in entries
        )
        if unresolved_order:
            # Snapshot observations have no event-sequence coordinate. Neither
            # their iterator position nor their timestamp orders a same-time effect.
            observed = False
            entries = []
        for entry in entries:
            entry_time = int(entry["timestamp_ns"])
            entry_order = tuple(entry["order_key"])
            if entry_time > timestamp_ns or (
                through_order is not None and entry_order > through_order
            ):
                if valid_to is None or entry_time < int(valid_to):
                    valid_to = str(entry_time)
                break
            if anchor_order is not None and entry_order <= anchor_order:
                continue
            if anchor_order is None and anchor_ns is not None and entry_time <= anchor_ns:
                continue
            operation = entry["operation"]
            if operation in RESOURCE_CREATION_OPERATIONS:
                state = {}
                exists = True
            elif operation in RESOURCE_DELETION_OPERATIONS:
                exists = False
            # A modify/update after a delete intentionally retains latent
            # state but must not recreate lifecycle existence. Only an
            # explicit create/add/insert operation reopens the resource.
            state.update(entry["after"])
            valid_from = str(entry_time)
            source_event_uid = entry.get("event_uid")
            observed = True
            applied_entries += 1
        # A replayed create cannot extend an authoritative lifecycle interval.
        active_lifecycle = active_interval(lifecycle, timestamp_ns)
        if lifecycle and active_lifecycle is None:
            exists = False
            previous_ends = [
                int(item["valid_to_ns"]) for item in lifecycle
                if item.get("valid_to_ns") is not None
                and int(item["valid_to_ns"]) <= timestamp_ns
            ]
            next_starts = [
                int(item["valid_from_ns"]) for item in lifecycle
                if item.get("valid_from_ns") is not None
                and int(item["valid_from_ns"]) > timestamp_ns
            ]
            valid_from = str(max(previous_ends)) if previous_ends else None
            valid_to = str(min(next_starts)) if next_starts else None
        elif exists is True and active_lifecycle is not None:
            start = active_lifecycle.get("valid_from_ns")
            end = active_lifecycle.get("valid_to_ns")
            if start is not None and (valid_from is None or int(start) > int(valid_from)):
                valid_from = str(start)
            if end is not None and (valid_to is None or int(end) < int(valid_to)):
                valid_to = str(end)
        if not observed:
            return {
                "exists": None,
                "status": "unknown",
                "status_class": "unknown",
                "state": None,
                "valid_from_ns": None,
                "valid_to_ns": None,
                "source_event_uid": None,
                "quality": "unknown",
                "unknown_fields": [
                    {
                        "name": "status",
                        "reason_code": (
                            "snapshot_event_order_unknown" if unresolved_order
                            else "selected_perspective_status_missing"
                        ),
                    }
                ],
            }
        if exists is False:
            status = "absent"
        elif exists is None:
            status = "unknown"
        elif initial_available and not applied_entries:
            status = str(initial.get("status", "unknown"))
        else:
            status = str(
                state.get("status")
                or state.get("oper_state")
                or state.get("program_state")
                or "observed"
            )
        normalized_status = status.casefold()
        status_class = (
            "unknown"
            if exists is None
            else
            "healthy"
            if normalized_status in set(perspective["usable_statuses"])
            else "error"
            if normalized_status in set(perspective["unusable_statuses"])
            else "unknown"
        )
        return {
            "exists": exists,
            "status": status,
            "status_class": status_class,
            "state": state,
            "valid_from_ns": valid_from,
            "valid_to_ns": valid_to,
            "source_event_uid": source_event_uid,
            "quality": (
                "exact"
                if applied_entries and exists is not None
                else "partial"
                if applied_entries
                else initial.get("quality", "observed_snapshot")
                if initial_available
                else "unknown"
            ),
            "unknown_fields": (
                initial.get("unknown_fields", [])
                if initial_available
                else [] if exists is not None
                else [
                    {
                        "name": "exists",
                        "reason_code": "lifecycle_evidence_missing",
                    }
                ]
            ),
        }

    @staticmethod
    def _unknown_resource(
        record: dict[str, Any],
        node_id: str,
        reason: str,
        perspective: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "resource_id": str(record["resource_id"]),
            "node_id": node_id,
            "layer": (
                perspective["layer"]
                if perspective is not None
                else str(record.get("layer", "unknown"))
            ),
            "status_layer": perspective["layer"] if perspective is not None else None,
            "status_perspective_id": (
                perspective["perspective_id"] if perspective is not None else None
            ),
            "native_layer": str(record.get("layer", "unknown")),
            "kind": str(record.get("kind", "UNKNOWN")),
            "label": str(record.get("label", record["resource_id"])),
            "key": record.get("key", {}),
            "exists": None,
            "status": "unknown",
            "status_class": "unknown",
            "state": None,
            "properties": None,
            "quality": "unknown",
            "temporal_resolution": "unknown",
            "possible_states": [],
            "unknown_fields": [{"name": "*", "reason_code": reason}],
        }

    def _relationship_candidates(
        self, timestamp_ns: int, resource_ids: set[str]
    ) -> list[dict[str, Any]]:
        if self.runtime is None:
            return _materialize_provider_items(
                _invoke_provider_callback(
                    self.relationship_reader,
                    "relationship read",
                    timestamp_ns,
                ),
                "relationship read",
            )
        unique: dict[str, dict[str, Any]] = {}
        for identifier in resource_ids:
            for item in self.runtime.relationships_by_endpoint.get(identifier, []):
                valid_from = item.get("valid_from_ns")
                valid_to = item.get("valid_to_ns")
                if contains_time(
                    timestamp_ns,
                    (
                        None
                        if valid_from is None
                        else _ns(valid_from, "relationship.valid_from_ns")
                    ),
                    (
                        None
                        if valid_to is None
                        else _ns(valid_to, "relationship.valid_to_ns")
                    ),
                ):
                    unique[_relationship_key(item)] = item
        return list(unique.values())

    def _relationship_views(
        self,
        projection: dict[str, Any],
        node_times: list[dict[str, Any]],
        resource_ids: set[str],
        relationship_limit: int,
        connectivity_limit: int,
        *,
        requested_relation_types: set[str] | None = None,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        dict[str, Any],
    ]:
        node_time = next(
            (
                item
                for item in node_times
                if item["node_id"] == self.default_node
                and item.get("query_time_ns") is not None
            ),
            None,
        )
        if node_time is None:
            return [], [], {
                "total_count": 0,
                "returned_count": 0,
                "truncated": False,
                "connectivity_candidate_count": 0,
            }
        center_ns = int(node_time["query_time_ns"])
        min_ns = int(node_time["resolved_at_min_ns"])
        max_ns = int(node_time["resolved_at_max_ns"])
        declared_types = projection.get("relationship_types")
        relation_types = set(declared_types) if declared_types is not None else None
        if requested_relation_types is not None:
            relation_types = (
                requested_relation_types
                if relation_types is None
                else relation_types & requested_relation_types
            )
        probe_times = {min_ns, center_ns, max_ns}
        if self.runtime is not None:
            interval_candidates = {
                _relationship_key(item): item
                for identifier in resource_ids
                for item in self.runtime.relationships_by_endpoint.get(identifier, [])
            }.values()
        else:
            interval_candidates = self.dataset.get("relationship_intervals", [])
        for item in interval_candidates:
            relation_type = item.get("relation_type", item.get("type", "related_to"))
            if relation_types is not None and relation_type not in relation_types:
                continue
            if resource_ids and not (
                item.get("source") in resource_ids
                or item.get("target") in resource_ids
            ):
                continue
            for boundary in (item.get("valid_from_ns"), item.get("valid_to_ns")):
                if boundary is None:
                    continue
                boundary_ns = int(boundary)
                if min_ns <= boundary_ns <= max_ns:
                    probe_times.add(boundary_ns)
                    if boundary_ns > min_ns:
                        probe_times.add(boundary_ns - 1)
        ordered_probe_times = sorted(probe_times)
        samples = [
            self._relationship_candidates(timestamp_ns, resource_ids)
            for timestamp_ns in ordered_probe_times
        ]
        maps = [
            {
                _relationship_key(item): item
                for item in values
                if (
                    relation_types is None
                    or item.get("relation_type", item.get("type")) in relation_types
                )
                and relationship_presence(item) is not False
                and (
                    not resource_ids
                    or item.get("source") in resource_ids
                    or item.get("target") in resource_ids
                )
            }
            for values in samples
        ]
        center_map = maps[ordered_probe_times.index(center_ns)]
        keys = sorted(set().union(*(set(item) for item in maps)))
        total = len(keys)
        result: list[dict[str, Any]] = []
        connectivity_sources: list[dict[str, Any]] = []
        connectivity_types = set(projection.get("connectivity_relation_types") or [])
        connectivity_candidate_count = 0
        for key in keys:
            item = center_map.get(key) or next(
                mapping[key] for mapping in maps if key in mapping
            )
            relation_type = item.get("relation_type", item.get("type", "related_to"))
            is_connectivity = relation_type in connectivity_types
            if is_connectivity:
                connectivity_candidate_count += 1
            need_relationship = len(result) < relationship_limit
            need_connectivity = (
                is_connectivity
                and len(connectivity_sources) < connectivity_limit
            )
            if not need_relationship and not need_connectivity:
                continue
            possible_presence = sorted({
                value
                for mapping in maps
                for value in possible_relationship_presence(mapping.get(key))
            })
            confirmed_present = possible_presence == [True]
            view = {
                "relationship_id": key,
                "source": item["source"],
                "target": item["target"],
                "source_resource_id": item["source"],
                "target_resource_id": item["target"],
                "relation_type": relation_type,
                "present": True if confirmed_present else None,
                "temporal_resolution": (
                    "stable_within_clock_window" if confirmed_present else "ambiguous"
                ),
                "possible_presence": possible_presence,
                "valid_from_ns": item.get("valid_from_ns"),
                "valid_to_ns": item.get("valid_to_ns"),
                "quality": (
                    item.get("quality", "unknown") if confirmed_present else "ambiguous"
                ),
                "provenance": item.get("provenance", "unknown"),
                "evidence": item.get("evidence", []),
            }
            if need_relationship:
                result.append(view)
            if need_connectivity:
                connectivity_sources.append(view)
        return result, connectivity_sources, {
            "total_count": total,
            "returned_count": len(result),
            "truncated": total > len(result),
            "connectivity_candidate_count": connectivity_candidate_count,
        }

    def _inferred_connectivity(
        self,
        projection: dict[str, Any],
        perspective: dict[str, Any],
        node_times: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        time_by_node = {item["node_id"]: item for item in node_times}
        for connection in projection.get("static_connectivity", []):
            node_id = str(connection.get("status_node_id", self.default_node))
            node_time = time_by_node.get(node_id)
            source_ids = connection.get("status_sources", {}).get(
                perspective["perspective_id"], []
            )
            source_views = []
            for identifier in source_ids:
                record = self.resource_by_id.get(identifier)
                if not record:
                    source_views.append(
                        self._missing_status_source(
                            identifier, "plugin_declared_status_source_missing"
                        )
                    )
                elif node_time and node_time.get("query_time_ns") is not None:
                    source_views.append(
                        self._state_with_uncertainty(
                            record, node_id, node_time, perspective
                        )
                    )
                else:
                    source_views.append(
                        self._missing_status_source(identifier, "clock_unaligned")
                    )
            policy = connection.get(
                "status_source_combination_policy",
                projection.get(
                    "status_source_combination_policy", "all_required_usable"
                ),
            )
            operational = self._operational_status(
                source_views, perspective, str(policy), len(source_ids)
            )
            result.append(
                {
                    "connectivity_id": connection["connectivity_id"],
                    "endpoint_a": connection["endpoint_a"],
                    "endpoint_b": connection["endpoint_b"],
                    "directed": bool(connection.get("directed", False)),
                    "exists": True,
                    "operational": operational,
                    "status_sources": [
                        {
                            "resource_id": item["resource_id"],
                            "status": item["status"],
                            "temporal_resolution": item["temporal_resolution"],
                        }
                        for item in source_views
                    ],
                    "inference": {
                        "owner": "plugin",
                        "rule_id": connection["rule_id"],
                    },
                    "quality": operational["quality"],
                    "unknown_fields": (
                        []
                        if operational["usable"] is not None
                        else [
                            {
                                "name": "usability",
                                "reason_code": operational["reason"],
                            }
                        ]
                    ),
                }
            )
        dynamic_types = set(projection.get("connectivity_relation_types") or [])
        for relationship in relationships:
            if relationship["relation_type"] not in dynamic_types:
                continue
            source_views = []
            for identifier in (relationship["source"], relationship["target"]):
                record = self.resource_by_id.get(identifier)
                if not record:
                    source_views.append(
                        self._missing_status_source(
                            identifier, "relationship_endpoint_missing"
                        )
                    )
                    continue
                node_id = _resource_node(record, self.default_node)
                node_time = time_by_node.get(node_id)
                if node_time and node_time.get("query_time_ns") is not None:
                    source_views.append(
                        self._state_with_uncertainty(
                            record, node_id, node_time, perspective
                        )
                    )
                else:
                    source_views.append(
                        self._missing_status_source(identifier, "clock_unaligned")
                    )
            relationship_ambiguous = relationship.get("present") is not True
            operational = (
                {
                    "usable": None,
                    "status": "ambiguous",
                    "quality": "ambiguous",
                    "reason": "relationship_presence_ambiguous",
                }
                if relationship_ambiguous
                else self._operational_status(
                    source_views,
                    perspective,
                    str(
                        projection.get(
                            "status_source_combination_policy",
                            "all_required_usable",
                        )
                    ),
                    2,
                )
            )
            result.append(
                {
                    "connectivity_id": f"relation:{relationship['relationship_id']}",
                    "endpoint_a": {
                        "topology_node_id": relationship["source"],
                        "resource_id": relationship["source"],
                    },
                    "endpoint_b": {
                        "topology_node_id": relationship["target"],
                        "resource_id": relationship["target"],
                    },
                    "directed": True,
                    "exists": None if relationship_ambiguous else True,
                    "possible_presence": relationship.get("possible_presence", [True]),
                    "relationship_temporal_resolution": relationship.get(
                        "temporal_resolution"
                    ),
                    "operational": operational,
                    "status_sources": [
                        {
                            "resource_id": item["resource_id"],
                            "status": item["status"],
                            "temporal_resolution": item["temporal_resolution"],
                        }
                        for item in source_views
                    ],
                    "inference": {
                        "owner": "plugin",
                        "rule_id": f"relationship:{relationship['relation_type']}",
                    },
                    "quality": operational["quality"],
                    "unknown_fields": (
                        [
                            {
                                "name": "existence",
                                "reason_code": "relationship_presence_ambiguous",
                            }
                        ]
                        if relationship_ambiguous
                        else []
                    ),
                }
            )
        return result

    @staticmethod
    def _missing_status_source(resource_id: str, reason: str) -> dict[str, Any]:
        return {
            "resource_id": resource_id,
            "status": "unknown",
            "temporal_resolution": "unknown",
            "quality": "unknown",
            "unknown_fields": [{"name": "status", "reason_code": reason}],
        }

    @staticmethod
    def _operational_status(
        views: list[dict[str, Any]],
        perspective: dict[str, Any],
        policy: str,
        declared_source_count: int,
    ) -> dict[str, Any]:
        if policy not in {"all_required_usable", "any_declared_usable"}:
            return {
                "usable": None,
                "status": "unknown",
                "quality": "unknown",
                "reason": "unsupported_plugin_status_combination_policy",
            }
        if not views or declared_source_count == 0:
            return {
                "usable": None,
                "status": "unknown",
                "quality": "unknown",
                "reason": "no_status_source_in_selected_perspective",
            }
        usable_statuses = set(perspective["usable_statuses"])
        unusable_statuses = set(perspective["unusable_statuses"])
        classifications = []
        for item in views:
            if item.get("temporal_resolution") == "ambiguous":
                classifications.append("ambiguous")
                continue
            status = str(item.get("status", "unknown")).casefold()
            if status in usable_statuses:
                classifications.append("usable")
            elif status in unusable_statuses:
                classifications.append("unusable")
            else:
                classifications.append("unknown")
        if policy == "all_required_usable" and "unusable" in classifications:
            return {
                "usable": False,
                "status": "unusable",
                "quality": "exact",
                "reason": "plugin_declared_all_required_policy",
            }
        if (
            policy == "all_required_usable"
            and len(classifications) == declared_source_count
            and classifications
            and set(classifications) == {"usable"}
        ):
            return {
                "usable": True,
                "status": "usable",
                "quality": "exact",
                "reason": "plugin_declared_all_required_policy",
            }
        if policy == "any_declared_usable" and "usable" in classifications:
            return {
                "usable": True,
                "status": "usable",
                "quality": "exact",
                "reason": "plugin_declared_any_usable_policy",
            }
        if (
            policy == "any_declared_usable"
            and len(classifications) == declared_source_count
            and classifications
            and set(classifications) == {"unusable"}
        ):
            return {
                "usable": False,
                "status": "unusable",
                "quality": "exact",
                "reason": "plugin_declared_any_usable_policy",
            }
        if "ambiguous" in classifications:
            return {
                "usable": None,
                "status": "ambiguous",
                "quality": "ambiguous",
                "reason": "clock_window_crosses_source_transition",
            }
        return {
            "usable": None,
            "status": "unknown",
            "quality": "unknown",
            "reason": "plugin_status_sources_incomplete_or_unmapped",
        }

    def _changes(
        self,
        projection: dict[str, Any],
        perspective: dict[str, Any],
        start_ns: int,
        end_ns: int,
        resource_ids: set[str],
        limit: int,
        *,
        after: tuple[int, int, int, str] | None,
        position: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        position = _page_count(position, "change_cursor position")
        if end_ns < start_ns:
            raise TemporalTopologyRequestError(
                "change_start_ns must not exceed the resolved time"
            )

        event_left = bisect_left(self._event_times, start_ns)
        event_right = bisect_left(self._event_times, end_ns)
        local_node = next(
            item
            for item in self.contract["nodes"]
            if item["node_id"] == self.default_node
        )
        local_clock = self._clock(local_node, perspective)

        def time_fields(timestamp: int, observed_clock_domain: Any = None) -> dict[str, Any]:
            local_time = (
                timestamp
                + _ns(
                    local_clock["local_minus_absolute_ns"],
                    "clock.local_minus_absolute_ns",
                )
                if local_clock is not None
                else None
            )
            return {
                "local_time_ns": None if local_time is None else str(local_time),
                "local_clock_domain": (
                    local_clock["clock_domain"] if local_clock is not None else observed_clock_domain
                ),
                "absolute_min_ns": str(timestamp),
                "absolute_max_ns": str(timestamp),
                "time_uncertainty_ns": "0",
            }

        def event_changes():
            for index in range(event_left, event_right):
                event = self._events[index]
                timestamp, source_sequence, event_uid = temporal_order_key(
                    event,
                    time_field="timestamp_ns",
                    identifier_fields=("event_uid", "event_id"),
                )
                order_key = (
                    timestamp,
                    0,
                    source_sequence,
                    event_uid,
                )
                if after is not None and order_key <= after:
                    continue
                if _event_layer(event) != perspective["layer"]:
                    continue
                affected = [
                    str(item)
                    for item in event.get("affected_resources", [])
                    if not resource_ids or str(item) in resource_ids
                ]
                if resource_ids and not affected:
                    continue
                state_changes = []
                for resource_id in affected:
                    record = self.resource_by_id.get(resource_id)
                    if record is None:
                        continue
                    status_events = self._perspective_status_events(
                        resource_id, perspective
                    )
                    before = self._perspective_state_at(
                        record,
                        perspective,
                        timestamp,
                        status_events,
                        through_order=(
                            timestamp,
                            source_sequence,
                            event_uid,
                            -1,
                        ),
                    )
                    after_state = self._perspective_state_at(
                        record,
                        perspective,
                        timestamp,
                        status_events,
                        through_order=(
                            timestamp,
                            source_sequence,
                            event_uid,
                            2**31 - 1,
                        ),
                    )
                    state_changes.append(
                        {
                            "resource_id": resource_id,
                            "before": before,
                            "after": after_state,
                        }
                    )
                before_value: Any = None
                after_value: Any = None
                if len(state_changes) == 1:
                    before_value = state_changes[0]["before"]
                    after_value = state_changes[0]["after"]
                elif state_changes:
                    before_value = {
                        item["resource_id"]: item["before"] for item in state_changes
                    }
                    after_value = {
                        item["resource_id"]: item["after"] for item in state_changes
                    }
                yield order_key, {
                    "change_id": f"event:{event['event_uid']}",
                    "effective_time_ns": str(timestamp),
                    "node_id": self.default_node,
                    "change_kind": "resource_event",
                    "resource_ids": affected,
                    "event_uid": event["event_uid"],
                    "cause_event_id": event["event_uid"],
                    "operation": event.get("action"),
                    "outcome": event.get("outcome", "unknown"),
                    # Outcome and mutation are independent normalized fields.
                    # A failed callback may still report a partial, explicit
                    # state change; an OK callback may be a no-op.
                    "applied": bool(event.get("state_changed", False)),
                    "before": before_value,
                    "after": after_value,
                    "state_changes": state_changes,
                    "evidence": [{"event_uid": event["event_uid"]}],
                    "quality": "exact",
                    **time_fields(timestamp, event.get("clock_domain")),
                }

        relation_types = set(projection.get("relationship_types") or [])
        mutation_left = bisect_left(self._mutation_times, start_ns)
        mutation_right = bisect_left(self._mutation_times, end_ns)

        def mutation_changes():
            for index in range(mutation_left, mutation_right):
                mutation = self._mutations[index]
                (
                    timestamp,
                    source_sequence,
                    declared_mutation_id,
                ) = temporal_order_key(
                    mutation,
                    time_field="effective_time_ns",
                    identifier_fields=("mutation_id",),
                )
                relation_type = mutation.get(
                    "relation_type", mutation.get("type")
                )
                mutation_id = str(
                    declared_mutation_id
                    or f"relationship:{mutation.get('source')}:{relation_type}:"
                    f"{mutation.get('target')}:{timestamp}:"
                    f"{mutation.get('operation')}"
                )
                order_key = (
                    timestamp,
                    1,
                    source_sequence,
                    mutation_id,
                )
                if after is not None and order_key <= after:
                    continue
                if relation_types and relation_type not in relation_types:
                    continue
                if resource_ids and not {
                    mutation.get("source"),
                    mutation.get("target"),
                } & resource_ids:
                    continue
                operation = str(mutation.get("operation", "unknown"))
                present_before = (
                    operation.casefold() not in RESOURCE_CREATION_OPERATIONS
                )
                present_after = (
                    operation.casefold() not in RESOURCE_DELETION_OPERATIONS
                )
                yield order_key, {
                    "change_id": str(
                        mutation.get("mutation_id")
                        or f"relationship:{mutation.get('source')}:{relation_type}:"
                        f"{mutation.get('target')}:{timestamp}:{mutation.get('operation')}"
                    ),
                    "effective_time_ns": str(timestamp),
                    "node_id": self.default_node,
                    "change_kind": "relationship",
                    "source": mutation.get("source"),
                    "target": mutation.get("target"),
                    "relation_type": relation_type,
                    "operation": mutation.get("operation"),
                    "before": {"present": present_before},
                    "after": {"present": present_after},
                    "event_uid": mutation.get("cause_event_uid"),
                    "cause_event_id": mutation.get("cause_event_uid"),
                    "evidence": (
                        [{"event_uid": mutation.get("cause_event_uid")}]
                        if mutation.get("cause_event_uid")
                        else []
                    ),
                    "quality": mutation.get("quality", "unknown"),
                    **time_fields(timestamp),
                }

        buffered: list[
            tuple[tuple[int, int, int, str], dict[str, Any]]
        ] = []
        for item in heapq.merge(event_changes(), mutation_changes(), key=lambda row: row[0]):
            buffered.append(item)
            if len(buffered) > limit:
                break
        page = buffered[:limit]
        has_more = len(buffered) > limit
        next_after = page[-1][0] if has_more and page else None
        returned_count = len(page)
        next_position = _page_count(position + returned_count, "change page count")
        minimum_total = _page_count(
            next_position + (1 if has_more else 0), "change page count"
        )
        return [item[1] for item in page], {
            "total_count": None if has_more else next_position,
            "total_count_is_exact": not has_more,
            "minimum_total_count": minimum_total,
            "returned_count": returned_count,
            "position": position,
            "truncated": has_more,
            "next_after": next_after,
            "next_position": next_position if has_more else None,
        }

    @staticmethod
    def _primary_query_time(node_times: list[dict[str, Any]]) -> int:
        for item in node_times:
            if item.get("resources_available") and item.get("query_time_ns") is not None:
                return int(item["query_time_ns"])
        raise TemporalTopologyRequestError("no selected node has a resolvable resource time")

    @staticmethod
    def _public_projection(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in item.items()
            if key not in {"static_connectivity"}
        }

    def _public_perspective(self, item: dict[str, Any]) -> dict[str, Any]:
        available_ids = {
            str(resource["resource_id"])
            for resource in self.resource_by_id.values()
            if resource.get("layer") == item["layer"]
        }
        for event in self._events:
            if _event_layer(event) != item["layer"]:
                continue
            available_ids.update(str(value) for value in event.get("affected_resources", []))
            available_ids.update(
                str(effect["resource_id"])
                for effect in event.get("effects", [])
                if effect.get("resource_id")
            )
        count = len(available_ids & set(self.resource_by_id))
        return {
            **item,
            "available_resource_count": count,
            "available": count > 0,
        }

    @staticmethod
    def _public_node(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "node_id": item["node_id"],
            "resources_available": bool(item.get("resources_available")),
            "status_scope": item.get("status_scope"),
            "clock_domains": {
                key: {
                    "clock_domain": value["clock_domain"],
                    "mapping_method": value["method"],
                    "mapping_quality": value["quality"],
                    "uncertainty_ns": str(value["uncertainty_ns"]),
                }
                for key, value in item.get("clocks", {}).items()
            },
            "watermarks": {
                perspective_id: {
                    projection_id: {
                        key: str(value) if key.endswith("_ns") else value
                        for key, value in watermark.items()
                    }
                    for projection_id, watermark in projections.items()
                }
                for perspective_id, projections in item.get("watermarks", {}).items()
            },
        }
