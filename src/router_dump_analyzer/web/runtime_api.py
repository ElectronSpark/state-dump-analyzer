"""Core-owned HTTP API over one dynamically loaded analysis runtime."""

from __future__ import annotations

import json
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, NoReturn

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi import HTTPException as FastAPIHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_dump_analyzer.control_plane import (
    DatasetIntegrityError,
    validate_revision_consistency_dataset,
)
from router_dump_analyzer.history_search_core import HistorySearchCapacityError
from router_dump_analyzer.load_progress import AnalysisLoadStage
from router_dump_analyzer.multi_node_route import MultiNodeRouteRequestError
from router_dump_analyzer.multi_node_topology import MultiNodeTopologyRequestError
from router_dump_analyzer.normalized_data import (
    project_consistency_findings_for_client,
    project_consistency_materialization_for_client,
)
from router_dump_analyzer.plugin_api import MAX_TIMESTAMP_NS, MIN_TIMESTAMP_NS
from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS
from router_dump_analyzer.public_text import (
    bounded_public_error_detail,
)
from router_dump_analyzer.source_record_core import (
    SourceRecordRequestError,
    project_source_record_for_log,
    project_source_record_text_selection,
    query_source_records,
    record_lanes_for_window,
    source_record_event_uids,
    source_record_haystack,
)
from router_dump_analyzer.temporal_core import (
    TEMPORAL_ORDER_VERSION,
    contains_time as _contains_time,
    overlaps_range as _overlaps_window,
    possible_relationship_presence,
    relationship_presence,
    temporal_integer,
    temporal_order_key,
)
from router_dump_analyzer.temporal_topology import TemporalTopologyRequestError
from router_dump_analyzer.value_core import (
    MAX_JSON_SAFE_INTEGER,
    parse_decimal_integer,
)
from router_dump_analyzer.web.runtime_context import current_runtime_session
from router_dump_analyzer.web.service_api import service_router


def _data_service() -> Any:
    return current_runtime_session().data_service


def revision_store() -> Any:
    return current_runtime_session().revision_store


def revision_scope(revision_id: str) -> AbstractContextManager[Any]:
    return _data_service().revision_scope(revision_id)


def load_dataset(
    revision_id: str | None = None,
    **selection: Any,
) -> dict[str, Any]:
    return _data_service().load_dataset(revision_id, **selection)


def client_dataset(
    revision_id: str | None = None,
    **selection: Any,
) -> dict[str, Any]:
    return _data_service().client_dataset(revision_id, **selection)


def current_revision_id(dataset: Any | None = None) -> str:
    return _data_service().current_revision_id(dataset)


def _analysis_metadata(dataset: dict[str, Any]) -> dict[str, Any]:
    return _data_service().analysis_metadata(dataset)


def history_runtime(dataset: Any | None = None) -> Any:
    return _data_service().history_runtime(dataset)


def has_indexed_history(dataset: Any | None = None) -> bool:
    return bool(_data_service().has_indexed_history(dataset))


def route_resolution_capability(
    dataset: Any | None = None,
) -> dict[str, Any]:
    return _data_service().route_resolution_capability(dataset)


def route_row(
    route_id: str,
    dataset: Any | None = None,
) -> dict[str, Any] | None:
    return _data_service().route_row(route_id, dataset)


def resource_id(record: dict[str, Any]) -> str:
    from router_dump_analyzer.normalized_data import resource_id as identify

    return identify(record)


def resource_state_at(resource_identifier: str, timestamp_ns: int) -> dict[str, Any]:
    return _data_service().resource_state_at(resource_identifier, timestamp_ns)


def relationships_at(timestamp_ns: int) -> list[dict[str, Any]]:
    return _data_service().relationships_at(timestamp_ns)


def resources_at(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _data_service().resources_at(*args, **kwargs)


def events_in_range(start_ns: int, end_ns: int) -> list[dict[str, Any]]:
    return _data_service().events_in_range(start_ns, end_ns)


def dashboard_query(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _data_service().dashboard_query(*args, **kwargs)


def range_summary(start_ns: int, end_ns: int) -> dict[str, Any]:
    return _data_service().range_summary(start_ns, end_ns)


def redact_event_for_client(
    event: dict[str, Any],
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    return _data_service().redact_event_for_client(event, *args, **kwargs)


def _event_redaction_policy(*args: Any, **kwargs: Any) -> Any:
    return _data_service().event_redaction_policy(*args, **kwargs)


def _redact_resource_for_client(*args: Any, **kwargs: Any) -> Any:
    return _data_service().redact_resource_for_client(*args, **kwargs)


def _redact_resource_view(*args: Any, **kwargs: Any) -> Any:
    return _data_service().redact_resource_view(*args, **kwargs)


def source_record_for_event(event: dict[str, Any]) -> dict[str, Any]:
    return _data_service().source_record_for_event(event)


MAX_CORRELATION_NODES = 500
MAX_TIMELINE_RESOURCE_LANES = 100
MAX_TIMELINE_GLYPHS = 10_000
MAX_TIMELINE_VIEWPORT_PIXELS = 100_000
MAX_TIMELINE_CLUSTER_DETAIL = 50
MAX_DENSITY_BINS = 4_096
MAX_EVENT_LOG_LIMIT = 500
MAX_EVENT_LOG_OFFSET = 10_000_000
MAX_EVENT_LOG_FILTER_VALUES = 64
MAX_EVENT_LOG_FILTER_LENGTH = 128
MAX_EVENT_LOG_SEARCH_LENGTH = 256
MAX_EVENT_LOG_UID_LENGTH = 256
MAX_EVENT_LOG_SELECTION_RANGES = 128
MAX_EVENT_LOG_SELECTION_ITEMS = 5_000
_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS = 1_024


class _RuntimeHTTPResponse(FastAPIHTTPException):
    """An HTTP response explicitly owned by this adapter."""

    def __init__(
        self,
        status_code: int,
        detail: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=status_code,
            detail=bounded_public_error_detail(
                detail,
                fallback="analysis request was rejected",
                maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
            ),
            headers=headers,
        )


@dataclass(frozen=True, slots=True)
class _RuntimeApiErrorPolicy:
    status_code: int
    public_detail: str
    expose_message: bool = False


# This inventory is deliberately exact. MRO resolution chooses the most
# specific declared policy independently of table order, while message
# exposure remains an exact-class capability. A new subclass therefore cannot
# inherit permission to publish arbitrary exception text.
_RUNTIME_API_ERROR_POLICY_BY_CLASS: Mapping[type[Exception], _RuntimeApiErrorPolicy] = (
    MappingProxyType(
        {
            TemporalTopologyRequestError: _RuntimeApiErrorPolicy(
                422,
                "temporal topology request was rejected",
                expose_message=True,
            ),
            MultiNodeRouteRequestError: _RuntimeApiErrorPolicy(
                422,
                "route trace request was rejected",
                expose_message=True,
            ),
            MultiNodeTopologyRequestError: _RuntimeApiErrorPolicy(
                422,
                "topology request was rejected",
                expose_message=True,
            ),
            SourceRecordRequestError: _RuntimeApiErrorPolicy(
                422,
                "source-record request was rejected",
                expose_message=True,
            ),
            # Bare built-ins can originate in storage, paths, plug-ins, or
            # integration code. They are never a caller-validation contract.
            ValueError: _RuntimeApiErrorPolicy(
                500,
                "internal analysis operation failed",
            ),
            TypeError: _RuntimeApiErrorPolicy(
                500,
                "internal analysis operation failed",
            ),
            TimeoutError: _RuntimeApiErrorPolicy(504, "analysis operation timed out"),
        }
    )
)

_RUNTIME_API_REQUEST_ERROR_ROOTS = (
    TemporalTopologyRequestError,
    MultiNodeTopologyRequestError,
    SourceRecordRequestError,
)


def _runtime_api_error_policy(
    error: Exception,
) -> _RuntimeApiErrorPolicy | None:
    """Resolve the nearest explicitly declared policy through the error MRO."""

    for error_class in type(error).__mro__:
        policy = _RUNTIME_API_ERROR_POLICY_BY_CLASS.get(error_class)
        if policy is not None:
            return policy
    return None


def _bounded_runtime_public_error_detail(
    error: Exception,
    policy: _RuntimeApiErrorPolicy,
) -> str:
    """Return exact safe request text or the policy's closed fallback."""

    fallback = policy.public_detail
    if (
        not policy.expose_message
        or _RUNTIME_API_ERROR_POLICY_BY_CLASS.get(type(error)) is not policy
    ):
        return fallback
    return bounded_public_error_detail(
        str(error),
        fallback=fallback,
        maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
    )


def _raise_runtime_api_error(error: Exception) -> NoReturn:
    if type(error) is _RuntimeHTTPResponse:
        raise error
    if isinstance(error, RequestValidationError):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="request validation failed",
        ) from error
    if isinstance(error, StarletteHTTPException):
        # This translator is entered only after a data/provider operation was
        # caught by `_runtime_api_call`. A framework HTTPException raised there
        # is not endpoint-owned validation and must not smuggle arbitrary status
        # or detail through the public boundary.
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="internal analysis operation failed",
        ) from error
    policy = _runtime_api_error_policy(error)
    if policy is None:
        raise error
    raise _RuntimeHTTPResponse(
        status_code=policy.status_code,
        detail=_bounded_runtime_public_error_detail(error, policy),
    ) from error


def _runtime_api_call(
    operation: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    try:
        return operation(*args, **kwargs)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:  # noqa: BLE001 - closed policy re-raises unknowns
        _raise_runtime_api_error(error)
    except BaseException as error:
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="internal analysis operation failed",
        ) from error


class _BoundedRuntimeApiRoute(APIRoute):
    """Apply the public error policy to the complete request lifecycle.

    The route handler returned by FastAPI includes dependency resolution and
    Python argument evaluation.  Keeping the fence here therefore covers
    provider acquisition as well as the selected provider method calls that
    use ``_runtime_api_call`` directly.
    """

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()

        async def bounded(request: Request) -> Any:
            try:
                return await original(request)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except Exception as error:  # noqa: BLE001 - closed boundary policy
                _raise_runtime_api_error(error)
            except BaseException as error:
                raise _RuntimeHTTPResponse(
                    status_code=500,
                    detail="internal analysis operation failed",
                ) from error

        return bounded


def _body_integer(
    body: dict[str, Any],
    field: str,
    default: int,
    *,
    minimum: int | None,
    maximum: int | None,
) -> int:
    """Read one explicitly bounded integer-shaped JSON field.

    Bounds are mandatory at every call site. A deliberately unbounded side
    must therefore be written as ``None`` instead of inheriting a semantically
    unrelated domain by omission.
    """

    if field not in body:
        value = default
    else:
        try:
            value = parse_decimal_integer(body[field], field)
        except ValueError as error:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail=f"{field} must be an integer or decimal integer string",
            ) from error
    if minimum is not None and value < minimum:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=f"{field} must be at least {minimum}",
        )
    if maximum is not None and value > maximum:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=f"{field} must be at most {maximum}",
        )
    return value


def _body_timestamp_ns(
    body: dict[str, Any],
    field: str,
    default: int,
) -> int:
    """Read one signed-64-bit nanosecond field from a JSON request body."""

    return _body_integer(
        body,
        field,
        default,
        minimum=MIN_TIMESTAMP_NS,
        maximum=MAX_TIMESTAMP_NS,
    )


def _body_string_list(body: dict[str, Any], field: str) -> list[str]:
    if field not in body:
        return []
    raw = body[field]
    if not isinstance(raw, list) or any(
        not isinstance(item, str) or not item for item in raw
    ):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=f"{field} must be an array of non-empty strings",
        )
    return list(dict.fromkeys(raw))


def _body_object_list(body: dict[str, Any], field: str) -> list[dict[str, Any]]:
    if field not in body:
        return []
    raw = body[field]
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=f"{field} must be an array of objects",
        )
    return raw


def _body_boolean(body: dict[str, Any], field: str, default: bool = False) -> bool:
    if field not in body:
        return default
    raw = body[field]
    if not isinstance(raw, bool):
        raise _RuntimeHTTPResponse(status_code=422, detail=f"{field} must be a boolean")
    return raw


async def _bind_request_revision_scope(
    request: Request,
) -> AsyncIterator[None]:
    """Bind the exact revision parsed by Starlette for this API operation.

    Revision identifiers intentionally may contain ``/``.  Request middleware
    runs before routing and therefore cannot safely distinguish an identifier
    such as ``a/inventory`` from revision ``a`` followed by the ``inventory``
    operation.  A router dependency runs after path matching, so the
    ``revision_id`` below is the same value injected into the endpoint.
    """

    parsed_revision_id = request.path_params.get("revision_id")
    if parsed_revision_id is None:
        yield
        return
    revision_id = str(parsed_revision_id)
    _require_revision(revision_id)
    with revision_scope(revision_id):
        yield


api_router: APIRouter = APIRouter(
    dependencies=[Depends(_bind_request_revision_scope)],
    route_class=_BoundedRuntimeApiRoute,
)
api_router.include_router(service_router)


def _require_revision_store():
    """Return the opened runtime revision store or fail the API closed."""

    store = revision_store()
    if store is None:
        raise _RuntimeHTTPResponse(
            status_code=503,
            detail="analysis input is not open",
        )
    return store


def _require_revision(revision_id: str) -> Any:
    store = _require_revision_store()
    lookup_error: KeyError | None = None
    descriptor = None
    # Revision lookup itself may be the first touch of a lazy core store. Keep
    # that materialization visible, but consume an expected lookup miss inside
    # the operation so a normal 404 cannot poison global load state.
    with _data_service()._loading_operation():
        try:
            descriptor = store.revision(revision_id)
        except KeyError as error:
            lookup_error = error
    if lookup_error is not None:
        raise _RuntimeHTTPResponse(
            status_code=404,
            detail="unknown node revision",
        ) from lookup_error
    return descriptor


def _temporal_topology(revision_id: str | None = None) -> Any:
    """Return the plug-in-policy-backed temporal engine for one revision."""

    provider = current_runtime_session().temporal_provider
    if provider is None:
        raise _RuntimeHTTPResponse(
            status_code=501,
            detail="the loaded plug-in does not provide temporal topology",
        )
    from router_dump_analyzer.temporal_topology import (
        TemporalTopologyService,
    )

    service = _runtime_api_call(
        provider.for_revision,
        revision_id,
        _data_service(),
    )
    if not isinstance(service, TemporalTopologyService):
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="temporal provider returned a non-core query service",
        )
    return service


def _temporal_topology_query(body: dict[str, Any]) -> dict[str, Any]:
    revision_id = current_revision_id(load_dataset())
    return _runtime_api_call(_temporal_topology(revision_id).query, body)


def _temporal_topology_changes_query(body: dict[str, Any]) -> dict[str, Any]:
    revision_id = current_revision_id(load_dataset())
    return _runtime_api_call(_temporal_topology(revision_id).query_changes, body)


def _multi_node_topology() -> Any:
    provider = current_runtime_session().topology_provider
    if provider is None:
        raise _RuntimeHTTPResponse(
            status_code=501,
            detail="the loaded plug-in does not provide multi-node topology",
        )
    from router_dump_analyzer.multi_node_topology import (
        MultiNodeTopologyService,
    )

    # A topology provider may lazily parse one or more node dumps while it
    # constructs its core query service.  Bind that work to the same progress
    # operation used by ordinary revision loads, even when the provider reads
    # through its own format-aware source.
    with _data_service()._loading_operation():
        service = _runtime_api_call(provider.get)
    if not isinstance(service, MultiNodeTopologyService):
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="topology provider returned a non-core query service",
        )
    return service


def _multi_node_route() -> Any:
    provider = current_runtime_session().route_provider
    if provider is None:
        raise _RuntimeHTTPResponse(
            status_code=501,
            detail="the loaded plug-in does not provide route tracing",
        )
    from router_dump_analyzer.multi_node_route import MultiNodeRouteService

    with _data_service()._loading_operation():
        service = _runtime_api_call(provider.get)
    if not isinstance(service, MultiNodeRouteService):
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="route provider returned a non-core query service",
        )
    return service


def _multi_node_call(operation: Callable[..., Any], *args: Any) -> Any:
    return _runtime_api_call(operation, *args)


def _require_topology_assembly(assembly_id: str) -> None:
    store = _require_revision_store()
    with _data_service()._loading_operation():
        active_assembly_id = store.assembly.assembly_id
    if assembly_id != active_assembly_id:
        raise _RuntimeHTTPResponse(status_code=404, detail="unknown topology assembly")


def _active_topology_assembly_id() -> str:
    store = _require_revision_store()
    with _data_service()._loading_operation():
        return store.assembly.assembly_id


def _resource_id(record: dict[str, Any]) -> str:
    return resource_id(record)


def _indexed_resource_exists(runtime: Any, identifier: str, timestamp_ns: int) -> bool:
    return any(
        _contains_time(
            timestamp_ns,
            interval.get("valid_from_ns"),
            interval.get("valid_to_ns"),
        )
        for interval in runtime.lifecycle_by_resource.get(identifier, [])
    )


def _graph_edge_payload(
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
        "temporal_note": temporal_note if temporal_note is not None else item.get("temporal_note"),
        "valid_from_ns": item.get("valid_from_ns"),
        "valid_to_ns": item.get("valid_to_ns"),
        "start_event_uid": item.get("start_event_uid"),
        "end_event_uid": item.get("end_event_uid"),
    }


def _graph_payload(timestamp_ns: int) -> dict[str, Any]:
    dataset = load_dataset()
    complete = {_resource_id(item): item for item in dataset["resources"]}
    descriptor_index = {item["kind"]: item for item in dataset["kind_descriptors"]}
    active_views = {
        identifier: view
        for identifier in complete
        if (view := resource_state_at(identifier, timestamp_ns))["exists"] is not False
    }
    relationships = [
        item
        for item in relationships_at(timestamp_ns)
        if item["source"] in active_views and item["target"] in active_views
    ]

    nodes: list[dict[str, Any]] = []
    for identifier in sorted(active_views):
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
        _graph_edge_payload(item, item.get("relationship_id", f"edge-{index}"))
        for index, item in enumerate(relationships)
    ]
    return {
        "revision_id": current_revision_id(dataset),
        "time_ns": str(timestamp_ns),
        "nodes": nodes,
        "edges": edges,
        "incomplete_node_count": sum(not node["complete_record"] for node in nodes),
        "note": (
            "Nodes require an active resource lifecycle; edges additionally require "
            "an active relationship interval and two active endpoints. Explicitly "
            "absent relationships are excluded; unknown presence remains ambiguous."
        ),
    }


def _correlation_payload(body: dict[str, Any]) -> dict[str, Any]:
    dataset = load_dataset()
    if has_indexed_history(dataset):
        return _indexed_correlation_payload(dataset, body)
    timestamp_ns = _body_timestamp_ns(
        body,
        "time_ns",
        int(_analysis_metadata(dataset)["capture_ns"]),
    )
    payload = _graph_payload(timestamp_ns)
    relation_types = set(_body_string_list(body, "relation_types"))
    edges = [
        edge
        for edge in payload["edges"]
        if not relation_types or edge["type"] in relation_types
    ]
    requested_roots = _body_string_list(body, "resource_ids")
    direction_value = body.get("direction", "both")
    if not isinstance(direction_value, str):
        raise _RuntimeHTTPResponse(status_code=422, detail="direction must be a string")
    direction = direction_value
    if direction not in {"incoming", "outgoing", "both"}:
        raise _RuntimeHTTPResponse(
            status_code=422, detail="direction must be incoming, outgoing or both"
        )
    depth = _body_integer(body, "depth", 3, minimum=0, maximum=20)
    max_nodes = _body_integer(
        body,
        "max_nodes",
        MAX_CORRELATION_NODES,
        minimum=1,
        maximum=MAX_CORRELATION_NODES,
    )
    active_node_ids = {str(node["id"]) for node in payload["nodes"]}
    known_node_ids = {resource_id(record) for record in dataset.get("resources", [])}
    unknown_roots = [
        identifier for identifier in requested_roots if identifier not in known_node_ids
    ]
    inactive_roots = [
        identifier
        for identifier in requested_roots
        if identifier in known_node_ids and identifier not in active_node_ids
    ]
    active_roots = [
        identifier for identifier in requested_roots if identifier in active_node_ids
    ]
    dropped_roots = active_roots[max_nodes:]
    roots = active_roots[:max_nodes]

    if not requested_roots:
        accepted_ids = sorted(active_node_ids)[:max_nodes]
        accepted_set = set(accepted_ids)
        payload["nodes"] = [
            node for node in payload["nodes"] if node["id"] in accepted_set
        ]
        payload["edges"] = [
            edge
            for edge in edges
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
    for _ in range(depth):
        following: set[str] = set()
        for edge in edges:
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
    payload["nodes"] = [node for node in payload["nodes"] if node["id"] in reached]
    payload["edges"] = [
        edge
        for edge in edges
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
    dataset: dict[str, Any],
    body: dict[str, Any],
) -> dict[str, Any]:
    """Return a bounded, time-valid neighborhood from the scale indexes."""

    runtime = history_runtime(dataset)
    if runtime is None:  # pragma: no cover - guarded by the caller
        raise _RuntimeHTTPResponse(
            status_code=500, detail="scale indexes are unavailable"
        )
    timestamp_ns = _body_timestamp_ns(
        body,
        "time_ns",
        int(_analysis_metadata(dataset)["capture_ns"]),
    )
    direction_value = body.get("direction", "both")
    if not isinstance(direction_value, str):
        raise _RuntimeHTTPResponse(status_code=422, detail="direction must be a string")
    direction = direction_value
    if direction not in {"incoming", "outgoing", "both"}:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="direction must be incoming, outgoing or both",
        )
    depth = _body_integer(body, "depth", 3, minimum=0, maximum=20)
    if depth < 0 or depth > 20:
        raise _RuntimeHTTPResponse(
            status_code=422, detail="depth must be between 0 and 20"
        )
    relation_types = set(_body_string_list(body, "relation_types"))
    requested_roots = _body_string_list(body, "resource_ids")
    defaulted = not requested_roots
    if defaulted:
        requested_roots = runtime.initial_resource_ids[:4]
    max_nodes = _body_integer(
        body,
        "max_nodes",
        MAX_CORRELATION_NODES,
        minimum=1,
        maximum=MAX_CORRELATION_NODES,
    )
    known_roots = [
        identifier
        for identifier in requested_roots
        if identifier in runtime.resource_by_id
    ]
    unknown_roots = [
        identifier
        for identifier in requested_roots
        if identifier not in runtime.resource_by_id
    ]
    active_roots = [
        identifier
        for identifier in known_roots
        if _indexed_resource_exists(runtime, identifier, timestamp_ns)
    ]
    active_root_set = set(active_roots)
    inactive_roots = [
        identifier for identifier in known_roots if identifier not in active_root_set
    ]
    roots = active_roots[:max_nodes]
    dropped_roots = active_roots[max_nodes:]
    reached = set(roots)
    frontier = set(roots)
    truncated = bool(dropped_roots)
    for _ in range(depth):
        following: set[str] = set()
        for identifier in frontier:
            for relationship in runtime.relationships_by_endpoint.get(identifier, []):
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
                    and _indexed_resource_exists(runtime, other, timestamp_ns)
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
    for identifier in reached:
        for relationship in runtime.relationships_by_endpoint.get(identifier, []):
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

    descriptor_index = {item["kind"]: item for item in dataset["kind_descriptors"]}
    nodes: list[dict[str, Any]] = []
    for identifier in sorted(reached):
        view = resource_state_at(identifier, timestamp_ns)
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
    node_ids = {node["id"] for node in nodes}
    edges = [
        _graph_edge_payload(
            item, key, temporal_note="selected from full-scale validity interval"
        )
        for key, item in sorted(edge_records.items())
        if item["source"] in node_ids and item["target"] in node_ids
    ]
    return {
        "revision_id": current_revision_id(dataset),
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


def analysis_health_projection() -> dict[str, Any]:
    """Project the opened analysis session for the shared health route.

    The shared service boundary validates this result and converts every
    exception or malformed provider value into a stable degraded response.
    """

    # Load through the normalized-data service before consulting revision-store
    # properties.  A core ingestion store may still be lazy here; touching its
    # default revision first would run the parser outside the tracked load
    # operation and make a health probe invisible to the progress surface.
    dataset = load_dataset()
    opened_revision_store = revision_store()
    runtime = history_runtime(dataset)
    search_status: Any = (
        runtime.event_search.status_snapshot()
        if runtime is not None
        else {
            "ready": False,
            "document_count": 0,
            "storage": "eager",
            "backend": "eager",
        }
    )
    metadata = _analysis_metadata(dataset)
    with _data_service()._loading_operation():
        assembly = opened_revision_store.assembly
        loaded_revision_ids = list(opened_revision_store.loaded_revision_ids())
    revisions = tuple(assembly.revisions)
    return {
        "analysis_ready": True,
        "revision_id": current_revision_id(dataset),
        "mode": metadata.get("mode", "analysis"),
        "event_count": metadata.get("event_count", 0),
        "matched_event_count": metadata.get(
            "matched_event_count",
            metadata.get("event_count", 0),
        ),
        "resource_count": metadata.get("resource_count", 0),
        "source_record_count": metadata.get(
            "source_record_count",
            len(dataset.get("source_records", [])),
        ),
        "history_search_ready": search_status["ready"],
        "history_search_document_count": search_status["document_count"],
        "history_search_storage": search_status["storage"],
        "history_search_backend": search_status["backend"],
        "assembly": {
            "assembly_id": assembly.assembly_id,
            "node_count": len(revisions),
            "coverage_case_count": len(assembly.coverage_case_ids),
            "events_per_node_min": min(item.event_count for item in revisions),
            "resources_per_node_min": min(item.resource_count for item in revisions),
            "resources_per_node_max": max(item.resource_count for item in revisions),
            "loaded_revision_ids": loaded_revision_ids,
        },
    }


def _client_workspace_json() -> bytes:
    session = current_runtime_session()
    return session.cached(
        ("client-workspace-json",),
        lambda: json.dumps(
            client_dataset(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8"),
    )


@api_router.get("/v1/workspace")
def workspace_dataset() -> Response:
    """Return the browser bootstrap fixture without server-only indexes."""

    return Response(content=_client_workspace_json(), media_type="application/json")


_NODE_WORKSPACE_LAYER_COLORS = (
    "#5eead4",
    "#60a5fa",
    "#a78bfa",
    "#f59e0b",
    "#fb7185",
    "#34d399",
)


def _node_workspace_dataset(
    node_id: str,
    query: dict[str, Any],
) -> dict[str, Any]:
    """Adapt one plug-in-projected member snapshot to the generic node UI.

    The adapter intentionally does not infer vendor resource semantics.  It
    preserves the plug-in's resource identities, state, status perspective,
    and local-link declarations while supplying the generic timeline/table
    envelope consumed by the browser workspace.
    """

    snapshot = _multi_node_call(_multi_node_topology().query_node, node_id, query)
    node = snapshot["node"]
    resolved = node.get("resolved_time") or snapshot.get("resolved_basis") or {}
    capture_ns = int(
        resolved.get("query_time_ns")
        or resolved.get("resolved_time_ns")
        or resolved.get("time_ns")
        or _analysis_metadata(load_dataset())["capture_ns"]
    )
    timeline_start_ns = capture_ns - 1_000_000_000
    timeline_end_ns = capture_ns + 1_000_000_000

    resources: list[dict[str, Any]] = []
    layers: dict[str, dict[str, Any]] = {}
    for item in node.get("resources", []):
        if item.get("exists") is False:
            continue
        plugin = item.get("plugin_provenance") or {}
        layer = str(
            item.get("status_perspective_id")
            or plugin.get("projection_id")
            or plugin.get("plugin_id")
            or "unknown"
        )
        if layer not in layers:
            layers[layer] = {
                "id": layer,
                "layer": layer,
                # Descriptor identifiers are plug-in vocabulary.  The generic
                # adapter preserves them literally when no display label was
                # supplied instead of guessing human wording.
                "label": str(
                    item.get("status_perspective_label")
                    or plugin.get("projection_label")
                    or layer
                ),
                "color": _NODE_WORKSPACE_LAYER_COLORS[
                    len(layers) % len(_NODE_WORKSPACE_LAYER_COLORS)
                ],
            }
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        properties = (
            item.get("properties") if isinstance(item.get("properties"), dict) else {}
        )
        normalized_state = {**properties, **state}
        if "status" not in normalized_state and item.get("status") is not None:
            normalized_state["status"] = item["status"]
        resources.append(
            {
                **item,
                "resource_id": str(item["resource_id"]),
                "layer": layer,
                "kind": str(item.get("kind") or "unknown"),
                "label": str(item.get("label") or item["resource_id"]),
                "state": normalized_state,
                "properties": properties,
                "node_id": node["node_id"],
                "member_id": node["member_id"],
            }
        )

    resource_ids = {item["resource_id"] for item in resources}
    relationship_intervals: list[dict[str, Any]] = []
    for index, item in enumerate(node.get("local_links", [])):
        source = str(item.get("source_resource_id") or item.get("source") or "")
        target = str(item.get("target_resource_id") or item.get("target") or "")
        if source not in resource_ids or target not in resource_ids:
            continue
        relation_type = str(
            item.get("relation_type") or item.get("link_type") or "unknown"
        )
        relationship_intervals.append(
            {
                **item,
                "relationship_id": str(
                    item.get("relationship_id")
                    or item.get("link_id")
                    or f"{node_id}:local-link:{index}"
                ),
                "source": source,
                "target": target,
                "relation_type": relation_type,
                "type": relation_type,
                "valid_from_ns": None,
                "valid_to_ns": None,
                "quality": str(item.get("quality") or "plugin_declared"),
                "provenance": str(
                    (item.get("plugin_provenance") or {}).get("plugin_id")
                    or "plugin_projection"
                ),
            }
        )

    lifecycle_intervals = [
        {
            "resource": item["resource_id"],
            "valid_from_ns": None,
            "valid_to_ns": None,
            "start_event_uid": None,
            "end_event_uid": None,
        }
        for item in resources
    ]
    state_intervals = [
        {
            "resource": item["resource_id"],
            "valid_from_ns": None,
            "valid_to_ns": None,
            "status": item.get("status"),
            "status_class": item.get("status_class", "unknown"),
            "state": item.get("state", {}),
            "properties": item.get("state", {}),
            "quality": item.get("quality", "best_effort"),
        }
        for item in resources
    ]
    timeline_lanes = [
        {
            "lane_id": item["resource_id"],
            "resource_id": item["resource_id"],
            "layer": item["layer"],
            "kind": item["kind"],
            "label": item["label"],
            "resource": item,
            "lifecycle_intervals": [lifecycle_intervals[index]],
            "status_intervals": [state_intervals[index]],
            "event_marks": [],
        }
        for index, item in enumerate(resources)
    ]

    kinds = sorted({item["kind"] for item in resources})
    kind_descriptors = [
        {
            "kind": kind,
            "label": next(
                (
                    str(item.get("kind_label"))
                    for item in resources
                    if item["kind"] == kind and item.get("kind_label")
                ),
                kind,
            ),
            "description": "Plug-in-projected resource kind.",
            "plugin_defined": True,
            "presentation_tags": [],
        }
        for kind in kinds
    ]
    relation_types = sorted({item["relation_type"] for item in relationship_intervals})
    relationship_descriptors = [
        {
            "relation_type": relation_type,
            "label": next(
                (
                    str(item.get("relation_label"))
                    for item in relationship_intervals
                    if item["relation_type"] == relation_type
                    and item.get("relation_label")
                ),
                relation_type,
            ),
            "directed": True,
            "plugin_defined": True,
        }
        for relation_type in relation_types
    ]

    projections: list[dict[str, Any]] = []
    perspectives: list[dict[str, Any]] = []
    seen_projections: set[str] = set()
    seen_perspectives: set[str] = set()
    for selection in node.get("selected_plugins", []):
        projection_id = str(selection.get("projection_id") or "resource-relationships")
        perspective_id = str(
            selection.get("status_perspective_id") or "plugin-observed"
        )
        if projection_id not in seen_projections:
            seen_projections.add(projection_id)
            projections.append(
                {
                    "projection_id": projection_id,
                    "label": str(selection.get("projection_label") or projection_id),
                    "supported_status_perspective_ids": [perspective_id],
                    "default_status_perspective_id": perspective_id,
                    "plugin_id": selection.get("plugin_id"),
                }
            )
        if perspective_id not in seen_perspectives:
            seen_perspectives.add(perspective_id)
            perspectives.append(
                {
                    "status_perspective_id": perspective_id,
                    "layer_id": perspective_id,
                    "label": str(
                        selection.get("status_perspective_label") or perspective_id
                    ),
                }
            )
    if not projections:
        projections.append(
            {
                "projection_id": "resource-relationships",
                "label": "resource-relationships",
                "supported_status_perspective_ids": ["plugin-observed"],
                "default_status_perspective_id": "plugin-observed",
            }
        )
    if not perspectives:
        perspectives.append(
            {
                "status_perspective_id": "plugin-observed",
                "layer_id": "plugin-observed",
                "label": "plugin-observed",
            }
        )
    topology_capabilities = {
        "projections": projections,
        "status_perspectives": perspectives,
        "nodes": [
            {
                "node_id": node["node_id"],
                "member_id": node["member_id"],
                "label": node["label"],
                "site": node.get("site"),
                "revision_id": node["revision_id"],
                "resources_available": True,
            }
        ],
        "defaults": {
            "projection_id": projections[0]["projection_id"],
            "status_perspective_id": perspectives[0]["status_perspective_id"],
            "clock_policy": str(query.get("clock_policy") or "best_effort"),
        },
        "time_bounds": {
            "start_ns": str(timeline_start_ns),
            "end_ns": str(timeline_end_ns),
        },
        "capability_source": "multi_node_plugin_projection",
    }
    revision_id = str(node["revision_id"])
    return {
        "workspace": {
            "workspace_id": f"node-workspace:{revision_id}",
            "revision_id": revision_id,
            "scope": "node",
            "workspace_kind": "point-in-time-snapshot",
            "history_mode": "point-in-time",
            "capabilities": {
                "historical_state": False,
                "server_windowed_history": False,
            },
            "node_id": str(node["node_id"]),
            "node_label": str(node["label"]),
            "label": str(node["label"]),
            "event_count": 0,
            "matched_event_count": 0,
            "resource_count": len(resources),
            "source_record_count": 0,
            "timeline_start_ns": str(timeline_start_ns),
            "timeline_end_ns": str(timeline_end_ns),
            "capture_ns": str(capture_ns),
            "time_bounds": {
                "start_ns": str(timeline_start_ns),
                "end_ns": str(timeline_end_ns),
                "capture_ns": str(capture_ns),
            },
            "scale_mode": False,
            "large_dataset": False,
            "initial_resource_ids": [item["resource_id"] for item in resources[:20]],
            "initial_focus_resource_id": (
                resources[0]["resource_id"] if resources else None
            ),
            "disclosure": (
                "Point-in-time member snapshot projected by the selected "
                "device plug-ins."
            ),
        },
        "resources": resources,
        "events": [],
        "source_records": [],
        "source_record_descriptors": [],
        "record_lane_presets": [],
        "lifecycle_intervals": lifecycle_intervals,
        "state_intervals": state_intervals,
        "relationship_intervals": relationship_intervals,
        "relationships": relationship_intervals,
        "relationship_mutations": [],
        "relationship_descriptors": relationship_descriptors,
        "kind_descriptors": kind_descriptors,
        "timeline": {"lanes": timeline_lanes, "clusters": []},
        "presentation": {"layers": list(layers.values())},
        "layers": list(layers.values()),
        "topology_capabilities": topology_capabilities,
        "topology_nodes": topology_capabilities["nodes"],
        "schema": {
            "semantic_owner": "plugin",
            "core_interprets_domain_types": False,
            "resource_kinds": kind_descriptors,
            "relationship_types": relationship_descriptors,
            "resource_table_views": [],
            "dashboards": [],
            "topology": topology_capabilities,
        },
        "summary": {
            "parse": {
                "artifacts": len(node.get("plugin_results", [])),
                "errors": 0,
                "skipped": 0,
            },
            "consistency": {"pass": 0, "fail": 0, "unknown": 0},
        },
        "coverage": {
            "exact_outputs": len(resources),
            "best_effort_outputs": 0,
            "unknown_outputs": 0,
        },
        "findings": [],
        "gaps": [],
        "review_prompts": [],
        "inventory": {
            "archive": f"{node['node_id']} plug-in projection",
            "compressed_size": 0,
            "members": [],
            "mode": "point-in-time-plugin-snapshot",
        },
        "node_snapshot": snapshot,
    }


@api_router.get("/v1/nodes/{node_id}/workspace")
def node_workspace_dataset(
    node_id: str,
    plugin_set_id: str | None = None,
    plugin_id: str | None = None,
    projection_id: str | None = None,
    status_perspective_id: str | None = None,
    time_ns: int | None = Query(
        default=None,
        ge=MIN_TIMESTAMP_NS,
        le=MAX_TIMESTAMP_NS,
    ),
    basis_kind: str | None = None,
    basis_offset_ns: int | None = Query(
        default=None,
        ge=MIN_TIMESTAMP_NS,
        le=MAX_TIMESTAMP_NS,
    ),
    clock_domain: str = "utc",
    clock_policy: str = "best_effort",
) -> dict[str, Any]:
    """Return one exact member revision used by the fabric view."""

    if basis_kind not in {None, "absolute_time", "relative_to_watermark"}:
        raise _RuntimeHTTPResponse(
            status_code=422, detail="unsupported node workspace basis_kind"
        )
    if time_ns is not None and basis_offset_ns is not None:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="time_ns and basis_offset_ns cannot both be supplied",
        )
    if basis_kind == "absolute_time":
        if time_ns is None:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail="absolute_time requires time_ns",
            )
        if basis_offset_ns is not None:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail="absolute_time does not accept basis_offset_ns",
            )
    elif basis_kind == "relative_to_watermark" and time_ns is not None:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="relative_to_watermark does not accept time_ns",
        )
    # Member workspaces are exact revisions loaded through the selected
    # plug-in source. The separate snapshot adapter remains a generic
    # point-in-time projection used by focused algorithm tests.
    store = _require_revision_store()
    lookup_error: KeyError | None = None
    descriptor = None
    assembly_id = None
    # Descriptor lookup may itself parse the lazy assembly. Consume an expected
    # unknown-node miss inside the operation so it remains a normal 404 rather
    # than a global dump-load failure.
    with _data_service()._loading_operation():
        try:
            descriptor = store.revision_for_node(node_id)
            assembly_id = store.assembly.assembly_id
        except KeyError as error:
            lookup_error = error
    if lookup_error is not None:
        raise _RuntimeHTTPResponse(
            status_code=404,
            detail="unknown topology member",
        ) from lookup_error
    # Once the node has been validated, load its safe client projection through
    # the ordinary tracked normalized-data boundary.
    client = client_dataset(node_id=node_id)
    client["node_snapshot"] = {
        "assembly_id": assembly_id,
        "node_id": descriptor.node_id,
        "revision_id": descriptor.revision_id,
        "event_count": descriptor.event_count,
        "resource_count": descriptor.resource_count,
        "basis": {
            "kind": basis_kind
            or ("absolute_time" if time_ns is not None else "relative_to_watermark"),
            "time_ns": str(time_ns) if time_ns is not None else None,
            "offset_ns": (str(basis_offset_ns) if basis_offset_ns is not None else "0"),
            "clock_domain": clock_domain,
            "clock_policy": clock_policy,
        },
        "plugin_selection": {
            "plugin_set_id": plugin_set_id,
            "plugin_id": plugin_id,
            "projection_id": projection_id,
            "status_perspective_id": status_perspective_id,
        },
        "source": "plugin-revision-store",
    }
    client["workspace"] = {
        **client["workspace"],
        "assembly_id": assembly_id,
        "node_id": descriptor.node_id,
        "node_label": descriptor.label,
        "revision_id": descriptor.revision_id,
    }
    return client


@api_router.get("/v1/revisions/{revision_id:path}/routes/capabilities")
def route_capabilities(revision_id: str) -> dict[str, Any]:
    """Return the selected node plug-in's bounded route choices."""

    return _route_capabilities_payload(revision_id)


@api_router.post("/v1/revisions/{revision_id:path}/routes/resolve")
def resolve_route(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    return _resolve_route_payload(revision_id, body)


@api_router.get("/v1/revisions/{revision_id:path}/topology/capabilities")
def topology_capabilities(revision_id: str) -> dict[str, Any]:
    """Describe plug-in topology projections, perspectives, clocks, and bounds."""

    return _topology_capabilities_payload(revision_id)


@api_router.get("/v1/revisions/{revision_id:path}/multi-node/capabilities")
def revision_multi_node_topology_capabilities(
    revision_id: str,
) -> dict[str, Any]:
    return _revision_multi_node_topology_capabilities_payload(revision_id)


@api_router.get("/v1/revisions/{revision_id:path}/capabilities")
def capabilities(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    session = current_runtime_session()
    implemented = [
        "canonical_resource_lanes",
        "lifecycle_and_status_intervals",
        "failed_event_without_implicit_mutation",
        "generic_retained_source_records",
        "paged_source_record_queries",
        "validated_regex_source_lanes",
        "stable_source_to_normalized_navigation",
        "time_varying_relationship_view",
        "point_in_time_resource_tables",
        "plugin_declared_relationship_grouped_resource_tables",
        "plugin_defined_dashboard_descriptors",
        "selected_range_summary_and_endpoint_diff",
        "consistency_finding_view",
        "archive_inventory",
        "review_notes_local_to_browser",
    ]
    if route_resolution_capability(dataset).get("available"):
        implemented.append("precomputed_route_explanation")
    if session.temporal_provider is not None:
        implemented.extend(
            (
                "temporal_topology_projection",
                "layer_selected_resource_status",
                "absolute_and_relative_capture_vector_basis",
                "clock_uncertainty_and_ambiguous_state",
            )
        )
    if session.topology_provider is not None:
        implemented.extend(
            (
                "heterogeneous_multi_node_topology_reconstruction",
                "per_node_plugin_set_and_projection_selection",
                "plugin_owned_inter_node_connector_resolution",
            )
        )
    if session.route_provider is not None:
        implemented.append("multi_node_route_tracing")
    return {
        "revision_id": revision_id,
        "implemented": implemented,
        "limitations": dataset.get("gaps", []),
        "disclosure": str(_analysis_metadata(dataset).get("disclosure") or ""),
    }


@api_router.get("/v1/revisions/{revision_id:path}/topology/providers")
def _topology_capabilities_payload(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    return _temporal_topology(revision_id).capabilities()


@api_router.post("/v1/revisions/{revision_id:path}/topology/query")
def topology_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Return a bounded temporal topology snapshot or historical change slice."""

    _require_revision(revision_id)
    return _temporal_topology_query(body)


@api_router.post("/v1/revisions/{revision_id:path}/topology/changes/query")
def topology_changes_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Return bounded resource/relationship changes for historical replay."""

    _require_revision(revision_id)
    return _temporal_topology_changes_query(body)


@api_router.post("/v1/revisions/{revision_id:path}/state/query")
@api_router.post("/v1/revisions/{revision_id:path}/resources/status/query")
def temporal_state_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Expose generic resource status and relationships at the requested basis."""

    _require_revision(revision_id)
    normalized = dict(body)
    normalized["include"] = ["resources"]
    if _body_boolean(body, "include_relationships", default=True):
        normalized["include"].append("relationships")
    if "relation_types" in body:
        normalized["relation_types"] = _body_string_list(body, "relation_types")
    return _temporal_topology_query(normalized)


@api_router.get("/v1/topologies/capabilities")
@api_router.get("/v1/topology-assemblies/{assembly_id}/capabilities")
def multi_node_topology_capabilities(
    assembly_id: str | None = None,
) -> dict[str, Any]:
    """Advertise executable, node-specific plug-in projection selections."""

    _require_topology_assembly(assembly_id or _active_topology_assembly_id())
    return _multi_node_topology().capabilities()


def _revision_multi_node_topology_capabilities_payload(
    revision_id: str,
) -> dict[str, Any]:
    _require_revision(revision_id)
    return _multi_node_topology().capabilities()


@api_router.post("/v1/topologies/reconstruct")
@api_router.post("/v1/topologies/query")
def reconstruct_multi_node_topology(
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Reconstruct and federate independently projected node snapshots."""

    return _multi_node_call(_multi_node_topology().query, body)


@api_router.post("/v1/topology-assemblies/{assembly_id}/query")
def query_topology_assembly(
    assembly_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_topology_assembly(assembly_id)
    return _multi_node_call(_multi_node_topology().query, body)


@api_router.post("/v1/revisions/{revision_id:path}/multi-node/query")
def revision_multi_node_topology_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    return _multi_node_call(_multi_node_topology().query, body)


@api_router.get("/v1/topologies/nodes/{node_id}/capabilities")
def multi_node_member_capabilities(node_id: str) -> dict[str, Any]:
    return _multi_node_call(_multi_node_topology().node_capabilities, node_id)


@api_router.post("/v1/topologies/nodes/{node_id}/query")
def query_multi_node_member(
    node_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    return _multi_node_call(_multi_node_topology().query_node, node_id, body)


@api_router.get("/v1/topologies/routes/capabilities")
@api_router.get("/v1/topology-assemblies/{assembly_id}/routes/capabilities")
def multi_node_route_capabilities(
    assembly_id: str | None = None,
) -> dict[str, Any]:
    """Advertise cross-node route resolvers and candidate-path semantics."""

    _require_topology_assembly(assembly_id or _active_topology_assembly_id())
    return _multi_node_call(_multi_node_route().capabilities)


@api_router.post("/v1/topologies/routes/tables/query")
@api_router.post("/v1/topology-assemblies/{assembly_id}/routes/tables/query")
def query_multi_node_route_tables(
    body: dict[str, Any] = Body(default_factory=dict),
    assembly_id: str | None = None,
) -> dict[str, Any]:
    """Return time-bound, plug-in-owned route-table rows for selected nodes."""

    _require_topology_assembly(assembly_id or _active_topology_assembly_id())
    return _multi_node_call(_multi_node_route().route_tables, body)


@api_router.post("/v1/topologies/routes/trace")
def trace_route_across_default_topology(
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Trace all candidate paths across the default topology assembly."""

    return _multi_node_call(_multi_node_route().trace, body)


@api_router.post("/v1/topology-assemblies/{assembly_id}/routes/trace")
def trace_route_across_topology_assembly(
    assembly_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Trace all candidate paths across one named topology assembly."""

    _require_topology_assembly(assembly_id)
    return _multi_node_call(_multi_node_route().trace, body)


@api_router.get("/v1/topology-contexts/{context_id}/members/{member_id}")
def topology_context_member(context_id: str, member_id: str) -> dict[str, Any]:
    return _multi_node_call(
        _multi_node_topology().context_member,
        context_id,
        member_id,
    )


@api_router.get("/v1/revisions/{revision_id:path}/resources")
def resources(
    revision_id: str,
    kind: str | None = None,
    layer: str | None = None,
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    descriptor_by_kind = {
        str(item.get("kind")): item
        for item in dataset.get("kind_descriptors", [])
        if isinstance(item, dict) and item.get("kind")
    }
    items = [
        _redact_resource_for_client(
            record,
            descriptor_by_kind.get(str(record.get("kind", "UNKNOWN"))),
        )
        for record in dataset["resources"]
    ]
    if kind:
        items = [item for item in items if item.get("kind") == kind]
    if layer:
        items = [item for item in items if item.get("layer") == layer]
    return {"items": items, "count": len(items), "next_cursor": None}


def _validate_resource_table_view_id(
    dataset: dict[str, Any],
    view_id: str | None,
) -> None:
    """Reject an unknown caller-owned view before entering data-service code."""

    if view_id is None:
        return
    descriptors = dataset.get("resource_table_view_descriptors") or dataset.get(
        "schema", {}
    ).get("resource_table_views", [])
    if not any(
        isinstance(item, dict) and item.get("view_id") == view_id
        for item in descriptors
    ):
        raise _RuntimeHTTPResponse(
            status_code=400, detail="unknown resource table view"
        )


@api_router.get("/v1/revisions/{revision_id:path}/resources/at")
def resource_tables_at(
    revision_id: str,
    time_ns: int | None = Query(
        default=None,
        ge=MIN_TIMESTAMP_NS,
        le=MAX_TIMESTAMP_NS,
    ),
    kind: list[str] = Query(default=[]),
    layer: list[str] = Query(default=[]),
    search: str | None = None,
    view: str | None = None,
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    _validate_resource_table_view_id(dataset, view)
    timestamp_ns = int(
        _analysis_metadata(dataset)["capture_ns"] if time_ns is None else time_ns
    )
    return _runtime_api_call(
        resources_at,
        timestamp_ns,
        kinds=set(kind) or None,
        layers=set(layer) or None,
        search=search,
        limit=limit if has_indexed_history(dataset) or view else None,
        offset=offset,
        view_id=view,
    )


@api_router.post("/v1/revisions/{revision_id:path}/resources/query")
def resource_tables_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    view_id = body.get("view_id")
    if view_id is not None and not isinstance(view_id, str):
        raise _RuntimeHTTPResponse(status_code=422, detail="view_id must be a string")
    _validate_resource_table_view_id(dataset, view_id)
    kinds = _body_string_list(body, "kinds")
    layers = _body_string_list(body, "layers")
    if (
        "search" in body
        and body["search"] is not None
        and not isinstance(body["search"], str)
    ):
        raise _RuntimeHTTPResponse(
            status_code=422, detail="search must be a string or null"
        )
    timestamp_ns = _body_timestamp_ns(
        body,
        "time_ns",
        int(_analysis_metadata(dataset)["capture_ns"]),
    )
    offset = _body_integer(
        body,
        "offset",
        0,
        minimum=0,
        maximum=MAX_JSON_SAFE_INTEGER,
    )
    limit = None
    if "limit" in body:
        limit = _body_integer(body, "limit", 500, minimum=1, maximum=1000)
    return _runtime_api_call(
        resources_at,
        timestamp_ns,
        kinds=set(kinds) or None,
        layers=set(layers) or None,
        search=body.get("search"),
        limit=limit if has_indexed_history(dataset) or view_id else None,
        offset=offset,
        view_id=view_id,
    )


@api_router.post("/v1/revisions/{revision_id:path}/dashboards/query")
def dashboards_query(
    revision_id: str,
    body: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Evaluate plug-in dashboards over one complete temporal population.

    Dashboard descriptors own resource kinds, field paths, filters, columns,
    and aggregation choices.  This revision-scoped core endpoint owns the
    selected instant, safe declarative evaluation, and result bounds.
    """

    _require_revision(revision_id)
    dataset = load_dataset()
    timestamp_ns = _body_timestamp_ns(
        body,
        "time_ns",
        int(_analysis_metadata(dataset)["capture_ns"]),
    )
    dashboard_ids = (
        _body_string_list(body, "dashboard_ids") if "dashboard_ids" in body else None
    )
    return dashboard_query(timestamp_ns, dashboard_ids=dashboard_ids)


@api_router.get("/v1/revisions/{revision_id:path}/events")
def events(
    revision_id: str,
    layer: str | None = None,
    outcome: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    policy = _event_redaction_policy(dataset)
    needle = search.casefold() if search else None
    source_events = dataset["events"]
    if not layer and not outcome and needle is None:
        return {
            "items": [
                redact_event_for_client(item, dataset, policy=policy)
                for item in source_events[:limit]
            ],
            "count": len(source_events),
            "next_cursor": None,
        }
    page: list[dict[str, Any]] = []
    matched_count = 0

    # Filter normalized structural fields without copying the full stream, but
    # always apply the central plug-in property policy before free-text search
    # or client serialization.  This preserves exact count/limit semantics for
    # 100K+ streams while preventing raw sensitive values from becoming a
    # search oracle.
    for item in source_events:
        if layer:
            subjects = item.get("subjects") or [{}]
            if subjects[0].get("layer") != layer:
                continue
        if outcome and item.get("outcome") != outcome:
            continue
        projected = redact_event_for_client(item, dataset, policy=policy)
        if needle and needle not in str(projected).casefold():
            continue
        matched_count += 1
        if len(page) < limit:
            page.append(projected)
    return {"items": page, "count": matched_count, "next_cursor": None}


def _event_layer_values(event: dict[str, Any]) -> set[str]:
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


def _bounded_history_filter_values(
    body: dict[str, Any],
    field: str,
) -> list[str]:
    values = _body_string_list(body, field)
    if len(values) > MAX_EVENT_LOG_FILTER_VALUES:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                f"{field} must contain at most {MAX_EVENT_LOG_FILTER_VALUES} values"
            ),
        )
    if any(len(value) > MAX_EVENT_LOG_FILTER_LENGTH for value in values):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                f"{field} values must be at most "
                f"{MAX_EVENT_LOG_FILTER_LENGTH} characters"
            ),
        )
    return values


def _selected_history_range(
    body: dict[str, Any],
) -> tuple[int, int] | None:
    supplied = {field for field in ("start_ns", "end_ns") if field in body}
    if not supplied:
        return None
    if len(supplied) != 2:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="start_ns and end_ns must be supplied together",
        )
    start_ns = _body_timestamp_ns(body, "start_ns", 0)
    end_ns = _body_timestamp_ns(body, "end_ns", 0)
    if end_ns < start_ns:
        raise _RuntimeHTTPResponse(status_code=422, detail="end_ns must be >= start_ns")
    return start_ns, end_ns


def _event_log_locate(body: dict[str, Any]) -> tuple[str, str] | None:
    if "locate" not in body or body["locate"] is None:
        return None
    raw = body["locate"]
    if not isinstance(raw, dict):
        raise _RuntimeHTTPResponse(status_code=422, detail="locate must be an object")
    kind = raw.get("kind")
    uid = raw.get("uid")
    if kind not in {"event", "source"}:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="locate.kind must be event or source",
        )
    if not isinstance(uid, str) or not uid or len(uid) > MAX_EVENT_LOG_UID_LENGTH:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                "locate.uid must be a non-empty string no longer than "
                f"{MAX_EVENT_LOG_UID_LENGTH} characters"
            ),
        )
    return str(kind), uid


def _indexed_event_search_documents(
    dataset: dict[str, Any],
    runtime: Any,
    policy: Any,
):
    """Yield the exact case-folded, client-safe event search projection."""

    for event in runtime.events:
        projected = redact_event_for_client(event, dataset, policy=policy)
        yield json.dumps(
            projected,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).casefold()


def _warm_event_search(dataset: dict[str, Any]) -> None:
    """Build one immutable revision's safe corpus under tracked indexing."""

    runtime = history_runtime(dataset)
    if runtime is None:
        return
    policy = _event_redaction_policy(dataset)
    with _data_service()._loading_operation(AnalysisLoadStage.INDEXING):
        try:
            runtime.event_search.ensure(
                lambda: _indexed_event_search_documents(dataset, runtime, policy)
            )
        except HistorySearchCapacityError:
            # Exact queries retain the compatible streaming fallback when a
            # future input exceeds the bounded serving corpus.  Capacity is a
            # supported outcome, so the progress operation completes rather
            # than presenting it as a dump-load failure.
            return


def _query_event_search(
    dataset: dict[str, Any],
    runtime: Any,
    policy: Any,
    search: str,
):
    """Run a first-use corpus build and query as one visible core operation."""

    capacity_error: HistorySearchCapacityError | None = None
    matches = None
    with _data_service()._loading_operation(AnalysisLoadStage.INDEXING):
        try:
            matches = runtime.event_search.query(
                search,
                lambda: _indexed_event_search_documents(dataset, runtime, policy),
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
    *,
    revision_id: str,
    dataset: dict[str, Any],
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

    matches = _query_event_search(dataset, runtime, policy, search)
    if layers:
        filtered_matches = [
            index
            for index in matches
            if _event_layer_values(runtime.events[index]) & layers
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
                        for index in range(same_time_start, same_time_end)
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
    for display_index in range(offset, page_end):
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
                "entry": redact_event_for_client(event, dataset, policy=policy),
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
    *,
    revision_id: str,
    dataset: dict[str, Any],
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
                    for index in range(same_time_start, same_time_end)
                    if str(
                        events[index].get("event_uid") or events[index].get("event_id")
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
                    located_display_index = inside_count + left + target_index - right

    page_end = min(total_count, offset + limit)
    items: list[dict[str, Any]] = []
    for display_index in range(offset, page_end):
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
                "entry": redact_event_for_client(event, dataset, policy=policy),
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


def _density_secondary_indexes(
    runtime: Any,
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
    for event in runtime.events:
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


def _density_bin_bounds(
    start_ns: int,
    integer_span: int,
    bin_count: int,
    index: int,
) -> tuple[int, int]:
    """Return one bin's inclusive bounds in the canonical density partition."""

    bin_start_ns = start_ns + (integer_span * index) // bin_count
    bin_end_ns = start_ns + (integer_span * (index + 1)) // bin_count - 1
    return bin_start_ns, bin_end_ns


def _density_bin_index(
    timestamp_ns: int,
    start_ns: int,
    integer_span: int,
    bin_count: int,
) -> int:
    """Invert ``_density_bin_bounds`` exactly for a timestamp in the span."""

    offset = timestamp_ns - start_ns
    return min(
        bin_count - 1,
        (((offset + 1) * bin_count) - 1) // integer_span,
    )


def _density_type_counts_by_bin(
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
    """Sweep each event-type index once for one bounded density page.

    The previous nested loop bisected every event-type list for every populated
    bin, making work proportional to ``bins * distinct_types``.  This sweep is
    proportional to the number of distinct types plus matching event points.
    """

    counts_by_bin: dict[int, Counter[str]] = {}
    for raw_event_type, timestamps in event_times_by_type.items():
        event_type = str(raw_event_type)
        type_left = bisect_left(timestamps, page_start_ns)
        type_right = bisect_left(
            timestamps,
            page_end_exclusive,
            type_left,
        )
        for position in range(type_left, type_right):
            timestamp_ns = timestamps[position]
            index = _density_bin_index(
                timestamp_ns,
                start_ns,
                integer_span,
                bin_count,
            )
            if index < bin_start_index or index >= bin_end_index:
                continue
            counts_by_bin.setdefault(index, Counter())[event_type] += 1
    return counts_by_bin


@api_router.post("/v1/revisions/{revision_id:path}/events/density/query")
def event_density_query(
    revision_id: str,
    body: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    """Aggregate one exact event window into a bounded set of nonempty bins.

    Event type and outcome values remain opaque plug-in values.  The core only
    groups their normalized strings and counts the normalized ``failure``
    outcome used by the generic event contract.
    """

    _require_revision(revision_id)
    if "start_ns" not in body or "end_ns" not in body:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="start_ns and end_ns are required",
        )
    start_ns = _body_timestamp_ns(body, "start_ns", 0)
    end_ns = _body_timestamp_ns(body, "end_ns", 0)
    if end_ns < start_ns:
        raise _RuntimeHTTPResponse(status_code=422, detail="end_ns must be >= start_ns")
    requested_bin_count = _body_integer(
        body,
        "bin_count",
        180,
        minimum=1,
        maximum=MAX_JSON_SAFE_INTEGER,
    )
    integer_span = end_ns - start_ns + 1
    paged_request = "bin_start_index" in body or "bin_end_index" in body
    if paged_request and not {
        "bin_start_index",
        "bin_end_index",
    }.issubset(body):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="bin_start_index and bin_end_index must be supplied together",
        )
    # A paged request describes bins in one immutable global coordinate
    # system. Only the requested bounded slice is materialized, so deep zoom
    # does not require a huge response and adjacent pages cannot repartition
    # the same timestamps differently.
    bin_count = min(requested_bin_count, integer_span)
    if paged_request:
        bin_start_index = _body_integer(
            body,
            "bin_start_index",
            0,
            minimum=0,
            maximum=bin_count - 1,
        )
        bin_end_index = _body_integer(
            body,
            "bin_end_index",
            bin_count,
            minimum=1,
            maximum=bin_count,
        )
        if bin_end_index <= bin_start_index:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail="bin_end_index must be greater than bin_start_index",
            )
        if bin_end_index - bin_start_index > MAX_DENSITY_BINS:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail=f"density page must contain at most {MAX_DENSITY_BINS} bins",
            )
    else:
        bin_count = min(bin_count, MAX_DENSITY_BINS)
        bin_start_index = 0
        bin_end_index = bin_count

    dataset = load_dataset()
    runtime = history_runtime(dataset)
    if runtime is not None:
        failure_event_times, event_times_by_type = _density_secondary_indexes(runtime)
        left = bisect_left(runtime.event_times, start_ns)
        right = bisect_right(runtime.event_times, end_ns)
        total_count = right - left
        page_start_ns = start_ns + (integer_span * bin_start_index) // bin_count
        page_end_exclusive = start_ns + (integer_span * bin_end_index) // bin_count
        type_counts_by_bin = _density_type_counts_by_bin(
            event_times_by_type,
            page_start_ns=page_start_ns,
            page_end_exclusive=page_end_exclusive,
            start_ns=start_ns,
            integer_span=integer_span,
            bin_count=bin_count,
            bin_start_index=bin_start_index,
            bin_end_index=bin_end_index,
        )
        response_bins: list[dict[str, Any]] = []
        for index in range(bin_start_index, bin_end_index):
            bin_start_ns, bin_end_ns = _density_bin_bounds(
                start_ns,
                integer_span,
                bin_count,
                index,
            )
            bin_end_exclusive = bin_end_ns + 1
            bin_left = bisect_left(
                runtime.event_times,
                bin_start_ns,
                left,
                right,
            )
            bin_right = bisect_left(
                runtime.event_times,
                bin_end_exclusive,
                bin_left,
                right,
            )
            count = bin_right - bin_left
            if not count:
                continue
            failure_count = bisect_left(
                failure_event_times,
                bin_end_exclusive,
            ) - bisect_left(failure_event_times, bin_start_ns)
            response_bins.append(
                {
                    "index": index,
                    "start_ns": str(bin_start_ns),
                    "end_ns": str(bin_end_ns),
                    "count": count,
                    "failure_count": failure_count,
                    "top_types": [
                        {"event_type": event_type, "count": type_count}
                        for event_type, type_count in sorted(
                            type_counts_by_bin.get(index, {}).items(),
                            key=lambda item: (-item[1], item[0]),
                        )[:4]
                    ],
                }
            )
    else:
        selected_events = [
            event
            for event in dataset.get("events", [])
            if start_ns <= int(event.get("timestamp_ns", 0)) <= end_ns
        ]
        total_count = len(selected_events)

        # The sparse map keeps response and aggregation memory proportional to
        # populated bins, never to the requested timeline resolution.
        bins: dict[int, dict[str, Any]] = {}
        for event in selected_events:
            timestamp_ns = int(event.get("timestamp_ns", 0))
            index = _density_bin_index(
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
        for index, aggregate in sorted(bins.items()):
            bin_start_ns, bin_end_ns = _density_bin_bounds(
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
                        for event_type, count in sorted(
                            aggregate["types"].items(),
                            key=lambda item: (-item[1], item[0]),
                        )[:4]
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


@api_router.post("/v1/revisions/{revision_id:path}/event-log/query")
def event_log_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Merge normalized events and retained sources into one bounded page.

    Plug-ins own event, layer, and source-type vocabulary.  The core applies
    generic filters, redaction, selected-range grouping, stable ordering, and
    paging without assigning router-specific meaning to those values.
    """

    _require_revision(revision_id)
    dataset = load_dataset()
    include_normalized = _body_boolean(body, "include_normalized", True)
    source_types_supplied = "source_types" in body
    source_types = _bounded_history_filter_values(body, "source_types")
    layers = set(_bounded_history_filter_values(body, "layers"))
    raw_search = body.get("search", "")
    if raw_search is None:
        raw_search = ""
    if not isinstance(raw_search, str):
        raise _RuntimeHTTPResponse(status_code=422, detail="search must be a string")
    if len(raw_search) > MAX_EVENT_LOG_SEARCH_LENGTH:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(f"search must be at most {MAX_EVENT_LOG_SEARCH_LENGTH} characters"),
        )
    search = raw_search.casefold()
    selected_range = _selected_history_range(body)
    offset = _body_integer(
        body,
        "offset",
        0,
        minimum=0,
        maximum=MAX_EVENT_LOG_OFFSET,
    )
    limit = _body_integer(
        body,
        "limit",
        100,
        minimum=1,
        maximum=MAX_EVENT_LOG_LIMIT,
    )
    locate = _event_log_locate(body)

    source_records = dataset.get("source_records", [])
    known_source_types = {
        str(item["source_type"])
        for item in dataset.get("source_record_descriptors", [])
        if isinstance(item, dict) and item.get("source_type")
    }
    known_source_types.update(
        str(item["source_type"])
        for item in source_records
        if isinstance(item, dict) and item.get("source_type")
    )
    if source_types_supplied:
        unknown_source_types = set(source_types) - known_source_types
        if unknown_source_types:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail=bounded_public_error_detail(
                    "event-log query references unknown source types: "
                    + ", ".join(sorted(unknown_source_types)),
                    fallback="event-log query references unknown source types",
                    maximum_characters=_MAX_PUBLIC_ERROR_DETAIL_CHARACTERS,
                ),
            )
    selected_source_types = set(source_types)
    policy = _event_redaction_policy(dataset)
    runtime = history_runtime(dataset)
    if (
        runtime is not None
        and include_normalized
        and source_types_supplied
        and not selected_source_types
    ):
        if search:
            try:
                return _indexed_event_search_log_page(
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
            return _indexed_event_only_log_page(
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
    candidates: list[tuple[int, int, int, str, str, str, str, dict[str, Any]]] = []
    inside_count = 0

    def append_candidate(
        *,
        stream_kind: str,
        uid: str,
        timestamp_ns: int,
        entry: dict[str, Any],
    ) -> None:
        nonlocal inside_count
        if selected_range is None:
            membership = "all"
            group_rank = 0
        else:
            in_range = selected_range[0] <= timestamp_ns <= selected_range[1]
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
                event_indices = _query_event_search(
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
        for index in event_indices:
            event = event_source[index]
            if layers and not (_event_layer_values(event) & layers):
                continue
            projected = None
            if search and not indexed_event_search:
                projected = redact_event_for_client(event, dataset, policy=policy)
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
                timestamp_ns=temporal_integer(
                    event.get("timestamp_ns", 0),
                    "timestamp_ns",
                ),
                entry=event,
            )

    if not source_types_supplied or selected_source_types:
        for index, record in enumerate(source_records):
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
                timestamp_ns=temporal_integer(
                    record.get("timestamp_ns", 0),
                    "timestamp_ns",
                ),
                entry=record,
            )

    candidates.sort(key=lambda item: item[:4])
    total_count = len(candidates)
    outside_count = total_count - inside_count
    located_display_index = None
    if locate is not None:
        located_display_index = next(
            (
                index
                for index, candidate in enumerate(candidates)
                if candidate[4] == locate[0] and candidate[5] == locate[1]
            ),
            None,
        )

    selected = candidates[offset : offset + limit]
    items: list[dict[str, Any]] = []
    for display_index, candidate in enumerate(selected, start=offset):
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
            redact_event_for_client(entry, dataset, policy=policy)
            if stream_kind == "event"
            else project_source_record_for_log(entry)
        )
        items.append(
            {
                "display_index": display_index,
                "stream_kind": stream_kind,
                "uid": uid,
                "timestamp_ns": str(timestamp_ns),
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


@api_router.get("/v1/revisions/{revision_id:path}/events/{event_uid:path}")
def event_detail(revision_id: str, event_uid: str) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    runtime = history_runtime(dataset)
    if runtime is not None:
        item = runtime.event_by_uid.get(event_uid)
        if item is not None:
            return redact_event_for_client(item, dataset)
        raise _RuntimeHTTPResponse(status_code=404, detail="event not found")
    for item in dataset["events"]:
        if item["event_uid"] == event_uid:
            return redact_event_for_client(item, dataset)
    raise _RuntimeHTTPResponse(status_code=404, detail="event not found")


@api_router.post("/v1/revisions/{revision_id:path}/source-records/query")
def source_records_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Page retained CTF and non-CTF input records without domain assumptions."""

    _require_revision(revision_id)
    dataset = load_dataset()
    known_source_types = {
        str(item["source_type"])
        for item in dataset.get("source_record_descriptors", [])
        if item.get("source_type")
    }
    result = _runtime_api_call(
        query_source_records,
        dataset.get("source_records", []),
        body,
        known_source_types=known_source_types,
    )
    result["items"] = [
        {key: value for key, value in item.items() if key != "copy_text"}
        for item in result.get("items", [])
    ]
    return {
        "revision_id": revision_id,
        **result,
        "source_record_types": dataset.get("source_record_descriptors", []),
    }


def _event_resource_ids(event: dict[str, Any]) -> list[str]:
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


def _event_log_selection_ranges(
    body: dict[str, Any],
) -> list[tuple[int, int]]:
    raw_ranges = body.get("selection_ranges")
    if not isinstance(raw_ranges, list) or not raw_ranges:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="selection_ranges must be a non-empty array",
        )
    if len(raw_ranges) > MAX_EVENT_LOG_SELECTION_RANGES:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                "selection_ranges must contain at most "
                f"{MAX_EVENT_LOG_SELECTION_RANGES} ranges"
            ),
        )
    parsed: list[tuple[int, int]] = []
    for raw in raw_ranges:
        if not isinstance(raw, dict):
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail="each selection range must be an object",
            )
        start = _body_integer(
            raw,
            "start",
            0,
            minimum=0,
            maximum=MAX_JSON_SAFE_INTEGER,
        )
        end = _body_integer(
            raw,
            "end",
            0,
            minimum=0,
            maximum=MAX_JSON_SAFE_INTEGER,
        )
        if end < start:
            raise _RuntimeHTTPResponse(
                status_code=422,
                detail="selection range end must be >= start",
            )
        parsed.append((start, end))

    merged: list[list[int]] = []
    for start, end in sorted(parsed):
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    total = sum(end - start + 1 for start, end in merged)
    if total > MAX_EVENT_LOG_SELECTION_ITEMS:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                "selection contains "
                f"{total:,} rows; actions support at most "
                f"{MAX_EVENT_LOG_SELECTION_ITEMS:,} at once"
            ),
        )
    return [(start, end) for start, end in merged]


@api_router.post("/v1/revisions/{revision_id:path}/event-log/selection")
def event_log_selection(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Resolve query-scoped row ranges for safe bulk UI actions.

    The core owns immutable revision ordering, bounds, redaction and copy
    quotas. The device plug-in owns each source record's optional ``copy_text``
    and the source-to-normalized-event links.
    """

    _require_revision(revision_id)
    ranges = _event_log_selection_ranges(body)
    query_fields = {
        key: body[key]
        for key in (
            "include_normalized",
            "source_types",
            "layers",
            "search",
            "start_ns",
            "end_ns",
        )
        if key in body
    }
    selected_items: list[dict[str, Any]] = []
    selection_refs: list[dict[str, str]] = []
    for range_start, range_end in ranges:
        offset = range_start
        while offset <= range_end:
            limit = min(MAX_EVENT_LOG_LIMIT, range_end - offset + 1)
            payload = event_log_query(
                revision_id,
                {
                    **query_fields,
                    "offset": offset,
                    "limit": limit,
                },
            )
            page = payload.get("items", [])
            if not page:
                break
            for item in page:
                kind = str(item.get("stream_kind") or "event")
                uid = str(item.get("uid") or "")
                entry = item.get("entry") if isinstance(item.get("entry"), dict) else {}
                selection_refs.append({"kind": kind, "uid": uid})
                selected_items.append(
                    {
                        "entry_id": f"{kind}:{uid}",
                        "display_index": int(item.get("display_index", 0)),
                        "stream_kind": kind,
                        "uid": uid,
                        "timestamp_ns": str(item.get("timestamp_ns", "0")),
                        "resource_ids": (
                            _event_resource_ids(entry) if kind == "event" else []
                        ),
                        "entry": entry,
                    }
                )
            offset += len(page)
            if len(page) < limit:
                break

    dataset = load_dataset()
    source_records = list(dataset.get("source_records", []))
    copy_linked_events = {
        event_uid
        for record in source_records
        if record.get("copy_text") is not None
        for event_uid in source_record_event_uids(record)
    }
    runtime = history_runtime(dataset)
    event_lookup = (
        runtime.event_by_uid
        if runtime is not None
        else {
            str(event.get("event_uid") or event.get("event_id")): event
            for event in dataset.get("events", [])
        }
    )
    for reference in selection_refs:
        if reference["kind"] != "event":
            continue
        event_uid = reference["uid"]
        if event_uid in copy_linked_events:
            continue
        event = event_lookup.get(event_uid)
        if event is None:
            continue
        source_records.append(source_record_for_event(event))
        copy_linked_events.add(event_uid)

    copy_projection = project_source_record_text_selection(
        source_records,
        selection_refs,
    )
    source_group_by_type = {
        str(descriptor.get("source_type")): str(descriptor.get("stream_group"))
        for descriptor in dataset.get("source_record_descriptors", [])
        if (
            isinstance(descriptor, dict)
            and descriptor.get("source_type")
            and descriptor.get("stream_group")
        )
    }
    copy_label_by_group = {
        str(group.get("group_id")): str(group.get("copy_action_label"))
        for group in dataset.get("source_record_group_descriptors", [])
        if (
            isinstance(group, dict)
            and group.get("group_id")
            and group.get("copy_action_label")
        )
    }
    selected_copy_labels = {
        copy_label_by_group[group_id]
        for item in copy_projection.get("items", [])
        if (
            (group_id := source_group_by_type.get(str(item.get("source_type"))))
            and group_id in copy_label_by_group
        )
    }
    if (
        not selected_copy_labels
        and copy_projection.get("items")
        and len(copy_label_by_group) == 1
    ):
        selected_copy_labels = set(copy_label_by_group.values())
    copy_action_label = (
        next(iter(selected_copy_labels))
        if len(selected_copy_labels) == 1
        else "Copy plug-in text"
    )
    return {
        "revision_id": revision_id,
        "selection_ranges": [{"start": start, "end": end} for start, end in ranges],
        "selection_count": len(selected_items),
        "items": selected_items,
        "copy_action_label": copy_action_label,
        "copy": copy_projection,
    }


def _interval_duration(start: Any, end: Any) -> str | None:
    if start is None or end is None:
        return None
    return str(int(end) - int(start))


def _effective_relationship_intervals(
    dataset: dict[str, Any],
    lane_ids: set[str],
    query_start_ns: int,
    query_end_ns: int,
) -> list[dict[str, Any]]:
    """Project relationships onto the overlapping lifecycles of both endpoints."""

    runtime = history_runtime(dataset)
    if runtime is not None:
        lifecycle_by_resource = runtime.lifecycle_by_resource
        candidate_map: dict[str, dict[str, Any]] = {}
        for identifier in lane_ids:
            for relationship in runtime.relationships_by_endpoint.get(identifier, []):
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
        lifecycle_by_resource: dict[str, list[dict[str, Any]]] = {}
        for lifecycle in dataset["lifecycle_intervals"]:
            lifecycle_by_resource.setdefault(lifecycle["resource"], []).append(
                lifecycle
            )
        relationship_candidates = dataset["relationship_intervals"]
    descriptors = {
        item["relation_type"]: item for item in dataset["relationship_descriptors"]
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for relationship in relationship_candidates:
        source = relationship["source"]
        target = relationship["target"]
        if source not in lane_ids or target not in lane_ids:
            continue
        source_lifecycles = lifecycle_by_resource.get(source, [])
        target_lifecycles = lifecycle_by_resource.get(target, [])
        for source_lifecycle in source_lifecycles:
            for target_lifecycle in target_lifecycles:
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
                    item for item in start_candidates if item[0] is not None
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
                finite_ends = [item for item in end_candidates if item[0] is not None]
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
                        "relationship_valid_from_ns": relationship.get("valid_from_ns"),
                        "relationship_valid_to_ns": relationship.get("valid_to_ns"),
                        "relationship_start_event_uid": relationship.get(
                            "start_event_uid"
                        ),
                        "relationship_end_event_uid": relationship.get("end_event_uid"),
                        "valid_from_ns": start_ns,
                        "valid_to_ns": end_ns,
                        "start_ns": start_ns,
                        "end_ns": end_ns,
                        "start_event_uid": effective_start[1],
                        "end_event_uid": effective_end[1],
                        "effective_start_source": effective_start[2],
                        "effective_end_source": effective_end[2],
                        "duration_ns": _interval_duration(start_ns, end_ns),
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
    dataset: dict[str, Any],
    lane_ids: set[str],
    query_start_ns: int,
    query_end_ns: int,
) -> list[dict[str, Any]]:
    descriptors = {
        item["relation_type"]: item for item in dataset["relationship_descriptors"]
    }
    runtime = history_runtime(dataset)
    if runtime is not None:
        candidate_map: dict[str, dict[str, Any]] = {}
        for identifier in lane_ids:
            for mutation in runtime.mutations_by_endpoint.get(identifier, []):
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
        for item in mutation_candidates
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


def _timeline_mark(
    event: dict[str, Any], resource_identifier: str, next_change_ns: int | None
) -> dict[str, Any]:
    effect = next(
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


def _timeline_glyph_allocations(
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


def _timeline_cluster_preview(
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


def _bounded_timeline_clusters(
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
    allocations = _timeline_glyph_allocations(lanes, glyph_budget)
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
            preview = _timeline_cluster_preview(group, selected_event_uid)
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


@api_router.post("/v1/revisions/{revision_id:path}/timeline/query")
def timeline_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    start_ns = _body_timestamp_ns(
        body,
        "start_ns",
        int(_analysis_metadata(dataset)["timeline_start_ns"]),
    )
    end_ns = _body_timestamp_ns(
        body,
        "end_ns",
        int(_analysis_metadata(dataset)["timeline_end_ns"]),
    )
    if end_ns < start_ns:
        raise _RuntimeHTTPResponse(status_code=422, detail="end_ns must be >= start_ns")
    layers = set(_body_string_list(body, "layers"))
    kinds = set(_body_string_list(body, "kinds"))
    requested_id_values = _body_string_list(body, "resource_ids")
    originally_requested_ids = list(requested_id_values)
    allow_empty = _body_boolean(body, "allow_empty")
    only_with_activity = _body_boolean(body, "only_with_activity")
    runtime = history_runtime(dataset)
    if runtime is not None and not requested_id_values and not allow_empty:
        requested_id_values = list(dict.fromkeys(runtime.initial_resource_ids))
    history_roots = _body_string_list(body, "relationship_history_roots")
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
            for identifier in history_roots
            if identifier not in runtime.resource_by_id
        ]
        valid_history_roots = [
            identifier
            for identifier in history_roots
            if identifier in runtime.resource_by_id
        ]
        expanded: set[str] = set()
        for identifier in valid_history_roots:
            for relationship in runtime.relationships_by_endpoint.get(identifier, []):
                if not _overlaps_window(
                    relationship.get("valid_from_ns"),
                    relationship.get("valid_to_ns"),
                    start_ns,
                    end_ns,
                ):
                    continue
                for endpoint in (
                    str(relationship["source"]),
                    str(relationship["target"]),
                ):
                    if endpoint != identifier and endpoint in runtime.resource_by_id:
                        expanded.add(endpoint)
        base_ids = list(
            dict.fromkeys(
                identifier
                for identifier in [*requested_id_values, *valid_history_roots]
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
            for identifier in valid_history_roots
            if identifier in accepted_base
        ]
        history_dropped_roots = [
            identifier
            for identifier in valid_history_roots
            if identifier not in accepted_base
        ]
        expansion_capacity = MAX_TIMELINE_RESOURCE_LANES - len(accepted_base)
        history_expanded_ids = history_candidate_ids[:expansion_capacity]
        history_dropped_ids = history_candidate_ids[expansion_capacity:]
        requested_id_values = [*accepted_base, *history_expanded_ids]
    if runtime is not None and len(requested_id_values) > MAX_TIMELINE_RESOURCE_LANES:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail=(
                "full-scale timeline queries are limited to "
                f"{MAX_TIMELINE_RESOURCE_LANES} resource lanes"
            ),
        )
    requested_ids = set(requested_id_values)
    if (
        "search" in body
        and body["search"] is not None
        and not isinstance(body["search"], str)
    ):
        raise _RuntimeHTTPResponse(
            status_code=422, detail="search must be a string or null"
        )
    search = str(body.get("search") or "").casefold()
    if runtime is not None:
        filtered: list[dict[str, Any]] = []
        lifecycle_by_resource = runtime.lifecycle_by_resource
        state_by_resource = runtime.state_by_resource
        resource_candidates = [
            runtime.resource_by_id[identifier]
            for identifier in requested_id_values
            if identifier in runtime.resource_by_id
        ]
    else:
        filtered = events_in_range(start_ns, end_ns)
        lifecycle_by_resource: dict[str, list[dict[str, Any]]] = {}
        state_by_resource: dict[str, list[dict[str, Any]]] = {}
        for item in dataset["lifecycle_intervals"]:
            lifecycle_by_resource.setdefault(item["resource"], []).append(item)
        for item in dataset["state_intervals"]:
            state_by_resource.setdefault(item["resource"], []).append(item)
        resource_candidates = dataset["resources"]

    descriptor_by_kind = {
        str(item.get("kind")): item
        for item in dataset.get("kind_descriptors", [])
        if isinstance(item, dict) and item.get("kind")
    }
    lanes: list[dict[str, Any]] = []
    all_marks: list[dict[str, Any]] = []
    for order, resource in enumerate(resource_candidates):
        identifier = resource["resource_id"]
        descriptor = descriptor_by_kind.get(str(resource.get("kind", "UNKNOWN")))
        safe_projection = _redact_resource_view(
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
        lifecycles = [
            item
            for item in lifecycle_by_resource.get(identifier, [])
            if (item.get("valid_to_ns") is None or int(item["valid_to_ns"]) > start_ns)
            and (
                item.get("valid_from_ns") is None or int(item["valid_from_ns"]) < end_ns
            )
        ]
        statuses = [
            item
            for item in state_by_resource.get(identifier, [])
            if (item.get("valid_to_ns") is None or int(item["valid_to_ns"]) > start_ns)
            and (
                item.get("valid_from_ns") is None or int(item["valid_from_ns"]) < end_ns
            )
        ]
        if runtime is not None:
            resource_events = [
                item
                for item in runtime.events_by_resource.get(identifier, [])
                if start_ns <= int(item["timestamp_ns"]) <= end_ns
            ]
        else:
            resource_events = [
                item for item in filtered if identifier in _event_resource_ids(item)
            ]
        resource_events = [
            redact_event_for_client(item, dataset) for item in resource_events
        ]
        if only_with_activity and not (lifecycles or statuses or resource_events):
            continue
        change_times = sorted(
            int(item["valid_from_ns"])
            for item in state_by_resource.get(identifier, [])
            if item.get("valid_from_ns") is not None
        )
        marks = []
        for event in resource_events:
            next_change = next(
                (time for time in change_times if time > int(event["timestamp_ns"])),
                None,
            )
            mark = _timeline_mark(event, identifier, next_change)
            marks.append(mark)
            all_marks.append(mark)
        lifecycle_payload = [
            {
                **item,
                "start_ns": item.get("valid_from_ns"),
                "end_ns": item.get("valid_to_ns"),
                "duration_ns": _interval_duration(
                    item.get("valid_from_ns"), item.get("valid_to_ns")
                ),
                "open_start": item.get("valid_from_ns") is None,
                "open_end": item.get("valid_to_ns") is None,
            }
            for item in lifecycles
        ]
        status_payload = [
            {
                **item,
                "properties": _redact_resource_view(
                    {"state": dict(item.get("properties", {}))},
                    descriptor,
                ).get("state", {}),
                "start_ns": item.get("valid_from_ns"),
                "end_ns": item.get("valid_to_ns"),
                "duration_ns": _interval_duration(
                    item.get("valid_from_ns"), item.get("valid_to_ns")
                ),
                "start_event_uid": item.get(
                    "start_event_uid", item.get("cause_event_uid")
                ),
            }
            for item in statuses
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
                "lifecycle_intervals": lifecycle_payload,
                "status_intervals": status_payload,
                "event_marks": marks,
                "events": resource_events,
            }
        )

    cluster_window_ns = _body_integer(
        body,
        "cluster_window_ns",
        20_000_000,
        minimum=0,
        maximum=MAX_TIMESTAMP_NS,
    )
    requested_max_glyphs = _body_integer(
        body,
        "max_glyphs",
        MAX_TIMELINE_GLYPHS,
        minimum=1,
        maximum=MAX_TIMELINE_GLYPHS,
    )
    viewport_pixels = _body_integer(
        body,
        "viewport_pixels",
        MAX_TIMELINE_VIEWPORT_PIXELS,
        minimum=1,
        maximum=MAX_TIMELINE_VIEWPORT_PIXELS,
    )
    glyph_budget = min(requested_max_glyphs, max(1, viewport_pixels * 4))
    selected_event_uid = body.get("selected_event_uid")
    if selected_event_uid is not None and not isinstance(selected_event_uid, str):
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="selected_event_uid must be a string or null",
        )
    clusters, glyph_meta = _bounded_timeline_clusters(
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
    lane_ids = {lane["resource_id"] for lane in lanes}
    relationship_intervals = _effective_relationship_intervals(
        dataset,
        lane_ids,
        start_ns,
        end_ns,
    )
    relationship_mutations = _relationship_mutations_in_window(
        dataset,
        lane_ids,
        start_ns,
        end_ns,
    )
    cursor_time_ns = None
    if "cursor_time_ns" in body and body["cursor_time_ns"] is not None:
        cursor_time_ns = str(_body_timestamp_ns(body, "cursor_time_ns", start_ns))
    selected_range = body.get("range")
    if selected_range is not None and not isinstance(selected_range, dict):
        raise _RuntimeHTTPResponse(
            status_code=422, detail="range must be an object or null"
        )
    if isinstance(selected_range, dict):
        for key in ("start_ns", "end_ns"):
            if key in selected_range:
                selected_range[key] = str(
                    _body_timestamp_ns(selected_range, key, start_ns)
                )
        selected_range = {
            key: str(value) if key.endswith("_ns") and value is not None else value
            for key, value in selected_range.items()
        }
    known_source_types = {
        str(item["source_type"])
        for item in dataset.get("source_record_descriptors", [])
        if item.get("source_type")
    }
    record_lane_rules = _body_object_list(body, "record_lane_rules")
    max_record_marks = _body_integer(
        body,
        "max_record_marks",
        5_000,
        minimum=0,
        maximum=5_000,
    )
    record_lanes = _runtime_api_call(
        record_lanes_for_window,
        dataset.get("source_records", []),
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
        "event_count": len({item["event_uid"] for item in all_marks}),
        "mark_count": len(all_marks),
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


@api_router.post("/v1/revisions/{revision_id:path}/timeline/clusters/detail")
def timeline_cluster_detail(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Page the exact events represented by one bounded timeline cluster."""

    _require_revision(revision_id)
    identifier = body.get("resource_id")
    if not isinstance(identifier, str) or not identifier:
        raise _RuntimeHTTPResponse(
            status_code=422, detail="resource_id must be a non-empty canonical string"
        )
    dataset = load_dataset()
    start_ns = _body_timestamp_ns(
        body, "start_ns", int(_analysis_metadata(dataset)["timeline_start_ns"])
    )
    end_ns = _body_timestamp_ns(
        body, "end_ns", int(_analysis_metadata(dataset)["timeline_end_ns"])
    )
    if end_ns < start_ns:
        raise _RuntimeHTTPResponse(status_code=422, detail="end_ns must be >= start_ns")
    offset = _body_integer(
        body,
        "offset",
        0,
        minimum=0,
        maximum=MAX_JSON_SAFE_INTEGER,
    )
    limit = _body_integer(body, "limit", 100, minimum=1, maximum=200)
    runtime = history_runtime(dataset)
    if runtime is not None:
        if identifier not in runtime.resource_by_id:
            raise _RuntimeHTTPResponse(status_code=404, detail="resource not found")
        candidates = runtime.events_by_resource.get(identifier, [])
    else:
        if not any(resource_id(item) == identifier for item in dataset["resources"]):
            raise _RuntimeHTTPResponse(status_code=404, detail="resource not found")
        candidates = [
            item
            for item in dataset["events"]
            if identifier in _event_resource_ids(item)
        ]
    selected = [
        item for item in candidates if start_ns <= int(item["timestamp_ns"]) <= end_ns
    ]
    selected.sort(
        key=lambda item: temporal_order_key(
            item,
            time_field="timestamp_ns",
            identifier_fields=("event_uid", "event_id"),
        )
    )
    page = selected[offset : offset + limit]
    items = [
        _timeline_mark(redact_event_for_client(item, dataset), identifier, None)
        for item in page
    ]
    next_offset = offset + len(items)
    return {
        "revision_id": revision_id,
        "resource_id": identifier,
        "start_ns": str(start_ns),
        "end_ns": str(end_ns),
        "offset": offset,
        "limit": limit,
        "total_count": len(selected),
        "items": items,
        "next_offset": next_offset if next_offset < len(selected) else None,
        "truncated": next_offset < len(selected),
    }


@api_router.post("/v1/revisions/{revision_id:path}/range/summary")
def selected_range_summary(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    start_ns = _body_timestamp_ns(
        body,
        "start_ns",
        int(_analysis_metadata(dataset)["timeline_start_ns"]),
    )
    end_ns = _body_timestamp_ns(
        body,
        "end_ns",
        int(_analysis_metadata(dataset)["timeline_end_ns"]),
    )
    if end_ns < start_ns:
        raise _RuntimeHTTPResponse(status_code=422, detail="end_ns must be >= start_ns")
    return range_summary(start_ns, end_ns)


@api_router.post("/v1/revisions/{revision_id:path}/graph/query")
def graph_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    _require_revision(revision_id)
    return _correlation_payload(body)


@api_router.post("/v1/revisions/{revision_id:path}/correlations/query")
def correlation_query(
    revision_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
) -> dict[str, Any]:
    """Return the typed relationship subgraph at one selected moment."""

    _require_revision(revision_id)
    return _correlation_payload(body)


@api_router.get("/v1/revisions/{revision_id:path}/consistency-findings")
def consistency_findings(
    revision_id: str,
    limit: int = Query(default=1_000, ge=1, le=5_000),
    offset: int = Query(default=0, ge=0, le=MAX_JSON_SAFE_INTEGER),
) -> dict[str, Any]:
    descriptor = _require_revision(revision_id)
    dataset = load_dataset()
    try:
        raw_items, materialization = validate_revision_consistency_dataset(
            dataset,
            execution_plan=descriptor.execution_plan,
        )
    except DatasetIntegrityError as error:
        raise _RuntimeHTTPResponse(
            status_code=500,
            detail="revision consistency materialization is invalid",
        ) from error
    page = raw_items[offset : offset + limit]
    items = project_consistency_findings_for_client(dataset, page)
    total_count = len(raw_items)
    next_offset = offset + len(page)
    if next_offset >= total_count:
        next_offset = None
    return {
        "revision_id": revision_id,
        "materialization": project_consistency_materialization_for_client(
            materialization,
        ),
        "items": items,
        "count": len(items),
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


def _route_capabilities_payload(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    return route_resolution_capability(load_dataset())


def _resolve_route_payload(
    revision_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    _require_revision(revision_id)
    dataset = load_dataset()
    capability = route_resolution_capability(dataset)
    route_id = body.get("route_id")
    basis = body.get("basis_kind")
    if not isinstance(route_id, str) or not route_id:
        raise _RuntimeHTTPResponse(status_code=422, detail="route_id is required")
    advertised_basis = {
        str(item.get("basis_kind"))
        for item in capability.get("basis_kinds", [])
        if isinstance(item, dict) and item.get("basis_kind")
    }
    if not isinstance(basis, str) or basis not in advertised_basis:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="basis_kind must be one of the plug-in-advertised values",
        )
    try:
        row = route_row(route_id, dataset)
    except KeyError as error:
        raise _RuntimeHTTPResponse(
            status_code=422,
            detail="route_id was not advertised for this node revision",
        ) from error

    candidate_next_hops = [
        dict(item)
        for item in row.get("candidate_next_hops", [])
        if isinstance(item, dict)
    ]
    next_hops = [
        str(item["node_id"]) for item in candidate_next_hops if item.get("node_id")
    ]
    egress_interfaces = [
        str(item["via"]) for item in candidate_next_hops if item.get("via")
    ]
    children = [
        {
            "kind": "next_hop",
            "resource_id": item.get("node_id") or item.get("via"),
            "state": (
                "active"
                if item.get("active") is True
                else "inactive"
                if item.get("active") is False
                else "unknown"
            ),
            "relation_type": "candidate_next_hop",
            "children": [],
        }
        for item in candidate_next_hops
    ]
    return {
        "revision_id": revision_id,
        "basis": {
            "kind": basis,
            "time_ns": row.get("observed_at_ns"),
            "provenance": "plugin_projection",
            "quality": "exact",
        },
        "result": (
            "resolved"
            if str(row.get("decision") or "") == "active"
            else "partially_resolved"
        ),
        "route_id": row["route_id"],
        "scenario_id": row.get("scenario_id"),
        "matched_prefix": row.get("destination"),
        "next_hops": next_hops,
        "egress_interfaces": egress_interfaces,
        "branches": [
            {
                "next_hop": item.get("node_id"),
                "egress_interface_resource_id": item.get("via"),
                "active": item.get("active"),
            }
            for item in candidate_next_hops
        ],
        "explanation": {
            "kind": row.get("route_type") or "route",
            "resource_id": row["route_id"],
            "state": row.get("decision"),
            "relation_type": None,
            "children": children,
        },
        "route_attributes": {
            key: row[key]
            for key in (
                "route_type",
                "route_family",
                "address_family",
                "vrf",
                "protocol",
                "metric",
                "label_stack",
                "sid_stack",
                "encapsulation",
            )
            if key in row
        },
        "plugin_provenance": capability.get("provider", {}),
        "quality": "exact",
    }


@api_router.get("/v1/revisions/{revision_id:path}/inventory")
def inventory(revision_id: str) -> dict[str, Any]:
    _require_revision(revision_id)
    return load_dataset()["inventory"]


def reset_runtime_api_caches() -> None:
    """Clear projections only for the active application session."""

    try:
        current_runtime_session().clear_cache()
    except RuntimeError:
        # Opening a new application begins with a fresh session-local cache.
        pass


def start_runtime_warmup() -> None:
    """Synchronously load/index a headless runtime before it starts serving.

    Frontend deployments deliberately skip this function: their first
    revision request performs the lazy load while either browser workspace
    polls ``/v1/analysis-load``.  API-only deployments retain fail-fast startup
    and native process-control propagation by warming on the lifespan owner.
    """

    _warm_event_search(load_dataset())


__all__ = [
    "analysis_health_projection",
    "api_router",
    "reset_runtime_api_caches",
    "start_runtime_warmup",
]
