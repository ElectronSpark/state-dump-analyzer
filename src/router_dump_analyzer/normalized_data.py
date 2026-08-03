"""Core-owned services over one plug-in-supplied normalized dataset.

The core applies the common temporal envelope, descriptor-driven redaction,
resource-table traversal, dashboard evaluation, and bounded range algorithms.
Plug-ins remain responsible for loading an input, interpreting device evidence,
and supplying presentation/route/source-record policy.
"""

from __future__ import annotations

import json
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from contextlib import AbstractContextManager
from functools import lru_cache
from hashlib import sha256
from types import TracebackType
from typing import Any, Protocol, runtime_checkable

from .dashboard_core import (
    DashboardDescriptorValidationError,
    evaluate_dashboards,
    validate_dashboard_descriptors,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .source_record_core import project_source_record_for_log

MAX_RESOURCE_TABLE_TRAVERSAL_NODES = 5_000
MAX_RESOURCE_PAGE_SIZE = 1_000
MAX_RANGE_DETAILS = 500
_CSS_COLOR_PALETTE = (
    "#52e0c4",
    "#a58bff",
    "#f5b85b",
    "#66b8ff",
    "#ff8eb5",
    "#9bd66f",
    "#df9dff",
)
_CLIENT_DATASET_FIELDS = frozenset(
    {
        "causal_link_descriptors",
        "causal_links",
        "coverage",
        "dashboard_descriptors",
        "demo",
        "event_count",
        "events",
        "findings",
        "gaps",
        "inventory",
        "kind_descriptors",
        "layers",
        "lifecycle_intervals",
        "node_id",
        "node_snapshot",
        "nodes",
        "presentation",
        "record_lane_presets",
        "relationship_descriptors",
        "relationship_intervals",
        "relationship_mutations",
        "relationship_type_descriptors",
        "relationships",
        "resource_table_view_descriptors",
        "resources",
        "review_prompts",
        "scale",
        "schema",
        "source_record_descriptors",
        "source_record_group_descriptors",
        "source_records",
        "state_intervals",
        "summary",
        "timeline",
        "topology_capabilities",
        "topology_defaults",
        "topology_nodes",
    }
)
_CLIENT_DEMO_FIELDS = frozenset(
    {
        "assembly_id",
        "capabilities",
        "capture_ns",
        "disclosure",
        "event_count",
        "failure_event_count",
        "fixture",
        "history_mode",
        "initial_focus_resource_id",
        "initial_resource_ids",
        "label",
        "large_dataset",
        "matched_event_count",
        "mode",
        "name",
        "node",
        "node_id",
        "node_label",
        "packed_event_count",
        "packed_container_count",
        "packed_resource_count",
        "packed_scenario_id",
        "projection_capabilities",
        "relationship_count",
        "relationship_mutation_count",
        "resource_count",
        "revision_id",
        "scale_mode",
        "scenario",
        "scope",
        "source_record_count",
        "time_bounds",
        "timeline_end_ns",
        "timeline_start_ns",
        "unmatched_source_record_count",
        "workspace_kind",
    }
)
_CLIENT_PRESENTATION_COLOR_ROOTS = frozenset(
    {
        "causal_link_descriptors",
        "dashboard_descriptors",
        "kind_descriptors",
        "layers",
        "presentation",
        "record_lane_presets",
        "relationship_descriptors",
        "relationship_type_descriptors",
        "resource_table_view_descriptors",
        "source_record_descriptors",
        "source_record_group_descriptors",
    }
)
_CLIENT_SCHEMA_PRESENTATION_FIELDS = frozenset(
    {
        "causal_link_types",
        "dashboards",
        "record_lane_presets",
        "relationship_types",
        "resource_kinds",
        "resource_table_views",
        "source_record_groups",
        "source_record_types",
    }
)
_CLIENT_RESOURCE_ENVELOPE_FIELDS = frozenset(
    {
        "canonical_resource_id",
        "condition",
        "condition_class",
        "evidence",
        "exists",
        "incarnation",
        "kind",
        "label",
        "layer",
        "presentation_tags",
        "provenance",
        "quality",
        "resource_id",
        "resource_uid",
        "source_event_uid",
        "status",
        "status_class",
        "unknown_fields",
        "valid_from_ns",
        "valid_to_ns",
    }
)
_CLIENT_PLUGIN_DATASET_PAYLOAD_FIELDS = frozenset(
    {
        "causal_links",
        "coverage",
        "findings",
        "gaps",
        "inventory",
        "lifecycle_intervals",
        "node_snapshot",
        "nodes",
        "relationship_intervals",
        "relationship_mutations",
        "relationships",
        "review_prompts",
        "summary",
        "timeline",
        "topology_capabilities",
        "topology_defaults",
        "topology_nodes",
    }
)
_CLIENT_PLUGIN_PROPERTY_CONTAINER_FIELDS = frozenset(
    {
        "after",
        "attributes",
        "before",
        "key",
        "properties",
        "result",
        "state",
    }
)
_CLIENT_EVIDENCE_FIELDS = frozenset(
    {
        "artifact_id",
        "clock_domain",
        "evidence_id",
        "excerpt_sha256",
        "locator",
        "raw_timestamp_ns",
        "source_record_uid",
    }
)
_CLIENT_PROVENANCE_FIELDS = frozenset(
    {
        "actor",
        "kind",
        "mapping_method",
        "method",
        "origin",
        "plugin_id",
        "plugin_instance_id",
        "plugin_run_id",
        "reason_code",
        "rule_id",
        "schema_digest",
        "source",
    }
)
_CLIENT_UNKNOWN_FIELD_FIELDS = frozenset(
    {
        "evidence",
        "evidence_ids",
        "message",
        "name",
        "reason_code",
    }
)
_CLIENT_EVENT_CORE_FIELDS = frozenset(
    {
        "action",
        "absolute_timestamp_ns",
        "burst_id",
        "clock_domain",
        "condition",
        "condition_class",
        "display_name",
        "event_id",
        "event_name",
        "event_type",
        "event_uid",
        "kind",
        "layer",
        "message",
        "operation",
        "outcome",
        "phase",
        "quality",
        "resource",
        "resource_id",
        "resource_kind",
        "resource_uid",
        "source_record_uid",
        "source_sequence",
        "state_changed",
        "status",
        "status_class",
        "timestamp_ns",
        "timestamp_uncertainty_ns",
        "time_ns",
    }
)
_CLIENT_EVENT_PAYLOAD_FIELDS = frozenset(
    {
        "attributes",
        "properties",
        "result",
    }
)
_CLIENT_EVENT_SUBJECT_CORE_FIELDS = frozenset(
    {
        "kind",
        "label",
        "layer",
        "resource",
        "resource_id",
        "resource_kind",
        "resource_uid",
    }
)
_CLIENT_EVENT_EFFECT_CORE_FIELDS = frozenset(
    {
        "action",
        "condition",
        "condition_class",
        "effect_type",
        "kind",
        "label",
        "layer",
        "operation",
        "outcome",
        "resource",
        "resource_id",
        "resource_kind",
        "resource_uid",
        "state_changed",
        "status",
        "status_class",
    }
)
_CLIENT_EVENT_EFFECT_PAYLOAD_FIELDS = frozenset(
    {
        "after",
        "attributes",
        "before",
        "properties",
        "result",
        "state",
    }
)
_CLIENT_RELATIONSHIP_EFFECT_CORE_FIELDS = frozenset(
    {
        "operation",
        "relation_type",
        "source",
        "target",
        "type",
    }
)
_CLIENT_STATE_INTERVAL_FIELDS = frozenset(
    {
        "condition",
        "condition_class",
        "evidence",
        "field_quality",
        "incarnation",
        "observed_at_max_ns",
        "observed_at_min_ns",
        "perspective_ref",
        "properties",
        "provenance",
        "quality",
        "resource",
        "source_event_uid",
        "start_event_uid",
        "status",
        "status_class",
        "unknown_fields",
        "valid_from_ns",
        "valid_to_ns",
    }
)
_PUBLIC_STATUS_CLASSES = frozenset(
    {
        "absent",
        "degraded",
        "error",
        "healthy",
        "unknown",
    }
)
_SENSITIVE_PATH_TERMINAL = object()
_DROP_CLIENT_FIELD = object()


@runtime_checkable
class IndexedHistory(Protocol):
    """Structural contract for an optional exact, revision-local index.

    An input adapter may build this object while decoding its format.  Every
    field is domain-neutral and mirrors the normalized dataset vocabulary; the
    core never depends on the concrete index implementation.
    """

    resources: list[dict[str, Any]]
    resource_by_id: Mapping[str, dict[str, Any]]
    resources_by_kind: Mapping[str, list[dict[str, Any]]]
    resource_counts: Mapping[str, int]
    events: list[dict[str, Any]]
    event_by_uid: Mapping[str, dict[str, Any]]
    event_times: list[int]
    events_by_resource: Mapping[str, list[dict[str, Any]]]
    lifecycle_by_resource: Mapping[str, list[dict[str, Any]]]
    state_by_resource: Mapping[str, list[dict[str, Any]]]
    relationships: list[dict[str, Any]]
    relationships_by_endpoint: Mapping[str, list[dict[str, Any]]]
    mutations: list[dict[str, Any]]
    mutation_times: list[int]
    mutations_by_endpoint: Mapping[str, list[dict[str, Any]]]
    initial_resource_ids: list[str]
    event_search: Any
    resource_search: Any
    event_redaction_policy: Any


@runtime_checkable
class NormalizedDatasetSource(Protocol):
    """Small input/revision surface supplied by a plug-in runtime."""

    def revision_scope(
        self,
        revision_id: str,
    ) -> AbstractContextManager[Any]: ...

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]: ...

    def revision_id(
        self,
        dataset: Mapping[str, Any],
    ) -> str: ...

    def indexed_history(
        self,
        dataset: Mapping[str, Any],
    ) -> IndexedHistory | None: ...


@runtime_checkable
class NormalizedDataPolicy(Protocol):
    """Device/input-specific presentation callbacks used by core services."""

    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def workspace_metadata(
        self,
        dataset: Mapping[str, Any],
        *,
        revision_id: str,
        history_mode: str,
    ) -> Mapping[str, Any]: ...

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def resource_id(record: Mapping[str, Any]) -> str:
    """Return the canonical identity or a type-preserving legacy fallback."""

    explicit = (
        record.get("resource_id")
        or record.get("canonical_resource_id")
        or record.get("resource_uid")
    )
    if explicit:
        return str(explicit)
    identity = {
        "layer": record.get("layer"),
        "kind": record.get("kind"),
        "key": record.get("key", {}),
    }
    canonical = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=lambda value: {
            "python_type": (
                f"{type(value).__module__}.{type(value).__qualname__}"
            ),
            "value": str(value),
        },
    ).encode("utf-8")
    return f"legacy-resource:{sha256(canonical).hexdigest()}"


def resource_label(
    record: Mapping[str, Any] | None,
    identifier: str,
) -> str:
    """Use explicit plug-in evidence, otherwise preserve the opaque identity."""

    if record is not None and record.get("label"):
        return str(record["label"])
    return identifier


def contains_time(timestamp_ns: int, start: Any, end: Any) -> bool:
    return (start is None or timestamp_ns >= int(start)) and (
        end is None or timestamp_ns < int(end)
    )


def overlaps_range(
    start: Any,
    end: Any,
    query_start_ns: int,
    query_end_ns: int,
) -> bool:
    return (end is None or int(end) > query_start_ns) and (
        start is None or int(start) < query_end_ns
    )


def active_interval(
    records: Iterable[dict[str, Any]],
    timestamp_ns: int,
) -> dict[str, Any] | None:
    candidates = [
        item
        for item in records
        if contains_time(
            timestamp_ns,
            item.get("valid_from_ns"),
            item.get("valid_to_ns"),
        )
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: int(item.get("valid_from_ns") or -1),
    )


def descriptor_property_rules(
    descriptor: Mapping[str, Any] | None,
) -> dict[str, Mapping[str, Any]]:
    if not descriptor:
        return {}
    return {
        str(item["name"]): item
        for item in descriptor.get("properties", [])
        if isinstance(item, Mapping) and item.get("name")
    }


def descriptor_sensitive_condition(
    descriptor: Mapping[str, Any] | None,
) -> bool:
    if not descriptor or not descriptor.get("condition_field"):
        return False
    condition = str(descriptor["condition_field"])
    rule = descriptor_property_rules(descriptor).get(condition, {})
    return bool(
        rule.get("sensitive")
        or rule.get("client_visible", True) is False
    )


@lru_cache(maxsize=256)
def _sensitive_path_trie(
    sensitive_fields: frozenset[str],
) -> dict[object, Any]:
    root: dict[object, Any] = {}
    for field in sensitive_fields:
        parts = tuple(
            part
            for part in str(field).split(".")
            if part
        )
        if not parts:
            continue
        branch = root
        for part in parts:
            branch = branch.setdefault(part, {})
        branch[_SENSITIVE_PATH_TERMINAL] = True
    return root


def _redact_relative_paths(
    value: Any,
    branch: Mapping[object, Any],
) -> Any:
    if isinstance(value, list):
        return [
            _redact_relative_paths(item, branch)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_relative_paths(item, branch)
            for item in value
        )
    if not isinstance(value, Mapping):
        return value
    result: dict[Any, Any] = {}
    for key, nested in value.items():
        child = branch.get(str(key))
        if isinstance(child, Mapping) and child.get(_SENSITIVE_PATH_TERMINAL):
            continue
        result[key] = (
            _redact_relative_paths(nested, child)
            if isinstance(child, Mapping)
            else nested
        )
    return result


def _redact_sensitive_tree(
    value: Any,
    *,
    exact_names: frozenset[str],
    path_trie: Mapping[object, Any],
) -> Any:
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, nested in value.items():
            name = str(key)
            if name in exact_names:
                continue
            child = path_trie.get(name)
            if isinstance(child, Mapping) and child.get(
                _SENSITIVE_PATH_TERMINAL
            ):
                continue
            projected = _redact_sensitive_tree(
                nested,
                exact_names=exact_names,
                path_trie=path_trie,
            )
            result[key] = (
                _redact_relative_paths(projected, child)
                if isinstance(child, Mapping)
                else projected
            )
        return result
    if isinstance(value, list):
        return [
            _redact_sensitive_tree(
                nested,
                exact_names=exact_names,
                path_trie=path_trie,
            )
            for nested in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_sensitive_tree(
                nested,
                exact_names=exact_names,
                path_trie=path_trie,
            )
            for nested in value
        )
    return value


def redact_sensitive_tree(value: Any, sensitive_fields: set[str]) -> Any:
    """Remove declared names and dotted paths inside a plug-in payload."""

    exact_names = frozenset(str(field) for field in sensitive_fields)
    return _redact_sensitive_tree(
        value,
        exact_names=exact_names,
        path_trie=_sensitive_path_trie(exact_names),
    )


def _safe_public_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return _DROP_CLIENT_FIELD


def _project_evidence_for_client(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: projected
            for key, nested in value.items()
            if str(key) in _CLIENT_EVIDENCE_FIELDS
            and (projected := _safe_public_scalar(nested))
            is not _DROP_CLIENT_FIELD
        }
    if isinstance(value, (list, tuple)):
        result = []
        for item in value:
            projected = _project_evidence_for_client(item)
            if projected is not _DROP_CLIENT_FIELD:
                result.append(projected)
        return result
    return _safe_public_scalar(value)


def _project_provenance_for_client(value: Any) -> Any:
    scalar = _safe_public_scalar(value)
    if scalar is not _DROP_CLIENT_FIELD:
        return scalar
    if not isinstance(value, Mapping):
        return _DROP_CLIENT_FIELD
    return {
        key: projected
        for key, nested in value.items()
        if str(key) in _CLIENT_PROVENANCE_FIELDS
        and (projected := _safe_public_scalar(nested))
        is not _DROP_CLIENT_FIELD
    }


def _project_unknown_fields_for_client(value: Any) -> Any:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[dict[Any, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        projected: dict[Any, Any] = {}
        for key, nested in item.items():
            name = str(key)
            if name not in _CLIENT_UNKNOWN_FIELD_FIELDS:
                continue
            if name == "evidence":
                public = _project_evidence_for_client(nested)
            elif name == "evidence_ids" and isinstance(
                nested,
                (list, tuple),
            ):
                public = [
                    scalar
                    for value_item in nested
                    if (scalar := _safe_public_scalar(value_item))
                    is not _DROP_CLIENT_FIELD
                ]
            else:
                public = _safe_public_scalar(nested)
            if public is not _DROP_CLIENT_FIELD:
                projected[key] = public
        result.append(projected)
    return result


def _project_incarnation_for_client(value: Any) -> Any:
    if isinstance(value, bool):
        return _DROP_CLIENT_FIELD
    if isinstance(value, (str, int)):
        return value
    return _DROP_CLIENT_FIELD


def _safe_status_class(value: Any, *, exists: Any = None) -> str:
    if exists is False:
        return "absent"
    candidate = str(value or "unknown").casefold()
    return candidate if candidate in _PUBLIC_STATUS_CLASSES else "unknown"


def _sanitize_resource_metadata(
    projected: dict[str, Any],
    *,
    exists: Any = None,
) -> None:
    handlers = {
        "evidence": _project_evidence_for_client,
        "incarnation": _project_incarnation_for_client,
        "provenance": _project_provenance_for_client,
        "unknown_fields": _project_unknown_fields_for_client,
    }
    for field, handler in handlers.items():
        if field not in projected:
            continue
        public = handler(projected[field])
        if public is _DROP_CLIENT_FIELD:
            projected.pop(field, None)
        else:
            projected[field] = public
    if "status_class" in projected:
        projected["status_class"] = _safe_status_class(
            projected["status_class"],
            exists=exists,
        )
    if "condition_class" in projected:
        projected["condition_class"] = _safe_status_class(
            projected["condition_class"],
            exists=exists,
        )


def _sanitize_plugin_payload_tree(
    value: Any,
    sensitive_fields: set[str],
) -> Any:
    """Sanitize plug-in leaves without applying names to structural envelopes."""

    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, nested in value.items():
            name = str(key)
            if name in _CLIENT_PLUGIN_PROPERTY_CONTAINER_FIELDS:
                result[key] = redact_sensitive_tree(
                    nested,
                    sensitive_fields,
                )
            elif name == "evidence":
                public = _project_evidence_for_client(nested)
                if public is not _DROP_CLIENT_FIELD:
                    result[key] = public
            elif name == "provenance":
                public = _project_provenance_for_client(nested)
                if public is not _DROP_CLIENT_FIELD:
                    result[key] = public
            elif name == "unknown_fields":
                result[key] = _project_unknown_fields_for_client(nested)
            elif name == "incarnation":
                public = _project_incarnation_for_client(nested)
                if public is not _DROP_CLIENT_FIELD:
                    result[key] = public
            else:
                result[key] = _sanitize_plugin_payload_tree(
                    nested,
                    sensitive_fields,
                )
        return result
    if isinstance(value, list):
        return [
            _sanitize_plugin_payload_tree(item, sensitive_fields)
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            _sanitize_plugin_payload_tree(item, sensitive_fields)
            for item in value
        )
    return value


def _project_declared_fields(
    value: Any,
    field_names: set[str],
) -> dict[str, Any]:
    """Project a mapping through descriptor-declared dotted field paths."""

    if not isinstance(value, Mapping) or not field_names:
        return {}
    result: dict[str, Any] = {}
    for raw_key, nested in value.items():
        key = str(raw_key)
        if key in field_names:
            result[raw_key] = nested
            continue
        descendants = {
            field[len(key) + 1 :]
            for field in field_names
            if field.startswith(f"{key}.")
        }
        if descendants and isinstance(nested, Mapping):
            projected = _project_declared_fields(nested, descendants)
            if projected:
                result[raw_key] = projected
    return result


def _client_visible_property_names(
    descriptor: Mapping[str, Any],
) -> set[str]:
    return {
        name
        for name, rule in descriptor_property_rules(descriptor).items()
        if not bool(rule.get("sensitive"))
        and rule.get("client_visible", True) is not False
    }


def redact_resource_view(
    view: Mapping[str, Any],
    descriptor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if descriptor is None:
        # Legacy/ad-hoc callers may reach the generic redactor before dataset
        # conformance validation.  Preserve only the core envelope instead of
        # returning an undeclared plug-in payload unchanged.
        record = view.get("resource")
        source = record if isinstance(record, Mapping) else view
        safe_record = {
            key: source[key]
            for key in (
                "resource_id",
                "canonical_resource_id",
                "resource_uid",
                "kind",
                "layer",
                "label",
                "presentation_tags",
            )
            if key in source
        }
        return {
            **{
                key: view[key]
                for key in (
                    "resource_id",
                    "kind",
                    "layer",
                    "label",
                    "exists",
                    "valid_from_ns",
                    "valid_to_ns",
                    "source_event_uid",
                    "quality",
                )
                if key in view
            },
            "status": "unknown" if view.get("exists") else "absent",
            "status_class": "unknown",
            "state": {},
            "key": {},
            **({"resource": safe_record} if isinstance(record, Mapping) else {}),
        }
    rules = descriptor_property_rules(descriptor)
    sensitive = {
        name
        for name, rule in rules.items()
        if bool(rule.get("sensitive"))
        or rule.get("client_visible", True) is False
    }
    visible_properties = _client_visible_property_names(descriptor)
    visible_key_fields = {
        str(name)
        for name in descriptor.get("key_fields", ())
        if isinstance(name, str)
    } | visible_properties
    projected = {
        key: nested
        for key, nested in view.items()
        if str(key) in _CLIENT_RESOURCE_ENVELOPE_FIELDS
    }
    _sanitize_resource_metadata(
        projected,
        exists=view.get("exists"),
    )
    if descriptor_sensitive_condition(descriptor):
        if "status" in projected:
            projected["status"] = "unknown"
        if "condition" in projected:
            projected["condition"] = "unknown"
    projected["state"] = redact_sensitive_tree(
        _project_declared_fields(
            view.get("state", {}),
            visible_properties,
        ),
        sensitive,
    )
    if "key" in view:
        projected["key"] = redact_sensitive_tree(
            _project_declared_fields(
                view.get("key", {}),
                visible_key_fields,
            ),
            sensitive,
        )
    raw_record = view.get("resource")
    if isinstance(raw_record, Mapping):
        safe_record = {
            key: nested
            for key, nested in raw_record.items()
            if str(key) in _CLIENT_RESOURCE_ENVELOPE_FIELDS
        }
        _sanitize_resource_metadata(
            safe_record,
            exists=view.get("exists"),
        )
        safe_record["state"] = redact_sensitive_tree(
            _project_declared_fields(
                raw_record.get("state", {}),
                visible_properties,
            ),
            sensitive,
        )
        safe_record["key"] = redact_sensitive_tree(
            _project_declared_fields(
                raw_record.get("key", {}),
                visible_key_fields,
            ),
            sensitive,
        )
        for name in visible_properties:
            if "." not in name and name in raw_record:
                safe_record[name] = redact_sensitive_tree(
                    raw_record[name],
                    sensitive,
                )
        if descriptor_sensitive_condition(descriptor):
            if "status" in safe_record:
                safe_record["status"] = "unknown"
            if "condition" in safe_record:
                safe_record["condition"] = "unknown"
        projected["resource"] = safe_record
    return projected


def redact_resource_for_client(
    record: Mapping[str, Any],
    descriptor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    projected = redact_resource_view(
        {
            "state": dict(record.get("state", {})),
            "key": dict(record.get("key", {})),
            "resource": record,
        },
        descriptor,
    )
    safe_record = dict(projected.get("resource") or record)
    safe_record["state"] = projected.get("state", {})
    safe_record["key"] = projected.get("key", {})
    return safe_record


def _safe_css_color(value: Any, identity: str) -> str:
    candidate = str(value or "")
    if (
        len(candidate) == 7
        and candidate.startswith("#")
        and all(char in "0123456789abcdefABCDEF" for char in candidate[1:])
    ):
        return candidate
    digest = sha256(identity.encode("utf-8", errors="replace")).digest()
    return _CSS_COLOR_PALETTE[digest[0] % len(_CSS_COLOR_PALETTE)]


def _sanitize_client_presentation(
    value: Any,
    *,
    path: tuple[str, ...] = (),
) -> Any:
    """Copy a public payload while constraining CSS presentation primitives."""

    if isinstance(value, Mapping):
        identity = next(
            (
                str(value[field])
                for field in (
                    "id",
                    "layer",
                    "kind",
                    "source_type",
                    "relation_type",
                    "label",
                )
                if value.get(field) is not None
            ),
            "/".join(path) or "unknown",
        )
        presentation_context = bool(path) and (
            path[0] in _CLIENT_PRESENTATION_COLOR_ROOTS
            or (
                len(path) > 1
                and path[0] == "schema"
                and path[1] in _CLIENT_SCHEMA_PRESENTATION_FIELDS
            )
        )
        return {
            key: (
                _safe_css_color(nested, identity)
                if str(key) == "color" and presentation_context
                else _sanitize_client_presentation(
                    nested,
                    path=(*path, str(key)),
                )
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_client_presentation(item, path=(*path, str(index)))
            for index, item in enumerate(value)
        ]
    if isinstance(value, tuple):
        return tuple(
            _sanitize_client_presentation(item, path=(*path, str(index)))
            for index, item in enumerate(value)
        )
    return value


def _client_dataset_envelope(
    dataset: Mapping[str, Any],
    sensitive_fields: set[str],
    *,
    omit_fields: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Build the explicit public bootstrap envelope.

    Normalized adapters may retain private caches and format-specific metadata
    beside the public model.  The browser bootstrap must never become an
    accidental serialization of those adapter internals.
    """

    client: dict[str, Any] = {}
    for key, value in dataset.items():
        name = str(key)
        if name not in _CLIENT_DATASET_FIELDS or name in omit_fields:
            continue
        client[key] = (
            _sanitize_plugin_payload_tree(value, sensitive_fields)
            if name in _CLIENT_PLUGIN_DATASET_PAYLOAD_FIELDS
            else value
        )
    demo = client.get("demo")
    if isinstance(demo, Mapping):
        client["demo"] = {
            key: value
            for key, value in demo.items()
            if str(key) in _CLIENT_DEMO_FIELDS
        }
    scale = client.get("scale")
    if isinstance(scale, Mapping):
        client["scale"] = {
            "metrics": scale.get("metrics", {}),
        }
    return _sanitize_client_presentation(client)


type EventRedactionPolicy = tuple[
    dict[str, frozenset[str]],
    dict[str, str],
    frozenset[str],
]


def event_redaction_policy(
    dataset: Mapping[str, Any],
    runtime: IndexedHistory | None = None,
) -> EventRedactionPolicy:
    cached = (
        getattr(runtime, "event_redaction_policy", None)
        if runtime is not None
        else None
    )
    if cached is not None:
        return cached
    sensitive_by_kind: dict[str, frozenset[str]] = {}
    all_sensitive: set[str] = set()
    for descriptor in dataset.get("kind_descriptors", []):
        if not isinstance(descriptor, Mapping) or not descriptor.get("kind"):
            continue
        sensitive = frozenset(
            name
            for name, rule in descriptor_property_rules(descriptor).items()
            if bool(rule.get("sensitive"))
            or rule.get("client_visible", True) is False
        )
        sensitive_by_kind[str(descriptor["kind"])] = sensitive
        all_sensitive.update(sensitive)
    records = (
        runtime.resource_by_id.values()
        if runtime is not None
        else dataset.get("resources", [])
    )
    kind_by_id = {
        resource_id(record): str(record.get("kind", "UNKNOWN"))
        for record in records
        if isinstance(record, Mapping)
    }
    compiled = (
        sensitive_by_kind,
        kind_by_id,
        frozenset(all_sensitive),
    )
    if runtime is not None:
        runtime.event_redaction_policy = compiled
    return compiled


def _event_resource_kinds(
    event: Mapping[str, Any],
    kind_by_resource_id: Mapping[str, str],
) -> tuple[set[str], bool]:
    kinds: set[str] = set()
    identifiers: set[str] = set()

    def collect(
        value: Any,
        *,
        nested_resource: bool,
    ) -> None:
        if not isinstance(value, Mapping):
            return
        if value.get("resource_kind"):
            kinds.add(str(value["resource_kind"]))
        if nested_resource and value.get("kind"):
            kinds.add(str(value["kind"]))
        for field in ("resource_id", "resource"):
            if value.get(field):
                identifiers.add(str(value[field]))

    collect(event, nested_resource=False)
    collect(event.get("subject"), nested_resource=True)
    for subject in event.get("subjects", []):
        collect(subject, nested_resource=True)
    for effect in event.get("effects", []):
        collect(effect, nested_resource=True)
    for affected in event.get("affected_resources", []):
        if isinstance(affected, Mapping):
            collect(affected, nested_resource=True)
        elif affected:
            identifiers.add(str(affected))
    kinds.update(
        kind_by_resource_id[identifier]
        for identifier in identifiers
        if identifier in kind_by_resource_id
    )
    return kinds, any(
        identifier not in kind_by_resource_id
        for identifier in identifiers
    )


def _redact_event_nested_record(
    value: Any,
    sensitive: set[str],
    *,
    core_fields: frozenset[str],
    payload_fields: frozenset[str],
    sensitive_condition: bool,
) -> Any:
    if not isinstance(value, Mapping):
        return redact_sensitive_tree(value, sensitive)
    result: dict[Any, Any] = {}
    for key, nested in value.items():
        name = str(key)
        if name in core_fields:
            if name in {"status_class", "condition_class"}:
                result[key] = _safe_status_class(nested)
            elif sensitive_condition and name in {"status", "condition"}:
                result[key] = "unknown"
            else:
                public = _safe_public_scalar(nested)
                if public is not _DROP_CLIENT_FIELD:
                    result[key] = public
            continue
        if name not in payload_fields:
            continue
        projected = redact_sensitive_tree(
            {key: nested},
            sensitive,
        )
        if key not in projected:
            continue
        result[key] = (
            redact_sensitive_tree(projected[key], sensitive)
            if name in payload_fields
            else projected[key]
        )
    return result


def redact_event_for_client(
    event: Mapping[str, Any],
    dataset: Mapping[str, Any],
    *,
    runtime: IndexedHistory | None = None,
    policy: EventRedactionPolicy | None = None,
) -> dict[str, Any]:
    sensitive_by_kind, kind_by_id, all_sensitive = (
        policy or event_redaction_policy(dataset, runtime)
    )
    kinds, unresolved_identifiers = _event_resource_kinds(
        event,
        kind_by_id,
    )
    sensitive: set[str] = set()
    for kind in kinds:
        sensitive.update(sensitive_by_kind.get(kind, ()))
    if (
        not kinds
        or unresolved_identifiers
        or any(kind not in sensitive_by_kind for kind in kinds)
    ):
        sensitive.update(all_sensitive)
    descriptors = {
        str(item.get("kind")): item
        for item in dataset.get("kind_descriptors", [])
        if isinstance(item, Mapping) and item.get("kind")
    }
    sensitive_condition = any(
        descriptor_sensitive_condition(descriptors.get(kind))
        for kind in kinds
    )
    result: dict[Any, Any] = {}
    for key, nested in event.items():
        name = str(key)
        if name in _CLIENT_EVENT_CORE_FIELDS:
            if name in {"status_class", "condition_class"}:
                result[key] = _safe_status_class(nested)
            elif sensitive_condition and name in {"status", "condition"}:
                result[key] = "unknown"
            else:
                public = _safe_public_scalar(nested)
                if public is not _DROP_CLIENT_FIELD:
                    result[key] = public
        elif name == "subject":
            result[key] = _redact_event_nested_record(
                nested,
                sensitive,
                core_fields=_CLIENT_EVENT_SUBJECT_CORE_FIELDS,
                payload_fields=_CLIENT_EVENT_PAYLOAD_FIELDS
                | frozenset({"key", "raw_key", "state"}),
                sensitive_condition=sensitive_condition,
            )
        elif name == "affected_resources" and isinstance(
            nested,
            (list, tuple),
        ):
            projected_resources: list[Any] = []
            for item in nested:
                projected = (
                    _redact_event_nested_record(
                        item,
                        sensitive,
                        core_fields=_CLIENT_EVENT_SUBJECT_CORE_FIELDS,
                        payload_fields=_CLIENT_EVENT_PAYLOAD_FIELDS
                        | frozenset({"key", "raw_key", "state"}),
                        sensitive_condition=sensitive_condition,
                    )
                    if isinstance(item, Mapping)
                    else _safe_public_scalar(item)
                )
                if projected is not _DROP_CLIENT_FIELD:
                    projected_resources.append(projected)
            result[key] = projected_resources
        elif name == "subjects" and isinstance(nested, (list, tuple)):
            result[key] = [
                _redact_event_nested_record(
                    item,
                    sensitive,
                    core_fields=_CLIENT_EVENT_SUBJECT_CORE_FIELDS,
                    payload_fields=_CLIENT_EVENT_PAYLOAD_FIELDS
                    | frozenset({"key", "raw_key", "state"}),
                    sensitive_condition=sensitive_condition,
                )
                for item in nested
            ]
        elif name == "effects" and isinstance(nested, (list, tuple)):
            result[key] = [
                _redact_event_nested_record(
                    item,
                    sensitive,
                    core_fields=_CLIENT_EVENT_EFFECT_CORE_FIELDS,
                    payload_fields=_CLIENT_EVENT_EFFECT_PAYLOAD_FIELDS,
                    sensitive_condition=sensitive_condition,
                )
                for item in nested
            ]
        elif name == "relationship_effects" and isinstance(
            nested,
            (list, tuple),
        ):
            result[key] = [
                _redact_event_nested_record(
                    item,
                    sensitive,
                    core_fields=_CLIENT_RELATIONSHIP_EFFECT_CORE_FIELDS,
                    payload_fields=_CLIENT_EVENT_PAYLOAD_FIELDS,
                    sensitive_condition=False,
                )
                for item in nested
            ]
        elif name == "evidence":
            public = _project_evidence_for_client(nested)
            if public is not _DROP_CLIENT_FIELD:
                result[key] = public
        elif name == "provenance":
            public = _project_provenance_for_client(nested)
            if public is not _DROP_CLIENT_FIELD:
                result[key] = public
        elif name == "unknown_fields":
            result[key] = _project_unknown_fields_for_client(nested)
        elif name == "incarnation":
            public = _project_incarnation_for_client(nested)
            if public is not _DROP_CLIENT_FIELD:
                result[key] = public
        elif name in _CLIENT_EVENT_PAYLOAD_FIELDS:
            projected = redact_sensitive_tree({key: nested}, sensitive)
            if key in projected:
                result[key] = projected[key]
    return result


def resource_search_text(
    record: Mapping[str, Any],
    view: Mapping[str, Any],
    descriptor: Mapping[str, Any] | None,
) -> str:
    """Build client-safe search text from declared searchable properties."""

    rules = descriptor_property_rules(descriptor)
    sensitive = {
        name for name, rule in rules.items() if bool(rule.get("sensitive"))
    }
    visible = _client_visible_property_names(descriptor or {})
    visible_key_fields = visible | {
        str(name)
        for name in (
            descriptor.get("key_fields", ())
            if descriptor
            else ()
        )
        if isinstance(name, str)
    }
    values: list[Any] = [
        view.get("resource_id", resource_id(record)),
        view.get("label", record.get("label", "")),
        view.get("kind", record.get("kind", "")),
        view.get("layer", record.get("layer", "")),
        view.get("status", ""),
        view.get("status_class", ""),
        view.get("exists", ""),
    ]
    key = view.get("key") or record.get("key") or {}
    if isinstance(key, Mapping):
        values.extend(
            nested
            for name, nested in key.items()
            if str(name) in visible_key_fields
            and str(name) not in sensitive
        )
    state = view.get("state") or {}
    if rules:
        for name, rule in rules.items():
            if (
                rule.get("sensitive")
                or rule.get("client_visible", True) is False
                or not rule.get("searchable")
            ):
                continue
            if isinstance(state, Mapping) and name in state:
                values.append(state[name])
            elif name in record:
                values.append(record[name])
        for name in (
            descriptor.get("display_name_fields", ())
            if descriptor
            else ()
        ):
            if name in sensitive:
                continue
            if isinstance(state, Mapping) and name in state:
                values.append(state[name])
            elif isinstance(key, Mapping) and name in key:
                values.append(key[name])
    return " ".join(
        json.dumps(value, sort_keys=True, ensure_ascii=False)
        if isinstance(value, (Mapping, list, tuple))
        else str(value)
        for value in values
        if value is not None
    ).casefold()


class NormalizedProviderError(RuntimeError):
    """A plug-in provider failed outside the ordinary ``Exception`` domain."""


def _snapshot_provider_member(
    provider: Any,
    member_name: str,
    *,
    role: str,
) -> Any:
    try:
        member = getattr(provider, member_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - plug-in descriptor boundary.
        raise NormalizedProviderError(
            f"normalized {role} member could not be resolved"
        ) from None
    if not callable(member):
        raise TypeError(f"normalized {role} member must be callable")
    return member


def _invoke_provider(member: Any, operation: str, /, *args: Any, **kwargs: Any) -> Any:
    try:
        return member(*args, **kwargs)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - plug-in callback boundary.
        raise NormalizedProviderError(
            f"normalized provider {operation} failed"
        ) from None


class _ContainedRevisionScope(AbstractContextManager[Any]):
    """Contain a provider context's complete descriptor and call lifecycle."""

    def __init__(self, context: Any) -> None:
        self._enter = _snapshot_provider_member(
            context,
            "__enter__",
            role="revision context entry",
        )
        self._exit = _snapshot_provider_member(
            context,
            "__exit__",
            role="revision context exit",
        )

    def __enter__(self) -> Any:
        return _invoke_provider(self._enter, "revision context entry")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        try:
            result = self._exit(exc_type, exc_value, traceback)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except Exception:
            if exc_value is None:
                raise
            exc_value.add_note("plug-in provider context cleanup failed")
            return False
        except BaseException:  # noqa: BLE001 - plug-in cleanup boundary.
            if exc_value is None:
                raise NormalizedProviderError(
                    "normalized provider revision context exit failed"
                ) from None
            exc_value.add_note("plug-in provider context cleanup failed")
            return False
        # A provider context may release resources but may not suppress a failure
        # raised by core code inside the revision scope.
        return bool(result) if exc_value is None else False


class NormalizedDataService:
    """Core query engine bound to one plug-in source and policy."""

    def __init__(
        self,
        source: NormalizedDatasetSource,
        policy: NormalizedDataPolicy,
    ) -> None:
        if not isinstance(source, NormalizedDatasetSource):
            raise TypeError("normalized source does not implement its contract")
        if not isinstance(policy, NormalizedDataPolicy):
            raise TypeError("normalized policy does not implement its contract")
        self.source = source
        self.policy = policy
        self._source_revision_scope = _snapshot_provider_member(
            source,
            "revision_scope",
            role="source revision scope",
        )
        self._source_load_dataset = _snapshot_provider_member(
            source,
            "load_dataset",
            role="source dataset loader",
        )
        self._source_revision_id = _snapshot_provider_member(
            source,
            "revision_id",
            role="source revision identifier",
        )
        self._source_indexed_history = _snapshot_provider_member(
            source,
            "indexed_history",
            role="source history index",
        )
        self._policy_analysis_metadata = _snapshot_provider_member(
            policy,
            "analysis_metadata",
            role="policy analysis metadata",
        )
        self._policy_workspace_metadata = _snapshot_provider_member(
            policy,
            "workspace_metadata",
            role="policy workspace metadata",
        )
        self._policy_route_resolution_capability = _snapshot_provider_member(
            policy,
            "route_resolution_capability",
            role="policy route capability",
        )
        self._policy_route_row = _snapshot_provider_member(
            policy,
            "route_row",
            role="policy route row",
        )
        self._policy_source_record_for_event = _snapshot_provider_member(
            policy,
            "source_record_for_event",
            role="policy source record",
        )

    def revision_scope(
        self,
        revision_id: str,
    ) -> AbstractContextManager[Any]:
        context = _invoke_provider(
            self._source_revision_scope,
            "revision scope construction",
            revision_id,
        )
        return _ContainedRevisionScope(context)

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        return _invoke_provider(
            self._source_load_dataset,
            "dataset loading",
            revision_id,
            **selection,
        )

    def current_revision_id(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> str:
        return _invoke_provider(
            self._source_revision_id,
            "revision identification",
            dataset or self.load_dataset(),
        )

    def history_runtime(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> IndexedHistory | None:
        return _invoke_provider(
            self._source_indexed_history,
            "history indexing",
            dataset or self.load_dataset(),
        )

    def has_indexed_history(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> bool:
        return self.history_runtime(dataset) is not None

    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return _invoke_provider(
            self._policy_analysis_metadata,
            "analysis metadata projection",
            dataset,
        )

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return dict(
            _invoke_provider(
                self._policy_route_resolution_capability,
                "route capability projection",
                dataset or self.load_dataset()
            )
        )

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return dict(
            _invoke_provider(
                self._policy_route_row,
                "route row projection",
                route_id,
                dataset or self.load_dataset(),
            )
        )

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> dict[str, Any]:
        return dict(
            _invoke_provider(
                self._policy_source_record_for_event,
                "source record projection",
                event,
            )
        )

    def event_redaction_policy(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> EventRedactionPolicy:
        active = dataset or self.load_dataset()
        return event_redaction_policy(
            active,
            self.history_runtime(active),
        )

    def redact_event_for_client(
        self,
        event: Mapping[str, Any],
        dataset: Mapping[str, Any] | None = None,
        *,
        policy: EventRedactionPolicy | None = None,
    ) -> dict[str, Any]:
        active = dataset or self.load_dataset()
        return redact_event_for_client(
            event,
            active,
            runtime=self.history_runtime(active),
            policy=policy,
        )

    @staticmethod
    def redact_resource_for_client(
        record: Mapping[str, Any],
        descriptor: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return redact_resource_for_client(record, descriptor)

    @staticmethod
    def redact_resource_view(
        view: Mapping[str, Any],
        descriptor: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return redact_resource_view(view, descriptor)

    def client_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        """Return the safe bootstrap while keeping plug-in metadata opaque."""

        dataset = self.load_dataset(revision_id, **selection)
        runtime = self.history_runtime(dataset)
        descriptors = {
            str(item.get("kind")): item
            for item in dataset.get("kind_descriptors", [])
            if isinstance(item, Mapping) and item.get("kind")
        }
        resource_records = (
            runtime.resources
            if runtime is not None
            else dataset.get("resources", [])
        )
        for record in resource_records:
            if not isinstance(record, Mapping):
                continue
            self._required_descriptor(
                descriptors,
                str(record.get("kind", "UNKNOWN")),
            )
        _, _, all_sensitive = self.event_redaction_policy(dataset)
        projected_stream_fields = {
            "events",
            "resources",
            "source_records",
            "state_intervals",
        }
        server_windowed_fields = {
            "causal_links",
            "lifecycle_intervals",
            "relationship_intervals",
            "relationship_mutations",
            "relationships",
        }
        client = _client_dataset_envelope(
            dataset,
            set(all_sensitive),
            omit_fields=frozenset(
                projected_stream_fields
                | (server_windowed_fields if runtime is not None else set())
            ),
        )
        if runtime is None:
            client["resources"] = [
                redact_resource_for_client(
                    record,
                    descriptors.get(str(record.get("kind", "UNKNOWN"))),
                )
                for record in dataset.get("resources", [])
                if isinstance(record, Mapping)
            ]
            client["events"] = [
                self.redact_event_for_client(item, dataset)
                for item in dataset.get("events", [])
                if isinstance(item, Mapping)
            ]
            client["state_intervals"] = [
                self.redact_state_interval_for_client(
                    str(item.get("resource", "")),
                    item,
                    dataset,
                )
                for item in dataset.get("state_intervals", [])
                if isinstance(item, Mapping)
            ]
            client["source_records"] = [
                project_source_record_for_log(dict(item))
                for item in dataset.get("source_records", [])
                if isinstance(item, Mapping)
            ]
            history_mode = "embedded-history"
        else:
            client["resources"] = [
                {
                    "resource_id": resource_id(item),
                    "kind": item.get("kind", "UNKNOWN"),
                    "layer": item.get("layer", "unknown"),
                    "label": resource_label(item, resource_id(item)),
                    **(
                        {"presentation_tags": item["presentation_tags"]}
                        if item.get("presentation_tags")
                        else {}
                    ),
                }
                for item in runtime.resources
            ]
            client["events"] = []
            client["source_records"] = []
            client["state_intervals"] = []
            for field in server_windowed_fields:
                client[field] = []
            history_mode = "server-windowed"

        selected_revision = self.current_revision_id(dataset)
        if runtime is not None:
            client["history_transport"] = {
                "mode": history_mode,
                "events": {
                    "server_windowed": True,
                    "total_count": len(runtime.events),
                    "query_endpoint": (
                        f"/v1/revisions/{selected_revision}/event-log/query"
                    ),
                    "detail_endpoint_template": (
                        f"/v1/revisions/{selected_revision}/events/"
                        "{event_uid}"
                    ),
                },
                "source_records": {
                    "server_windowed": True,
                    "total_count": len(dataset.get("source_records", [])),
                    "query_endpoint": (
                        f"/v1/revisions/{selected_revision}/event-log/query"
                    ),
                },
                "density": {
                    "server_windowed": True,
                    "query_endpoint": (
                        f"/v1/revisions/{selected_revision}/events/"
                        "density/query"
                    ),
                },
            }
        client["workspace"] = dict(
            _invoke_provider(
                self._policy_workspace_metadata,
                "workspace metadata projection",
                dataset,
                revision_id=selected_revision,
                history_mode=history_mode,
            )
        )
        client["route_resolution"] = self.route_resolution_capability(dataset)
        return _sanitize_client_presentation(client)

    def _descriptors(
        self,
        dataset: Mapping[str, Any],
    ) -> dict[str, Mapping[str, Any]]:
        return {
            str(item["kind"]): item
            for item in dataset.get("kind_descriptors", [])
            if isinstance(item, Mapping) and item.get("kind")
        }

    @staticmethod
    def _required_descriptor(
        descriptors: Mapping[str, Mapping[str, Any]],
        kind: str,
    ) -> Mapping[str, Any]:
        try:
            return descriptors[kind]
        except KeyError as error:
            raise RuntimeError(
                "normalized evidence lacks a resource descriptor for "
                f"kind {kind!r}"
            ) from error

    def resource_state_at(
        self,
        resource_identifier: str,
        timestamp_ns: int,
    ) -> dict[str, Any]:
        dataset = self.load_dataset()
        runtime = self.history_runtime(dataset)
        if runtime is not None:
            record = runtime.resource_by_id.get(resource_identifier)
            lifecycle = runtime.lifecycle_by_resource.get(
                resource_identifier,
                (),
            )
            states = runtime.state_by_resource.get(resource_identifier, ())
        else:
            record = next(
                (
                    item
                    for item in dataset.get("resources", [])
                    if resource_id(item) == resource_identifier
                ),
                None,
            )
            lifecycle = [
                item
                for item in dataset.get("lifecycle_intervals", [])
                if item.get("resource") == resource_identifier
            ]
            states = [
                item
                for item in dataset.get("state_intervals", [])
                if item.get("resource") == resource_identifier
            ]
        lifecycle_interval = active_interval(lifecycle, timestamp_ns)
        exists = lifecycle_interval is not None
        state_interval = active_interval(states, timestamp_ns)
        state = (
            dict(state_interval.get("properties", {}))
            if state_interval
            else {}
        )
        if not state and record is not None and exists:
            state = dict(record.get("state", {}))
        kind = str(record.get("kind", "UNKNOWN")) if record else "UNKNOWN"
        descriptors = self._descriptors(dataset)
        descriptor = (
            self._required_descriptor(descriptors, kind)
            if record is not None
            else None
        )
        condition_is_sensitive = descriptor_sensitive_condition(descriptor)
        condition = (
            str(descriptor["condition_field"])
            if descriptor and descriptor.get("condition_field")
            and not condition_is_sensitive
            else None
        )
        if not exists:
            status = status_class = "absent"
        else:
            status = (
                (
                    (state_interval or {}).get("status")
                    if not condition_is_sensitive
                    else None
                )
                or (state.get(condition) if condition else None)
                or "unknown"
            )
            status_class = (
                (state_interval or {}).get("status_class")
                or state.get("status_class")
                or "unknown"
            )
            status_class = _safe_status_class(
                status_class,
                exists=exists,
            )
        view = {
            "resource_id": resource_identifier,
            "kind": kind,
            "layer": (
                record.get("layer", "unknown")
                if record
                else "unknown"
            ),
            "label": resource_label(record, resource_identifier),
            "exists": exists,
            "status": status,
            "status_class": status_class,
            "state": state,
            "key": (
                dict(record.get("key", {}))
                if record is not None
                and isinstance(record.get("key", {}), Mapping)
                else {}
            ),
            "valid_from_ns": (
                state_interval.get("valid_from_ns")
                if state_interval
                else None
            ),
            "valid_to_ns": (
                state_interval.get("valid_to_ns")
                if state_interval
                else None
            ),
            "source_event_uid": (
                state_interval.get("start_event_uid")
                if state_interval
                else None
            ),
            "quality": (
                state_interval.get("quality", "unknown")
                if state_interval
                else "unknown"
            ),
            "resource": record,
        }
        return redact_resource_view(view, descriptor)

    def relationships_at(
        self,
        timestamp_ns: int,
    ) -> list[dict[str, Any]]:
        dataset = self.load_dataset()
        runtime = self.history_runtime(dataset)
        if runtime is not None:
            result = []
            for item in runtime.relationships:
                if not contains_time(
                    timestamp_ns,
                    item.get("valid_from_ns"),
                    item.get("valid_to_ns"),
                ):
                    continue
                if active_interval(
                    runtime.lifecycle_by_resource.get(item["source"], ()),
                    timestamp_ns,
                ) is None or active_interval(
                    runtime.lifecycle_by_resource.get(item["target"], ()),
                    timestamp_ns,
                ) is None:
                    continue
                result.append(
                    {
                        **item,
                        "type": item.get(
                            "type",
                            item.get("relation_type", "related_to"),
                        ),
                        "temporal_note": (
                            "selected from indexed validity interval"
                        ),
                    }
                )
            return result

        active_ids = {
            str(item["resource"])
            for item in dataset.get("lifecycle_intervals", [])
            if item.get("resource")
            and contains_time(
                timestamp_ns,
                item.get("valid_from_ns"),
                item.get("valid_to_ns"),
            )
        }
        intervals = dataset.get("relationship_intervals", [])
        interval_keys = {
            (
                item.get("source"),
                item.get("target"),
                item.get("relation_type", item.get("type")),
            )
            for item in intervals
        }
        result: list[dict[str, Any]] = []
        for item in dataset.get("relationships", []):
            if not {item.get("source"), item.get("target")} <= active_ids:
                continue
            key = (
                item.get("source"),
                item.get("target"),
                item.get("type", item.get("relation_type")),
            )
            if key in interval_keys:
                continue
            result.append(
                {
                    **item,
                    "temporal_note": (
                        "capture observation without reconstructed interval"
                    ),
                }
            )
        for interval in intervals:
            if not contains_time(
                timestamp_ns,
                interval.get("valid_from_ns"),
                interval.get("valid_to_ns"),
            ):
                continue
            if not {
                interval.get("source"),
                interval.get("target"),
            } <= active_ids:
                continue
            active = dict(interval)
            active["type"] = active.pop(
                "relation_type",
                active.get("type", "related_to"),
            )
            active["temporal_note"] = "selected from validity interval"
            result.append(active)
        return result

    def redact_state_interval_for_client(
        self,
        resource_identifier: str,
        interval: Mapping[str, Any],
        dataset: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        active = dataset or self.load_dataset()
        runtime = self.history_runtime(active)
        record = (
            runtime.resource_by_id.get(resource_identifier)
            if runtime is not None
            else next(
                (
                    item
                    for item in active.get("resources", [])
                    if resource_id(item) == resource_identifier
                ),
                None,
            )
        )
        kind = str(record.get("kind", "UNKNOWN")) if record else "UNKNOWN"
        descriptor = self._required_descriptor(self._descriptors(active), kind)
        projected = {
            key: nested
            for key, nested in interval.items()
            if str(key) in _CLIENT_STATE_INTERVAL_FIELDS
        }
        _sanitize_resource_metadata(
            projected,
            exists=True,
        )
        projected["properties"] = redact_resource_view(
            {"state": dict(interval.get("properties", {}))},
            descriptor,
        ).get("state", {})
        if descriptor_sensitive_condition(descriptor):
            projected["status"] = "unknown"
            if "condition" in projected:
                projected["condition"] = "unknown"
        if "status_class" in projected:
            projected["status_class"] = _safe_status_class(
                projected["status_class"],
                exists=True,
            )
        if "condition_class" in projected:
            projected["condition_class"] = _safe_status_class(
                projected["condition_class"],
                exists=True,
            )
        return projected

    def _resource_table_view_at(
        self,
        dataset: dict[str, Any],
        timestamp_ns: int,
        view_id: str,
        *,
        search: str | None,
        limit: int | None,
        offset: int,
    ) -> dict[str, Any]:
        descriptors = (
            dataset.get("resource_table_view_descriptors")
            or dataset.get("schema", {}).get("resource_table_views", [])
        )
        descriptor = next(
            (
                item
                for item in descriptors
                if item.get("view_id") == view_id
            ),
            None,
        )
        if descriptor is None:
            raise ValueError(f"unknown resource table view: {view_id}")

        runtime = self.history_runtime(dataset)
        if runtime is not None:
            resource_by_id = runtime.resource_by_id
            root_records = [
                record
                for kind in descriptor.get("root_kinds", [])
                for record in runtime.resources_by_kind.get(kind, [])
            ]
            counts_by_kind = dict(sorted(runtime.resource_counts.items()))

            def endpoint_relationships(
                identifier: str,
            ) -> Iterable[dict[str, Any]]:
                return runtime.relationships_by_endpoint.get(identifier, ())

        else:
            resource_by_id = {
                resource_id(record): record
                for record in dataset.get("resources", [])
            }
            root_kinds = set(descriptor.get("root_kinds", []))
            root_records = [
                record
                for record in dataset.get("resources", [])
                if record.get("kind") in root_kinds
            ]
            counts_by_kind = dict(
                sorted(
                    Counter(
                        record.get("kind", "UNKNOWN")
                        for record in resource_by_id.values()
                    ).items()
                )
            )
            by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for relationship in self.relationships_at(timestamp_ns):
                by_endpoint[str(relationship["source"])].append(relationship)
                if relationship["target"] != relationship["source"]:
                    by_endpoint[str(relationship["target"])].append(
                        relationship
                    )

            def endpoint_relationships(
                identifier: str,
            ) -> Iterable[dict[str, Any]]:
                return by_endpoint.get(identifier, ())

        descriptors_by_kind = self._descriptors(dataset)
        include_absent = bool(descriptor.get("include_absent", False))
        levels = list(descriptor.get("levels", []))
        max_children = max(
            1,
            min(int(descriptor.get("max_children_per_node", 16)), 100),
        )
        traversal_limit = max(
            1,
            min(
                int(
                    descriptor.get(
                        "max_nodes",
                        MAX_RESOURCE_TABLE_TRAVERSAL_NODES,
                    )
                ),
                MAX_RESOURCE_TABLE_TRAVERSAL_NODES,
            ),
        )
        descriptor_limit = max(
            1,
            min(int(descriptor.get("max_roots", 100)), 500),
        )
        safe_limit = max(
            1,
            min(int(limit or descriptor_limit), descriptor_limit),
        )
        safe_offset = max(0, int(offset))
        needle = search.casefold() if search else None
        state_cache: dict[str, dict[str, Any]] = {}
        existence_cache: dict[str, bool] = {}
        neighbor_cache: dict[
            tuple[str, int],
            list[tuple[dict[str, Any], dict[str, Any]]],
        ] = {}

        def temporal_state(identifier: str) -> dict[str, Any]:
            if identifier not in state_cache:
                state_cache[identifier] = self.resource_state_at(
                    identifier,
                    timestamp_ns,
                )
            return state_cache[identifier]

        def exists(identifier: str) -> bool:
            cached = existence_cache.get(identifier)
            if cached is not None:
                return cached
            value = (
                active_interval(
                    runtime.lifecycle_by_resource.get(identifier, ()),
                    timestamp_ns,
                )
                is not None
                if runtime is not None
                else bool(temporal_state(identifier)["exists"])
            )
            existence_cache[identifier] = value
            return value

        def neighbors(
            identifier: str,
            depth: int,
        ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
            cache_key = (identifier, depth)
            if cache_key in neighbor_cache:
                return neighbor_cache[cache_key]
            if depth >= len(levels):
                return []
            level = levels[depth]
            relation_types = set(level.get("relation_types", []))
            target_kinds = set(level.get("target_kinds", []))
            direction = str(level.get("direction", "outgoing"))
            found: list[tuple[dict[str, Any], dict[str, Any]]] = []
            seen: set[tuple[Any, ...]] = set()
            for relationship in endpoint_relationships(identifier):
                relation_type = relationship.get(
                    "relation_type",
                    relationship.get("type", "related_to"),
                )
                if relation_types and relation_type not in relation_types:
                    continue
                if runtime is not None and not contains_time(
                    timestamp_ns,
                    relationship.get("valid_from_ns"),
                    relationship.get("valid_to_ns"),
                ):
                    continue
                candidates: list[str] = []
                if (
                    direction in {"outgoing", "both"}
                    and relationship.get("source") == identifier
                ):
                    candidates.append(str(relationship.get("target")))
                if (
                    direction in {"incoming", "both"}
                    and relationship.get("target") == identifier
                ):
                    candidates.append(str(relationship.get("source")))
                for target_id in candidates:
                    target = resource_by_id.get(target_id)
                    if target is None:
                        continue
                    if target_kinds and target.get("kind") not in target_kinds:
                        continue
                    if not include_absent and not exists(target_id):
                        continue
                    relationship_id = relationship.get("relationship_id")
                    identity = (
                        ("id", str(relationship_id), target_id)
                        if relationship_id is not None
                        else (
                            "structural",
                            str(relation_type),
                            str(relationship.get("source")),
                            str(relationship.get("target")),
                            relationship.get("valid_from_ns"),
                            relationship.get("valid_to_ns"),
                            target_id,
                        )
                    )
                    if identity in seen:
                        continue
                    seen.add(identity)
                    found.append((dict(relationship), target))
            found.sort(
                key=lambda pair: (
                    pair[1].get("kind", "UNKNOWN"),
                    resource_label(pair[1], resource_id(pair[1])),
                    resource_id(pair[1]),
                    str(pair[0].get("relationship_id", "")),
                )
            )
            neighbor_cache[cache_key] = found
            return found

        match_cache: dict[tuple[str, int], bool] = {}
        search_traversal_count = 0
        search_traversal_truncated = False

        def branch_matches(record: dict[str, Any], depth: int) -> bool:
            nonlocal search_traversal_count, search_traversal_truncated
            identifier = resource_id(record)
            cache_key = (identifier, depth)
            if cache_key in match_cache:
                return match_cache[cache_key]
            if needle is not None:
                if search_traversal_count >= traversal_limit:
                    search_traversal_truncated = True
                    match_cache[cache_key] = False
                    return False
                search_traversal_count += 1
            if not include_absent and not exists(identifier):
                match_cache[cache_key] = False
                return False
            matched = needle is None or needle in resource_search_text(
                record,
                temporal_state(identifier),
                descriptors_by_kind.get(
                    str(record.get("kind", "UNKNOWN"))
                ),
            )
            if not matched and depth < len(levels):
                matched = any(
                    branch_matches(target, depth + 1)
                    for _, target in neighbors(identifier, depth)[
                        :max_children
                    ]
                )
            match_cache[cache_key] = matched
            return matched

        occurrence_count = 0
        traversal_truncated = False

        def build_node(
            record: dict[str, Any],
            depth: int,
            relationship: dict[str, Any] | None = None,
        ) -> dict[str, Any] | None:
            nonlocal occurrence_count, traversal_truncated
            if occurrence_count >= traversal_limit:
                traversal_truncated = True
                return None
            identifier = resource_id(record)
            view = temporal_state(identifier)
            if not include_absent and not view["exists"]:
                return None
            occurrence_count += 1
            node: dict[str, Any] = {
                "resource": view,
                "depth": depth,
                "children": [],
                "child_count": 0,
                "truncated_child_count": 0,
            }
            if relationship is not None:
                relation_type = relationship.get(
                    "relation_type",
                    relationship.get("type", "related_to"),
                )
                node["relationship"] = {
                    "relationship_id": relationship.get("relationship_id"),
                    "type": relation_type,
                    "source": relationship.get("source"),
                    "target": relationship.get("target"),
                    "quality": relationship.get("quality", "unknown"),
                    "valid_from_ns": relationship.get("valid_from_ns"),
                    "valid_to_ns": relationship.get("valid_to_ns"),
                }
                node["relation_label"] = levels[depth - 1].get(
                    "label",
                    relation_type,
                )
            if depth < len(levels):
                candidates = neighbors(identifier, depth)
                children: list[dict[str, Any]] = []
                for child_relationship, child_record in candidates[
                    :max_children
                ]:
                    child = build_node(
                        child_record,
                        depth + 1,
                        child_relationship,
                    )
                    if child is not None:
                        children.append(child)
                    if occurrence_count >= traversal_limit:
                        traversal_truncated = True
                        break
                node["child_count"] = len(candidates)
                node["children"] = children
                node["truncated_child_count"] = max(
                    0,
                    len(candidates) - len(children),
                )
                traversal_truncated |= bool(node["truncated_child_count"])
            return node

        root_records.sort(
            key=lambda record: (
                record.get("kind", "UNKNOWN"),
                resource_label(record, resource_id(record)),
                resource_id(record),
            )
        )
        matched_records: list[dict[str, Any]] = []
        matched_count = 0
        for record in root_records:
            if not include_absent and not exists(resource_id(record)):
                continue
            if not branch_matches(record, 0):
                continue
            if safe_offset <= matched_count < safe_offset + safe_limit:
                matched_records.append(record)
            matched_count += 1
        bundles: list[dict[str, Any]] = []
        for record in matched_records:
            node = build_node(record, 0)
            if node is not None:
                bundles.append(node)
            if occurrence_count >= traversal_limit:
                break
        unique_items: dict[str, dict[str, Any]] = {}

        def collect(node: dict[str, Any]) -> None:
            view = node["resource"]
            unique_items[view["resource_id"]] = view
            for child in node["children"]:
                collect(child)

        for bundle in bundles:
            collect(bundle)
        return {
            "revision_id": self.current_revision_id(dataset),
            "time_ns": str(timestamp_ns),
            "view_id": view_id,
            "view": descriptor,
            "bundles": bundles,
            "items": list(unique_items.values()),
            "count": matched_count,
            "matched_count": matched_count,
            "returned_count": len(bundles),
            "returned_node_count": occurrence_count,
            "traversal_node_limit": traversal_limit,
            "traversal_truncated": traversal_truncated,
            "search_traversal_count": search_traversal_count,
            "search_traversal_truncated": search_traversal_truncated,
            "matched_count_exact": not search_traversal_truncated,
            "total_count": len(root_records),
            "counts_by_kind": counts_by_kind,
            "limit": safe_limit,
            "offset": safe_offset,
            "next_offset": (
                safe_offset + len(bundles)
                if safe_offset + len(bundles) < matched_count
                else None
            ),
            "tables": [],
            "windowed": runtime is not None or matched_count > len(bundles),
        }

    def resources_at(
        self,
        timestamp_ns: int,
        *,
        kinds: set[str] | None = None,
        layers: set[str] | None = None,
        search: str | None = None,
        limit: int | None = None,
        offset: int = 0,
        view_id: str | None = None,
    ) -> dict[str, Any]:
        dataset = self.load_dataset()
        if view_id:
            return self._resource_table_view_at(
                dataset,
                timestamp_ns,
                view_id,
                search=search,
                limit=limit,
                offset=offset,
            )
        needle = search.casefold() if search else None
        runtime = self.history_runtime(dataset)
        descriptors = self._descriptors(dataset)
        if runtime is not None:
            safe_offset = max(0, int(offset))
            safe_limit = max(
                1,
                min(int(limit or 500), MAX_RESOURCE_PAGE_SIZE),
            )
            search_documents: Mapping[str, str] | None = None
            if needle:

                def build_search_documents() -> dict[str, str]:
                    return {
                        resource_id(record): resource_search_text(
                            record,
                            self.resource_state_at(
                                resource_id(record),
                                timestamp_ns,
                            ),
                            descriptors.get(
                                str(record.get("kind", "UNKNOWN"))
                            ),
                        )
                        for record in runtime.resources
                    }

                search_documents = runtime.resource_search.get_or_build(
                    timestamp_ns,
                    build_search_documents,
                )
            counts_by_kind: Counter[str] = Counter()
            matched_count = 0
            page_records: list[dict[str, Any]] = []
            for record in runtime.resources:
                kind = str(record.get("kind", "UNKNOWN"))
                layer = str(record.get("layer", "unknown"))
                identifier = resource_id(record)
                if layers and layer not in layers:
                    continue
                if (
                    needle
                    and search_documents is not None
                    and needle not in search_documents.get(identifier, "")
                ):
                    continue
                counts_by_kind[kind] += 1
                if kinds and kind not in kinds:
                    continue
                if safe_offset <= matched_count < safe_offset + safe_limit:
                    page_records.append(record)
                matched_count += 1
            rows = [
                self.resource_state_at(resource_id(record), timestamp_ns)
                for record in page_records
            ]
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                grouped[str(row["kind"])].append(row)
            return {
                "revision_id": self.current_revision_id(dataset),
                "time_ns": str(timestamp_ns),
                "items": rows,
                "count": matched_count,
                "matched_count": matched_count,
                "returned_count": len(rows),
                "total_count": len(runtime.resources),
                "counts_by_kind": dict(sorted(counts_by_kind.items())),
                "limit": safe_limit,
                "offset": safe_offset,
                "next_offset": (
                    safe_offset + len(rows)
                    if safe_offset + len(rows) < matched_count
                    else None
                ),
                "tables": [
                    {
                        "kind": kind,
                        "descriptor": self._required_descriptor(
                            descriptors,
                            kind,
                        ),
                        "count": counts_by_kind[kind],
                        "items": items,
                    }
                    for kind, items in sorted(grouped.items())
                ],
                "windowed": True,
            }

        rows: list[dict[str, Any]] = []
        for record in dataset.get("resources", []):
            kind = str(record.get("kind", "UNKNOWN"))
            layer = str(record.get("layer", "unknown"))
            if kinds and kind not in kinds:
                continue
            if layers and layer not in layers:
                continue
            view = self.resource_state_at(resource_id(record), timestamp_ns)
            if needle and needle not in resource_search_text(
                record,
                view,
                descriptors.get(kind),
            ):
                continue
            rows.append(view)
        rows.sort(
            key=lambda item: (
                item["kind"],
                item["label"],
                item["resource_id"],
            )
        )
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[str(row["kind"])].append(row)
        return {
            "revision_id": self.current_revision_id(dataset),
            "time_ns": str(timestamp_ns),
            "items": rows,
            "count": len(rows),
            "tables": [
                {
                    "kind": kind,
                    "descriptor": self._required_descriptor(
                        descriptors,
                        kind,
                    ),
                    "count": len(items),
                    "items": items,
                }
                for kind, items in sorted(grouped.items())
            ],
        }

    def events_in_range(
        self,
        start_ns: int,
        end_ns: int,
    ) -> list[dict[str, Any]]:
        dataset = self.load_dataset()
        runtime = self.history_runtime(dataset)
        if runtime is not None:
            left = bisect_left(runtime.event_times, start_ns)
            right = bisect_right(runtime.event_times, end_ns)
            return runtime.events[left:right]
        return [
            event
            for event in dataset.get("events", [])
            if start_ns <= int(event["timestamp_ns"]) <= end_ns
        ]

    def dashboard_query(
        self,
        timestamp_ns: int,
        *,
        dashboard_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        dataset = self.load_dataset()
        selected_ids = (
            {str(item) for item in dashboard_ids if str(item)}
            if dashboard_ids is not None
            else None
        )
        schema = dataset.get("schema")
        raw_descriptors = dataset.get("dashboard_descriptors")
        if not raw_descriptors and isinstance(schema, Mapping):
            raw_descriptors = schema.get("dashboards", ())
        if raw_descriptors is None:
            raw_descriptors = ()
        try:
            descriptors = list(
                validate_dashboard_descriptors(raw_descriptors)
            )
        except DashboardDescriptorValidationError as error:
            return {
                "revision_id": self.current_revision_id(dataset),
                "time_ns": str(timestamp_ns),
                "population_count": 0,
                "dashboards": [],
                "descriptor_errors": [error.as_dict()],
            }
        selected = [
            item
            for item in descriptors
            if selected_ids is None
            or str(item["dashboard_id"]) in selected_ids
        ]
        relevant_kinds: set[str] = set()
        unfiltered = False
        for descriptor in selected:
            for widget in (
                *descriptor.get("statistics", []),
                *descriptor.get("tables", []),
            ):
                if not isinstance(widget, Mapping):
                    continue
                if str(widget.get("aggregation", "count")) == "precomputed":
                    continue
                widget_kinds = {
                    str(item) for item in widget.get("resource_kinds", [])
                }
                if widget_kinds:
                    relevant_kinds.update(widget_kinds)
                else:
                    unfiltered = True
        runtime = self.history_runtime(dataset)
        records = (
            runtime.resources
            if runtime is not None
            else dataset.get("resources", [])
        )
        rows: list[dict[str, Any]] = []
        if selected and (relevant_kinds or unfiltered):
            for record in records:
                kind = str(record.get("kind", "UNKNOWN"))
                if not unfiltered and kind not in relevant_kinds:
                    continue
                rows.append(
                    self.resource_state_at(
                        resource_id(record),
                        timestamp_ns,
                    )
                )
        return {
            "revision_id": self.current_revision_id(dataset),
            "time_ns": str(timestamp_ns),
            "population_count": len(rows),
            "dashboards": evaluate_dashboards(
                selected,
                rows,
                dashboard_ids=selected_ids,
            ),
            "descriptor_errors": [],
        }

    def range_summary(
        self,
        start_ns: int,
        end_ns: int,
    ) -> dict[str, Any]:
        dataset = self.load_dataset()
        selected = self.events_in_range(start_ns, end_ns)
        policy = self.event_redaction_policy(dataset)
        projected_selected = [
            self.redact_event_for_client(
                item,
                dataset,
                policy=policy,
            )
            for item in selected
        ]
        all_sensitive = set(policy[2])
        runtime = self.history_runtime(dataset)
        if runtime is not None:
            affected_ids = {
                str(identifier)
                for event in projected_selected
                for identifier in event.get("affected_resources", [])
                if identifier
            }
            mutation_left = bisect_left(runtime.mutation_times, start_ns)
            mutation_right = bisect_right(runtime.mutation_times, end_ns)
            mutations = runtime.mutations[mutation_left:mutation_right]
            for mutation in mutations:
                affected_ids.update(
                    (str(mutation["source"]), str(mutation["target"]))
                )
            descriptors = {
                str(item["relation_type"]): item
                for item in dataset.get("relationship_descriptors", [])
                if isinstance(item, Mapping) and item.get("relation_type")
            }
            affected = sorted(affected_ids)
            endpoint_diff: list[dict[str, Any]] = []
            for identifier in affected[:MAX_RANGE_DETAILS]:
                before = self.resource_state_at(identifier, start_ns)
                after = self.resource_state_at(identifier, end_ns)
                if (
                    before["exists"],
                    before["status"],
                    before["state"],
                ) != (
                    after["exists"],
                    after["status"],
                    after["state"],
                ):
                    endpoint_diff.append(
                        {
                            "resource_id": identifier,
                            "before": before,
                            "after": after,
                        }
                    )
            status_segments: list[dict[str, Any]] = []
            status_truncated = False
            for identifier in affected:
                for interval in runtime.state_by_resource.get(identifier, []):
                    if not overlaps_range(
                        interval.get("valid_from_ns"),
                        interval.get("valid_to_ns"),
                        start_ns,
                        end_ns,
                    ):
                        continue
                    if len(status_segments) >= MAX_RANGE_DETAILS:
                        status_truncated = True
                        break
                    status_segments.append(interval)
                if status_truncated:
                    break
            return {
                "revision_id": self.current_revision_id(dataset),
                "start_ns": str(start_ns),
                "end_ns": str(end_ns),
                "event_count": len(selected),
                "failure_count": sum(
                    item.get("outcome") == "failure"
                    for item in projected_selected
                ),
                "events": projected_selected[:MAX_RANGE_DETAILS],
                "counts": {
                    "by_outcome": dict(
                        Counter(
                            item.get("outcome", "unknown")
                            for item in projected_selected
                        )
                    ),
                    "by_action": dict(
                        Counter(
                            item.get("action", "unknown")
                            for item in projected_selected
                        )
                    ),
                },
                "affected_resource_count": len(affected),
                "affected_resources": affected[:MAX_RANGE_DETAILS],
                "status_segments": [
                    self.redact_state_interval_for_client(
                        str(item.get("resource", "")),
                        item,
                        dataset,
                    )
                    for item in status_segments
                ],
                "endpoint_diff": endpoint_diff[:MAX_RANGE_DETAILS],
                "endpoint_diff_evaluated_count": min(
                    len(affected),
                    MAX_RANGE_DETAILS,
                ),
                "relationship_change_count": len(mutations),
                "relationship_changes": [
                    redact_sensitive_tree(
                        {
                            **item,
                            "event_uid": item.get("cause_event_uid"),
                            "descriptor": descriptors.get(
                                str(item.get("relation_type"))
                            ),
                        },
                        all_sensitive,
                    )
                    for item in mutations[:MAX_RANGE_DETAILS]
                ],
                "truncated": {
                    "events": len(selected) > MAX_RANGE_DETAILS,
                    "affected_resources": (
                        len(affected) > MAX_RANGE_DETAILS
                    ),
                    "status_segments": status_truncated,
                    "endpoint_diff": len(affected) > MAX_RANGE_DETAILS,
                    "relationship_changes": (
                        len(mutations) > MAX_RANGE_DETAILS
                    ),
                },
                "selection_behavior": (
                    "highlight events and status spans; exact counts use the "
                    "full stream while detail arrays are bounded"
                ),
            }

        affected_ids = {
            str(effect["resource_id"])
            for event in projected_selected
            for effect in event.get("effects", [])
            if effect.get("resource_id")
        } | {
            str(subject["resource_id"])
            for event in projected_selected
            for subject in event.get("subjects", [])
            if subject.get("resource_id")
        }
        descriptor_by_type = {
            str(item["relation_type"]): item
            for item in dataset.get("relationship_descriptors", [])
            if isinstance(item, Mapping) and item.get("relation_type")
        }
        relationship_changes: list[dict[str, Any]] = []
        for mutation in dataset.get("relationship_mutations", []):
            if not (
                start_ns
                <= int(mutation["effective_time_ns"])
                <= end_ns
            ):
                continue
            boundary = (
                "valid_from_ns"
                if mutation["operation"] == "add"
                else "valid_to_ns"
            )
            interval = next(
                (
                    item
                    for item in dataset.get("relationship_intervals", [])
                    if item["source"] == mutation["source"]
                    and item["target"] == mutation["target"]
                    and item["relation_type"]
                    == mutation["relation_type"]
                    and item.get(boundary)
                    == mutation["effective_time_ns"]
                ),
                None,
            )
            relationship_changes.append(
                redact_sensitive_tree(
                    {
                        **mutation,
                        "relationship_id": (
                            interval.get("relationship_id")
                            if interval
                            else None
                        ),
                        "event_uid": mutation.get("cause_event_uid"),
                        "descriptor": descriptor_by_type.get(
                            str(mutation["relation_type"])
                        ),
                    },
                    all_sensitive,
                )
            )
            affected_ids.update(
                (str(mutation["source"]), str(mutation["target"]))
            )
        affected = sorted(affected_ids)
        endpoint_diff: list[dict[str, Any]] = []
        for identifier in affected:
            before = self.resource_state_at(identifier, start_ns)
            after = self.resource_state_at(identifier, end_ns)
            if (
                before["exists"],
                before["status"],
                before["state"],
            ) != (
                after["exists"],
                after["status"],
                after["state"],
            ):
                endpoint_diff.append(
                    {
                        "resource_id": identifier,
                        "before": before,
                        "after": after,
                    }
                )
        status_segments = [
            item
            for item in dataset.get("state_intervals", [])
            if item.get("resource") in affected_ids
            and overlaps_range(
                item.get("valid_from_ns"),
                item.get("valid_to_ns"),
                start_ns,
                end_ns,
            )
        ]
        return {
            "revision_id": self.current_revision_id(dataset),
            "start_ns": str(start_ns),
            "end_ns": str(end_ns),
            "event_count": len(selected),
            "failure_count": sum(
                item.get("outcome") == "failure"
                for item in projected_selected
            ),
            "events": projected_selected,
            "counts": {
                "by_outcome": dict(
                    Counter(
                        item.get("outcome", "unknown")
                        for item in projected_selected
                    )
                ),
                "by_action": dict(
                    Counter(
                        item.get("action", "unknown")
                        for item in projected_selected
                    )
                ),
            },
            "affected_resources": affected,
            "status_segments": [
                self.redact_state_interval_for_client(
                    str(item.get("resource", "")),
                    item,
                    dataset,
                )
                for item in status_segments
            ],
            "endpoint_diff": endpoint_diff,
            "relationship_changes": relationship_changes,
            "selection_behavior": (
                "highlight events and status spans; endpoint diff is "
                "supplemental"
            ),
        }


__all__ = [
    "MAX_RESOURCE_TABLE_TRAVERSAL_NODES",
    "EventRedactionPolicy",
    "IndexedHistory",
    "NormalizedDataPolicy",
    "NormalizedDataService",
    "NormalizedDatasetSource",
    "NormalizedProviderError",
    "active_interval",
    "contains_time",
    "descriptor_property_rules",
    "event_redaction_policy",
    "overlaps_range",
    "redact_event_for_client",
    "redact_resource_for_client",
    "redact_resource_view",
    "resource_id",
    "resource_label",
    "resource_search_text",
]
