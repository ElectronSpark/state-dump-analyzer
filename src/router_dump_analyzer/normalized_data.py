"""Core-owned services over one plug-in-supplied normalized dataset.

The core applies the common temporal envelope, descriptor-driven redaction,
resource-table traversal, dashboard evaluation, and bounded range algorithms.
Plug-ins remain responsible for loading an input, interpreting device evidence,
and supplying presentation/route/source-record policy.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from contextlib import AbstractContextManager
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from .dashboard_core import evaluate_dashboards
from .source_record_core import project_source_record_for_log


MAX_RESOURCE_TABLE_TRAVERSAL_NODES = 5_000
MAX_RESOURCE_PAGE_SIZE = 1_000
MAX_RANGE_DETAILS = 500


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


def _without_sensitive_fields(
    value: Any,
    sensitive_fields: set[str],
) -> Any:
    if not isinstance(value, Mapping) or not sensitive_fields:
        return value
    return {
        key: nested
        for key, nested in value.items()
        if str(key) not in sensitive_fields
    }


def redact_sensitive_tree(value: Any, sensitive_fields: set[str]) -> Any:
    """Remove declared sensitive names at every plug-in payload depth."""

    if isinstance(value, Mapping):
        return {
            key: redact_sensitive_tree(nested, sensitive_fields)
            for key, nested in value.items()
            if str(key) not in sensitive_fields
        }
    if isinstance(value, list):
        return [
            redact_sensitive_tree(nested, sensitive_fields)
            for nested in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_sensitive_tree(nested, sensitive_fields)
            for nested in value
        )
    return value


def redact_resource_view(
    view: Mapping[str, Any],
    descriptor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    rules = descriptor_property_rules(descriptor)
    sensitive = {
        name for name, rule in rules.items() if bool(rule.get("sensitive"))
    }
    projected = dict(view)
    if not sensitive:
        return projected
    projected["state"] = _without_sensitive_fields(
        projected.get("state", {}),
        sensitive,
    )
    projected["key"] = _without_sensitive_fields(
        projected.get("key", {}),
        sensitive,
    )
    record = projected.get("resource")
    if isinstance(record, Mapping):
        safe_record = {
            key: nested
            for key, nested in record.items()
            if str(key) not in sensitive
        }
        safe_record["state"] = _without_sensitive_fields(
            record.get("state", {}),
            sensitive,
        )
        safe_record["key"] = _without_sensitive_fields(
            record.get("key", {}),
            sensitive,
        )
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
) -> set[str]:
    kinds: set[str] = set()
    identifiers: set[str] = set()

    def collect(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        for field in ("resource_kind", "kind"):
            if value.get(field):
                kinds.add(str(value[field]))
        for field in ("resource_id", "resource"):
            if value.get(field):
                identifiers.add(str(value[field]))

    collect(event)
    collect(event.get("subject"))
    for subject in event.get("subjects", []):
        collect(subject)
    for effect in event.get("effects", []):
        collect(effect)
    kinds.update(
        kind_by_resource_id[identifier]
        for identifier in identifiers
        if identifier in kind_by_resource_id
    )
    return kinds


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
    if not all_sensitive:
        return dict(event)
    kinds = _event_resource_kinds(event, kind_by_id)
    sensitive: set[str] = set()
    for kind in kinds:
        sensitive.update(sensitive_by_kind.get(kind, ()))
    if not kinds or any(kind not in sensitive_by_kind for kind in kinds):
        sensitive.update(all_sensitive)
    return (
        redact_sensitive_tree(event, sensitive)
        if sensitive
        else dict(event)
    )


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
            if str(name) not in sensitive
        )
    state = view.get("state") or {}
    if rules:
        for name, rule in rules.items():
            if rule.get("sensitive") or not rule.get("searchable"):
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
    else:
        values.append(state)
    return " ".join(
        json.dumps(value, sort_keys=True, ensure_ascii=False)
        if isinstance(value, (Mapping, list, tuple))
        else str(value)
        for value in values
        if value is not None
    ).casefold()


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

    def revision_scope(
        self,
        revision_id: str,
    ) -> AbstractContextManager[Any]:
        return self.source.revision_scope(revision_id)

    def load_dataset(
        self,
        revision_id: str | None = None,
        **selection: Any,
    ) -> dict[str, Any]:
        return self.source.load_dataset(revision_id, **selection)

    def current_revision_id(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> str:
        return self.source.revision_id(dataset or self.load_dataset())

    def history_runtime(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> IndexedHistory | None:
        return self.source.indexed_history(dataset or self.load_dataset())

    def has_indexed_history(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> bool:
        return self.history_runtime(dataset) is not None

    def analysis_metadata(
        self,
        dataset: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self.policy.analysis_metadata(dataset)

    def route_resolution_capability(
        self,
        dataset: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return dict(
            self.policy.route_resolution_capability(
                dataset or self.load_dataset()
            )
        )

    def route_row(
        self,
        route_id: str,
        dataset: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return dict(
            self.policy.route_row(route_id, dataset or self.load_dataset())
        )

    def source_record_for_event(
        self,
        event: Mapping[str, Any],
    ) -> dict[str, Any]:
        return dict(self.policy.source_record_for_event(event))

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
        if runtime is None:
            client = {
                key: value
                for key, value in dataset.items()
                if not str(key).startswith("_")
            }
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
            client["source_records"] = [
                project_source_record_for_log(dict(item))
                for item in dataset.get("source_records", [])
                if isinstance(item, Mapping)
            ]
            history_mode = "embedded-history"
        else:
            client = {
                key: value
                for key, value in dataset.items()
                if not str(key).startswith("_")
            }
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
            self.policy.workspace_metadata(
                dataset,
                revision_id=selected_revision,
                history_mode=history_mode,
            )
        )
        client["route_resolution"] = self.route_resolution_capability(dataset)
        return client

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
        condition = (
            str(descriptor["condition_field"])
            if descriptor and descriptor.get("condition_field")
            else None
        )
        if not exists:
            status = status_class = "absent"
        else:
            status = (
                (state_interval or {}).get("status")
                or (state.get(condition) if condition else None)
                or "unknown"
            )
            status_class = (
                (state_interval or {}).get("status_class")
                or state.get("status_class")
                or "unknown"
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
        descriptor = self._descriptors(active).get(kind)
        projected = dict(interval)
        projected["properties"] = redact_resource_view(
            {"state": dict(interval.get("properties", {}))},
            descriptor,
        ).get("state", {})
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
        descriptors = [
            item
            for item in (
                dataset.get("dashboard_descriptors")
                or dataset.get("schema", {}).get("dashboards", [])
            )
            if isinstance(item, Mapping) and item.get("dashboard_id")
        ]
        selected_ids = (
            {str(item) for item in dashboard_ids if str(item)}
            if dashboard_ids is not None
            else None
        )
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
        }

    def range_summary(
        self,
        start_ns: int,
        end_ns: int,
    ) -> dict[str, Any]:
        dataset = self.load_dataset()
        selected = self.events_in_range(start_ns, end_ns)
        runtime = self.history_runtime(dataset)
        if runtime is not None:
            affected_ids = {
                str(identifier)
                for event in selected
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
                    for item in selected
                ),
                "events": [
                    self.redact_event_for_client(item, dataset)
                    for item in selected[:MAX_RANGE_DETAILS]
                ],
                "counts": {
                    "by_outcome": dict(
                        Counter(
                            item.get("outcome", "unknown")
                            for item in selected
                        )
                    ),
                    "by_action": dict(
                        Counter(
                            item.get("action", "unknown")
                            for item in selected
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
                    {
                        **item,
                        "event_uid": item.get("cause_event_uid"),
                        "descriptor": descriptors.get(
                            str(item.get("relation_type"))
                        ),
                    }
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
            for event in selected
            for effect in event.get("effects", [])
            if effect.get("resource_id")
        } | {
            str(subject["resource_id"])
            for event in selected
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
                }
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
            "events": [
                self.redact_event_for_client(item, dataset)
                for item in selected
            ],
            "counts": {
                "by_outcome": dict(
                    Counter(
                        item.get("outcome", "unknown")
                        for item in selected
                    )
                ),
                "by_action": dict(
                    Counter(
                        item.get("action", "unknown")
                        for item in selected
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
    "EventRedactionPolicy",
    "IndexedHistory",
    "MAX_RESOURCE_TABLE_TRAVERSAL_NODES",
    "NormalizedDataPolicy",
    "NormalizedDataService",
    "NormalizedDatasetSource",
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
