"""Bounded, read-only analysis of explicitly scoped durable revisions.

This adapter never opens a plug-in, switches the application's runtime, or
projects catalog metadata. Temporal state is the existing normalized engine's
observation reconstruction, not inferred network behavior.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterator, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .annotation_store import ReviewScope
from .control_plane import ControlPlane, DatasetIntegrityError
from .ingestion import IngestedDataPolicy, IngestedDatasetSource
from .normalized_data import (
    IndexedHistory,
    NormalizedDataService,
    event_redaction_policy,
    project_consistency_findings_for_client,
    project_consistency_materialization_for_client,
    redact_event_for_client,
    resource_id,
)
from .revision_store import AssemblyDescriptor, RevisionDescriptor
from .session_store import (
    AnalysisSession,
    RevisionSetSnapshot,
    SessionConflictError,
    SessionMemberDescriptor,
    validate_catalog_identifier,
)
from .temporal_core import relationship_presence
from .value_core import (
    MAX_JSON_SAFE_INTEGER,
    CanonicalIntegerError,
    parse_canonical_decimal_integer,
)

MAX_ANALYSIS_MEMBERS = 128
MAX_ANALYSIS_PAGE_SIZE = 500
MAX_ANALYSIS_RESPONSE_BYTES = 1024 * 1024
_MIN_NS = -(1 << 63)
_MAX_NS = (1 << 63) - 1
_SECTIONS = ("summary", "resources", "events", "relationships", "findings")
_COLLECTIONS = (
    "resources",
    "events",
    "state_intervals",
    "lifecycle_intervals",
    "relationships",
    "relationship_intervals",
    "findings",
)


class ManagementAnalysisRequestError(ValueError):
    """A bounded selector or query is invalid, with safe core-owned detail."""


@dataclass(frozen=True, slots=True)
class ManagementAnalysisQuery:
    selector: Mapping[str, Any]
    selected_revision_id: str | None = None
    selected_member_id: str | None = None
    expected_revision_vector_digest: str | None = None
    section: str = "summary"
    limit: int = 100
    offset: int = 0
    search: str = ""
    time_ns: int | None = None
    start_ns: int | None = None
    end_ns: int | None = None


def _identifier(value: Any) -> str:
    try:
        return validate_catalog_identifier(value, "analysis identifier")
    except (TypeError, ValueError) as error:
        raise ManagementAnalysisRequestError(
            "analysis identifier is invalid"
        ) from error


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            field,
            minimum=minimum,
            maximum=maximum,
        )
    except CanonicalIntegerError as error:
        raise ManagementAnalysisRequestError(
            f"{field} must be a canonical integer in {minimum}..{maximum}"
        ) from error


def parse_management_analysis_query(
    payload: Mapping[str, Any],
) -> ManagementAnalysisQuery:
    """Parse a closed request before accessing the catalog or datasets."""

    allowed = {
        "selector",
        "selected_revision_id",
        "selected_member_id",
        "section",
        "expected_revision_vector_digest",
        "limit",
        "offset",
        "search",
        "time_ns",
        "start_ns",
        "end_ns",
    }
    if not isinstance(payload, Mapping) or set(payload) - allowed:
        raise ManagementAnalysisRequestError(
            "analysis query contains unsupported fields"
        )
    selector = payload.get("selector")
    if not isinstance(selector, dict) or len(selector) != 1:
        raise ManagementAnalysisRequestError(
            "exactly one analysis selector is required"
        )
    if "revision_ids" in selector:
        values = selector["revision_ids"]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_ANALYSIS_MEMBERS:
            raise ManagementAnalysisRequestError(
                "revision_ids requires 1 to 128 values"
            )
        revisions = tuple(_identifier(value) for value in values)
        if len(set(revisions)) != len(revisions):
            raise ManagementAnalysisRequestError("revision_ids must be unique")
        selected_selector: dict[str, Any] = {"revision_ids": revisions}
    elif "session_id" in selector or "snapshot_id" in selector:
        field = next(iter(selector))
        selected_selector = {field: _identifier(selector[field])}
    else:
        raise ManagementAnalysisRequestError("analysis selector is unsupported")
    section = payload.get("section", "summary")
    if type(section) is not str or section not in _SECTIONS:
        raise ManagementAnalysisRequestError("analysis section is unsupported")
    search = payload.get("search", "")
    if type(search) is not str or len(search) > 256 or any(ord(c) < 32 for c in search):
        raise ManagementAnalysisRequestError(
            "search must be at most 256 printable characters"
        )
    times = {
        field: None
        if payload.get(field) is None
        else _integer(
            payload[field],
            field,
            _MIN_NS,
            _MAX_NS,
        )
        for field in ("time_ns", "start_ns", "end_ns")
    }
    if (times["start_ns"] is None) != (times["end_ns"] is None):
        raise ManagementAnalysisRequestError(
            "start_ns and end_ns must be supplied together"
        )
    range_start, range_end = times["start_ns"], times["end_ns"]
    if range_start is not None and range_end is not None and range_end < range_start:
        raise ManagementAnalysisRequestError("end_ns must not precede start_ns")
    if section != "events" and times["start_ns"] is not None:
        raise ManagementAnalysisRequestError("time ranges apply only to events")
    if section == "summary" and search:
        raise ManagementAnalysisRequestError("search does not apply to summary")
    expected_digest = payload.get("expected_revision_vector_digest")
    if expected_digest is not None and (
        type(expected_digest) is not str
        or len(expected_digest) != 71
        or not expected_digest.startswith("sha256:")
        or any(c not in "0123456789abcdef" for c in expected_digest[7:])
    ):
        raise ManagementAnalysisRequestError(
            "expected_revision_vector_digest is invalid"
        )
    return ManagementAnalysisQuery(
        selector=MappingProxyType(selected_selector),
        expected_revision_vector_digest=expected_digest,
        selected_revision_id=(
            None
            if payload.get("selected_revision_id") is None
            else _identifier(payload["selected_revision_id"])
        ),
        selected_member_id=(
            None
            if payload.get("selected_member_id") is None
            else _identifier(payload["selected_member_id"])
        ),
        section=section,
        limit=_integer(payload.get("limit", 100), "limit", 1, MAX_ANALYSIS_PAGE_SIZE),
        offset=_integer(payload.get("offset", 0), "offset", 0, MAX_JSON_SAFE_INTEGER),
        search=search,
        **times,
    )


class _SelectedStore:
    """Request-local, single-revision adapter; no global default changes."""

    def __init__(self, dataset: dict[str, Any], member: dict[str, Any]) -> None:
        self.dataset: dict[str, Any] = dataset
        self.descriptor: RevisionDescriptor = RevisionDescriptor(
            node_id=member["node_id"],
            revision_id=member["revision_id"],
            label=member["node_id"],
            event_count=len(dataset.get("events", [])),
            resource_count=len(dataset.get("resources", [])),
        )

    @property
    def default_revision_id(self) -> str:
        return self.descriptor.revision_id

    @property
    def assembly(self) -> AssemblyDescriptor:
        return AssemblyDescriptor("durable-selected", (self.descriptor,))

    def revision(self, revision_id: str) -> RevisionDescriptor:
        if revision_id != self.descriptor.revision_id:
            raise KeyError(revision_id)
        return self.descriptor

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        if node_id != self.descriptor.node_id:
            raise KeyError(node_id)
        return self.descriptor

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        self.revision(revision_id)
        return self.dataset

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        self.revision_for_node(node_id)
        return self.dataset

    def loaded_revision_ids(self) -> tuple[str, ...]:
        return (self.default_revision_id,)


class _ResourceIndex:
    """Exact observation index used solely by resource_state_at, not inference."""

    def __init__(self, dataset: Mapping[str, Any]) -> None:
        self.resources: list[dict[str, Any]] = dataset.get("resources", [])
        self.resource_by_id: Mapping[str, dict[str, Any]] = {
            resource_id(row): row for row in self.resources
        }
        by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self.resources:
            by_kind[str(row.get("kind", "UNKNOWN"))].append(row)
        self.resources_by_kind: Mapping[str, list[dict[str, Any]]] = by_kind
        self.resource_counts: Mapping[str, int] = {
            key: len(rows) for key, rows in by_kind.items()
        }
        self.lifecycle_by_resource: Mapping[str, list[dict[str, Any]]] = self._group(
            dataset.get("lifecycle_intervals", [])
        )
        self.state_by_resource: Mapping[str, list[dict[str, Any]]] = self._group(
            dataset.get("state_intervals", [])
        )
        self.events: list[dict[str, Any]] = []
        self.event_by_uid: Mapping[str, dict[str, Any]] = {}
        self.event_times: list[int] = []
        self.events_by_resource: Mapping[str, list[dict[str, Any]]] = {}
        self.relationships: list[dict[str, Any]] = []
        self.relationships_by_endpoint: Mapping[str, list[dict[str, Any]]] = {}
        self.mutations: list[dict[str, Any]] = []
        self.mutation_times: list[int] = []
        self.mutations_by_endpoint: Mapping[str, list[dict[str, Any]]] = {}
        self.initial_resource_ids: list[str] = []
        self.event_search: Any = None
        self.resource_search: Any = None
        self.event_redaction_policy: Any = None

    @staticmethod
    def _group(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            groups[str(row.get("resource", ""))].append(row)
        return groups


class _ResourceSource:
    def __init__(self, store: _SelectedStore) -> None:
        self.store: _SelectedStore = store
        self.index: _ResourceIndex = _ResourceIndex(store.dataset)

    def revision_scope(self, revision_id: str) -> Any:
        self.store.revision(revision_id)
        return nullcontext()

    def load_dataset(
        self, revision_id: str | None = None, **selection: Any
    ) -> dict[str, Any]:
        if selection:
            raise KeyError("unsupported selection")
        self.store.revision(revision_id or self.store.default_revision_id)
        return self.store.dataset

    def revision_id(self, dataset: Mapping[str, Any]) -> str:
        return self.store.default_revision_id

    def indexed_history(self, dataset: Mapping[str, Any]) -> IndexedHistory:
        return self.index


def _selection(
    control_plane: ControlPlane,
    scope: ReviewScope,
    query: ManagementAnalysisQuery,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    control_plane.validate_scope(scope.tenant_id, scope.project_id, scope.workspace_id)
    selector = query.selector
    default_member_id = None
    if "revision_ids" in selector:
        members = tuple(
            SessionMemberDescriptor(value, "", value, "")
            for value in selector["revision_ids"]
        )
        selection: dict[str, Any] = {"kind": "revisions"}
    else:
        selected: AnalysisSession | RevisionSetSnapshot
        if "session_id" in selector:
            selected = control_plane.sessions.get_session(
                scope.tenant_id, selector["session_id"]
            )
            selection = {
                "kind": "session",
                "session_id": selected.session_id,
                "version": str(selected.version),
            }
        else:
            selected = control_plane.sessions.get_snapshot(
                scope.tenant_id, selector["snapshot_id"]
            )
            selection = {
                "kind": "snapshot",
                "snapshot_id": selected.snapshot_id,
                "session_id": selected.session_id,
                "version": str(selected.session_version),
            }
        if selected.workspace_id != scope.workspace_id:
            raise KeyError("selected scope")
        members = selected.members
        default_member_id = selected.default_member_id
    if not 1 <= len(members) <= MAX_ANALYSIS_MEMBERS:
        raise ManagementAnalysisRequestError(
            "analysis selection requires 1 to 128 members"
        )
    if len({item.member_id for item in members}) != len(members) or len(
        {item.revision_id for item in members}
    ) != len(members):
        raise ManagementAnalysisRequestError(
            "analysis members and revisions must be unique"
        )
    vector = []
    for member in members:
        descriptor = control_plane.sessions.get_revision(
            scope.tenant_id, member.revision_id
        )
        if descriptor.workspace_id != scope.workspace_id:
            raise KeyError("selected scope")
        if member.fixture_id and (
            member.fixture_id != descriptor.fixture_id
            or member.node_id != descriptor.node_id
        ):
            raise DatasetIntegrityError("stored analysis member binding is invalid")
        vector.append(
            {
                "member_id": member.member_id,
                "fixture_id": descriptor.fixture_id,
                "revision_id": descriptor.revision_id,
                "node_id": descriptor.node_id,
                "role": member.role,
                "identity_digest": descriptor.identity_digest,
            }
        )
    # The default determines selection when a caller has not chosen a member;
    # bind it too so a continuation cannot silently switch the inspected node.
    digest = hashlib.sha256(
        json.dumps(
            {"members": vector, "default_member_id": default_member_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    selection["revision_vector_digest"] = f"sha256:{digest}"
    if (
        query.expected_revision_vector_digest is not None
        and query.expected_revision_vector_digest != selection["revision_vector_digest"]
    ):
        raise SessionConflictError(
            "analysis revision vector changed; refresh the selection"
        )
    candidates = [
        row
        for row in vector
        if (
            (
                query.selected_member_id is None
                or row["member_id"] == query.selected_member_id
            )
            and (
                query.selected_revision_id is None
                or row["revision_id"] == query.selected_revision_id
            )
        )
    ]
    if not candidates:
        raise ManagementAnalysisRequestError(
            "selected member is not in the analysis selection"
        )
    if query.selected_member_id is None and query.selected_revision_id is None:
        chosen = next(
            (row for row in candidates if row["member_id"] == default_member_id),
            candidates[0],
        )
    else:
        chosen = candidates[0]
    return selection, vector, chosen


def _stored_ns(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return parse_canonical_decimal_integer(
            value, "stored timestamp", minimum=_MIN_NS, maximum=_MAX_NS
        )
    except CanonicalIntegerError as error:
        raise DatasetIntegrityError("stored analysis timestamp is invalid") from error


def _public_row(row: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Closed scalar envelope: never copy snapshot metadata/evidence locators."""

    projected = {
        key: row[key]
        for key in fields
        if key in row
        and (row[key] is None or type(row[key]) in {str, int, float, bool})
    }
    for key in (
        "timestamp_ns",
        "timestamp_uncertainty_ns",
        "valid_from_ns",
        "valid_to_ns",
    ):
        if key in projected and projected[key] is not None:
            projected[key] = str(_stored_ns(projected[key]))
    return projected


def _section_rows(
    dataset: dict[str, Any],
    member: dict[str, Any],
    query: ManagementAnalysisQuery,
    time_ns: int,
) -> Iterator[dict[str, Any] | None]:
    store = _SelectedStore(dataset, member)
    if query.section == "resources":
        service = NormalizedDataService(
            _ResourceSource(store), IngestedDataPolicy(store)
        )
        for index, record in enumerate(dataset.get("resources", [])):
            if (
                not query.search
                and not query.offset <= index < query.offset + query.limit
            ):
                yield None
                continue
            view = service.resource_state_at(resource_id(record), time_ns)
            row = _public_row(
                view,
                (
                    "resource_id",
                    "kind",
                    "layer",
                    "label",
                    "exists",
                    "status",
                    "status_class",
                    "quality",
                    "valid_from_ns",
                    "valid_to_ns",
                    "source_event_uid",
                ),
            )
            row["state"] = view.get("state", {})
            row["key"] = view.get("key", {})
            # Unknown reasons remain visible, but not arbitrary messages or locators.
            row["unknown_fields"] = [
                _public_row(item, ("name", "reason_code"))
                for item in view.get("unknown_fields", [])
                if isinstance(item, Mapping)
            ]
            yield row
    elif query.section == "events":
        policy = None
        matched_index = 0
        for event in dataset.get("events", []):
            if query.start_ns is not None:
                assert query.end_ns is not None
                timestamp = _stored_ns(event.get("timestamp_ns"))
                if timestamp is None or not query.start_ns <= timestamp <= query.end_ns:
                    continue
            index = matched_index
            matched_index += 1
            if (
                not query.search
                and not query.offset <= index < query.offset + query.limit
            ):
                yield None
                continue
            timestamp = _stored_ns(event.get("timestamp_ns"))
            if policy is None:
                policy = event_redaction_policy(dataset)
            projected = redact_event_for_client(event, dataset, policy=policy)
            row = _public_row(
                projected,
                (
                    "event_uid",
                    "event_id",
                    "event_type",
                    "event_name",
                    "timestamp_ns",
                    "timestamp_uncertainty_ns",
                    "action",
                    "outcome",
                    "quality",
                    "layer",
                    "status",
                    "status_class",
                    "condition",
                    "condition_class",
                    "provenance",
                ),
            )
            row["timestamp_ns"] = str(timestamp) if timestamp is not None else None
            row["subjects"] = [
                _public_row(
                    item, ("resource_id", "canonical_resource_id", "kind", "layer")
                )
                for item in projected.get("subjects", [])
                if isinstance(item, Mapping)
            ]
            yield row
    elif query.section == "relationships":
        # The embedded-history path already enforces lifecycle and interval
        # precedence; do not replace it with inferred topology or route edges.
        service = NormalizedDataService(
            IngestedDatasetSource(store), IngestedDataPolicy(store)
        )
        for index, relationship in enumerate(service.relationships_at(time_ns)):
            if (
                not query.search
                and not query.offset <= index < query.offset + query.limit
            ):
                yield None
                continue
            row = _public_row(
                relationship,
                (
                    "relationship_id",
                    "source",
                    "target",
                    "type",
                    "relation_type",
                    "valid_from_ns",
                    "valid_to_ns",
                    "quality",
                    "provenance",
                    "temporal_note",
                ),
            )
            # Unknown presence is an observation, not a confirmed active edge.
            # Legacy records without this field retain their normalized meaning.
            row["present"] = relationship_presence(relationship)
            yield row
    elif query.section == "findings":
        for index, finding in enumerate(dataset.get("findings", [])):
            if (
                not query.search
                and not query.offset <= index < query.offset + query.limit
            ):
                yield None
                continue
            projected = project_consistency_findings_for_client(dataset, [finding])[0]
            yield projected


def query_management_analysis(
    control_plane: ControlPlane,
    scope: ReviewScope,
    query: ManagementAnalysisQuery,
) -> dict[str, Any]:
    """Return one bounded client-safe page, independent of any active runtime."""

    # Revalidate detached contract objects as well as HTTP parser results;
    # a direct in-process caller must not bypass the same bounded contract.
    if type(query) is not ManagementAnalysisQuery:
        raise ManagementAnalysisRequestError("analysis query type is invalid")
    selector = dict(query.selector)
    if isinstance(selector.get("revision_ids"), tuple):
        selector["revision_ids"] = list(selector["revision_ids"])
    query = parse_management_analysis_query(
        {
            "selector": selector,
            "selected_revision_id": query.selected_revision_id,
            "selected_member_id": query.selected_member_id,
            "expected_revision_vector_digest": query.expected_revision_vector_digest,
            "section": query.section,
            "search": query.search,
            "limit": query.limit,
            "offset": query.offset,
            "time_ns": query.time_ns,
            "start_ns": query.start_ns,
            "end_ns": query.end_ns,
        }
    )
    selection, vector, member = _selection(control_plane, scope, query)
    dataset = control_plane.load_revision_dataset(scope, member["revision_id"])
    for field in _COLLECTIONS:
        collection = dataset.get(field, [])
        if not isinstance(collection, list) or any(
            not isinstance(row, dict) for row in collection
        ):
            raise DatasetIntegrityError("stored analysis collection is invalid")
    ingestion = dataset.get("_ingestion", {})
    timeline_start = _stored_ns(ingestion.get("timeline_start_ns"))
    timeline_end = _stored_ns(ingestion.get("timeline_end_ns"))
    if timeline_start is None or timeline_end is None:
        times = [
            timestamp
            for event in dataset.get("events", [])
            if (timestamp := _stored_ns(event.get("timestamp_ns"))) is not None
        ]
        timeline_start = (
            min(times, default=0) if timeline_start is None else timeline_start
        )
        timeline_end = (
            max(times, default=timeline_start) if timeline_end is None else timeline_end
        )
    time_ns = timeline_end if query.time_ns is None else query.time_ns
    if query.section == "summary":
        rows: Iterator[dict[str, Any] | None] = iter(
            [
                {
                    "resource_count": len(dataset.get("resources", [])),
                    "event_count": len(dataset.get("events", [])),
                    "relationship_count": len(dataset.get("relationships", [])),
                    "relationship_interval_count": len(
                        dataset.get("relationship_intervals", [])
                    ),
                    "finding_count": len(dataset.get("findings", [])),
                    "consistency_materialization": project_consistency_materialization_for_client(
                        dataset.get(
                            "consistency_materialization", {"state": "not_materialized"}
                        ),
                    ),
                }
            ]
        )
    else:
        rows = _section_rows(dataset, member, query, time_ns)
    page: list[dict[str, Any]] = []
    page_bytes = 0
    total = 0
    needle = query.search.casefold()
    for row in rows:
        if row is None:
            total += 1
            continue
        if (
            needle
            and needle
            not in json.dumps(row, ensure_ascii=False, sort_keys=True).casefold()
        ):
            continue
        if query.offset <= total < query.offset + query.limit:
            page_bytes += len(
                json.dumps(row, ensure_ascii=False, allow_nan=False).encode("utf-8")
            )
            if page_bytes > MAX_ANALYSIS_RESPONSE_BYTES:
                raise ManagementAnalysisRequestError(
                    "analysis page exceeds the 1 MiB response limit; request fewer rows"
                )
            page.append(row)
        total += 1
    result = {
        "scope": {
            "tenant_id": scope.tenant_id,
            "project_id": scope.project_id,
            "workspace_id": scope.workspace_id,
        },
        "selection": selection,
        "revision_vector": vector,
        "selected_member": member,
        "section": query.section,
        "time_ns": str(time_ns),
        "timeline": {
            "start_ns": str(timeline_start),
            "end_ns": str(timeline_end),
            "time_basis": ingestion.get("timeline_time_basis")
            if ingestion.get("timeline_time_basis")
            in {"absolute_unix_ns", "revision_start_relative_ns"}
            else None,
        },
        "capabilities": {
            "sections": list(_SECTIONS),
            "route": {
                "available": False,
                "reason": "Durable inspection does not execute route providers.",
            },
            "topology": {
                "available": False,
                "reason": "Relationships are observations, not an inferred network topology.",
            },
        },
        "items": page,
        "total_count": total,
        "count": len(page),
        "limit": query.limit,
        "offset": query.offset,
        "next_offset": query.offset + len(page)
        if query.offset + len(page) < total
        else None,
    }
    if (
        len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        > MAX_ANALYSIS_RESPONSE_BYTES
    ):
        raise ManagementAnalysisRequestError(
            "analysis page exceeds the 1 MiB response limit; request fewer rows"
        )
    return result


__all__ = [
    "ManagementAnalysisQuery",
    "ManagementAnalysisRequestError",
    "parse_management_analysis_query",
    "query_management_analysis",
]
