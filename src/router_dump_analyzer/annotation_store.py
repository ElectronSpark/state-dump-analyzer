"""Core-owned mutable review annotations over immutable analysis revisions.

The analyzer's normalized revisions remain immutable.  This module provides a
separate, tenant/project/workspace-scoped overlay for human review markers and
manual event correlations.  It deliberately has no dependency on a plug-in,
the web application, or a concrete revision repository:

* callers validate that revision-qualified subjects are visible in the
  workspace before writing them;
* this store validates shape, bounds, optimistic concurrency, idempotency, and
  scope isolation;
* report callers supply already-authorized, client-safe event/source
  projections and generic corroboration facts.

SQLite is the local durable implementation.  Every mutation uses one
thread-safe ``BEGIN IMMEDIATE`` transaction, foreign keys are enabled, and
file-backed databases use WAL mode.  Deletion creates a tombstone and an
append-only audit entry; rows are never physically removed through this API.
"""

from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any, Self
from uuid import uuid4

from .canonical import (
    CanonicalValueError,
    strict_canonical_json,
    strict_canonical_json_sha256,
)
from .corroboration import CorroborationOutcome
from .public_text import escape_unsafe_display_text
from .value_core import parse_canonical_decimal_integer

MAX_SCOPE_ID_LENGTH = 256
MAX_IDENTIFIER_LENGTH = 1_024
MAX_AUTHOR_LENGTH = 512
MAX_TITLE_LENGTH = 512
MAX_BODY_LENGTH = 65_536
MAX_RATIONALE_LENGTH = 65_536
MAX_TAG_LENGTH = 128
MAX_TAGS = 64
MAX_ANNOTATION_SUBJECTS = 5_000
MAX_CORRELATION_SUBJECTS = 1_024
MAX_CORRELATION_EDGES = 4_096
MAX_LINK_TYPE_LENGTH = 256
MAX_IDEMPOTENCY_KEY_LENGTH = 512
MAX_LIST_LIMIT = 5_000
MAX_REPORT_ITEMS_PER_COLLECTION = 10_000
MAX_REPORT_JSON_DEPTH = 16
MAX_REPORT_JSON_CONTAINER_ITEMS = 20_000
MAX_REPORT_JSON_STRING_LENGTH = 1_048_576
MAX_REPORT_JSON_UNITS = 500_000
MAX_REPORT_JSON_INTEGER_BITS = 4_096
MAX_SQLITE_INTEGER = (1 << 63) - 1
MAX_RETENTION_CANDIDATES = 5_000
MAX_REFERENCE_REVISION_IDS = 100_000
CORRELATION_REPORT_SCHEMA_VERSION = "router_dump_analyzer.correlation_report.v2"
_BIDI_CONTROL_CHARACTERS = frozenset(
    chr(codepoint)
    for codepoint in (
        0x061C,
        0x200E,
        0x200F,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    )
)


class ReviewOverlayError(RuntimeError):
    """Base error raised by the review overlay."""


class ReviewValidationError(ValueError, ReviewOverlayError):
    """A review record or report value violates the bounded contract."""


class CorrelationReportProvenanceClass(StrEnum):
    """Core-declared origin classes kept separate in correlation reports."""

    PLUGIN_INFERRED = "plugin_inferred"
    USER_ASSERTED = "user_asserted"
    CORE_CORROBORATION = "core_corroboration"


class ReviewConflictError(ReviewOverlayError):
    """Optimistic concurrency or identity conflicts with stored state."""


class ReviewIdempotencyConflictError(ReviewConflictError):
    """An idempotency key was reused for a different request."""


class ReviewRetentionDisabledError(ReviewOverlayError):
    """A destructive retention request did not explicitly opt in."""


class ReviewSubjectKind(StrEnum):
    EVENT = "event"
    SOURCE_RECORD = "source_record"
    RESOURCE = "resource"
    RELATIONSHIP = "relationship"
    TIME_RANGE = "time_range"


class ReviewAnnotationKind(StrEnum):
    MARKER = "marker"
    NOTE = "note"
    TAG = "tag"


class ReviewAuditRetentionMode(StrEnum):
    """Whether compliance policy permits physical audit-history pruning."""

    PRESERVE = "preserve"
    PRUNE_EXPLICIT = "prune_explicit"


# Compatibility alias for the original annotation-store export.  Report
# validation and core corroboration now share one closed result vocabulary.
CorroborationResult = CorroborationOutcome


def _bounded_text(
    value: Any,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = False,
    allow_line_breaks: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ReviewValidationError(f"{label} must be a string")
    if not allow_empty and not value:
        raise ReviewValidationError(f"{label} must be non-empty")
    if len(value) > maximum:
        raise ReviewValidationError(
            f"{label} must contain at most {maximum} characters"
        )
    permitted_controls = "\t\n\r" if allow_line_breaks else ""
    if any(
        (ord(character) < 32 and character not in permitted_controls)
        or ord(character) == 127
        for character in value
    ):
        raise ReviewValidationError(f"{label} must not contain control characters")
    if any(character in _BIDI_CONTROL_CHARACTERS for character in value):
        raise ReviewValidationError(
            f"{label} must not contain bidirectional formatting controls"
        )
    return value


def _exact_non_negative_int(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
        raise ReviewValidationError(f"{label} must be a non-negative integer")
    return value


def _exact_positive_int(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SQLITE_INTEGER:
        raise ReviewValidationError(f"{label} must be a positive integer")
    return value


def _normalize_tags(tags: Iterable[str]) -> tuple[str, ...]:
    if isinstance(tags, (str, bytes)) or not isinstance(tags, Iterable):
        raise ReviewValidationError("tags must be an iterable of strings")
    materialized = tuple(_bounded_text(tag, "tag", MAX_TAG_LENGTH) for tag in tags)
    if len(materialized) > MAX_TAGS:
        raise ReviewValidationError(f"at most {MAX_TAGS} tags are supported")
    if len(set(materialized)) != len(materialized):
        raise ReviewValidationError("tags must not contain duplicates")
    return tuple(sorted(materialized))


@dataclass(frozen=True, slots=True)
class ReviewScope:
    tenant_id: str
    project_id: str
    workspace_id: str

    def __post_init__(self) -> None:
        for label, value in (
            ("tenant_id", self.tenant_id),
            ("project_id", self.project_id),
            ("workspace_id", self.workspace_id),
        ):
            _bounded_text(value, label, MAX_SCOPE_ID_LENGTH)

    def to_dict(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
        }


@dataclass(frozen=True, slots=True)
class ReviewSubject:
    """One exact immutable-revision subject of a mutable review record."""

    revision_id: str
    kind: ReviewSubjectKind
    subject_id: str | None = None
    node_id: str | None = None
    start_ns: int | None = None
    end_ns: int | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.revision_id, "revision_id", MAX_IDENTIFIER_LENGTH)
        try:
            normalized_kind = ReviewSubjectKind(self.kind)
        except (TypeError, ValueError) as error:
            raise ReviewValidationError("unsupported review subject kind") from error
        object.__setattr__(self, "kind", normalized_kind)
        if self.node_id is not None:
            _bounded_text(self.node_id, "node_id", MAX_IDENTIFIER_LENGTH)
        if normalized_kind is ReviewSubjectKind.TIME_RANGE:
            if self.subject_id is not None:
                raise ReviewValidationError(
                    "time_range subjects must not contain subject_id"
                )
            start = _exact_non_negative_int(self.start_ns, "start_ns")
            end = _exact_non_negative_int(self.end_ns, "end_ns")
            if end < start:
                raise ReviewValidationError("time_range end_ns precedes start_ns")
        else:
            if self.start_ns is not None or self.end_ns is not None:
                raise ReviewValidationError(
                    f"{normalized_kind.value} subjects must not contain time bounds"
                )
            _bounded_text(
                self.subject_id,
                "subject_id",
                MAX_IDENTIFIER_LENGTH,
            )

    def identity_key(self) -> tuple[Any, ...]:
        return (
            self.revision_id,
            self.node_id,
            self.kind.value,
            self.subject_id,
            self.start_ns,
            self.end_ns,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "revision_id": self.revision_id,
            "kind": self.kind.value,
        }
        if self.node_id is not None:
            result["node_id"] = self.node_id
        if self.kind is ReviewSubjectKind.TIME_RANGE:
            result["start_ns"] = self.start_ns
            result["end_ns"] = self.end_ns
        else:
            result["subject_id"] = self.subject_id
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReviewSubject:
        if not isinstance(value, Mapping):
            raise ReviewValidationError("review subject must be an object")
        return cls(
            revision_id=value.get("revision_id"),  # type: ignore[arg-type]
            kind=value.get("kind"),  # type: ignore[arg-type]
            subject_id=value.get("subject_id"),  # type: ignore[arg-type]
            node_id=value.get("node_id"),  # type: ignore[arg-type]
            start_ns=value.get("start_ns"),  # type: ignore[arg-type]
            end_ns=value.get("end_ns"),  # type: ignore[arg-type]
        )


def _normalize_subjects(
    subjects: Iterable[ReviewSubject],
    *,
    maximum: int,
    event_only: bool = False,
) -> tuple[ReviewSubject, ...]:
    if isinstance(subjects, (str, bytes)) or not isinstance(subjects, Iterable):
        raise ReviewValidationError("subjects must be an iterable")
    materialized = tuple(subjects)
    if not 1 <= len(materialized) <= maximum:
        raise ReviewValidationError(
            f"subjects must contain between 1 and {maximum} items"
        )
    if any(type(subject) is not ReviewSubject for subject in materialized):
        raise ReviewValidationError("subjects must contain exact ReviewSubject values")
    if event_only and any(
        subject.kind is not ReviewSubjectKind.EVENT for subject in materialized
    ):
        raise ReviewValidationError(
            "manual event correlations may reference only event subjects"
        )
    identities = [subject.identity_key() for subject in materialized]
    if len(identities) != len(set(identities)):
        raise ReviewValidationError("subjects must not contain duplicates")
    return materialized


@dataclass(frozen=True, slots=True)
class ReviewAnnotation:
    annotation_id: str
    scope: ReviewScope
    kind: ReviewAnnotationKind
    subjects: tuple[ReviewSubject, ...]
    author: str
    title: str = ""
    body: str = ""
    tags: tuple[str, ...] = ()
    version: int = 1
    created_at_ns: int = 0
    updated_at_ns: int = 0
    deleted_at_ns: int | None = None

    def __post_init__(self) -> None:
        _bounded_text(
            self.annotation_id,
            "annotation_id",
            MAX_IDENTIFIER_LENGTH,
        )
        if type(self.scope) is not ReviewScope:
            raise ReviewValidationError("scope must be an exact ReviewScope")
        try:
            normalized_kind = ReviewAnnotationKind(self.kind)
        except (TypeError, ValueError) as error:
            raise ReviewValidationError("unsupported review annotation kind") from error
        object.__setattr__(self, "kind", normalized_kind)
        object.__setattr__(
            self,
            "subjects",
            _normalize_subjects(
                self.subjects,
                maximum=MAX_ANNOTATION_SUBJECTS,
            ),
        )
        _bounded_text(self.author, "author", MAX_AUTHOR_LENGTH)
        _bounded_text(
            self.title,
            "title",
            MAX_TITLE_LENGTH,
            allow_empty=True,
        )
        _bounded_text(
            self.body,
            "body",
            MAX_BODY_LENGTH,
            allow_empty=True,
            allow_line_breaks=True,
        )
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        _exact_positive_int(self.version, "version")
        _exact_non_negative_int(self.created_at_ns, "created_at_ns")
        _exact_non_negative_int(self.updated_at_ns, "updated_at_ns")
        if self.updated_at_ns < self.created_at_ns:
            raise ReviewValidationError("updated_at_ns precedes created_at_ns")
        if self.deleted_at_ns is not None:
            _exact_non_negative_int(self.deleted_at_ns, "deleted_at_ns")
            if self.deleted_at_ns < self.updated_at_ns:
                raise ReviewValidationError("deleted_at_ns precedes updated_at_ns")

    @property
    def tombstoned(self) -> bool:
        return self.deleted_at_ns is not None

    def to_dict(self, *, include_scope: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "annotation_id": self.annotation_id,
            "kind": self.kind.value,
            "subjects": [subject.to_dict() for subject in self.subjects],
            "author": self.author,
            "title": self.title,
            "body": self.body,
            "tags": list(self.tags),
            "version": self.version,
            "created_at_ns": self.created_at_ns,
            "updated_at_ns": self.updated_at_ns,
            "deleted_at_ns": self.deleted_at_ns,
            "tombstoned": self.tombstoned,
        }
        if include_scope:
            result["scope"] = self.scope.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class ManualCorrelationEdge:
    source_ordinal: int
    target_ordinal: int
    link_type: str
    directed: bool = True

    def __post_init__(self) -> None:
        _exact_non_negative_int(self.source_ordinal, "source_ordinal")
        _exact_non_negative_int(self.target_ordinal, "target_ordinal")
        if self.source_ordinal == self.target_ordinal:
            raise ReviewValidationError(
                "manual correlation edges must connect distinct subjects"
            )
        _bounded_text(self.link_type, "link_type", MAX_LINK_TYPE_LENGTH)
        if type(self.directed) is not bool:
            raise ReviewValidationError("directed must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ordinal": self.source_ordinal,
            "target_ordinal": self.target_ordinal,
            "link_type": self.link_type,
            "directed": self.directed,
        }


def _normalize_edges(
    edges: Iterable[ManualCorrelationEdge],
    *,
    subject_count: int,
) -> tuple[ManualCorrelationEdge, ...]:
    if isinstance(edges, (str, bytes)) or not isinstance(edges, Iterable):
        raise ReviewValidationError("edges must be an iterable")
    materialized = tuple(edges)
    if not 1 <= len(materialized) <= MAX_CORRELATION_EDGES:
        raise ReviewValidationError(
            f"edges must contain between 1 and {MAX_CORRELATION_EDGES} items"
        )
    if any(type(edge) is not ManualCorrelationEdge for edge in materialized):
        raise ReviewValidationError(
            "edges must contain exact ManualCorrelationEdge values"
        )
    identities: set[tuple[Any, ...]] = set()
    for edge in materialized:
        if edge.source_ordinal >= subject_count or edge.target_ordinal >= subject_count:
            raise ReviewValidationError(
                "manual correlation edge references an unknown subject ordinal"
            )
        identity = (
            (
                edge.source_ordinal,
                edge.target_ordinal,
                edge.link_type,
                True,
            )
            if edge.directed
            else (
                min(edge.source_ordinal, edge.target_ordinal),
                max(edge.source_ordinal, edge.target_ordinal),
                edge.link_type,
                False,
            )
        )
        if identity in identities:
            raise ReviewValidationError("manual correlation edges contain duplicates")
        identities.add(identity)
    return materialized


@dataclass(frozen=True, slots=True)
class ManualEventCorrelation:
    correlation_id: str
    scope: ReviewScope
    subjects: tuple[ReviewSubject, ...]
    edges: tuple[ManualCorrelationEdge, ...]
    author: str
    rationale: str = ""
    tags: tuple[str, ...] = ()
    confidence: float | None = None
    version: int = 1
    created_at_ns: int = 0
    updated_at_ns: int = 0
    deleted_at_ns: int | None = None

    def __post_init__(self) -> None:
        _bounded_text(
            self.correlation_id,
            "correlation_id",
            MAX_IDENTIFIER_LENGTH,
        )
        if type(self.scope) is not ReviewScope:
            raise ReviewValidationError("scope must be an exact ReviewScope")
        subjects = _normalize_subjects(
            self.subjects,
            maximum=MAX_CORRELATION_SUBJECTS,
            event_only=True,
        )
        if len(subjects) < 2:
            raise ReviewValidationError(
                "manual event correlations require at least two subjects"
            )
        object.__setattr__(self, "subjects", subjects)
        object.__setattr__(
            self,
            "edges",
            _normalize_edges(self.edges, subject_count=len(subjects)),
        )
        _bounded_text(self.author, "author", MAX_AUTHOR_LENGTH)
        _bounded_text(
            self.rationale,
            "rationale",
            MAX_RATIONALE_LENGTH,
            allow_empty=True,
            allow_line_breaks=True,
        )
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        if self.confidence is not None:
            if (
                isinstance(self.confidence, bool)
                or not isinstance(self.confidence, (int, float))
                or not math.isfinite(float(self.confidence))
                or not 0.0 <= float(self.confidence) <= 1.0
            ):
                raise ReviewValidationError(
                    "confidence must be a finite number between 0 and 1"
                )
            object.__setattr__(self, "confidence", float(self.confidence))
        _exact_positive_int(self.version, "version")
        _exact_non_negative_int(self.created_at_ns, "created_at_ns")
        _exact_non_negative_int(self.updated_at_ns, "updated_at_ns")
        if self.updated_at_ns < self.created_at_ns:
            raise ReviewValidationError("updated_at_ns precedes created_at_ns")
        if self.deleted_at_ns is not None:
            _exact_non_negative_int(self.deleted_at_ns, "deleted_at_ns")
            if self.deleted_at_ns < self.updated_at_ns:
                raise ReviewValidationError("deleted_at_ns precedes updated_at_ns")

    @property
    def tombstoned(self) -> bool:
        return self.deleted_at_ns is not None

    def to_dict(self, *, include_scope: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "correlation_id": self.correlation_id,
            "subjects": [subject.to_dict() for subject in self.subjects],
            "edges": [edge.to_dict() for edge in self.edges],
            "author": self.author,
            "rationale": self.rationale,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "version": self.version,
            "created_at_ns": self.created_at_ns,
            "updated_at_ns": self.updated_at_ns,
            "deleted_at_ns": self.deleted_at_ns,
            "tombstoned": self.tombstoned,
        }
        if include_scope:
            result["scope"] = self.scope.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class ReviewAuditEntry:
    sequence: int
    scope: ReviewScope
    entity_kind: str
    entity_id: str
    operation: str
    version: int
    actor: str
    occurred_at_ns: int
    snapshot: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ReviewOverlaySnapshot:
    """One transactionally consistent review-overlay report input."""

    scope: ReviewScope
    audit_watermark: int
    annotations: tuple[ReviewAnnotation, ...]
    correlations: tuple[ManualEventCorrelation, ...]


@dataclass(frozen=True, slots=True)
class CorrelationReport:
    json_document: Mapping[str, Any]
    canonical_json: str
    markdown: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ReviewRetentionPolicy:
    """Explicit, disabled-by-default review-overlay retention policy."""

    enabled: bool = False
    tombstone_before_ns: int | None = None
    idempotency_before_ns: int | None = None
    audit_mode: ReviewAuditRetentionMode = ReviewAuditRetentionMode.PRESERVE
    audit_before_sequence: int | None = None
    maximum_candidates: int = 1_000

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ReviewValidationError("retention enabled must be a boolean")
        for label, value in (
            ("tombstone_before_ns", self.tombstone_before_ns),
            ("idempotency_before_ns", self.idempotency_before_ns),
            ("audit_before_sequence", self.audit_before_sequence),
        ):
            if value is not None:
                _exact_non_negative_int(value, label)
        try:
            mode = ReviewAuditRetentionMode(self.audit_mode)
        except (TypeError, ValueError) as error:
            raise ReviewValidationError(
                "unsupported review audit retention mode"
            ) from error
        object.__setattr__(self, "audit_mode", mode)
        if mode is ReviewAuditRetentionMode.PRESERVE:
            if self.audit_before_sequence is not None:
                raise ReviewValidationError(
                    "audit_before_sequence requires prune_explicit audit mode"
                )
        elif self.audit_before_sequence is None:
            raise ReviewValidationError(
                "prune_explicit audit mode requires audit_before_sequence"
            )
        if (
            type(self.maximum_candidates) is not int
            or not 1 <= self.maximum_candidates <= MAX_RETENTION_CANDIDATES
        ):
            raise ReviewValidationError("maximum_candidates must be between 1 and 5000")


@dataclass(frozen=True, slots=True)
class ReviewRetentionCandidate:
    category: str
    identifier: str
    retention_value: int
    blockers: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return not self.blockers


@dataclass(frozen=True, slots=True)
class ReviewRetentionInventory:
    scope: ReviewScope
    policy: ReviewRetentionPolicy
    total_candidate_count: int
    candidates: tuple[ReviewRetentionCandidate, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class ReviewRetentionResult:
    inventory: ReviewRetentionInventory
    purged: tuple[ReviewRetentionCandidate, ...]


@dataclass(frozen=True, slots=True)
class ReviewRetentionAuditEntry:
    sequence: int
    scope: ReviewScope
    operation_id: str
    actor: str
    occurred_at_ns: int
    policy: Mapping[str, Any]
    candidate_count: int
    purged_count: int
    purged: tuple[Mapping[str, Any], ...]
    purged_sha256: str


_REVIEW_RETENTION_RESULT_SCHEMA_VERSION = (
    "router_dump_analyzer.review_retention_result.v1"
)


def _review_retention_policy_document(
    policy: ReviewRetentionPolicy,
) -> dict[str, Any]:
    return {
        "enabled": policy.enabled,
        "tombstone_before_ns": policy.tombstone_before_ns,
        "idempotency_before_ns": policy.idempotency_before_ns,
        "audit_mode": policy.audit_mode.value,
        "audit_before_sequence": policy.audit_before_sequence,
        "maximum_candidates": policy.maximum_candidates,
    }


def _review_retention_candidate_document(
    candidate: ReviewRetentionCandidate,
) -> dict[str, Any]:
    return {
        "category": candidate.category,
        "identifier": candidate.identifier,
        "retention_value": candidate.retention_value,
        "blockers": list(candidate.blockers),
    }


def _review_retention_result_document(
    result: ReviewRetentionResult,
) -> dict[str, Any]:
    return {
        "schema_version": _REVIEW_RETENTION_RESULT_SCHEMA_VERSION,
        "inventory": {
            "total_candidate_count": result.inventory.total_candidate_count,
            "candidates": [
                _review_retention_candidate_document(candidate)
                for candidate in result.inventory.candidates
            ],
            "truncated": result.inventory.truncated,
        },
        "purged": [
            _review_retention_candidate_document(candidate)
            for candidate in result.purged
        ],
    }


def _review_retention_candidate_from_document(
    value: Any,
    *,
    label: str,
) -> ReviewRetentionCandidate:
    if type(value) is not dict or set(value) != {
        "category",
        "identifier",
        "retention_value",
        "blockers",
    }:
        raise ReviewOverlayError(f"stored {label} is invalid")
    try:
        category = _bounded_text(
            value["category"],
            f"stored {label} category",
            MAX_IDENTIFIER_LENGTH,
        )
        identifier = _bounded_text(
            value["identifier"],
            f"stored {label} identifier",
            MAX_IDENTIFIER_LENGTH,
        )
        retention_value = _exact_non_negative_int(
            value["retention_value"],
            f"stored {label} retention_value",
        )
    except ReviewValidationError as error:
        raise ReviewOverlayError(f"stored {label} is invalid") from error
    blockers_value = value["blockers"]
    if type(blockers_value) is not list:
        raise ReviewOverlayError(f"stored {label} blockers are invalid")
    try:
        blockers = tuple(
            _bounded_text(
                blocker,
                f"stored {label} blocker",
                MAX_IDENTIFIER_LENGTH,
            )
            for blocker in blockers_value
        )
    except ReviewValidationError as error:
        raise ReviewOverlayError(f"stored {label} blockers are invalid") from error
    if len(blockers) > MAX_RETENTION_CANDIDATES or len(set(blockers)) != len(blockers):
        raise ReviewOverlayError(f"stored {label} blockers are invalid")
    return ReviewRetentionCandidate(
        category=category,
        identifier=identifier,
        retention_value=retention_value,
        blockers=blockers,
    )


def _review_retention_result_from_json(
    value: str,
    *,
    scope: ReviewScope,
    policy: ReviewRetentionPolicy,
) -> ReviewRetentionResult:
    try:
        document = json.loads(value)
    except (TypeError, json.JSONDecodeError) as error:
        raise ReviewOverlayError(
            "stored retention operation result is invalid"
        ) from error
    if type(document) is not dict or set(document) != {
        "schema_version",
        "inventory",
        "purged",
    }:
        raise ReviewOverlayError("stored retention operation result is invalid")
    if document["schema_version"] != _REVIEW_RETENTION_RESULT_SCHEMA_VERSION:
        raise ReviewOverlayError(
            "stored retention operation result has an unsupported schema"
        )
    inventory_value = document["inventory"]
    if type(inventory_value) is not dict or set(inventory_value) != {
        "total_candidate_count",
        "candidates",
        "truncated",
    }:
        raise ReviewOverlayError("stored retention inventory is invalid")
    candidate_values = inventory_value["candidates"]
    purged_values = document["purged"]
    if type(candidate_values) is not list or type(purged_values) is not list:
        raise ReviewOverlayError("stored retention operation result is invalid")
    if (
        len(candidate_values) > policy.maximum_candidates
        or len(purged_values) > policy.maximum_candidates
    ):
        raise ReviewOverlayError("stored retention operation result is invalid")
    candidates = tuple(
        _review_retention_candidate_from_document(
            candidate,
            label="retention candidate",
        )
        for candidate in candidate_values
    )
    purged = tuple(
        _review_retention_candidate_from_document(
            candidate,
            label="purged retention candidate",
        )
        for candidate in purged_values
    )
    try:
        total_candidate_count = _exact_non_negative_int(
            inventory_value["total_candidate_count"],
            "stored retention total_candidate_count",
        )
    except ReviewValidationError as error:
        raise ReviewOverlayError("stored retention inventory is invalid") from error
    truncated = inventory_value["truncated"]
    if type(truncated) is not bool:
        raise ReviewOverlayError("stored retention inventory is invalid")
    if truncated != (total_candidate_count > len(candidates)):
        raise ReviewOverlayError("stored retention inventory is invalid")
    if any(candidate.blockers for candidate in purged):
        raise ReviewOverlayError("stored purged retention candidate is invalid")
    available = list(candidates)
    for candidate in purged:
        try:
            available.remove(candidate)
        except ValueError as error:
            raise ReviewOverlayError(
                "stored purged retention candidate is not in its inventory"
            ) from error
    return ReviewRetentionResult(
        inventory=ReviewRetentionInventory(
            scope=scope,
            policy=policy,
            total_candidate_count=total_candidate_count,
            candidates=candidates,
            truncated=truncated,
        ),
        purged=purged,
    )


_UNSET = object()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_annotation (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    annotation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    author TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns),
    deleted_at_ns INTEGER,
    PRIMARY KEY (tenant_id, project_id, workspace_id, annotation_id)
);

CREATE TABLE IF NOT EXISTS review_annotation_subject (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    annotation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    revision_id TEXT NOT NULL,
    node_id TEXT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT,
    start_ns INTEGER,
    end_ns INTEGER,
    PRIMARY KEY (
        tenant_id, project_id, workspace_id, annotation_id, ordinal
    ),
    FOREIGN KEY (
        tenant_id, project_id, workspace_id, annotation_id
    ) REFERENCES review_annotation (
        tenant_id, project_id, workspace_id, annotation_id
    )
);

CREATE TABLE IF NOT EXISTS manual_event_correlation (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    author TEXT NOT NULL,
    rationale TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    confidence REAL,
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns),
    deleted_at_ns INTEGER,
    PRIMARY KEY (tenant_id, project_id, workspace_id, correlation_id)
);

CREATE TABLE IF NOT EXISTS manual_event_correlation_subject (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    revision_id TEXT NOT NULL,
    node_id TEXT,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    start_ns INTEGER,
    end_ns INTEGER,
    PRIMARY KEY (
        tenant_id, project_id, workspace_id, correlation_id, ordinal
    ),
    FOREIGN KEY (
        tenant_id, project_id, workspace_id, correlation_id
    ) REFERENCES manual_event_correlation (
        tenant_id, project_id, workspace_id, correlation_id
    )
);

CREATE TABLE IF NOT EXISTS manual_event_correlation_edge (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    source_ordinal INTEGER NOT NULL CHECK (source_ordinal >= 0),
    target_ordinal INTEGER NOT NULL CHECK (target_ordinal >= 0),
    link_type TEXT NOT NULL,
    directed INTEGER NOT NULL CHECK (directed IN (0, 1)),
    PRIMARY KEY (
        tenant_id, project_id, workspace_id, correlation_id, ordinal
    ),
    FOREIGN KEY (
        tenant_id, project_id, workspace_id, correlation_id
    ) REFERENCES manual_event_correlation (
        tenant_id, project_id, workspace_id, correlation_id
    )
);

CREATE TABLE IF NOT EXISTS review_overlay_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    actor TEXT NOT NULL,
    occurred_at_ns INTEGER NOT NULL CHECK (occurred_at_ns >= 0),
    snapshot_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS review_overlay_audit_scope_sequence
ON review_overlay_audit (
    tenant_id, project_id, workspace_id, sequence
);

CREATE TABLE IF NOT EXISTS review_overlay_idempotency (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
    PRIMARY KEY (
        tenant_id, project_id, workspace_id, idempotency_key
    )
);

CREATE TABLE IF NOT EXISTS review_retention_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    occurred_at_ns INTEGER NOT NULL CHECK (occurred_at_ns >= 0),
    policy_json TEXT NOT NULL,
    candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
    purged_count INTEGER NOT NULL CHECK (purged_count >= 0),
    purged_json TEXT NOT NULL,
    purged_sha256 TEXT NOT NULL,
    result_json TEXT,
    UNIQUE (tenant_id, project_id, workspace_id, operation_id)
);

CREATE INDEX IF NOT EXISTS review_retention_audit_scope_sequence
ON review_retention_audit (
    tenant_id, project_id, workspace_id, sequence
);
"""


def _scope_values(scope: ReviewScope) -> tuple[str, str, str]:
    if type(scope) is not ReviewScope:
        raise ReviewValidationError("scope must be an exact ReviewScope")
    return scope.tenant_id, scope.project_id, scope.workspace_id


def _canonical_json(value: Any) -> str:
    try:
        return strict_canonical_json(value)
    except CanonicalValueError as error:
        raise ReviewValidationError("value is not canonical JSON") from error


def _sanitize_ai_facing_text(value: str) -> str:
    """Encode AI-facing text without collapsing distinct source strings.

    Generated ``\\u``/``\\U`` escapes use one backslash.  Doubling every
    caller-supplied backslash first ensures that a literal escape-looking
    string cannot become identical to a string containing the corresponding
    unsafe Unicode character.  The resulting JSON and SHA-256 therefore
    preserve the semantic distinction.
    """

    return escape_unsafe_display_text(
        value,
        allow_prose_whitespace=True,
        make_escapes_unambiguous=True,
    )


def _bounded_json_copy(
    value: Any,
    *,
    label: str = "value",
    _units: list[int] | None = None,
    _sanitize_text: bool = True,
) -> Any:
    units = _units if _units is not None else [0]
    active: set[int] = set()

    def visit(item: Any, depth: int, path: str) -> Any:
        if depth > MAX_REPORT_JSON_DEPTH:
            raise ReviewValidationError(
                f"{label} exceeds {MAX_REPORT_JSON_DEPTH} JSON levels at {path}"
            )
        units[0] += 1
        if units[0] > MAX_REPORT_JSON_UNITS:
            raise ReviewValidationError(
                f"{label} exceeds {MAX_REPORT_JSON_UNITS} JSON units"
            )
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if item.bit_length() > MAX_REPORT_JSON_INTEGER_BITS:
                raise ReviewValidationError(
                    f"{label} contains an oversized integer at {path}"
                )
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ReviewValidationError(
                    f"{label} contains a non-finite float at {path}"
                )
            return item
        if type(item) is str:
            if len(item) > MAX_REPORT_JSON_STRING_LENGTH:
                raise ReviewValidationError(
                    f"{label} contains an oversized string at {path}"
                )
            if "\x00" in item:
                raise ReviewValidationError(f"{label} contains NUL at {path}")
            escaped = _sanitize_ai_facing_text(item) if _sanitize_text else item
            if len(escaped) > MAX_REPORT_JSON_STRING_LENGTH:
                raise ReviewValidationError(
                    f"{label} contains an oversized escaped string at {path}"
                )
            return escaped
        if isinstance(item, Mapping):
            if len(item) > MAX_REPORT_JSON_CONTAINER_ITEMS:
                raise ReviewValidationError(
                    f"{label} contains an oversized object at {path}"
                )
            identity = id(item)
            if identity in active:
                raise ReviewValidationError(
                    f"{label} contains a reference cycle at {path}"
                )
            active.add(identity)
            try:
                result: dict[str, Any] = {}
                for key, nested in item.items():
                    if type(key) is not str or not key:
                        raise ReviewValidationError(
                            f"{label} object keys must be non-empty strings at {path}"
                        )
                    if len(key) > MAX_IDENTIFIER_LENGTH or "\x00" in key:
                        raise ReviewValidationError(
                            f"{label} contains an invalid object key at {path}"
                        )
                    escaped_key = (
                        _sanitize_ai_facing_text(key) if _sanitize_text else key
                    )
                    if len(escaped_key) > MAX_IDENTIFIER_LENGTH:
                        raise ReviewValidationError(
                            f"{label} contains an oversized escaped object key "
                            f"at {path}"
                        )
                    if escaped_key in result:
                        raise ReviewValidationError(
                            f"{label} object keys collide after safe escaping at {path}"
                        )
                    result[escaped_key] = visit(
                        nested,
                        depth + 1,
                        f"{path}.{escaped_key}",
                    )
                return result
            finally:
                active.remove(identity)
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            if len(item) > MAX_REPORT_JSON_CONTAINER_ITEMS:
                raise ReviewValidationError(
                    f"{label} contains an oversized array at {path}"
                )
            identity = id(item)
            if identity in active:
                raise ReviewValidationError(
                    f"{label} contains a reference cycle at {path}"
                )
            active.add(identity)
            try:
                return [
                    visit(nested, depth + 1, f"{path}[{index}]")
                    for index, nested in enumerate(item)
                ]
            finally:
                active.remove(identity)
        raise ReviewValidationError(
            f"{label} contains unsupported {type(item).__name__} at {path}"
        )

    return visit(value, 0, "$")


def _scope_from_dict(value: Mapping[str, Any]) -> ReviewScope:
    if not isinstance(value, Mapping):
        raise ReviewValidationError("scope must be an object")
    return ReviewScope(
        tenant_id=value.get("tenant_id"),  # type: ignore[arg-type]
        project_id=value.get("project_id"),  # type: ignore[arg-type]
        workspace_id=value.get("workspace_id"),  # type: ignore[arg-type]
    )


def _annotation_from_dict(value: Mapping[str, Any]) -> ReviewAnnotation:
    return ReviewAnnotation(
        annotation_id=value.get("annotation_id"),  # type: ignore[arg-type]
        scope=_scope_from_dict(value.get("scope", {})),  # type: ignore[arg-type]
        kind=value.get("kind"),  # type: ignore[arg-type]
        subjects=tuple(
            ReviewSubject.from_dict(subject) for subject in value.get("subjects", ())
        ),
        author=value.get("author"),  # type: ignore[arg-type]
        title=value.get("title", ""),  # type: ignore[arg-type]
        body=value.get("body", ""),  # type: ignore[arg-type]
        tags=tuple(value.get("tags", ())),
        version=value.get("version"),  # type: ignore[arg-type]
        created_at_ns=value.get("created_at_ns"),  # type: ignore[arg-type]
        updated_at_ns=value.get("updated_at_ns"),  # type: ignore[arg-type]
        deleted_at_ns=value.get("deleted_at_ns"),  # type: ignore[arg-type]
    )


def _correlation_from_dict(value: Mapping[str, Any]) -> ManualEventCorrelation:
    return ManualEventCorrelation(
        correlation_id=value.get("correlation_id"),  # type: ignore[arg-type]
        scope=_scope_from_dict(value.get("scope", {})),  # type: ignore[arg-type]
        subjects=tuple(
            ReviewSubject.from_dict(subject) for subject in value.get("subjects", ())
        ),
        edges=tuple(
            ManualCorrelationEdge(
                source_ordinal=edge.get("source_ordinal"),
                target_ordinal=edge.get("target_ordinal"),
                link_type=edge.get("link_type"),
                directed=edge.get("directed", True),
            )
            for edge in value.get("edges", ())
        ),
        author=value.get("author"),  # type: ignore[arg-type]
        rationale=value.get("rationale", ""),  # type: ignore[arg-type]
        tags=tuple(value.get("tags", ())),
        confidence=value.get("confidence"),  # type: ignore[arg-type]
        version=value.get("version"),  # type: ignore[arg-type]
        created_at_ns=value.get("created_at_ns"),  # type: ignore[arg-type]
        updated_at_ns=value.get("updated_at_ns"),  # type: ignore[arg-type]
        deleted_at_ns=value.get("deleted_at_ns"),  # type: ignore[arg-type]
    )


class ReviewOverlayStore:
    """Durable scoped repository for mutable review overlay records."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock_ns: Any = time.time_ns,
    ) -> None:
        if not callable(clock_ns):
            raise TypeError("clock_ns must be callable")
        self._clock_ns = clock_ns
        self._lock = threading.RLock()
        self._closed = False
        if isinstance(path, Path):
            database = str(path)
        elif isinstance(path, str):
            database = path
        else:
            raise TypeError("path must be a string or Path")
        if not database:
            raise ValueError("path must be non-empty")
        database_uri = False
        if database != ":memory:":
            Path(database).expanduser().resolve().parent.mkdir(
                parents=True,
                exist_ok=True,
            )
        else:
            database = (
                "file:router-dump-analyzer-review-"
                f"{uuid4().hex}?mode=memory&cache=shared"
            )
            database_uri = True
        self._database = database
        self._database_uri = database_uri
        self._connection = self._open_connection()

    def _raw_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(
            self._database,
            isolation_level=None,
            check_same_thread=False,
            uri=self._database_uri,
        )

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(_SCHEMA)
        retention_audit_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(review_retention_audit)"
            ).fetchall()
        }
        if "result_json" not in retention_audit_columns:
            try:
                connection.execute(
                    "ALTER TABLE review_retention_audit ADD COLUMN result_json TEXT"
                )
            except sqlite3.OperationalError:
                # Another process may have completed the additive migration
                # after this connection read the table shape.
                migrated_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(review_retention_audit)"
                    ).fetchall()
                }
                if "result_json" not in migrated_columns:
                    raise

    def _open_connection(self) -> sqlite3.Connection:
        connection = self._raw_connection()
        try:
            self._configure_connection(connection)
        except BaseException:
            connection.close()
            raise
        return connection

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def _recover_failed_transaction(self) -> None:
        """Clear an aborted transaction or replace a poisoned connection.

        SQLite commit failures are ambiguous to the caller.  A successful
        rollback makes the shared connection reusable; if rollback itself
        fails or leaves the connection inside a transaction, file-backed
        stores discard it and reopen the durable database.  An in-memory
        database cannot be reconstructed without silently losing state, so it
        is closed and reported as unrecoverable instead.
        """

        connection = self._connection
        rollback_error: sqlite3.Error | None = None
        try:
            connection.rollback()
        except sqlite3.Error as error:
            rollback_error = error
        transaction_cleared = False
        if rollback_error is None:
            try:
                transaction_cleared = not connection.in_transaction
            except sqlite3.Error:
                transaction_cleared = False
        if transaction_cleared:
            return

        # Open first so a named shared-memory database stays alive while the
        # poisoned writer is retired.  Configuration follows close because
        # schema initialization may otherwise wait on the poisoned lock.
        replacement = self._raw_connection()
        with suppress(sqlite3.Error):
            connection.close()
        try:
            self._configure_connection(replacement)
        except BaseException as error:
            replacement.close()
            self._closed = True
            raise ReviewOverlayError(
                "review overlay could not reopen its SQLite connection"
            ) from error
        self._connection = replacement

    @contextmanager
    def _transaction(
        self,
        *,
        begin: str = "BEGIN IMMEDIATE",
    ) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            if begin not in {"BEGIN", "BEGIN IMMEDIATE"}:
                raise ValueError("unsupported review overlay transaction mode")
            self._connection.execute(begin)
            try:
                yield self._connection
                self._connection.commit()
            except BaseException:
                self._recover_failed_transaction()
                raise

    def _now(self) -> int:
        with self._lock:
            return _exact_non_negative_int(self._clock_ns(), "clock result")

    @staticmethod
    def _where(scope: ReviewScope) -> tuple[str, tuple[str, str, str]]:
        values = _scope_values(scope)
        return (
            "tenant_id = ? AND project_id = ? AND workspace_id = ?",
            values,
        )

    @staticmethod
    def _insert_subjects(
        connection: sqlite3.Connection,
        table: str,
        parent_column: str,
        scope: ReviewScope,
        parent_id: str,
        subjects: Sequence[ReviewSubject],
    ) -> None:
        scope_values = _scope_values(scope)
        for ordinal, subject in enumerate(subjects):
            connection.execute(
                f"""
                INSERT INTO {table} (
                    tenant_id, project_id, workspace_id, {parent_column},
                    ordinal, revision_id, node_id, subject_kind, subject_id,
                    start_ns, end_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *scope_values,
                    parent_id,
                    ordinal,
                    subject.revision_id,
                    subject.node_id,
                    subject.kind.value,
                    subject.subject_id,
                    subject.start_ns,
                    subject.end_ns,
                ),
            )

    @staticmethod
    def _subjects(
        connection: sqlite3.Connection,
        table: str,
        parent_column: str,
        scope: ReviewScope,
        parent_id: str,
    ) -> tuple[ReviewSubject, ...]:
        where, values = ReviewOverlayStore._where(scope)
        rows = connection.execute(
            f"""
            SELECT revision_id, node_id, subject_kind, subject_id,
                   start_ns, end_ns
            FROM {table}
            WHERE {where} AND {parent_column} = ?
            ORDER BY ordinal
            """,
            (*values, parent_id),
        ).fetchall()
        return tuple(
            ReviewSubject(
                revision_id=row["revision_id"],
                node_id=row["node_id"],
                kind=row["subject_kind"],
                subject_id=row["subject_id"],
                start_ns=row["start_ns"],
                end_ns=row["end_ns"],
            )
            for row in rows
        )

    def _annotation(
        self,
        connection: sqlite3.Connection,
        scope: ReviewScope,
        annotation_id: str,
        *,
        include_deleted: bool,
    ) -> ReviewAnnotation:
        _bounded_text(
            annotation_id,
            "annotation_id",
            MAX_IDENTIFIER_LENGTH,
        )
        where, values = self._where(scope)
        row = connection.execute(
            f"""
            SELECT * FROM review_annotation
            WHERE {where} AND annotation_id = ?
            """,
            (*values, annotation_id),
        ).fetchone()
        if row is None or (row["deleted_at_ns"] is not None and not include_deleted):
            raise KeyError(annotation_id)
        return ReviewAnnotation(
            annotation_id=row["annotation_id"],
            scope=scope,
            kind=row["kind"],
            subjects=self._subjects(
                connection,
                "review_annotation_subject",
                "annotation_id",
                scope,
                annotation_id,
            ),
            author=row["author"],
            title=row["title"],
            body=row["body"],
            tags=tuple(json.loads(row["tags_json"])),
            version=row["version"],
            created_at_ns=row["created_at_ns"],
            updated_at_ns=row["updated_at_ns"],
            deleted_at_ns=row["deleted_at_ns"],
        )

    def _correlation(
        self,
        connection: sqlite3.Connection,
        scope: ReviewScope,
        correlation_id: str,
        *,
        include_deleted: bool,
    ) -> ManualEventCorrelation:
        _bounded_text(
            correlation_id,
            "correlation_id",
            MAX_IDENTIFIER_LENGTH,
        )
        where, values = self._where(scope)
        row = connection.execute(
            f"""
            SELECT * FROM manual_event_correlation
            WHERE {where} AND correlation_id = ?
            """,
            (*values, correlation_id),
        ).fetchone()
        if row is None or (row["deleted_at_ns"] is not None and not include_deleted):
            raise KeyError(correlation_id)
        subjects = self._subjects(
            connection,
            "manual_event_correlation_subject",
            "correlation_id",
            scope,
            correlation_id,
        )
        edge_rows = connection.execute(
            f"""
            SELECT source_ordinal, target_ordinal, link_type, directed
            FROM manual_event_correlation_edge
            WHERE {where} AND correlation_id = ?
            ORDER BY ordinal
            """,
            (*values, correlation_id),
        ).fetchall()
        return ManualEventCorrelation(
            correlation_id=row["correlation_id"],
            scope=scope,
            subjects=subjects,
            edges=tuple(
                ManualCorrelationEdge(
                    source_ordinal=edge["source_ordinal"],
                    target_ordinal=edge["target_ordinal"],
                    link_type=edge["link_type"],
                    directed=bool(edge["directed"]),
                )
                for edge in edge_rows
            ),
            author=row["author"],
            rationale=row["rationale"],
            tags=tuple(json.loads(row["tags_json"])),
            confidence=row["confidence"],
            version=row["version"],
            created_at_ns=row["created_at_ns"],
            updated_at_ns=row["updated_at_ns"],
            deleted_at_ns=row["deleted_at_ns"],
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        scope: ReviewScope,
        entity_kind: str,
        entity_id: str,
        operation: str,
        version: int,
        actor: str,
        occurred_at_ns: int,
        snapshot: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO review_overlay_audit (
                tenant_id, project_id, workspace_id, entity_kind, entity_id,
                operation, version, actor, occurred_at_ns, snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *_scope_values(scope),
                entity_kind,
                entity_id,
                operation,
                version,
                actor,
                occurred_at_ns,
                _canonical_json(snapshot),
            ),
        )

    @staticmethod
    def _idempotent_result(
        connection: sqlite3.Connection,
        *,
        scope: ReviewScope,
        idempotency_key: str | None,
        request_sha256: str,
    ) -> Mapping[str, Any] | None:
        if idempotency_key is None:
            return None
        _bounded_text(
            idempotency_key,
            "idempotency_key",
            MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        where, values = ReviewOverlayStore._where(scope)
        row = connection.execute(
            f"""
            SELECT request_sha256, result_json
            FROM review_overlay_idempotency
            WHERE {where} AND idempotency_key = ?
            """,
            (*values, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_sha256:
            raise ReviewIdempotencyConflictError(
                "idempotency key was already used for a different request"
            )
        result = json.loads(row["result_json"])
        if not isinstance(result, dict):
            raise ReviewOverlayError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _remember_idempotency(
        connection: sqlite3.Connection,
        *,
        scope: ReviewScope,
        idempotency_key: str | None,
        request_sha256: str,
        entity_kind: str,
        entity_id: str,
        result: Mapping[str, Any],
        created_at_ns: int,
    ) -> None:
        if idempotency_key is None:
            return
        connection.execute(
            """
            INSERT INTO review_overlay_idempotency (
                tenant_id, project_id, workspace_id, idempotency_key,
                request_sha256, entity_kind, entity_id, result_json,
                created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *_scope_values(scope),
                idempotency_key,
                request_sha256,
                entity_kind,
                entity_id,
                _canonical_json(result),
                created_at_ns,
            ),
        )

    def create_annotation(
        self,
        scope: ReviewScope,
        *,
        kind: ReviewAnnotationKind,
        subjects: Iterable[ReviewSubject],
        author: str,
        title: str = "",
        body: str = "",
        tags: Iterable[str] = (),
        annotation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> ReviewAnnotation:
        _scope_values(scope)
        candidate_id = annotation_id or str(uuid4())
        now = self._now()
        candidate = ReviewAnnotation(
            annotation_id=candidate_id,
            scope=scope,
            kind=kind,
            subjects=tuple(subjects),
            author=author,
            title=title,
            body=body,
            tags=tuple(tags),
            version=1,
            created_at_ns=now,
            updated_at_ns=now,
        )
        request = candidate.to_dict()
        request["annotation_id"] = annotation_id
        request.pop("created_at_ns")
        request.pop("updated_at_ns")
        request.pop("version")
        request.pop("deleted_at_ns")
        request.pop("tombstoned")
        digest = strict_canonical_json_sha256(request)
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                scope=scope,
                idempotency_key=idempotency_key,
                request_sha256=digest,
            )
            if prior is not None:
                return _annotation_from_dict(prior)
            try:
                connection.execute(
                    """
                    INSERT INTO review_annotation (
                        tenant_id, project_id, workspace_id, annotation_id,
                        kind, author, title, body, tags_json, version,
                        created_at_ns, updated_at_ns, deleted_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)
                    """,
                    (
                        *_scope_values(scope),
                        candidate.annotation_id,
                        candidate.kind.value,
                        candidate.author,
                        candidate.title,
                        candidate.body,
                        _canonical_json(list(candidate.tags)),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ReviewConflictError(
                    f"annotation already exists: {candidate.annotation_id}"
                ) from error
            self._insert_subjects(
                connection,
                "review_annotation_subject",
                "annotation_id",
                scope,
                candidate.annotation_id,
                candidate.subjects,
            )
            stored = self._annotation(
                connection,
                scope,
                candidate.annotation_id,
                include_deleted=True,
            )
            snapshot = stored.to_dict()
            self._audit(
                connection,
                scope=scope,
                entity_kind="annotation",
                entity_id=stored.annotation_id,
                operation="create",
                version=stored.version,
                actor=author,
                occurred_at_ns=now,
                snapshot=snapshot,
            )
            self._remember_idempotency(
                connection,
                scope=scope,
                idempotency_key=idempotency_key,
                request_sha256=digest,
                entity_kind="annotation",
                entity_id=stored.annotation_id,
                result=snapshot,
                created_at_ns=now,
            )
            return stored

    def get_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ReviewAnnotation:
        _scope_values(scope)
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            return self._annotation(
                self._connection,
                scope,
                annotation_id,
                include_deleted=include_deleted,
            )

    def list_annotations(
        self,
        scope: ReviewScope,
        *,
        include_deleted: bool = False,
        limit: int = 1_000,
        offset: int = 0,
    ) -> tuple[ReviewAnnotation, ...]:
        values, _watermark = self.list_annotations_page(
            scope,
            include_deleted=include_deleted,
            limit=limit,
            offset=offset,
        )
        return values

    def list_annotations_page(
        self,
        scope: ReviewScope,
        *,
        include_deleted: bool = False,
        limit: int = 1_000,
        offset: int = 0,
        expected_audit_watermark: int | None = None,
    ) -> tuple[tuple[ReviewAnnotation, ...], int]:
        """Read one ordered page and its scope watermark from one snapshot.

        A caller can bind every page of a bounded scan to the watermark returned
        by its first page.  The expected-watermark check and row read occur in
        the same SQLite read transaction, so an accepted page can never contain
        rows from a different review-overlay revision.
        """

        _scope_values(scope)
        if type(limit) is not int or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ReviewValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        _exact_non_negative_int(offset, "offset")
        if expected_audit_watermark is not None:
            _exact_non_negative_int(
                expected_audit_watermark,
                "expected_audit_watermark",
            )
        where, values = self._where(scope)
        deleted = "" if include_deleted else " AND deleted_at_ns IS NULL"
        with self._transaction(begin="BEGIN") as connection:
            watermark_row = connection.execute(
                f"""
                SELECT COALESCE(MAX(sequence), 0) AS watermark
                FROM review_overlay_audit
                WHERE {where}
                """,
                values,
            ).fetchone()
            watermark = int(watermark_row["watermark"])
            if (
                expected_audit_watermark is not None
                and watermark != expected_audit_watermark
            ):
                raise ReviewConflictError(
                    "annotation audit watermark changed during pagination"
                )
            rows = connection.execute(
                f"""
                SELECT annotation_id FROM review_annotation
                WHERE {where}{deleted}
                ORDER BY annotation_id
                LIMIT ? OFFSET ?
                """,
                (*values, limit, offset),
            ).fetchall()
            annotations = tuple(
                self._annotation(
                    connection,
                    scope,
                    row["annotation_id"],
                    include_deleted=include_deleted,
                )
                for row in rows
            )
        return annotations, watermark

    def update_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        expected_version: int,
        actor: str,
        kind: ReviewAnnotationKind | object = _UNSET,
        subjects: Iterable[ReviewSubject] | object = _UNSET,
        title: str | object = _UNSET,
        body: str | object = _UNSET,
        tags: Iterable[str] | object = _UNSET,
    ) -> ReviewAnnotation:
        _scope_values(scope)
        _exact_positive_int(expected_version, "expected_version")
        _bounded_text(actor, "actor", MAX_AUTHOR_LENGTH)
        with self._transaction() as connection:
            current = self._annotation(
                connection,
                scope,
                annotation_id,
                include_deleted=False,
            )
            if current.version != expected_version:
                raise ReviewConflictError(
                    f"annotation version is {current.version}, expected "
                    f"{expected_version}"
                )
            next_value = ReviewAnnotation(
                annotation_id=current.annotation_id,
                scope=scope,
                kind=current.kind if kind is _UNSET else kind,  # type: ignore[arg-type]
                subjects=(
                    current.subjects if subjects is _UNSET else tuple(subjects)  # type: ignore[arg-type]
                ),
                author=current.author,
                title=current.title if title is _UNSET else title,  # type: ignore[arg-type]
                body=current.body if body is _UNSET else body,  # type: ignore[arg-type]
                tags=(
                    current.tags if tags is _UNSET else tuple(tags)  # type: ignore[arg-type]
                ),
                version=current.version + 1,
                created_at_ns=current.created_at_ns,
                updated_at_ns=self._now(),
            )
            where, values = self._where(scope)
            cursor = connection.execute(
                f"""
                UPDATE review_annotation
                SET kind = ?, title = ?, body = ?, tags_json = ?,
                    version = ?, updated_at_ns = ?
                WHERE {where} AND annotation_id = ? AND version = ?
                      AND deleted_at_ns IS NULL
                """,
                (
                    next_value.kind.value,
                    next_value.title,
                    next_value.body,
                    _canonical_json(list(next_value.tags)),
                    next_value.version,
                    next_value.updated_at_ns,
                    *values,
                    annotation_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ReviewConflictError("annotation changed concurrently")
            connection.execute(
                f"""
                DELETE FROM review_annotation_subject
                WHERE {where} AND annotation_id = ?
                """,
                (*values, annotation_id),
            )
            self._insert_subjects(
                connection,
                "review_annotation_subject",
                "annotation_id",
                scope,
                annotation_id,
                next_value.subjects,
            )
            stored = self._annotation(
                connection,
                scope,
                annotation_id,
                include_deleted=True,
            )
            self._audit(
                connection,
                scope=scope,
                entity_kind="annotation",
                entity_id=annotation_id,
                operation="update",
                version=stored.version,
                actor=actor,
                occurred_at_ns=stored.updated_at_ns,
                snapshot=stored.to_dict(),
            )
            return stored

    def delete_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        expected_version: int,
        actor: str,
    ) -> ReviewAnnotation:
        _scope_values(scope)
        _exact_positive_int(expected_version, "expected_version")
        _bounded_text(actor, "actor", MAX_AUTHOR_LENGTH)
        with self._transaction() as connection:
            current = self._annotation(
                connection,
                scope,
                annotation_id,
                include_deleted=False,
            )
            if current.version != expected_version:
                raise ReviewConflictError(
                    f"annotation version is {current.version}, expected "
                    f"{expected_version}"
                )
            now = self._now()
            next_version = current.version + 1
            where, values = self._where(scope)
            cursor = connection.execute(
                f"""
                UPDATE review_annotation
                SET version = ?, updated_at_ns = ?, deleted_at_ns = ?
                WHERE {where} AND annotation_id = ? AND version = ?
                      AND deleted_at_ns IS NULL
                """,
                (
                    next_version,
                    now,
                    now,
                    *values,
                    annotation_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ReviewConflictError("annotation changed concurrently")
            stored = self._annotation(
                connection,
                scope,
                annotation_id,
                include_deleted=True,
            )
            self._audit(
                connection,
                scope=scope,
                entity_kind="annotation",
                entity_id=annotation_id,
                operation="delete",
                version=stored.version,
                actor=actor,
                occurred_at_ns=now,
                snapshot=stored.to_dict(),
            )
            return stored

    def create_correlation(
        self,
        scope: ReviewScope,
        *,
        subjects: Iterable[ReviewSubject],
        edges: Iterable[ManualCorrelationEdge],
        author: str,
        rationale: str = "",
        tags: Iterable[str] = (),
        confidence: float | None = None,
        correlation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> ManualEventCorrelation:
        _scope_values(scope)
        candidate_id = correlation_id or str(uuid4())
        now = self._now()
        candidate = ManualEventCorrelation(
            correlation_id=candidate_id,
            scope=scope,
            subjects=tuple(subjects),
            edges=tuple(edges),
            author=author,
            rationale=rationale,
            tags=tuple(tags),
            confidence=confidence,
            version=1,
            created_at_ns=now,
            updated_at_ns=now,
        )
        request = candidate.to_dict()
        request["correlation_id"] = correlation_id
        for name in (
            "created_at_ns",
            "updated_at_ns",
            "version",
            "deleted_at_ns",
            "tombstoned",
        ):
            request.pop(name)
        digest = strict_canonical_json_sha256(request)
        with self._transaction() as connection:
            prior = self._idempotent_result(
                connection,
                scope=scope,
                idempotency_key=idempotency_key,
                request_sha256=digest,
            )
            if prior is not None:
                return _correlation_from_dict(prior)
            try:
                connection.execute(
                    """
                    INSERT INTO manual_event_correlation (
                        tenant_id, project_id, workspace_id, correlation_id,
                        author, rationale, tags_json, confidence, version,
                        created_at_ns, updated_at_ns, deleted_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)
                    """,
                    (
                        *_scope_values(scope),
                        candidate.correlation_id,
                        candidate.author,
                        candidate.rationale,
                        _canonical_json(list(candidate.tags)),
                        candidate.confidence,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ReviewConflictError(
                    f"correlation already exists: {candidate.correlation_id}"
                ) from error
            self._insert_subjects(
                connection,
                "manual_event_correlation_subject",
                "correlation_id",
                scope,
                candidate.correlation_id,
                candidate.subjects,
            )
            scope_values = _scope_values(scope)
            for ordinal, edge in enumerate(candidate.edges):
                connection.execute(
                    """
                    INSERT INTO manual_event_correlation_edge (
                        tenant_id, project_id, workspace_id, correlation_id,
                        ordinal, source_ordinal, target_ordinal, link_type,
                        directed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *scope_values,
                        candidate.correlation_id,
                        ordinal,
                        edge.source_ordinal,
                        edge.target_ordinal,
                        edge.link_type,
                        int(edge.directed),
                    ),
                )
            stored = self._correlation(
                connection,
                scope,
                candidate.correlation_id,
                include_deleted=True,
            )
            snapshot = stored.to_dict()
            self._audit(
                connection,
                scope=scope,
                entity_kind="manual_event_correlation",
                entity_id=stored.correlation_id,
                operation="create",
                version=stored.version,
                actor=author,
                occurred_at_ns=now,
                snapshot=snapshot,
            )
            self._remember_idempotency(
                connection,
                scope=scope,
                idempotency_key=idempotency_key,
                request_sha256=digest,
                entity_kind="manual_event_correlation",
                entity_id=stored.correlation_id,
                result=snapshot,
                created_at_ns=now,
            )
            return stored

    def get_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ManualEventCorrelation:
        _scope_values(scope)
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            return self._correlation(
                self._connection,
                scope,
                correlation_id,
                include_deleted=include_deleted,
            )

    def list_correlations(
        self,
        scope: ReviewScope,
        *,
        include_deleted: bool = False,
        limit: int = 1_000,
        offset: int = 0,
    ) -> tuple[ManualEventCorrelation, ...]:
        _scope_values(scope)
        if type(limit) is not int or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ReviewValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        _exact_non_negative_int(offset, "offset")
        where, values = self._where(scope)
        deleted = "" if include_deleted else " AND deleted_at_ns IS NULL"
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            rows = self._connection.execute(
                f"""
                SELECT correlation_id FROM manual_event_correlation
                WHERE {where}{deleted}
                ORDER BY correlation_id
                LIMIT ? OFFSET ?
                """,
                (*values, limit, offset),
            ).fetchall()
            return tuple(
                self._correlation(
                    self._connection,
                    scope,
                    row["correlation_id"],
                    include_deleted=include_deleted,
                )
                for row in rows
            )

    def update_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        expected_version: int,
        actor: str,
        subjects: Iterable[ReviewSubject] | object = _UNSET,
        edges: Iterable[ManualCorrelationEdge] | object = _UNSET,
        rationale: str | object = _UNSET,
        tags: Iterable[str] | object = _UNSET,
        confidence: float | None | object = _UNSET,
    ) -> ManualEventCorrelation:
        _scope_values(scope)
        _exact_positive_int(expected_version, "expected_version")
        _bounded_text(actor, "actor", MAX_AUTHOR_LENGTH)
        with self._transaction() as connection:
            current = self._correlation(
                connection,
                scope,
                correlation_id,
                include_deleted=False,
            )
            if current.version != expected_version:
                raise ReviewConflictError(
                    f"correlation version is {current.version}, expected "
                    f"{expected_version}"
                )
            next_rationale = current.rationale
            if rationale is not _UNSET:
                if type(rationale) is not str:
                    raise ReviewValidationError("rationale must be a string")
                next_rationale = rationale
            next_confidence = current.confidence
            if confidence is not _UNSET:
                if confidence is None:
                    next_confidence = None
                elif (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not math.isfinite(float(confidence))
                    or not 0.0 <= float(confidence) <= 1.0
                ):
                    raise ReviewValidationError(
                        "confidence must be a finite number between 0 and 1"
                    )
                else:
                    next_confidence = float(confidence)
            next_value = ManualEventCorrelation(
                correlation_id=current.correlation_id,
                scope=scope,
                subjects=(
                    current.subjects if subjects is _UNSET else tuple(subjects)  # type: ignore[arg-type]
                ),
                edges=(
                    current.edges if edges is _UNSET else tuple(edges)  # type: ignore[arg-type]
                ),
                author=current.author,
                rationale=next_rationale,
                tags=(
                    current.tags if tags is _UNSET else tuple(tags)  # type: ignore[arg-type]
                ),
                confidence=next_confidence,
                version=current.version + 1,
                created_at_ns=current.created_at_ns,
                updated_at_ns=self._now(),
            )
            where, values = self._where(scope)
            cursor = connection.execute(
                f"""
                UPDATE manual_event_correlation
                SET rationale = ?, tags_json = ?, confidence = ?,
                    version = ?, updated_at_ns = ?
                WHERE {where} AND correlation_id = ? AND version = ?
                      AND deleted_at_ns IS NULL
                """,
                (
                    next_value.rationale,
                    _canonical_json(list(next_value.tags)),
                    next_value.confidence,
                    next_value.version,
                    next_value.updated_at_ns,
                    *values,
                    correlation_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ReviewConflictError("correlation changed concurrently")
            connection.execute(
                f"""
                DELETE FROM manual_event_correlation_edge
                WHERE {where} AND correlation_id = ?
                """,
                (*values, correlation_id),
            )
            connection.execute(
                f"""
                DELETE FROM manual_event_correlation_subject
                WHERE {where} AND correlation_id = ?
                """,
                (*values, correlation_id),
            )
            self._insert_subjects(
                connection,
                "manual_event_correlation_subject",
                "correlation_id",
                scope,
                correlation_id,
                next_value.subjects,
            )
            for ordinal, edge in enumerate(next_value.edges):
                connection.execute(
                    """
                    INSERT INTO manual_event_correlation_edge (
                        tenant_id, project_id, workspace_id, correlation_id,
                        ordinal, source_ordinal, target_ordinal, link_type,
                        directed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *_scope_values(scope),
                        correlation_id,
                        ordinal,
                        edge.source_ordinal,
                        edge.target_ordinal,
                        edge.link_type,
                        int(edge.directed),
                    ),
                )
            stored = self._correlation(
                connection,
                scope,
                correlation_id,
                include_deleted=True,
            )
            self._audit(
                connection,
                scope=scope,
                entity_kind="manual_event_correlation",
                entity_id=correlation_id,
                operation="update",
                version=stored.version,
                actor=actor,
                occurred_at_ns=stored.updated_at_ns,
                snapshot=stored.to_dict(),
            )
            return stored

    def delete_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        expected_version: int,
        actor: str,
    ) -> ManualEventCorrelation:
        _scope_values(scope)
        _exact_positive_int(expected_version, "expected_version")
        _bounded_text(actor, "actor", MAX_AUTHOR_LENGTH)
        with self._transaction() as connection:
            current = self._correlation(
                connection,
                scope,
                correlation_id,
                include_deleted=False,
            )
            if current.version != expected_version:
                raise ReviewConflictError(
                    f"correlation version is {current.version}, expected "
                    f"{expected_version}"
                )
            now = self._now()
            next_version = current.version + 1
            where, values = self._where(scope)
            cursor = connection.execute(
                f"""
                UPDATE manual_event_correlation
                SET version = ?, updated_at_ns = ?, deleted_at_ns = ?
                WHERE {where} AND correlation_id = ? AND version = ?
                      AND deleted_at_ns IS NULL
                """,
                (
                    next_version,
                    now,
                    now,
                    *values,
                    correlation_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ReviewConflictError("correlation changed concurrently")
            stored = self._correlation(
                connection,
                scope,
                correlation_id,
                include_deleted=True,
            )
            self._audit(
                connection,
                scope=scope,
                entity_kind="manual_event_correlation",
                entity_id=correlation_id,
                operation="delete",
                version=stored.version,
                actor=actor,
                occurred_at_ns=now,
                snapshot=stored.to_dict(),
            )
            return stored

    def list_audit(
        self,
        scope: ReviewScope,
        *,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[ReviewAuditEntry, ...]:
        _scope_values(scope)
        _exact_non_negative_int(after_sequence, "after_sequence")
        if type(limit) is not int or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ReviewValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        where, values = self._where(scope)
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            rows = self._connection.execute(
                f"""
                SELECT * FROM review_overlay_audit
                WHERE {where} AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (*values, after_sequence, limit),
            ).fetchall()
        return tuple(
            ReviewAuditEntry(
                sequence=row["sequence"],
                scope=scope,
                entity_kind=row["entity_kind"],
                entity_id=row["entity_id"],
                operation=row["operation"],
                version=row["version"],
                actor=row["actor"],
                occurred_at_ns=row["occurred_at_ns"],
                snapshot=json.loads(row["snapshot_json"]),
            )
            for row in rows
        )

    def audit_watermark(self, scope: ReviewScope) -> int:
        _scope_values(scope)
        where, values = self._where(scope)
        with self._lock:
            if self._closed:
                raise ReviewOverlayError("review overlay store is closed")
            row = self._connection.execute(
                f"""
                SELECT COALESCE(MAX(sequence), 0) AS watermark
                FROM review_overlay_audit
                WHERE {where}
                """,
                values,
            ).fetchone()
        return int(row["watermark"])

    def referenced_revision_ids(
        self,
        scope: ReviewScope,
        *,
        maximum_revision_ids: int = MAX_REFERENCE_REVISION_IDS,
    ) -> tuple[str, ...]:
        """Return every revision referenced by retained review records.

        Both live records and soft-deleted tombstones are included.  The
        method is deliberately non-paginated so a retention coordinator
        cannot accidentally mistake one page for a complete reference set;
        it fails closed when the explicit bound would be exceeded.
        """

        scope_values = _scope_values(scope)
        if (
            type(maximum_revision_ids) is not int
            or not 1 <= maximum_revision_ids <= MAX_REFERENCE_REVISION_IDS
        ):
            raise ReviewValidationError(
                "maximum_revision_ids must be between 1 and "
                f"{MAX_REFERENCE_REVISION_IDS}"
            )
        with self._transaction(begin="BEGIN") as connection:
            rows = connection.execute(
                """
                SELECT revision_id
                FROM (
                    SELECT revision_id
                    FROM review_annotation_subject
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ?
                    UNION
                    SELECT revision_id
                    FROM manual_event_correlation_subject
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ?
                )
                ORDER BY revision_id
                LIMIT ?
                """,
                (
                    *scope_values,
                    *scope_values,
                    maximum_revision_ids + 1,
                ),
            ).fetchall()
        if len(rows) > maximum_revision_ids:
            raise ReviewValidationError(
                "retained review records exceed the bounded revision-reference "
                "query; no partial result was returned"
            )
        return tuple(str(row["revision_id"]) for row in rows)

    @staticmethod
    def _retention_inventory_from_connection(
        connection: sqlite3.Connection,
        scope: ReviewScope,
        policy: ReviewRetentionPolicy,
    ) -> ReviewRetentionInventory:
        scope_values = _scope_values(scope)
        maximum = policy.maximum_candidates
        candidates: list[ReviewRetentionCandidate] = []
        total = 0

        def remaining() -> int:
            return maximum - len(candidates)

        if policy.idempotency_before_ns is not None:
            cutoff = policy.idempotency_before_ns
            count_row = connection.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM review_overlay_idempotency
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND created_at_ns < ?
                """,
                (*scope_values, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                rows = connection.execute(
                    """
                    SELECT idempotency_key, created_at_ns
                    FROM review_overlay_idempotency
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ? AND created_at_ns < ?
                    ORDER BY created_at_ns, idempotency_key
                    LIMIT ?
                    """,
                    (*scope_values, cutoff, remaining()),
                ).fetchall()
                candidates.extend(
                    ReviewRetentionCandidate(
                        category="review_idempotency",
                        identifier=row["idempotency_key"],
                        retention_value=int(row["created_at_ns"]),
                    )
                    for row in rows
                )

        def append_tombstones(
            *,
            table: str,
            identifier_column: str,
            entity_kind: str,
            category: str,
        ) -> None:
            nonlocal total
            cutoff = policy.tombstone_before_ns
            if cutoff is None:
                return
            count_row = connection.execute(
                f"""
                SELECT COUNT(*) AS candidate_count FROM {table}
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND deleted_at_ns IS NOT NULL AND deleted_at_ns < ?
                """,
                (*scope_values, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() <= 0:
                return
            live_receipt_clause = ""
            parameters: list[Any] = []
            if policy.idempotency_before_ns is not None:
                live_receipt_clause = " AND i.created_at_ns >= ?"
                parameters.append(policy.idempotency_before_ns)
            rows = connection.execute(
                f"""
                SELECT item.{identifier_column} AS identifier,
                       item.deleted_at_ns,
                       EXISTS (
                           SELECT 1 FROM review_overlay_idempotency AS i
                           WHERE i.tenant_id = item.tenant_id
                             AND i.project_id = item.project_id
                             AND i.workspace_id = item.workspace_id
                             AND i.entity_kind = ?
                             AND i.entity_id = item.{identifier_column}
                             {live_receipt_clause}
                       ) AS has_live_receipt
                FROM {table} AS item
                WHERE item.tenant_id = ? AND item.project_id = ?
                  AND item.workspace_id = ?
                  AND item.deleted_at_ns IS NOT NULL
                  AND item.deleted_at_ns < ?
                ORDER BY item.deleted_at_ns, item.{identifier_column}
                LIMIT ?
                """,
                (
                    entity_kind,
                    *parameters,
                    *scope_values,
                    cutoff,
                    remaining(),
                ),
            ).fetchall()
            candidates.extend(
                ReviewRetentionCandidate(
                    category=category,
                    identifier=row["identifier"],
                    retention_value=int(row["deleted_at_ns"]),
                    blockers=(
                        ("unexpired_idempotency_receipt",)
                        if row["has_live_receipt"]
                        else ()
                    ),
                )
                for row in rows
            )

        append_tombstones(
            table="review_annotation",
            identifier_column="annotation_id",
            entity_kind="annotation",
            category="annotation_tombstone",
        )
        append_tombstones(
            table="manual_event_correlation",
            identifier_column="correlation_id",
            entity_kind="manual_event_correlation",
            category="correlation_tombstone",
        )

        if policy.audit_mode is ReviewAuditRetentionMode.PRUNE_EXPLICIT:
            assert policy.audit_before_sequence is not None
            cutoff = policy.audit_before_sequence
            count_row = connection.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM review_overlay_audit
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND sequence < ?
                """,
                (*scope_values, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                rows = connection.execute(
                    """
                    SELECT sequence FROM review_overlay_audit
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ? AND sequence < ?
                    ORDER BY sequence
                    LIMIT ?
                    """,
                    (*scope_values, cutoff, remaining()),
                ).fetchall()
                candidates.extend(
                    ReviewRetentionCandidate(
                        category="audit_history",
                        identifier=str(row["sequence"]),
                        retention_value=int(row["sequence"]),
                    )
                    for row in rows
                )

        return ReviewRetentionInventory(
            scope=scope,
            policy=policy,
            total_candidate_count=total,
            candidates=tuple(candidates),
            truncated=total > len(candidates),
        )

    def inventory_retention(
        self,
        scope: ReviewScope,
        policy: ReviewRetentionPolicy | None = None,
    ) -> ReviewRetentionInventory:
        """Return a bounded dry-run inventory without deleting anything."""

        _scope_values(scope)
        if policy is None:
            policy = ReviewRetentionPolicy()
        if type(policy) is not ReviewRetentionPolicy:
            raise ReviewValidationError("policy must be an exact ReviewRetentionPolicy")
        with self._transaction(begin="BEGIN") as connection:
            return self._retention_inventory_from_connection(
                connection,
                scope,
                policy,
            )

    def purge_retention(
        self,
        scope: ReviewScope,
        policy: ReviewRetentionPolicy,
        *,
        actor: str = "system",
        operation_id: str | None = None,
    ) -> ReviewRetentionResult:
        """Physically purge only the bounded, explicitly enabled inventory."""

        _scope_values(scope)
        if type(policy) is not ReviewRetentionPolicy:
            raise ReviewValidationError("policy must be an exact ReviewRetentionPolicy")
        if not policy.enabled:
            raise ReviewRetentionDisabledError(
                "review retention is disabled; dry-run with inventory_retention"
            )
        retention_actor = _bounded_text(actor, "actor", MAX_AUTHOR_LENGTH)
        retention_operation_id = _bounded_text(
            operation_id or f"review-retention-{uuid4()}",
            "operation_id",
            MAX_IDENTIFIER_LENGTH,
        )
        scope_values = _scope_values(scope)
        policy_document = _review_retention_policy_document(policy)
        policy_json = _canonical_json(policy_document)
        with self._transaction() as connection:
            existing_operation = connection.execute(
                """
                SELECT actor, policy_json, result_json
                FROM review_retention_audit
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND operation_id = ?
                """,
                (*scope_values, retention_operation_id),
            ).fetchone()
            if existing_operation is not None:
                try:
                    stored_policy_json = _canonical_json(
                        json.loads(existing_operation["policy_json"])
                    )
                except (
                    TypeError,
                    json.JSONDecodeError,
                    ReviewValidationError,
                ) as error:
                    raise ReviewOverlayError(
                        "stored retention operation policy is invalid"
                    ) from error
                if (
                    str(existing_operation["actor"]) != retention_actor
                    or stored_policy_json != policy_json
                ):
                    raise ReviewConflictError(
                        "retention operation_id was already used for a "
                        "different actor or policy"
                    )
                stored_result_json = existing_operation["result_json"]
                if not isinstance(stored_result_json, str) or not stored_result_json:
                    raise ReviewConflictError(
                        "retention operation_id belongs to a legacy operation "
                        "that cannot be replayed exactly"
                    )
                return _review_retention_result_from_json(
                    stored_result_json,
                    scope=scope,
                    policy=policy,
                )
            inventory = self._retention_inventory_from_connection(
                connection,
                scope,
                policy,
            )
            purged: list[ReviewRetentionCandidate] = []
            for candidate in inventory.candidates:
                if candidate.blockers:
                    continue
                if candidate.category == "review_idempotency":
                    assert policy.idempotency_before_ns is not None
                    cursor = connection.execute(
                        """
                        DELETE FROM review_overlay_idempotency
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND idempotency_key = ?
                          AND created_at_ns < ?
                        """,
                        (
                            *scope_values,
                            candidate.identifier,
                            policy.idempotency_before_ns,
                        ),
                    )
                elif candidate.category == "annotation_tombstone":
                    assert policy.tombstone_before_ns is not None
                    live = connection.execute(
                        """
                        SELECT 1 FROM review_overlay_idempotency
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND entity_kind = 'annotation'
                          AND entity_id = ? LIMIT 1
                        """,
                        (*scope_values, candidate.identifier),
                    ).fetchone()
                    if live is not None:
                        continue
                    connection.execute(
                        """
                        DELETE FROM review_annotation_subject
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND annotation_id = ?
                        """,
                        (*scope_values, candidate.identifier),
                    )
                    cursor = connection.execute(
                        """
                        DELETE FROM review_annotation
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND annotation_id = ?
                          AND deleted_at_ns IS NOT NULL
                          AND deleted_at_ns < ?
                        """,
                        (
                            *scope_values,
                            candidate.identifier,
                            policy.tombstone_before_ns,
                        ),
                    )
                elif candidate.category == "correlation_tombstone":
                    assert policy.tombstone_before_ns is not None
                    live = connection.execute(
                        """
                        SELECT 1 FROM review_overlay_idempotency
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ?
                          AND entity_kind = 'manual_event_correlation'
                          AND entity_id = ? LIMIT 1
                        """,
                        (*scope_values, candidate.identifier),
                    ).fetchone()
                    if live is not None:
                        continue
                    connection.execute(
                        """
                        DELETE FROM manual_event_correlation_edge
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND correlation_id = ?
                        """,
                        (*scope_values, candidate.identifier),
                    )
                    connection.execute(
                        """
                        DELETE FROM manual_event_correlation_subject
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND correlation_id = ?
                        """,
                        (*scope_values, candidate.identifier),
                    )
                    cursor = connection.execute(
                        """
                        DELETE FROM manual_event_correlation
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND correlation_id = ?
                          AND deleted_at_ns IS NOT NULL
                          AND deleted_at_ns < ?
                        """,
                        (
                            *scope_values,
                            candidate.identifier,
                            policy.tombstone_before_ns,
                        ),
                    )
                elif candidate.category == "audit_history":
                    assert policy.audit_before_sequence is not None
                    cursor = connection.execute(
                        """
                        DELETE FROM review_overlay_audit
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND sequence = ?
                          AND sequence < ?
                        """,
                        (
                            *scope_values,
                            candidate.retention_value,
                            policy.audit_before_sequence,
                        ),
                    )
                else:  # pragma: no cover - inventory is closed above
                    raise ReviewOverlayError(
                        f"unsupported retention category {candidate.category}"
                    )
                if cursor.rowcount == 1:
                    purged.append(candidate)
            result = ReviewRetentionResult(
                inventory=inventory,
                purged=tuple(purged),
            )
            purged_document = [
                {
                    "category": candidate.category,
                    "identifier": candidate.identifier,
                    "retention_value": candidate.retention_value,
                }
                for candidate in purged
            ]
            purged_json = _canonical_json(purged_document)
            result_json = _canonical_json(_review_retention_result_document(result))
            try:
                connection.execute(
                    """
                    INSERT INTO review_retention_audit (
                        tenant_id, project_id, workspace_id, operation_id,
                        actor, occurred_at_ns, policy_json, candidate_count,
                        purged_count, purged_json, purged_sha256, result_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *scope_values,
                        retention_operation_id,
                        retention_actor,
                        self._now(),
                        policy_json,
                        inventory.total_candidate_count,
                        len(purged),
                        purged_json,
                        sha256(purged_json.encode("utf-8")).hexdigest(),
                        result_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ReviewConflictError(
                    "retention operation_id was already used in this scope"
                ) from error
            return result

    def list_retention_audit(
        self,
        scope: ReviewScope,
        *,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[ReviewRetentionAuditEntry, ...]:
        """List the separate retention journal that ordinary pruning preserves."""

        scope_values = _scope_values(scope)
        _exact_non_negative_int(after_sequence, "after_sequence")
        if type(limit) is not int or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ReviewValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        with self._transaction(begin="BEGIN") as connection:
            rows = connection.execute(
                """
                SELECT * FROM review_retention_audit
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (*scope_values, after_sequence, limit),
            ).fetchall()
        result: list[ReviewRetentionAuditEntry] = []
        for row in rows:
            policy_document = json.loads(row["policy_json"])
            purged_document = json.loads(row["purged_json"])
            if not isinstance(policy_document, dict) or not isinstance(
                purged_document,
                list,
            ):
                raise ReviewOverlayError("stored retention audit is invalid")
            result.append(
                ReviewRetentionAuditEntry(
                    sequence=int(row["sequence"]),
                    scope=scope,
                    operation_id=str(row["operation_id"]),
                    actor=str(row["actor"]),
                    occurred_at_ns=int(row["occurred_at_ns"]),
                    policy=policy_document,
                    candidate_count=int(row["candidate_count"]),
                    purged_count=int(row["purged_count"]),
                    purged=tuple(
                        item for item in purged_document if isinstance(item, dict)
                    ),
                    purged_sha256=str(row["purged_sha256"]),
                )
            )
            if len(result[-1].purged) != len(purged_document):
                raise ReviewOverlayError("stored retention audit is invalid")
            if (
                result[-1].purged_count != len(result[-1].purged)
                or sha256(_canonical_json(purged_document).encode("utf-8")).hexdigest()
                != result[-1].purged_sha256
            ):
                raise ReviewOverlayError(
                    "stored retention audit digest or count is invalid"
                )
        return tuple(result)

    def snapshot_for_report(
        self,
        scope: ReviewScope,
        *,
        maximum_annotations: int = MAX_REPORT_ITEMS_PER_COLLECTION,
        maximum_correlations: int = MAX_REPORT_ITEMS_PER_COLLECTION,
    ) -> ReviewOverlaySnapshot:
        """Read review records and their audit watermark from one DB snapshot.

        The watermark is read first to establish the SQLite read snapshot.
        Concurrent writers may commit while the report is assembled, but
        every returned record is guaranteed to be no newer than this
        watermark and no record visible at the watermark can disappear
        between the annotation and correlation reads.
        """

        _scope_values(scope)
        for label, value in (
            ("maximum_annotations", maximum_annotations),
            ("maximum_correlations", maximum_correlations),
        ):
            if (
                type(value) is not int
                or not 1 <= value <= MAX_REPORT_ITEMS_PER_COLLECTION
            ):
                raise ReviewValidationError(
                    f"{label} must be between 1 and {MAX_REPORT_ITEMS_PER_COLLECTION}"
                )
        where, values = self._where(scope)
        with self._transaction(begin="BEGIN") as connection:
            watermark_row = connection.execute(
                f"""
                SELECT COALESCE(MAX(sequence), 0) AS watermark
                FROM review_overlay_audit
                WHERE {where}
                """,
                values,
            ).fetchone()
            annotation_rows = connection.execute(
                f"""
                SELECT annotation_id FROM review_annotation
                WHERE {where} AND deleted_at_ns IS NULL
                ORDER BY annotation_id
                LIMIT ?
                """,
                (*values, maximum_annotations + 1),
            ).fetchall()
            correlation_rows = connection.execute(
                f"""
                SELECT correlation_id FROM manual_event_correlation
                WHERE {where} AND deleted_at_ns IS NULL
                ORDER BY correlation_id
                LIMIT ?
                """,
                (*values, maximum_correlations + 1),
            ).fetchall()
            if len(annotation_rows) > maximum_annotations:
                raise ReviewOverlayError(
                    "review annotations exceed the report collection limit"
                )
            if len(correlation_rows) > maximum_correlations:
                raise ReviewOverlayError(
                    "manual correlations exceed the report collection limit"
                )
            annotations = tuple(
                self._annotation(
                    connection,
                    scope,
                    row["annotation_id"],
                    include_deleted=False,
                )
                for row in annotation_rows
            )
            correlations = tuple(
                self._correlation(
                    connection,
                    scope,
                    row["correlation_id"],
                    include_deleted=False,
                )
                for row in correlation_rows
            )
        return ReviewOverlaySnapshot(
            scope=scope,
            audit_watermark=int(watermark_row["watermark"]),
            annotations=annotations,
            correlations=correlations,
        )


def _bounded_collection(
    values: Iterable[Any],
    *,
    label: str,
    _units: list[int] | None = None,
) -> list[Any]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise ReviewValidationError(f"{label} must be an iterable")
    result: list[Any] = []
    for value in values:
        if len(result) >= MAX_REPORT_ITEMS_PER_COLLECTION:
            raise ReviewValidationError(
                f"{label} supports at most {MAX_REPORT_ITEMS_PER_COLLECTION} items"
            )
        result.append(
            _bounded_json_copy(
                value,
                label=label,
                _units=_units,
            )
        )
    return result


def _canonical_sort(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    copied = [dict(value) for value in values]
    return sorted(copied, key=_canonical_json)


def _revision_sort_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(value.get("node_id") or ""),
        str(value.get("revision_id") or ""),
        _canonical_json(value),
    )


def _observation_sort_key(value: Mapping[str, Any]) -> tuple[int, str, str, str]:
    raw_time = (
        value.get("timestamp_ns")
        if value.get("timestamp_ns") is not None
        else value.get("time_ns")
        if value.get("time_ns") is not None
        else value.get("absolute_timestamp_ns")
    )
    timestamp = (
        2**MAX_REPORT_JSON_INTEGER_BITS
        if raw_time is None
        else int(
            _report_ns_string(
                raw_time,
                label="observation timestamp",
            )
        )
    )
    identifier = str(
        value.get("event_uid")
        or value.get("source_record_uid")
        or value.get("resource_id")
        or value.get("id")
        or ""
    )
    return (
        timestamp,
        str(value.get("revision_id") or ""),
        identifier,
        _canonical_json(value),
    )


def _report_ns_string(value: Any, *, label: str) -> str:
    """Normalize one v2 nanosecond scalar to a canonical decimal string."""

    try:
        number = parse_canonical_decimal_integer(
            value,
            label,
            max_bits=MAX_REPORT_JSON_INTEGER_BITS,
        )
    except ValueError as error:
        if "exceeds" in str(error):
            raise ReviewValidationError(str(error)) from error
        raise ReviewValidationError(
            f"{label} must be a canonical decimal string or integer"
        ) from error
    return str(number)


_REPORT_EVENT_NS_FIELDS = frozenset(
    {
        "absolute_timestamp_ns",
        "time_ns",
        "timestamp_ns",
        "timestamp_uncertainty_ns",
    }
)
_REPORT_REVIEW_RECORD_NS_FIELDS = frozenset(
    {"created_at_ns", "deleted_at_ns", "updated_at_ns"}
)


def _project_report_ns_fields(
    value: Mapping[str, Any],
    fields: Iterable[str],
    *,
    path: str,
) -> dict[str, Any]:
    """Copy one core-owned record and project only its declared time fields."""

    result = dict(value)
    for field in fields:
        if field not in result:
            continue
        nested = result[field]
        result[field] = (
            None
            if nested is None
            else _report_ns_string(
                nested,
                label=f"correlation report {path}.{field}",
            )
        )
    return result


def _project_report_subjects(
    values: Any,
    *,
    path: str,
) -> Any:
    """Project time bounds in core-owned review subjects."""

    if not isinstance(values, list):
        return values
    result: list[Any] = []
    for index, value in enumerate(values):
        result.append(
            _project_report_ns_fields(
                value,
                ("start_ns", "end_ns"),
                path=f"{path}[{index}]",
            )
            if isinstance(value, Mapping)
            else value
        )
    return result


def _project_report_review_record(
    value: Mapping[str, Any],
    *,
    path: str,
) -> dict[str, Any]:
    result = _project_report_ns_fields(
        value,
        _REPORT_REVIEW_RECORD_NS_FIELDS,
        path=path,
    )
    if "subjects" in result:
        result["subjects"] = _project_report_subjects(
            result["subjects"],
            path=f"{path}.subjects",
        )
    return result


def _project_report_event_evidence(value: Any, *, path: str) -> Any:
    """Project only the declared evidence-record time field.

    Evidence records are a closed normalized envelope, but any mappings nested
    inside one record remain opaque plug-in values.  Do not recursively grant
    the core ownership of a key merely because it is named ``raw_timestamp_ns``.
    """

    if isinstance(value, Mapping):
        return _project_report_ns_fields(
            value,
            ("raw_timestamp_ns",),
            path=path,
        )
    if isinstance(value, list):
        return [
            _project_report_ns_fields(
                item,
                ("raw_timestamp_ns",),
                path=f"{path}[{index}]",
            )
            if isinstance(item, Mapping)
            else item
            for index, item in enumerate(value)
        ]
    return value


def _project_report_event(
    value: Mapping[str, Any],
    *,
    path: str,
) -> dict[str, Any]:
    result = _project_report_ns_fields(
        value,
        _REPORT_EVENT_NS_FIELDS,
        path=path,
    )
    if "evidence" in result:
        result["evidence"] = _project_report_event_evidence(
            result["evidence"],
            path=f"{path}.evidence",
        )
    return result


def _report_wire_projection(document: Mapping[str, Any]) -> dict[str, Any]:
    """Project declared core times onto the correlation-report v2 wire.

    The ``*_ns`` suffix is not reserved for core use. Plug-in-owned attributes,
    effects, causal-link values, and corroboration evidence therefore remain
    opaque and retain their original JSON types. Only fields at closed,
    core-owned report paths become canonical decimal strings.
    """

    result = dict(document)
    revision_vector = result.get("revision_vector")
    if isinstance(revision_vector, list):
        result["revision_vector"] = [
            _project_report_ns_fields(
                value,
                ("published_at_ns",),
                path=f"$.revision_vector[{index}]",
            )
            if isinstance(value, Mapping)
            else value
            for index, value in enumerate(revision_vector)
        ]

    annotations = result.get("annotations")
    if isinstance(annotations, list):
        result["annotations"] = [
            _project_report_review_record(
                value,
                path=f"$.annotations[{index}]",
            )
            if isinstance(value, Mapping)
            else value
            for index, value in enumerate(annotations)
        ]

    observations = result.get("observations")
    if isinstance(observations, Mapping):
        projected_observations = dict(observations)
        events = projected_observations.get("events")
        if isinstance(events, list):
            projected_observations["events"] = [
                _project_report_event(
                    value,
                    path=f"$.observations.events[{index}]",
                )
                if isinstance(value, Mapping)
                else value
                for index, value in enumerate(events)
            ]
        source_records = projected_observations.get("source_records")
        if isinstance(source_records, list):
            projected_observations["source_records"] = [
                _project_report_ns_fields(
                    value,
                    ("timestamp_ns",),
                    path=f"$.observations.source_records[{index}]",
                )
                if isinstance(value, Mapping)
                else value
                for index, value in enumerate(source_records)
            ]
        result["observations"] = projected_observations

    correlations = result.get("correlations")
    if isinstance(correlations, Mapping):
        projected_correlations = dict(correlations)
        manual = projected_correlations.get("manual_event_correlations")
        if isinstance(manual, list):
            projected_manual: list[Any] = []
            for index, wrapper in enumerate(manual):
                if not isinstance(wrapper, Mapping):
                    projected_manual.append(wrapper)
                    continue
                projected_wrapper = dict(wrapper)
                correlation = projected_wrapper.get("correlation")
                if isinstance(correlation, Mapping):
                    projected_wrapper["correlation"] = _project_report_review_record(
                        correlation,
                        path=(
                            "$.correlations.manual_event_correlations"
                            f"[{index}].correlation"
                        ),
                    )
                projected_manual.append(projected_wrapper)
            projected_correlations["manual_event_correlations"] = projected_manual
        result["correlations"] = projected_correlations
    return result


def _validate_observation_identities(
    values: Sequence[Mapping[str, Any]],
    *,
    label: str,
    identity_field: str,
) -> None:
    identities: set[tuple[str, str]] = set()
    for value in values:
        revision_id = _bounded_text(
            value.get("revision_id"),
            f"{label} revision_id",
            MAX_IDENTIFIER_LENGTH,
        )
        identifier = _bounded_text(
            value.get(identity_field),
            f"{label} {identity_field}",
            MAX_IDENTIFIER_LENGTH,
        )
        identity = (revision_id, identifier)
        if identity in identities:
            raise ReviewValidationError(
                f"{label} contains duplicate revision/{identity_field} identity"
            )
        identities.add(identity)


def _validate_revision_vector(
    values: Iterable[Any],
    *,
    _units: list[int] | None = None,
) -> list[dict[str, Any]]:
    copied = _bounded_collection(
        values,
        label="revision_vector",
        _units=_units,
    )
    if not copied:
        raise ReviewValidationError(
            "revision_vector must contain at least one revision"
        )
    result: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for value in copied:
        if not isinstance(value, dict):
            raise ReviewValidationError("revision_vector items must be objects")
        revision_id = _bounded_text(
            value.get("revision_id"),
            "revision_vector revision_id",
            MAX_IDENTIFIER_LENGTH,
        )
        node_id = str(value.get("node_id") or "")
        if node_id:
            _bounded_text(
                node_id,
                "revision_vector node_id",
                MAX_IDENTIFIER_LENGTH,
            )
        identity = (node_id, revision_id)
        if identity in identities:
            raise ReviewValidationError(
                "revision_vector contains duplicate node/revision identity"
            )
        identities.add(identity)
        result.append(value)
    return sorted(result, key=_revision_sort_key)


def _validate_corroboration_facts(
    values: Iterable[Any],
    *,
    _units: list[int] | None = None,
) -> list[dict[str, Any]]:
    copied = _bounded_collection(
        values,
        label="corroboration_facts",
        _units=_units,
    )
    result: list[dict[str, Any]] = []
    for value in copied:
        if not isinstance(value, dict):
            raise ReviewValidationError("corroboration_facts items must be objects")
        _bounded_text(
            value.get("fact_type"),
            "corroboration fact_type",
            MAX_IDENTIFIER_LENGTH,
        )
        raw_result = value.get("result")
        if type(raw_result) is not str:
            raise ReviewValidationError(
                "corroboration result must be supports, contradicts, or unknown"
            )
        try:
            CorroborationResult(raw_result)
        except (TypeError, ValueError) as error:
            raise ReviewValidationError(
                "corroboration result must be supports, contradicts, or unknown"
            ) from error
        result.append(value)
    return _canonical_sort(result)


def _report_markdown(document: Mapping[str, Any], digest: str) -> str:
    scope = document["scope"]
    summary = document["summary"]
    lines = [
        "# Router Dump Analyzer correlation report",
        "",
        f"- Schema: {_markdown_inline_code(document['schema_version'])}",
        f"- Tenant: {_markdown_inline_code(scope['tenant_id'])}",
        f"- Project: {_markdown_inline_code(scope['project_id'])}",
        f"- Workspace: {_markdown_inline_code(scope['workspace_id'])}",
        (
            "- Annotation watermark: "
            f"{_markdown_inline_code(document['annotation_watermark'])}"
        ),
        f"- Content SHA-256: {_markdown_inline_code(digest)}",
        "",
        "## Summary",
        "",
        f"- Revisions: {summary['revision_count']}",
        f"- Events: {summary['event_count']}",
        f"- Source records: {summary['source_record_count']}",
        f"- Review annotations: {summary['annotation_count']}",
        f"- Plug-in causal links: {summary['plugin_causal_link_count']}",
        f"- User-asserted correlations: {summary['manual_correlation_count']}",
        f"- Corroboration facts: {summary['corroboration_fact_count']}",
        f"- Unresolved references: {summary['unresolved_reference_count']}",
        "",
    ]
    sections = (
        ("Revision vector", document["revision_vector"]),
        ("Events", document["observations"]["events"]),
        ("Source records", document["observations"]["source_records"]),
        ("Review annotations", document["annotations"]),
        (
            "Plug-in causal links",
            document["correlations"]["plugin_causal_links"],
        ),
        (
            "User-asserted correlations",
            document["correlations"]["manual_event_correlations"],
        ),
        ("Corroboration facts", document["corroboration_facts"]),
        ("Unresolved references", document["unresolved_references"]),
        ("Warnings", document["warnings"]),
    )
    for heading, values in sections:
        lines.extend((f"## {heading}", ""))
        if not values:
            lines.extend(("(none)", ""))
            continue
        for value in values:
            lines.append(f"    {_canonical_json(value)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _markdown_inline_code(value: Any) -> str:
    """Render one untrusted scalar as newline-safe CommonMark inline code."""

    text = str(value).replace("\r", " ").replace("\n", " ")
    longest = 0
    run = 0
    for character in text:
        if character == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * (longest + 1)
    if text.startswith(("`", " ")) or text.endswith(("`", " ")):
        text = f" {text} "
    return f"{fence}{text}{fence}"


def build_correlation_report(
    scope: ReviewScope,
    *,
    revision_vector: Iterable[Mapping[str, Any]],
    annotation_watermark: int,
    annotations: Iterable[ReviewAnnotation] = (),
    manual_correlations: Iterable[ManualEventCorrelation] = (),
    events: Iterable[Mapping[str, Any]] = (),
    source_records: Iterable[Mapping[str, Any]] = (),
    plugin_causal_links: Iterable[Mapping[str, Any]] = (),
    corroboration_facts: Iterable[Mapping[str, Any]] = (),
    unresolved_references: Iterable[Mapping[str, Any]] = (),
    warnings: Iterable[str | Mapping[str, Any]] = (),
) -> CorrelationReport:
    """Build deterministic canonical JSON and Markdown for AI consumption.

    All supplied event/source/link values must already be authorized and
    redacted.  Plug-in causal links and user assertions are intentionally
    represented in separate arrays.  ``generated_at`` is omitted so the same
    frozen revisions, annotation watermark, and inputs produce identical
    bytes.
    """

    _scope_values(scope)
    _exact_non_negative_int(annotation_watermark, "annotation_watermark")
    input_units = [0]
    revision_items = _validate_revision_vector(
        revision_vector,
        _units=input_units,
    )

    annotation_items: list[dict[str, Any]] = []
    for annotation_index, annotation in enumerate(annotations):
        if annotation_index >= MAX_REPORT_ITEMS_PER_COLLECTION:
            raise ReviewValidationError("too many annotations for one report")
        if type(annotation) is not ReviewAnnotation:
            raise ReviewValidationError(
                "annotations must contain exact ReviewAnnotation values"
            )
        if annotation.scope != scope:
            raise KeyError(annotation.annotation_id)
        if annotation.tombstoned:
            continue
        annotation_items.append(
            _bounded_json_copy(
                annotation.to_dict(include_scope=False),
                label="annotations",
                _units=input_units,
            )
        )
    annotation_items.sort(key=lambda value: str(value["annotation_id"]))

    manual_items: list[dict[str, Any]] = []
    for correlation_index, correlation in enumerate(manual_correlations):
        if correlation_index >= MAX_REPORT_ITEMS_PER_COLLECTION:
            raise ReviewValidationError("too many manual correlations for one report")
        if type(correlation) is not ManualEventCorrelation:
            raise ReviewValidationError(
                "manual_correlations must contain exact ManualEventCorrelation values"
            )
        if correlation.scope != scope:
            raise KeyError(correlation.correlation_id)
        if correlation.tombstoned:
            continue
        manual_items.append(
            {
                "provenance_class": (
                    CorrelationReportProvenanceClass.USER_ASSERTED.value
                ),
                "correlation": _bounded_json_copy(
                    correlation.to_dict(include_scope=False),
                    label="manual_correlations",
                    _units=input_units,
                ),
            }
        )
    manual_items.sort(key=lambda value: str(value["correlation"]["correlation_id"]))

    event_items = _bounded_collection(
        events,
        label="events",
        _units=input_units,
    )
    source_items = _bounded_collection(
        source_records,
        label="source_records",
        _units=input_units,
    )
    if any(not isinstance(value, dict) for value in event_items):
        raise ReviewValidationError("events must contain objects")
    if any(not isinstance(value, dict) for value in source_items):
        raise ReviewValidationError("source_records must contain objects")
    _validate_observation_identities(
        event_items,
        label="events",
        identity_field="event_uid",
    )
    _validate_observation_identities(
        source_items,
        label="source_records",
        identity_field="source_record_uid",
    )
    event_items.sort(key=_observation_sort_key)
    source_items.sort(key=_observation_sort_key)

    plugin_items = _bounded_collection(
        plugin_causal_links,
        label="plugin_causal_links",
        _units=input_units,
    )
    if any(not isinstance(value, dict) for value in plugin_items):
        raise ReviewValidationError("plugin_causal_links must contain objects")
    separated_plugin_items = _canonical_sort(
        {
            "provenance_class": (
                CorrelationReportProvenanceClass.PLUGIN_INFERRED.value
            ),
            "link": value,
        }
        for value in plugin_items
    )
    corroboration_items = _validate_corroboration_facts(
        corroboration_facts,
        _units=input_units,
    )
    corroboration_items = [
        {
            "provenance_class": (
                CorrelationReportProvenanceClass.CORE_CORROBORATION.value
            ),
            "fact": value,
        }
        for value in corroboration_items
    ]
    unresolved_items = _bounded_collection(
        unresolved_references,
        label="unresolved_references",
        _units=input_units,
    )
    if any(not isinstance(value, dict) for value in unresolved_items):
        raise ReviewValidationError("unresolved_references must contain objects")
    unresolved_items = _canonical_sort(unresolved_items)
    warning_items = _bounded_collection(
        warnings,
        label="warnings",
        _units=input_units,
    )
    if any(not isinstance(value, (str, dict)) for value in warning_items):
        raise ReviewValidationError("warnings must contain strings or objects")
    warning_items.sort(key=_canonical_json)

    document: dict[str, Any] = {
        "schema_version": CORRELATION_REPORT_SCHEMA_VERSION,
        "scope": _bounded_json_copy(
            scope.to_dict(),
            label="scope",
            _units=input_units,
        ),
        "annotation_watermark": annotation_watermark,
        "revision_vector": revision_items,
        "summary": {
            "revision_count": len(revision_items),
            "event_count": len(event_items),
            "source_record_count": len(source_items),
            "annotation_count": len(annotation_items),
            "plugin_causal_link_count": len(separated_plugin_items),
            "manual_correlation_count": len(manual_items),
            "corroboration_fact_count": len(corroboration_items),
            "unresolved_reference_count": len(unresolved_items),
            "warning_count": len(warning_items),
        },
        "observations": {
            "events": event_items,
            "source_records": source_items,
        },
        "annotations": annotation_items,
        "correlations": {
            "plugin_causal_links": separated_plugin_items,
            "manual_event_correlations": manual_items,
        },
        "corroboration_facts": corroboration_items,
        "unresolved_references": unresolved_items,
        "warnings": warning_items,
    }
    bounded_document = _bounded_json_copy(
        _report_wire_projection(document),
        label="correlation report",
        _sanitize_text=False,
    )
    canonical = _canonical_json(bounded_document)
    digest = strict_canonical_json_sha256(bounded_document)
    markdown = _report_markdown(bounded_document, digest)
    return CorrelationReport(
        json_document=bounded_document,
        canonical_json=canonical,
        markdown=markdown,
        sha256=digest,
    )


__all__ = [
    "CORRELATION_REPORT_SCHEMA_VERSION",
    "CorrelationReport",
    "CorrelationReportProvenanceClass",
    "CorroborationResult",
    "ManualCorrelationEdge",
    "ManualEventCorrelation",
    "ReviewAnnotation",
    "ReviewAnnotationKind",
    "ReviewAuditEntry",
    "ReviewAuditRetentionMode",
    "ReviewConflictError",
    "ReviewIdempotencyConflictError",
    "ReviewOverlayError",
    "ReviewOverlaySnapshot",
    "ReviewOverlayStore",
    "ReviewRetentionAuditEntry",
    "ReviewRetentionCandidate",
    "ReviewRetentionDisabledError",
    "ReviewRetentionInventory",
    "ReviewRetentionPolicy",
    "ReviewRetentionResult",
    "ReviewScope",
    "ReviewSubject",
    "ReviewSubjectKind",
    "ReviewValidationError",
    "build_correlation_report",
]
