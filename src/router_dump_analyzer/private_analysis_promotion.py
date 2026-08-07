"""Durable, explicit human review of private-analysis proposals.

Model output is advisory.  This module is the only core bridge from one exact
terminal proposal to the mutable review overlay.  It deliberately never
interprets or applies a plug-in/model payload.  The authenticated human supplies
a separately validated annotation or manual-event-correlation target, while the
service pins the terminal run, result, and proposal digests.

Promotion is a small durable saga across two SQLite stores.  A pending decision
is reserved first; the review-overlay write uses a decision-derived idempotency
key and deterministic target ID; then the decision is completed.  A crash at
either boundary can therefore be resumed without duplicating the target.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, Self

from .annotation_store import (
    ManualCorrelationEdge,
    ManualEventCorrelation,
    ReviewAnnotation,
    ReviewAnnotationKind,
    ReviewScope,
    ReviewSubject,
)
from .canonical import strict_canonical_json, strict_canonical_json_sha256
from .private_analysis import (
    EvidenceScope,
    PrivateAnalysisProposal,
    PrivateAnalysisProposalKind,
)
from .private_analysis_service import (
    PrivateAnalysisRunReport,
    PrivateAnalysisService,
    PrivateAnalysisServiceConflict,
    PrivateAnalysisServiceError,
    PrivateAnalysisServiceInvalidRequest,
    PrivateAnalysisServiceNotFound,
    PrivateAnalysisServiceReportNotReady,
    PrivateAnalysisServiceUnavailable,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .value_core import MAX_JSON_SAFE_INTEGER

MAX_PROMOTION_IDENTIFIER_LENGTH = 1_024
MAX_PROMOTION_ACTOR_LENGTH = 512
MAX_PROMOTION_RATIONALE_LENGTH = 65_536
MAX_PROMOTION_IDEMPOTENCY_KEY_LENGTH = 512
MAX_PROMOTION_LIST_LIMIT = 5_000
MAX_PROMOTION_PENDING_DECISIONS = 5_000
MAX_PROMOTION_RETENTION_REVISION_IDS = 100_000
MAX_SQLITE_INTEGER = (1 << 63) - 1
PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES = 32
_PROPOSAL_REVIEW_AUTHORITY_VERSION = 1
_PROPOSAL_REVIEW_DECISION_ID_DOMAIN = (
    "router-dump-analyzer/private-analysis/proposal-review/decision-id/v1"
)
_PROPOSAL_REVIEW_TARGET_ID_DOMAIN = (
    "router-dump-analyzer/private-analysis/proposal-review/target-id/v1"
)


class ProposalReviewError(RuntimeError):
    """Base error for durable proposal review."""


class ProposalReviewValidationError(ValueError, ProposalReviewError):
    """Caller-owned review intent is malformed or unsupported."""


class ProposalReviewConflictError(ProposalReviewError):
    """The proposal, idempotency key, or pinned run changed."""


class ProposalReviewNotFoundError(KeyError, ProposalReviewError):
    """The exact scoped run, proposal, or decision is unavailable."""


class ProposalReviewUnavailableError(ProposalReviewError):
    """Durable review state could not be read or committed."""


class ProposalReviewDisposition(StrEnum):
    PROMOTE = "promote"
    REJECT = "reject"


class ProposalReviewState(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"


class ProposalReviewTargetKind(StrEnum):
    ANNOTATION = "annotation"
    MANUAL_EVENT_CORRELATION = "manual_event_correlation"


def _text(
    value: object,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = False,
    allow_line_breaks: bool = False,
    require_trimmed: bool = True,
) -> str:
    if type(value) is not str:
        raise ProposalReviewValidationError(f"{label} must be a string")
    if not allow_empty and not value:
        raise ProposalReviewValidationError(f"{label} must be non-empty")
    if len(value) > maximum or (require_trimmed and value != value.strip()):
        raise ProposalReviewValidationError(f"{label} is outside its bounded form")
    permitted = "\t\n\r" if allow_line_breaks else ""
    if any(
        (ord(character) < 32 and character not in permitted) or ord(character) == 127
        for character in value
    ):
        raise ProposalReviewValidationError(f"{label} contains control characters")
    return value


def _positive_sqlite(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SQLITE_INTEGER:
        raise ProposalReviewValidationError(
            f"{label} must be a positive signed-64 integer"
        )
    return value


def _non_negative(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_SAFE_INTEGER:
        raise ProposalReviewValidationError(
            f"{label} must be a non-negative JSON-safe integer"
        )
    return value


def _non_negative_sqlite(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
        raise ProposalReviewValidationError(
            f"{label} must be a non-negative signed-64 integer"
        )
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label, 71)
    if len(text) != 71 or not text.startswith("sha256:"):
        raise ProposalReviewValidationError(f"{label} must be a sha256 digest")
    suffix = text[7:]
    if any(character not in "0123456789abcdef" for character in suffix):
        raise ProposalReviewValidationError(f"{label} must be a sha256 digest")
    return text


def _scope_values(scope: ReviewScope) -> tuple[str, str, str]:
    if type(scope) is not ReviewScope:
        raise ProposalReviewValidationError("scope must be an exact ReviewScope")
    return scope.tenant_id, scope.project_id, scope.workspace_id


@dataclass(frozen=True, slots=True)
class AnnotationPromotionTarget:
    kind: ReviewAnnotationKind
    subjects: tuple[ReviewSubject, ...]
    title: str = ""
    body: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.kind) is not ReviewAnnotationKind:
            raise ProposalReviewValidationError(
                "annotation target kind must be ReviewAnnotationKind"
            )
        if type(self.subjects) is not tuple or any(
            type(value) is not ReviewSubject for value in self.subjects
        ):
            raise ProposalReviewValidationError(
                "annotation target subjects must be exact ReviewSubject values"
            )
        if type(self.tags) is not tuple or any(
            type(value) is not str for value in self.tags
        ):
            raise ProposalReviewValidationError(
                "annotation target tags must be strings"
            )


@dataclass(frozen=True, slots=True)
class CorrelationPromotionTarget:
    subjects: tuple[ReviewSubject, ...]
    edges: tuple[ManualCorrelationEdge, ...]
    rationale: str = ""
    tags: tuple[str, ...] = ()
    confidence: float | None = None

    def __post_init__(self) -> None:
        if type(self.subjects) is not tuple or any(
            type(value) is not ReviewSubject for value in self.subjects
        ):
            raise ProposalReviewValidationError(
                "correlation target subjects must be exact ReviewSubject values"
            )
        if type(self.edges) is not tuple or any(
            type(value) is not ManualCorrelationEdge for value in self.edges
        ):
            raise ProposalReviewValidationError(
                "correlation target edges must be exact ManualCorrelationEdge values"
            )
        if type(self.tags) is not tuple or any(
            type(value) is not str for value in self.tags
        ):
            raise ProposalReviewValidationError(
                "correlation target tags must be strings"
            )


PromotionTarget = AnnotationPromotionTarget | CorrelationPromotionTarget


@dataclass(frozen=True, slots=True)
class ProposalReviewDecision:
    scope: ReviewScope
    decision_id: str
    run_id: str
    proposal_id: str
    proposal_digest: str
    result_digest: str
    run_version: int
    disposition: ProposalReviewDisposition
    state: ProposalReviewState
    actor: str
    rationale: str
    request_digest: str
    target_kind: ProposalReviewTargetKind | None
    target_id: str | None
    created_at_ns: int
    updated_at_ns: int
    version: int

    def __post_init__(self) -> None:
        _scope_values(self.scope)
        for label, value in (
            ("decision_id", self.decision_id),
            ("run_id", self.run_id),
            ("proposal_id", self.proposal_id),
        ):
            _text(value, label, MAX_PROMOTION_IDENTIFIER_LENGTH)
        _digest(self.proposal_digest, "proposal_digest")
        _digest(self.result_digest, "result_digest")
        _digest(self.request_digest, "request_digest")
        _positive_sqlite(self.run_version, "run_version")
        _positive_sqlite(self.version, "version")
        _non_negative_sqlite(self.created_at_ns, "created_at_ns")
        _non_negative_sqlite(self.updated_at_ns, "updated_at_ns")
        if self.updated_at_ns < self.created_at_ns:
            raise ProposalReviewValidationError("updated_at_ns precedes created_at_ns")
        if type(self.disposition) is not ProposalReviewDisposition:
            raise ProposalReviewValidationError("disposition is invalid")
        if type(self.state) is not ProposalReviewState:
            raise ProposalReviewValidationError("state is invalid")
        _text(self.actor, "actor", MAX_PROMOTION_ACTOR_LENGTH)
        _text(
            self.rationale,
            "rationale",
            MAX_PROMOTION_RATIONALE_LENGTH,
            allow_empty=True,
            allow_line_breaks=True,
            require_trimmed=False,
        )
        if self.disposition is ProposalReviewDisposition.REJECT:
            if self.state is not ProposalReviewState.COMPLETED:
                raise ProposalReviewValidationError("rejection must be completed")
            if self.target_kind is not None or self.target_id is not None:
                raise ProposalReviewValidationError(
                    "rejection must not contain a target"
                )
        else:
            if type(self.target_kind) is not ProposalReviewTargetKind:
                raise ProposalReviewValidationError("promotion requires a target kind")
            _text(self.target_id, "target_id", MAX_PROMOTION_IDENTIFIER_LENGTH)

    def to_dict(self, *, include_scope: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "decision_id": self.decision_id,
            "run_id": self.run_id,
            "proposal_id": self.proposal_id,
            "proposal_digest": self.proposal_digest,
            "result_digest": self.result_digest,
            "run_version": self.run_version,
            "disposition": self.disposition.value,
            "state": self.state.value,
            "actor": self.actor,
            "rationale": self.rationale,
            "request_digest": self.request_digest,
            "target_kind": self.target_kind.value
            if self.target_kind is not None
            else None,
            "target_id": self.target_id,
            "created_at_ns": self.created_at_ns,
            "updated_at_ns": self.updated_at_ns,
            "version": self.version,
        }
        if include_scope:
            value["scope"] = self.scope.to_dict()
        return value


@dataclass(frozen=True, slots=True)
class ProposalReviewReservation:
    """Result of reserving one human decision without implicitly resuming it."""

    decision: ProposalReviewDecision
    created: bool

    def __post_init__(self) -> None:
        if type(self.decision) is not ProposalReviewDecision:
            raise ProposalReviewValidationError(
                "reservation decision must be an exact ProposalReviewDecision"
            )
        if type(self.created) is not bool:
            raise ProposalReviewValidationError("reservation created must be boolean")


@dataclass(frozen=True, slots=True)
class ProposalReviewRetentionReferences:
    """Bounded dependencies that keep a pending promotion recoverable."""

    revision_ids: tuple[str, ...]
    overlay_idempotency_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.revision_ids) is not tuple or any(
            type(value) is not str for value in self.revision_ids
        ):
            raise ProposalReviewValidationError("revision_ids must be exact strings")
        if type(self.overlay_idempotency_keys) is not tuple or any(
            type(value) is not str for value in self.overlay_idempotency_keys
        ):
            raise ProposalReviewValidationError(
                "overlay_idempotency_keys must be exact strings"
            )


class _ReviewWriter(Protocol):
    def validate_subjects(
        self,
        scope: ReviewScope,
        subjects: Iterable[ReviewSubject],
    ) -> tuple[ReviewSubject, ...]: ...

    def get_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ReviewAnnotation: ...

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
    ) -> ReviewAnnotation: ...

    def get_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ManualEventCorrelation: ...

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
    ) -> ManualEventCorrelation: ...


def _stored_target_document(
    target_kind_value: object,
    raw: object,
) -> tuple[ProposalReviewTargetKind, dict[str, Any]]:
    """Decode only a canonical target document retained by the core."""

    try:
        target_kind = ProposalReviewTargetKind(target_kind_value)
        if type(raw) is not str:
            raise ProposalReviewUnavailableError(
                "stored promotion target is unavailable"
            )
        value = json.loads(raw)
        if type(value) is not dict or strict_canonical_json(value) != raw:
            raise ProposalReviewUnavailableError("stored promotion target is invalid")
        return target_kind, value
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except ProposalReviewError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ProposalReviewUnavailableError(
            "stored promotion target is invalid"
        ) from error


class SqliteProposalReviewStore:
    """Tenant-scoped durable proposal decisions and recovery reservations."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority_key: bytes,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if (
            type(authority_key) is not bytes
            or len(authority_key) != PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES
        ):
            raise ProposalReviewValidationError(
                "authority_key must be an exact 32-byte secret"
            )
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock_ns = clock_ns
        self._authority_key = authority_key
        self._lock = threading.RLock()
        self._closed = False
        self._connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS proposal_review_decision (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                proposal_digest TEXT NOT NULL,
                result_digest TEXT NOT NULL,
                run_version INTEGER NOT NULL,
                disposition TEXT NOT NULL,
                state TEXT NOT NULL,
                actor TEXT NOT NULL,
                rationale TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                authority_attestation TEXT NOT NULL,
                target_kind TEXT,
                target_id TEXT,
                target_document_json TEXT,
                created_at_ns INTEGER NOT NULL,
                updated_at_ns INTEGER NOT NULL,
                version INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, project_id, workspace_id, decision_id),
                UNIQUE (tenant_id, project_id, workspace_id, run_id, proposal_id)
            );
            CREATE TABLE IF NOT EXISTS proposal_review_idempotency (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, project_id, workspace_id, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS proposal_review_run_index
            ON proposal_review_decision (
                tenant_id, project_id, workspace_id, run_id, created_at_ns, decision_id
            );
            """
        )
        columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(proposal_review_decision)"
            ).fetchall()
        }
        if "target_document_json" not in columns:
            self._connection.execute(
                "ALTER TABLE proposal_review_decision "
                "ADD COLUMN target_document_json TEXT"
            )
        if "authority_attestation" not in columns:
            self._connection.execute(
                "ALTER TABLE proposal_review_decision "
                "ADD COLUMN authority_attestation TEXT"
            )

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._closed:
                raise ProposalReviewUnavailableError("proposal review store is closed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.execute("COMMIT")
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _now(self) -> int:
        return _non_negative_sqlite(self._clock_ns(), "clock_ns")

    def _row(self, scope: ReviewScope, row: sqlite3.Row) -> ProposalReviewDecision:
        try:
            stored_scope = (
                row["tenant_id"],
                row["project_id"],
                row["workspace_id"],
            )
        except (IndexError, KeyError) as error:
            raise ProposalReviewUnavailableError(
                "stored proposal decision scope is invalid"
            ) from error
        if stored_scope != _scope_values(scope):
            raise ProposalReviewUnavailableError(
                "stored proposal decision scope does not match its row"
            )
        target_kind = row["target_kind"]
        decision = ProposalReviewDecision(
            scope=scope,
            decision_id=row["decision_id"],
            run_id=row["run_id"],
            proposal_id=row["proposal_id"],
            proposal_digest=row["proposal_digest"],
            result_digest=row["result_digest"],
            run_version=row["run_version"],
            disposition=ProposalReviewDisposition(row["disposition"]),
            state=ProposalReviewState(row["state"]),
            actor=row["actor"],
            rationale=row["rationale"],
            request_digest=row["request_digest"],
            target_kind=(
                None if target_kind is None else ProposalReviewTargetKind(target_kind)
            ),
            target_id=row["target_id"],
            created_at_ns=row["created_at_ns"],
            updated_at_ns=row["updated_at_ns"],
            version=row["version"],
        )
        if decision.target_kind is None:
            if row["target_document_json"] is not None:
                raise ProposalReviewUnavailableError(
                    "stored rejection contains a promotion target"
                )
            target_document = None
        else:
            stored_kind, target_document = _stored_target_document(
                target_kind,
                row["target_document_json"],
            )
            if stored_kind is not decision.target_kind:
                raise ProposalReviewUnavailableError(
                    "stored promotion target is invalid"
                )
        _validate_decision_authority(
            decision,
            target_document,
            authority_key=self._authority_key,
            stored_attestation=row["authority_attestation"],
        )
        return decision

    def _decision(
        self,
        connection: sqlite3.Connection,
        scope: ReviewScope,
        decision_id: str,
    ) -> ProposalReviewDecision:
        row = connection.execute(
            """
            SELECT * FROM proposal_review_decision
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND decision_id = ?
            """,
            (*_scope_values(scope), decision_id),
        ).fetchone()
        if row is None:
            raise ProposalReviewNotFoundError(decision_id)
        return self._row(scope, row)

    def reserve(
        self,
        scope: ReviewScope,
        *,
        decision_id: str,
        run_id: str,
        proposal_id: str,
        proposal_digest: str,
        result_digest: str,
        run_version: int,
        disposition: ProposalReviewDisposition,
        actor: str,
        rationale: str,
        request_digest: str,
        target_kind: ProposalReviewTargetKind | None,
        target_id: str | None,
        target_document: dict[str, Any] | None,
        idempotency_key: str,
    ) -> ProposalReviewReservation:
        now = self._now()
        candidate = ProposalReviewDecision(
            scope=scope,
            decision_id=decision_id,
            run_id=run_id,
            proposal_id=proposal_id,
            proposal_digest=proposal_digest,
            result_digest=result_digest,
            run_version=run_version,
            disposition=disposition,
            state=(
                ProposalReviewState.COMPLETED
                if disposition is ProposalReviewDisposition.REJECT
                else ProposalReviewState.PENDING
            ),
            actor=actor,
            rationale=rationale,
            request_digest=request_digest,
            target_kind=target_kind,
            target_id=target_id,
            created_at_ns=now,
            updated_at_ns=now,
            version=1,
        )
        key = _text(
            idempotency_key,
            "idempotency_key",
            MAX_PROMOTION_IDEMPOTENCY_KEY_LENGTH,
        )
        if target_document is not None and type(target_document) is not dict:
            raise ProposalReviewValidationError(
                "target_document must be an exact object or None"
            )
        target_document_json = (
            None if target_document is None else strict_canonical_json(target_document)
        )
        authority_attestation = _decision_authority_attestation(
            self._authority_key,
            candidate,
        )
        _validate_decision_authority(
            candidate,
            target_document,
            authority_key=self._authority_key,
            stored_attestation=authority_attestation,
        )
        with self._transaction() as connection:
            prior = connection.execute(
                """
                SELECT request_digest, decision_id
                FROM proposal_review_idempotency
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND idempotency_key = ?
                """,
                (*_scope_values(scope), key),
            ).fetchone()
            if prior is not None:
                if prior["request_digest"] != candidate.request_digest:
                    raise ProposalReviewConflictError(
                        "proposal review idempotency key was reused"
                    )
                if prior["decision_id"] != candidate.decision_id:
                    raise ProposalReviewUnavailableError(
                        "proposal review idempotency authority does not match"
                    )
                decision = self._decision(connection, scope, prior["decision_id"])
                if (
                    decision.decision_id != candidate.decision_id
                    or decision.request_digest != candidate.request_digest
                ):
                    raise ProposalReviewUnavailableError(
                        "proposal review idempotency authority does not match"
                    )
                return ProposalReviewReservation(
                    decision=decision,
                    created=False,
                )
            existing = connection.execute(
                """
                SELECT decision_id, request_digest, target_document_json
                FROM proposal_review_decision
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND run_id = ? AND proposal_id = ?
                """,
                (*_scope_values(scope), run_id, proposal_id),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != candidate.request_digest:
                    raise ProposalReviewConflictError(
                        "proposal already has a different durable review decision"
                    )
                if (
                    existing["target_document_json"] is None
                    and target_document_json is not None
                ):
                    connection.execute(
                        """
                        UPDATE proposal_review_decision
                        SET target_document_json = ?
                        WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                          AND decision_id = ? AND target_document_json IS NULL
                        """,
                        (
                            target_document_json,
                            *_scope_values(scope),
                            existing["decision_id"],
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO proposal_review_idempotency (
                        tenant_id, project_id, workspace_id, idempotency_key,
                        request_digest, decision_id, created_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *_scope_values(scope),
                        key,
                        candidate.request_digest,
                        existing["decision_id"],
                        candidate.created_at_ns,
                    ),
                )
                return ProposalReviewReservation(
                    decision=self._decision(connection, scope, existing["decision_id"]),
                    created=False,
                )
            connection.execute(
                """
                INSERT INTO proposal_review_decision (
                    tenant_id, project_id, workspace_id, decision_id, run_id,
                    proposal_id, proposal_digest, result_digest, run_version,
                    disposition, state, actor, rationale, request_digest,
                    authority_attestation, target_kind, target_id,
                    target_document_json, created_at_ns, updated_at_ns, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *_scope_values(scope),
                    candidate.decision_id,
                    candidate.run_id,
                    candidate.proposal_id,
                    candidate.proposal_digest,
                    candidate.result_digest,
                    candidate.run_version,
                    candidate.disposition.value,
                    candidate.state.value,
                    candidate.actor,
                    candidate.rationale,
                    candidate.request_digest,
                    authority_attestation,
                    candidate.target_kind.value if candidate.target_kind else None,
                    candidate.target_id,
                    target_document_json,
                    candidate.created_at_ns,
                    candidate.updated_at_ns,
                    candidate.version,
                ),
            )
            connection.execute(
                """
                INSERT INTO proposal_review_idempotency (
                    tenant_id, project_id, workspace_id, idempotency_key,
                    request_digest, decision_id, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *_scope_values(scope),
                    key,
                    candidate.request_digest,
                    candidate.decision_id,
                    candidate.created_at_ns,
                ),
            )
            return ProposalReviewReservation(decision=candidate, created=True)

    def promotion_target_document(
        self,
        scope: ReviewScope,
        decision_id: str,
    ) -> tuple[ProposalReviewTargetKind, dict[str, Any]]:
        """Load the exact validated target retained for pending-saga recovery."""

        _scope_values(scope)
        _text(decision_id, "decision_id", MAX_PROMOTION_IDENTIFIER_LENGTH)
        with self._lock:
            if self._closed:
                raise ProposalReviewUnavailableError("proposal review store is closed")
            row = self._connection.execute(
                """
                SELECT *
                FROM proposal_review_decision
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND decision_id = ?
                """,
                (*_scope_values(scope), decision_id),
            ).fetchone()
        if row is None:
            raise ProposalReviewNotFoundError(decision_id)
        decision = self._row(scope, row)
        if decision.disposition is not ProposalReviewDisposition.PROMOTE:
            raise ProposalReviewConflictError(
                "only a promotion has a recoverable target"
            )
        return _stored_target_document(
            row["target_kind"],
            row["target_document_json"],
        )

    def complete(
        self,
        scope: ReviewScope,
        decision_id: str,
    ) -> ProposalReviewDecision:
        with self._transaction() as connection:
            current = self._decision(connection, scope, decision_id)
            if current.disposition is not ProposalReviewDisposition.PROMOTE:
                raise ProposalReviewConflictError("only a promotion can be completed")
            if current.state is ProposalReviewState.COMPLETED:
                return current
            now = self._now()
            completed = replace(
                current,
                state=ProposalReviewState.COMPLETED,
                updated_at_ns=now,
                version=current.version + 1,
            )
            authority_attestation = _decision_authority_attestation(
                self._authority_key,
                completed,
            )
            cursor = connection.execute(
                """
                UPDATE proposal_review_decision
                SET state = ?, updated_at_ns = ?, version = ?,
                    authority_attestation = ?
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND decision_id = ? AND state = ? AND version = ?
                """,
                (
                    completed.state.value,
                    completed.updated_at_ns,
                    completed.version,
                    authority_attestation,
                    *_scope_values(scope),
                    decision_id,
                    ProposalReviewState.PENDING.value,
                    current.version,
                ),
            )
            if cursor.rowcount != 1:
                raise ProposalReviewConflictError(
                    "proposal review changed concurrently"
                )
            return self._decision(connection, scope, decision_id)

    def get(
        self,
        scope: ReviewScope,
        decision_id: str,
    ) -> ProposalReviewDecision:
        _scope_values(scope)
        with self._lock:
            if self._closed:
                raise ProposalReviewUnavailableError("proposal review store is closed")
            return self._decision(self._connection, scope, decision_id)

    def list(
        self,
        scope: ReviewScope,
        *,
        run_id: str | None = None,
        limit: int = 1_000,
        offset: int = 0,
    ) -> tuple[ProposalReviewDecision, ...]:
        _scope_values(scope)
        if run_id is not None:
            _text(run_id, "run_id", MAX_PROMOTION_IDENTIFIER_LENGTH)
        if type(limit) is not int or not 1 <= limit <= MAX_PROMOTION_LIST_LIMIT:
            raise ProposalReviewValidationError(
                f"limit must be between 1 and {MAX_PROMOTION_LIST_LIMIT}"
            )
        _non_negative(offset, "offset")
        where = "tenant_id = ? AND project_id = ? AND workspace_id = ?"
        values: tuple[Any, ...] = _scope_values(scope)
        if run_id is not None:
            where += " AND run_id = ?"
            values = (*values, run_id)
        with self._lock:
            if self._closed:
                raise ProposalReviewUnavailableError("proposal review store is closed")
            rows = self._connection.execute(
                f"""
                SELECT * FROM proposal_review_decision
                WHERE {where}
                ORDER BY created_at_ns, decision_id
                LIMIT ? OFFSET ?
                """,
                (*values, limit, offset),
            ).fetchall()
            return tuple(self._row(scope, row) for row in rows)

    def pending_retention_references(
        self,
        scope: ReviewScope,
        *,
        maximum_pending_decisions: int = MAX_PROMOTION_PENDING_DECISIONS,
        maximum_revision_ids: int = MAX_PROMOTION_RETENTION_REVISION_IDS,
    ) -> ProposalReviewRetentionReferences:
        """Return all bounded references required by pending saga recovery.

        Corrupt or oversized retained state fails closed so catalog/review
        retention cannot proceed with a partial protection set.
        """

        _scope_values(scope)
        if (
            type(maximum_pending_decisions) is not int
            or not 1 <= maximum_pending_decisions <= MAX_PROMOTION_PENDING_DECISIONS
        ):
            raise ProposalReviewValidationError(
                "maximum_pending_decisions is outside its bounded form"
            )
        if (
            type(maximum_revision_ids) is not int
            or not 1 <= maximum_revision_ids <= MAX_PROMOTION_RETENTION_REVISION_IDS
        ):
            raise ProposalReviewValidationError(
                "maximum_revision_ids is outside its bounded form"
            )
        revision_ids: set[str] = set()
        overlay_keys: list[str] = []
        with self._lock:
            if self._closed:
                raise ProposalReviewUnavailableError("proposal review store is closed")
            rows = self._connection.execute(
                """
                SELECT * FROM proposal_review_decision
                ORDER BY tenant_id, project_id, workspace_id,
                         created_at_ns, decision_id
                """,
            )
            for row in rows:
                try:
                    # Classify only after authenticating the complete row.  A
                    # forged lifecycle state must not disappear behind a SQL
                    # predicate before the keyed attestation is checked.
                    row_scope = ReviewScope(
                        tenant_id=row["tenant_id"],
                        project_id=row["project_id"],
                        workspace_id=row["workspace_id"],
                    )
                    decision = self._row(row_scope, row)
                    if row_scope != scope:
                        continue
                    if (
                        decision.disposition is not ProposalReviewDisposition.PROMOTE
                        or decision.state is not ProposalReviewState.PENDING
                    ):
                        continue
                    if len(overlay_keys) >= maximum_pending_decisions:
                        raise ProposalReviewUnavailableError(
                            "pending proposal decisions exceed the retention "
                            "safety bound"
                        )
                    target_kind, document = _stored_target_document(
                        row["target_kind"],
                        row["target_document_json"],
                    )
                    if decision.target_kind is not target_kind:
                        raise ProposalReviewUnavailableError(
                            "stored promotion target is invalid"
                        )
                    target = _target_from_document(target_kind, document)
                    if (
                        _decision_request_digest(decision, document)
                        != decision.request_digest
                    ):
                        raise ProposalReviewUnavailableError(
                            "stored promotion request digest does not match its target"
                        )
                    revision_ids.update(
                        subject.revision_id for subject in target.subjects
                    )
                    if len(revision_ids) > maximum_revision_ids:
                        raise ProposalReviewUnavailableError(
                            "pending proposal revision references exceed the retention "
                            "safety bound"
                        )
                    overlay_keys.append(
                        _proposal_review_overlay_key(decision.decision_id)
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except ProposalReviewError:
                    raise
                except (KeyError, TypeError, ValueError) as error:
                    raise ProposalReviewUnavailableError(
                        "stored pending proposal decision is invalid"
                    ) from error
        return ProposalReviewRetentionReferences(
            revision_ids=tuple(sorted(revision_ids)),
            overlay_idempotency_keys=tuple(overlay_keys),
        )


def _review_scope(scope: EvidenceScope) -> ReviewScope:
    if type(scope) is not EvidenceScope:
        raise ProposalReviewValidationError("scope must be an exact EvidenceScope")
    return ReviewScope(
        tenant_id=scope.tenant_id,
        project_id=scope.project_id,
        workspace_id=scope.workspace_id,
    )


def _proposal(
    report: PrivateAnalysisRunReport, proposal_id: str
) -> PrivateAnalysisProposal:
    result = report.outcome.result
    if result is None:
        raise ProposalReviewNotFoundError(proposal_id)
    matches = tuple(
        value for value in result.proposals if value.proposal_id == proposal_id
    )
    if len(matches) != 1:
        raise ProposalReviewNotFoundError(proposal_id)
    return matches[0]


def _target_document(
    target: PromotionTarget | None,
) -> tuple[str | None, dict[str, Any] | None]:
    if target is None:
        return None, None
    if type(target) is AnnotationPromotionTarget:
        return ProposalReviewTargetKind.ANNOTATION.value, {
            "kind": target.kind.value,
            "subjects": [subject.to_dict() for subject in target.subjects],
            "title": target.title,
            "body": target.body,
            "tags": sorted({*target.tags, "assistant-promoted"}),
        }
    if type(target) is CorrelationPromotionTarget:
        return ProposalReviewTargetKind.MANUAL_EVENT_CORRELATION.value, {
            "subjects": [subject.to_dict() for subject in target.subjects],
            "edges": [edge.to_dict() for edge in target.edges],
            "rationale": target.rationale,
            "tags": sorted({*target.tags, "assistant-promoted"}),
            "confidence": target.confidence,
        }
    raise ProposalReviewValidationError("promotion target is invalid")


def _proposal_review_request_document(
    *,
    scope: ReviewScope,
    run_id: str,
    proposal_id: str,
    proposal_digest: str,
    result_digest: str,
    run_version: int,
    disposition: ProposalReviewDisposition,
    actor: str,
    rationale: str,
    target_kind: str | None,
    target_document: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "authority_version": _PROPOSAL_REVIEW_AUTHORITY_VERSION,
        "scope": scope.to_dict(),
        "run_id": run_id,
        "proposal_id": proposal_id,
        "proposal_digest": proposal_digest,
        "result_digest": result_digest,
        "run_version": run_version,
        "disposition": disposition.value,
        "actor": actor,
        "rationale": rationale,
        "target_kind": target_kind,
        "target": target_document,
    }


def _proposal_review_request_digest(
    *,
    scope: ReviewScope,
    run_id: str,
    proposal_id: str,
    proposal_digest: str,
    result_digest: str,
    run_version: int,
    disposition: ProposalReviewDisposition,
    actor: str,
    rationale: str,
    target_kind: str | None,
    target_document: dict[str, Any] | None,
) -> str:
    return "sha256:" + strict_canonical_json_sha256(
        _proposal_review_request_document(
            scope=scope,
            run_id=run_id,
            proposal_id=proposal_id,
            proposal_digest=proposal_digest,
            result_digest=result_digest,
            run_version=run_version,
            disposition=disposition,
            actor=actor,
            rationale=rationale,
            target_kind=target_kind,
            target_document=target_document,
        )
    )


def _authority_identifier(domain: str, request_digest: str) -> str:
    """Project one scope-bound request into an opaque, domain-separated ID."""

    _digest(request_digest, "request_digest")
    return strict_canonical_json_sha256(
        {
            "domain": domain,
            "request_digest": request_digest,
        }
    )


def _proposal_review_decision_id(request_digest: str) -> str:
    return "proposal-review-decision-" + _authority_identifier(
        _PROPOSAL_REVIEW_DECISION_ID_DOMAIN,
        request_digest,
    )


def _proposal_review_target_id(request_digest: str) -> str:
    return "proposal-review-target-" + _authority_identifier(
        _PROPOSAL_REVIEW_TARGET_ID_DOMAIN,
        request_digest,
    )


def _proposal_review_overlay_key(decision_id: str) -> str:
    return "private-analysis-proposal:" + _text(
        decision_id,
        "decision_id",
        MAX_PROMOTION_IDENTIFIER_LENGTH,
    )


def _decision_request_digest(
    decision: ProposalReviewDecision,
    target_document: dict[str, Any] | None,
) -> str:
    return _proposal_review_request_digest(
        scope=decision.scope,
        run_id=decision.run_id,
        proposal_id=decision.proposal_id,
        proposal_digest=decision.proposal_digest,
        result_digest=decision.result_digest,
        run_version=decision.run_version,
        disposition=decision.disposition,
        actor=decision.actor,
        rationale=decision.rationale,
        target_kind=(
            decision.target_kind.value if decision.target_kind is not None else None
        ),
        target_document=target_document,
    )


def _decision_authority_document(
    decision: ProposalReviewDecision,
) -> dict[str, Any]:
    return {
        "authority_version": _PROPOSAL_REVIEW_AUTHORITY_VERSION,
        "scope": decision.scope.to_dict(),
        "decision_id": decision.decision_id,
        "request_digest": decision.request_digest,
        "disposition": decision.disposition.value,
        "state": decision.state.value,
        "target_kind": (
            decision.target_kind.value if decision.target_kind is not None else None
        ),
        "target_id": decision.target_id,
        "overlay_idempotency_key": (
            _proposal_review_overlay_key(decision.decision_id)
            if decision.disposition is ProposalReviewDisposition.PROMOTE
            else None
        ),
        "created_at_ns": decision.created_at_ns,
        "updated_at_ns": decision.updated_at_ns,
        "version": decision.version,
    }


def _decision_authority_attestation(
    authority_key: bytes,
    decision: ProposalReviewDecision,
) -> str:
    if (
        type(authority_key) is not bytes
        or len(authority_key) != PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES
    ):
        raise ProposalReviewValidationError(
            "authority_key must be an exact 32-byte secret"
        )
    message = strict_canonical_json(_decision_authority_document(decision)).encode(
        "utf-8"
    )
    return (
        "hmac-sha256:"
        + hmac.new(
            authority_key,
            message,
            digestmod="sha256",
        ).hexdigest()
    )


def _validate_decision_authority(
    decision: ProposalReviewDecision,
    target_document: dict[str, Any] | None,
    *,
    authority_key: bytes,
    stored_attestation: object,
) -> None:
    """Fail closed unless generated identities and the reservation seal are exact."""

    request_digest = _decision_request_digest(decision, target_document)
    if request_digest != decision.request_digest:
        raise ProposalReviewUnavailableError(
            "stored promotion request digest does not match its authority"
        )
    if decision.decision_id != _proposal_review_decision_id(request_digest):
        raise ProposalReviewUnavailableError(
            "stored proposal decision identity does not match its authority"
        )
    expected_target_id = (
        _proposal_review_target_id(request_digest)
        if decision.disposition is ProposalReviewDisposition.PROMOTE
        else None
    )
    if decision.target_id != expected_target_id:
        raise ProposalReviewUnavailableError(
            "stored promotion target identity does not match its authority"
        )
    if (
        type(stored_attestation) is not str
        or len(stored_attestation) != 76
        or not stored_attestation.startswith("hmac-sha256:")
        or any(
            character not in "0123456789abcdef" for character in stored_attestation[12:]
        )
    ):
        raise ProposalReviewUnavailableError(
            "stored proposal decision authority attestation is invalid"
        )
    expected_attestation = _decision_authority_attestation(authority_key, decision)
    if not hmac.compare_digest(stored_attestation, expected_attestation):
        raise ProposalReviewUnavailableError(
            "stored proposal decision authority attestation does not match"
        )


def _target_from_document(
    target_kind: ProposalReviewTargetKind,
    document: dict[str, Any],
) -> PromotionTarget:
    """Reconstruct only a core-generated, canonically stored review target."""

    try:
        subjects_value = document["subjects"]
        if type(subjects_value) is not list:
            raise TypeError("subjects are invalid")
        subjects = tuple(ReviewSubject.from_dict(value) for value in subjects_value)
        tags_value = document.get("tags", [])
        if type(tags_value) is not list or any(
            type(value) is not str for value in tags_value
        ):
            raise TypeError("tags are invalid")
        tags = tuple(tags_value)
        if target_kind is ProposalReviewTargetKind.ANNOTATION:
            if set(document) != {"kind", "subjects", "title", "body", "tags"}:
                raise TypeError("annotation target fields are invalid")
            return AnnotationPromotionTarget(
                kind=ReviewAnnotationKind(document["kind"]),
                subjects=subjects,
                title=document["title"],
                body=document["body"],
                tags=tags,
            )
        if set(document) != {
            "subjects",
            "edges",
            "rationale",
            "tags",
            "confidence",
        }:
            raise TypeError("correlation target fields are invalid")
        edges_value = document["edges"]
        if type(edges_value) is not list:
            raise TypeError("edges are invalid")
        return CorrelationPromotionTarget(
            subjects=subjects,
            edges=tuple(
                ManualCorrelationEdge(
                    source_ordinal=value["source_ordinal"],
                    target_ordinal=value["target_ordinal"],
                    link_type=value["link_type"],
                    directed=value["directed"],
                )
                for value in edges_value
            ),
            rationale=document["rationale"],
            tags=tags,
            confidence=document["confidence"],
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ProposalReviewUnavailableError(
            "stored promotion target is invalid"
        ) from error


class PrivateAnalysisProposalReviewService:
    """Pin, reserve, and explicitly apply one reviewed advisory proposal."""

    def __init__(
        self,
        private_analysis: PrivateAnalysisService,
        store: SqliteProposalReviewStore,
        writer: _ReviewWriter,
        *,
        admission_fence: Callable[[], AbstractContextManager[None]],
    ) -> None:
        if not callable(admission_fence):
            raise TypeError("admission_fence must be callable")
        self._private_analysis = private_analysis
        self._store = store
        self._writer = writer
        self._admission_fence = admission_fence

    @staticmethod
    def _annotation_matches(
        value: ReviewAnnotation,
        decision: ProposalReviewDecision,
        target: AnnotationPromotionTarget,
        tags: tuple[str, ...],
    ) -> bool:
        return (
            value.annotation_id == decision.target_id
            and value.scope == decision.scope
            and value.version == 1
            and not value.tombstoned
            and value.kind is target.kind
            and value.subjects == target.subjects
            and value.author == decision.actor
            and value.title == target.title
            and value.body == target.body
            and value.tags == tags
        )

    @staticmethod
    def _correlation_matches(
        value: ManualEventCorrelation,
        decision: ProposalReviewDecision,
        target: CorrelationPromotionTarget,
        tags: tuple[str, ...],
    ) -> bool:
        return (
            value.correlation_id == decision.target_id
            and value.scope == decision.scope
            and value.version == 1
            and not value.tombstoned
            and value.subjects == target.subjects
            and value.edges == target.edges
            and value.author == decision.actor
            and value.rationale == target.rationale
            and value.tags == tags
            and value.confidence == target.confidence
        )

    def _apply(
        self,
        scope: ReviewScope,
        decision: ProposalReviewDecision,
        target: PromotionTarget,
    ) -> ProposalReviewDecision:
        if decision.state is ProposalReviewState.COMPLETED:
            return decision
        if decision.disposition is not ProposalReviewDisposition.PROMOTE:
            raise ProposalReviewUnavailableError(
                "stored proposal decision is inconsistent"
            )
        target_id = decision.target_id
        if target_id is None:
            raise ProposalReviewUnavailableError(
                "stored promotion target is unavailable"
            )
        _target_kind, target_document = _target_document(target)
        if target_document is None:
            raise ProposalReviewUnavailableError(
                "stored promotion target is unavailable"
            )
        overlay_key = _proposal_review_overlay_key(decision.decision_id)
        if type(target) is AnnotationPromotionTarget:
            tags = tuple(target_document["tags"])
            try:
                existing_annotation = self._writer.get_annotation(
                    scope,
                    target_id,
                    include_deleted=True,
                )
            except KeyError:
                self._writer.create_annotation(
                    scope,
                    kind=target.kind,
                    subjects=target.subjects,
                    author=decision.actor,
                    title=target.title,
                    body=target.body,
                    tags=tags,
                    annotation_id=target_id,
                    idempotency_key=overlay_key,
                )
                try:
                    existing_annotation = self._writer.get_annotation(
                        scope,
                        target_id,
                        include_deleted=True,
                    )
                except KeyError as error:
                    raise ProposalReviewUnavailableError(
                        "promotion annotation was not durably stored"
                    ) from error
            if not self._annotation_matches(
                existing_annotation,
                decision,
                target,
                tags,
            ):
                raise ProposalReviewConflictError(
                    "promotion annotation conflicts with retained human intent"
                )
        elif type(target) is CorrelationPromotionTarget:
            tags = tuple(target_document["tags"])
            try:
                existing_correlation = self._writer.get_correlation(
                    scope,
                    target_id,
                    include_deleted=True,
                )
            except KeyError:
                self._writer.create_correlation(
                    scope,
                    subjects=target.subjects,
                    edges=target.edges,
                    author=decision.actor,
                    rationale=target.rationale,
                    tags=tags,
                    confidence=target.confidence,
                    correlation_id=target_id,
                    idempotency_key=overlay_key,
                )
                try:
                    existing_correlation = self._writer.get_correlation(
                        scope,
                        target_id,
                        include_deleted=True,
                    )
                except KeyError as error:
                    raise ProposalReviewUnavailableError(
                        "promotion correlation was not durably stored"
                    ) from error
            if not self._correlation_matches(
                existing_correlation,
                decision,
                target,
                tags,
            ):
                raise ProposalReviewConflictError(
                    "promotion correlation conflicts with retained human intent"
                )
        else:
            raise ProposalReviewUnavailableError(
                "stored promotion target is unavailable"
            )
        return self._store.complete(scope, decision.decision_id)

    def decide(
        self,
        scope: EvidenceScope,
        *,
        run_id: str,
        proposal_id: str,
        proposal_digest: str,
        result_digest: str,
        expected_run_version: int,
        disposition: ProposalReviewDisposition,
        actor: str,
        rationale: str,
        idempotency_key: str,
        target: PromotionTarget | None = None,
    ) -> ProposalReviewDecision:
        with self._admission_fence():
            return self._decide_under_fence(
                scope,
                run_id=run_id,
                proposal_id=proposal_id,
                proposal_digest=proposal_digest,
                result_digest=result_digest,
                expected_run_version=expected_run_version,
                disposition=disposition,
                actor=actor,
                rationale=rationale,
                idempotency_key=idempotency_key,
                target=target,
            )

    def _decide_under_fence(
        self,
        scope: EvidenceScope,
        *,
        run_id: str,
        proposal_id: str,
        proposal_digest: str,
        result_digest: str,
        expected_run_version: int,
        disposition: ProposalReviewDisposition,
        actor: str,
        rationale: str,
        idempotency_key: str,
        target: PromotionTarget | None = None,
    ) -> ProposalReviewDecision:
        review_scope = _review_scope(scope)
        _text(run_id, "run_id", MAX_PROMOTION_IDENTIFIER_LENGTH)
        _text(proposal_id, "proposal_id", MAX_PROMOTION_IDENTIFIER_LENGTH)
        _digest(proposal_digest, "proposal_digest")
        _digest(result_digest, "result_digest")
        _positive_sqlite(expected_run_version, "expected_run_version")
        if type(disposition) is not ProposalReviewDisposition:
            raise ProposalReviewValidationError("disposition is invalid")
        actor = _text(actor, "actor", MAX_PROMOTION_ACTOR_LENGTH)
        rationale = _text(
            rationale,
            "rationale",
            MAX_PROMOTION_RATIONALE_LENGTH,
            allow_empty=True,
            allow_line_breaks=True,
            require_trimmed=False,
        )
        idempotency_key = _text(
            idempotency_key,
            "idempotency_key",
            MAX_PROMOTION_IDEMPOTENCY_KEY_LENGTH,
        )
        try:
            report = self._private_analysis.get_report(scope, run_id)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PrivateAnalysisServiceNotFound as error:
            raise ProposalReviewNotFoundError(run_id) from error
        except PrivateAnalysisServiceReportNotReady as error:
            raise ProposalReviewConflictError(
                "private-analysis report is not ready"
            ) from error
        except PrivateAnalysisServiceConflict as error:
            raise ProposalReviewConflictError(
                "private-analysis run conflicts with durable state"
            ) from error
        except PrivateAnalysisServiceInvalidRequest as error:
            raise ProposalReviewValidationError(
                "private-analysis run identity is invalid"
            ) from error
        except PrivateAnalysisServiceUnavailable as error:
            raise ProposalReviewUnavailableError(
                "private-analysis service is unavailable"
            ) from error
        except PrivateAnalysisServiceError as error:
            raise ProposalReviewUnavailableError(
                "private-analysis report could not be reviewed"
            ) from error
        if report.run.cleanup_pending:
            raise ProposalReviewConflictError(
                "private-analysis run cleanup is not complete"
            )
        if report.run.version != expected_run_version:
            raise ProposalReviewConflictError("private-analysis run version changed")
        result = report.outcome.result
        if result is None or result.result_digest != result_digest:
            raise ProposalReviewConflictError("private-analysis result digest changed")
        proposal = _proposal(report, proposal_id)
        if proposal.proposal_digest != proposal_digest:
            raise ProposalReviewConflictError(
                "private-analysis proposal digest changed"
            )

        target_kind_value, target_document = _target_document(target)
        if disposition is ProposalReviewDisposition.REJECT:
            if target is not None:
                raise ProposalReviewValidationError(
                    "rejection must not contain a target"
                )
            target_kind = None
        else:
            if target is None:
                raise ProposalReviewValidationError("promotion requires a target")
            target_kind = ProposalReviewTargetKind(target_kind_value)
            if (
                target_kind is ProposalReviewTargetKind.MANUAL_EVENT_CORRELATION
                and proposal.kind is not PrivateAnalysisProposalKind.EVENT_CORRELATION
            ):
                raise ProposalReviewValidationError(
                    "only an event-correlation proposal may create a manual event correlation"
                )
            # Construct exact overlay values before reserving a durable saga.
            if type(target) is AnnotationPromotionTarget:
                ReviewAnnotation(
                    annotation_id="promotion-validation",
                    scope=review_scope,
                    kind=target.kind,
                    subjects=target.subjects,
                    author=actor,
                    title=target.title,
                    body=target.body,
                    tags=tuple(target_document["tags"]),
                    created_at_ns=0,
                    updated_at_ns=0,
                )
            else:
                assert type(target) is CorrelationPromotionTarget
                ManualEventCorrelation(
                    correlation_id="promotion-validation",
                    scope=review_scope,
                    subjects=target.subjects,
                    edges=target.edges,
                    author=actor,
                    rationale=target.rationale,
                    tags=tuple(target_document["tags"]),
                    confidence=target.confidence,
                    created_at_ns=0,
                    updated_at_ns=0,
                )
        revision_set = set(report.run.revision_ids)
        if target is not None and any(
            subject.revision_id not in revision_set for subject in target.subjects
        ):
            raise ProposalReviewValidationError(
                "promotion subjects must belong to the proposal run revisions"
            )
        if target is not None:
            try:
                resolved_subjects = self._writer.validate_subjects(
                    review_scope,
                    target.subjects,
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except (KeyError, ValueError) as error:
                raise ProposalReviewValidationError(
                    "promotion subjects do not resolve in the selected revisions"
                ) from error
            target = replace(target, subjects=resolved_subjects)
            target_kind_value, target_document = _target_document(target)
        request_digest = _proposal_review_request_digest(
            scope=review_scope,
            run_id=run_id,
            proposal_id=proposal_id,
            proposal_digest=proposal_digest,
            result_digest=result_digest,
            run_version=expected_run_version,
            disposition=disposition,
            actor=actor,
            rationale=rationale,
            target_kind=target_kind_value,
            target_document=target_document,
        )
        decision_id = _proposal_review_decision_id(request_digest)
        reservation = self._store.reserve(
            review_scope,
            decision_id=decision_id,
            run_id=run_id,
            proposal_id=proposal_id,
            proposal_digest=proposal_digest,
            result_digest=result_digest,
            run_version=expected_run_version,
            disposition=disposition,
            actor=actor,
            rationale=rationale,
            request_digest=request_digest,
            target_kind=target_kind,
            target_id=(
                _proposal_review_target_id(request_digest)
                if target is not None
                else None
            ),
            target_document=target_document,
            idempotency_key=idempotency_key,
        )
        decision = reservation.decision
        if target is None or not reservation.created:
            return decision
        return self._apply(review_scope, decision, target)

    def recover(
        self,
        scope: EvidenceScope,
        decision_id: str,
        *,
        expected_decision_version: int,
    ) -> ProposalReviewDecision:
        with self._admission_fence():
            return self._recover_under_fence(
                scope,
                decision_id,
                expected_decision_version=expected_decision_version,
            )

    def _recover_under_fence(
        self,
        scope: EvidenceScope,
        decision_id: str,
        *,
        expected_decision_version: int,
    ) -> ProposalReviewDecision:
        """Explicitly resume a pending promotion from its retained human target."""

        review_scope = _review_scope(scope)
        _text(decision_id, "decision_id", MAX_PROMOTION_IDENTIFIER_LENGTH)
        _positive_sqlite(expected_decision_version, "expected_decision_version")
        decision = self._store.get(review_scope, decision_id)
        if decision.version != expected_decision_version:
            raise ProposalReviewConflictError(
                "proposal review decision version changed"
            )
        if decision.state is ProposalReviewState.COMPLETED:
            return decision
        target_kind, document = self._store.promotion_target_document(
            review_scope,
            decision_id,
        )
        if decision.target_kind is not target_kind:
            raise ProposalReviewUnavailableError("stored promotion target is invalid")
        if _decision_request_digest(decision, document) != decision.request_digest:
            raise ProposalReviewUnavailableError(
                "stored promotion request digest does not match its target"
            )
        target = _target_from_document(target_kind, document)
        try:
            resolved_subjects = self._writer.validate_subjects(
                review_scope,
                target.subjects,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (KeyError, ValueError) as error:
            raise ProposalReviewUnavailableError(
                "stored promotion subjects no longer resolve"
            ) from error
        return self._apply(
            review_scope,
            decision,
            replace(target, subjects=resolved_subjects),
        )

    def get(
        self,
        scope: EvidenceScope,
        decision_id: str,
    ) -> ProposalReviewDecision:
        return self._store.get(_review_scope(scope), decision_id)

    def list(
        self,
        scope: EvidenceScope,
        *,
        run_id: str | None = None,
        limit: int = 1_000,
        offset: int = 0,
    ) -> tuple[ProposalReviewDecision, ...]:
        return self._store.list(
            _review_scope(scope),
            run_id=run_id,
            limit=limit,
            offset=offset,
        )


def proposal_review_decision_json(value: ProposalReviewDecision) -> str:
    if type(value) is not ProposalReviewDecision:
        raise TypeError("value must be an exact ProposalReviewDecision")
    return strict_canonical_json(value.to_dict())


__all__ = [
    "PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES",
    "AnnotationPromotionTarget",
    "CorrelationPromotionTarget",
    "PrivateAnalysisProposalReviewService",
    "ProposalReviewConflictError",
    "ProposalReviewDecision",
    "ProposalReviewDisposition",
    "ProposalReviewError",
    "ProposalReviewNotFoundError",
    "ProposalReviewReservation",
    "ProposalReviewRetentionReferences",
    "ProposalReviewState",
    "ProposalReviewTargetKind",
    "ProposalReviewUnavailableError",
    "ProposalReviewValidationError",
    "SqliteProposalReviewStore",
    "proposal_review_decision_json",
]
