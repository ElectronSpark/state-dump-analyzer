"""Durable, local-only lifecycle storage for private-analysis runs.

The store is deliberately transport and model neutral.  It persists exact
request/outcome contracts, immutable revision bindings, payload-free runner
seals, and a write-ahead disclosure ledger.  It does not execute a model,
open a network connection, load a plug-in, or expose an HTTP/CLI surface.

Request and outcome documents may contain proprietary material.  They live in
their own SQLite database, use explicit disabled-by-default retention, and are
never copied into the append-only audit or retention journals.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Final, Self, cast
from uuid import uuid4

from .canonical import (
    strict_canonical_json,
    validate_prefixed_lowercase_sha256,
)
from .filesystem_lock import exclusive_file_lock
from .private_analysis import (
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    PrivateAnalysisError,
    PrivateAnalysisErrorCode,
    PrivateAnalysisErrorStage,
    PrivateAnalysisOutcome,
    PrivateAnalysisOutcomeKind,
    PrivateAnalysisRequest,
    evidence_reference_dict,
    evidence_reference_from_dict,
    evidence_snapshot_digest,
    private_analysis_outcome_from_json,
    private_analysis_outcome_json,
    private_analysis_request_from_json,
    private_analysis_request_json,
    validate_private_analysis_result,
)
from .private_analysis_runner_support import (
    PrivateAnalysisTranscriptSummary,
    detached_private_analysis_budget_state,
    empty_private_analysis_budget_state,
    private_analysis_budget_payload,
    private_analysis_transcript_summary_from_json,
    private_analysis_transcript_summary_json,
)
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState
from .value_core import parse_canonical_decimal_integer

_SCHEMA_VERSION: Final = 1
_RUN_STORE_CONTRACT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.run_store.v1"
)
_RUN_AUDIT_VERSION: Final = "router_dump_analyzer.private_analysis.run_audit.v1"
_RETENTION_VERSION: Final = "router_dump_analyzer.private_analysis.run_retention.v1"
_STORE_METADATA_KEY: Final = "installation_id"
_ZERO_DIGEST: Final = "sha256:" + "0" * 64
_MAX_IDENTITY_CHARACTERS: Final = 256
_MAX_LIST_LIMIT: Final = 1_000
_MAX_RETENTION_CANDIDATES: Final = 10_000
_MAX_REFERENCE_PROTECTION_RUNS: Final = 10_000
_MAX_AUDIT_ENTRIES_PER_RUN: Final = 10_000
_MAX_LEASE_NS: Final = 24 * 60 * 60 * 1_000_000_000
_MAX_SIGNED_64: Final = (1 << 63) - 1
_IDENTITY_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}\Z")


class PrivateAnalysisRunStoreError(RuntimeError):
    """Base class for static, payload-free durable run-store failures."""


class PrivateAnalysisRunConflict(PrivateAnalysisRunStoreError):
    """A request, idempotency key, execution fence, or terminal value conflicts."""


class PrivateAnalysisRunNotFound(PrivateAnalysisRunStoreError):
    """The scoped run does not exist."""


class PrivateAnalysisRunStaleVersion(PrivateAnalysisRunConflict):
    """A mutation used an obsolete optimistic version."""


class PrivateAnalysisRunCorruptionError(PrivateAnalysisRunStoreError):
    """Stored state, its audit chain, or a self-digest is inconsistent."""


class PrivateAnalysisRunRetentionDisabled(PrivateAnalysisRunStoreError):
    """Destructive run retention was not explicitly enabled."""


class PrivateAnalysisRunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in {self.COMPLETED, self.CANCELLED}


class PrivateAnalysisRunAuditReason(StrEnum):
    ADMITTED = "admitted"
    CLAIMED = "claimed"
    LEASE_RENEWED = "lease_renewed"
    ACCOUNTING_COMMITTED = "accounting_committed"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED_BEFORE_START = "cancelled_before_start"
    COMPLETED = "completed"
    CANCELLED_DURING_RUN = "cancelled_during_run"
    EXPIRED_RUNNER_FAILED = "expired_runner_failed"
    EXPIRED_CANCELLED = "expired_cancelled"


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRecord:
    scope: EvidenceScope
    run_id: str
    state: PrivateAnalysisRunState
    version: int
    request: PrivateAnalysisRequest
    execution_id: str | None
    lease_expires_at_ns: int | None
    cancellation_requested_at_ns: int | None
    disclosed_references: tuple[EvidenceReference, ...]
    evidence_ledger_digest: str
    budget_state: PrivateAnalysisToolBudgetState
    outcome: PrivateAnalysisOutcome | None
    transcript_summary: PrivateAnalysisTranscriptSummary | None
    created_at_ns: int
    updated_at_ns: int
    completed_at_ns: int | None
    audit_root_digest: str
    audit_tip_sequence: int
    audit_tip_digest: str

    @property
    def request_digest(self) -> str:
        return self.request.request_digest


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunAuditEntry:
    scope: EvidenceScope
    run_id: str
    sequence: int
    run_version: int
    reason: PrivateAnalysisRunAuditReason
    from_state: PrivateAnalysisRunState | None
    to_state: PrivateAnalysisRunState
    actor_id: str
    execution_id: str | None
    created_at_ns: int
    request_digest: str
    evidence_ledger_digest: str
    transcript_digest: str | None
    outcome_digest: str | None
    state_snapshot_digest: str
    previous_entry_digest: str
    entry_digest: str


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRetentionPolicy:
    enabled: bool = False
    completed_before_ns: int = 0
    max_runs: int = 1_000

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be a boolean")
        _bounded_integer(
            self.completed_before_ns,
            "completed_before_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        _bounded_integer(
            self.max_runs,
            "max_runs",
            minimum=1,
            maximum=_MAX_RETENTION_CANDIDATES,
        )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRetentionCandidate:
    run_id: str
    state: PrivateAnalysisRunState
    completed_at_ns: int
    request_digest: str
    evidence_ledger_digest: str
    transcript_digest: str | None
    outcome_digest: str
    audit_tip_digest: str


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRetentionInventory:
    scope: EvidenceScope
    policy: PrivateAnalysisRunRetentionPolicy
    candidates: tuple[PrivateAnalysisRunRetentionCandidate, ...]
    inventory_digest: str


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRetentionResult:
    inventory: PrivateAnalysisRunRetentionInventory
    operation_id: str
    purged_run_ids: tuple[str, ...]
    result_digest: str


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunRetentionJournalEntry:
    scope: EvidenceScope
    operation_id: str
    inventory_digest: str
    purged_run_ids: tuple[str, ...]
    actor_id: str
    created_at_ns: int
    result_digest: str


PrivateAnalysisRunAdmissionValidator = Callable[[PrivateAnalysisRequest], None]
PrivateAnalysisRunAdmissionFence = Callable[[], AbstractContextManager[None]]


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _identity(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_IDENTITY_CHARACTERS
        or _IDENTITY_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(f"{label} must contain 1 to 256 characters")
    return value


def _scope(value: object) -> EvidenceScope:
    if type(value) is not EvidenceScope:
        raise TypeError("scope must be an exact EvidenceScope")
    return EvidenceScope(value.tenant_id, value.project_id, value.workspace_id)


def _digest(domain: str, value: object) -> str:
    wire = strict_canonical_json({"domain": domain, "value": value}).encode("utf-8")
    return "sha256:" + sha256(wire).hexdigest()


def _idempotency_key_digest(scope: EvidenceScope, key: str) -> str:
    return _digest(
        "private_analysis_run_idempotency_key",
        {
            "scope": {
                "tenant_id": scope.tenant_id,
                "project_id": scope.project_id,
                "workspace_id": scope.workspace_id,
            },
            "idempotency_key": key,
        },
    )


def _budget_json(value: PrivateAnalysisToolBudgetState) -> str:
    return strict_canonical_json(private_analysis_budget_payload(value))


def _budget_from_json(value: object) -> PrivateAnalysisToolBudgetState:
    if type(value) is not str:
        raise PrivateAnalysisRunCorruptionError("stored budget is not text")
    try:
        document = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise PrivateAnalysisRunCorruptionError("stored budget is invalid") from error
    expected = {
        "max_tool_calls",
        "tool_calls_consumed",
        "max_evidence_items",
        "evidence_items_disclosed",
        "max_evidence_bytes",
        "evidence_bytes_disclosed",
    }
    if type(document) is not dict or set(document) != expected:
        raise PrivateAnalysisRunCorruptionError("stored budget shape is invalid")
    try:
        budget = PrivateAnalysisToolBudgetState(**document)
    except (TypeError, ValueError) as error:
        raise PrivateAnalysisRunCorruptionError("stored budget is invalid") from error
    if strict_canonical_json(document) != value:
        raise PrivateAnalysisRunCorruptionError("stored budget is non-canonical")
    return budget


def _detached_references(
    value: tuple[EvidenceReference, ...],
) -> tuple[EvidenceReference, ...]:
    if type(value) is not tuple:
        raise TypeError("references must be a tuple")
    result = tuple(
        evidence_reference_from_dict(evidence_reference_dict(item)) for item in value
    )
    digests = tuple(item.reference_digest for item in result)
    if digests != tuple(sorted(digests)) or len(digests) != len(set(digests)):
        raise ValueError("references must be unique and canonical")
    return result


def _reference_json(value: EvidenceReference) -> str:
    return strict_canonical_json(evidence_reference_dict(value))


def _reference_from_json(value: object) -> EvidenceReference:
    if type(value) is not str:
        raise PrivateAnalysisRunCorruptionError("stored reference is not text")
    try:
        document = json.loads(value)
        reference = evidence_reference_from_dict(document)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise PrivateAnalysisRunCorruptionError(
            "stored reference is invalid"
        ) from error
    if strict_canonical_json(evidence_reference_dict(reference)) != value:
        raise PrivateAnalysisRunCorruptionError("stored reference is non-canonical")
    return reference


def _request_revision_keys(
    request: PrivateAnalysisRequest,
) -> frozenset[tuple[str, str]]:
    return frozenset(
        (revision.node_id, revision.revision_id) for revision in request.revisions
    )


def _validate_accounting(
    request: PrivateAnalysisRequest,
    references: tuple[EvidenceReference, ...],
    budget: PrivateAnalysisToolBudgetState,
) -> None:
    expected_scope = request.scope
    revision_keys = _request_revision_keys(request)
    for reference in references:
        if reference.scope != expected_scope:
            raise PrivateAnalysisRunConflict("disclosed reference scope conflicts")
        key = (reference.revision.node_id, reference.revision.revision_id)
        if key not in revision_keys:
            raise PrivateAnalysisRunConflict("disclosed reference revision conflicts")
        expected_binding = next(
            item
            for item in request.revisions
            if (item.node_id, item.revision_id) == key
        )
        if reference.revision != expected_binding:
            raise PrivateAnalysisRunConflict("disclosed reference binding conflicts")
    limits = request.limits
    if (
        budget.max_tool_calls != limits.max_tool_calls
        or budget.max_evidence_items != limits.max_evidence_items
        or budget.max_evidence_bytes != limits.max_evidence_bytes
    ):
        raise PrivateAnalysisRunConflict("tool budget ceiling conflicts with request")
    if budget.evidence_items_disclosed != len(references):
        raise PrivateAnalysisRunConflict("tool budget item count conflicts with ledger")


def _cancelled_outcome(request_digest: str) -> PrivateAnalysisOutcome:
    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=PrivateAnalysisError(
            request_digest=request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=PrivateAnalysisErrorCode.CANCELLED,
            retryable=False,
        ),
    )


def _expired_outcome(request_digest: str) -> PrivateAnalysisOutcome:
    return PrivateAnalysisOutcome(
        kind=PrivateAnalysisOutcomeKind.ERROR,
        error=PrivateAnalysisError(
            request_digest=request_digest,
            stage=PrivateAnalysisErrorStage.RUNNER,
            code=PrivateAnalysisErrorCode.RUNNER_FAILED,
            retryable=True,
        ),
    )


def _terminal_state(outcome: PrivateAnalysisOutcome) -> PrivateAnalysisRunState:
    if (
        outcome.kind is PrivateAnalysisOutcomeKind.ERROR
        and outcome.error is not None
        and outcome.error.code is PrivateAnalysisErrorCode.CANCELLED
    ):
        return PrivateAnalysisRunState.CANCELLED
    return PrivateAnalysisRunState.COMPLETED


def _state_snapshot_digest(
    *,
    state: PrivateAnalysisRunState,
    version: int,
    execution_id: str | None,
    lease_expires_at_ns: int | None,
    cancellation_requested_at_ns: int | None,
    evidence_ledger_digest: str,
    budget_state: PrivateAnalysisToolBudgetState,
    transcript_digest: str | None,
    outcome_digest: str | None,
    created_at_ns: int,
    updated_at_ns: int,
    completed_at_ns: int | None,
) -> str:
    return _digest(
        "private_analysis_run_state_snapshot",
        {
            "state": state.value,
            "version": version,
            "execution_id": execution_id,
            "lease_expires_at_ns": (
                str(lease_expires_at_ns) if lease_expires_at_ns is not None else None
            ),
            "cancellation_requested_at_ns": (
                str(cancellation_requested_at_ns)
                if cancellation_requested_at_ns is not None
                else None
            ),
            "evidence_ledger_digest": evidence_ledger_digest,
            "budget": private_analysis_budget_payload(budget_state),
            "transcript_digest": transcript_digest,
            "outcome_digest": outcome_digest,
            "created_at_ns": str(created_at_ns),
            "updated_at_ns": str(updated_at_ns),
            "completed_at_ns": (
                str(completed_at_ns) if completed_at_ns is not None else None
            ),
        },
    )


def _audit_entry_digest(entry: PrivateAnalysisRunAuditEntry) -> str:
    return _digest(
        "private_analysis_run_audit_entry",
        {
            "contract_version": _RUN_AUDIT_VERSION,
            "scope": {
                "tenant_id": entry.scope.tenant_id,
                "project_id": entry.scope.project_id,
                "workspace_id": entry.scope.workspace_id,
            },
            "run_id": entry.run_id,
            "sequence": entry.sequence,
            "run_version": entry.run_version,
            "reason": entry.reason.value,
            "from_state": (
                entry.from_state.value if entry.from_state is not None else None
            ),
            "to_state": entry.to_state.value,
            "actor_id": entry.actor_id,
            "execution_id": entry.execution_id,
            "created_at_ns": str(entry.created_at_ns),
            "request_digest": entry.request_digest,
            "evidence_ledger_digest": entry.evidence_ledger_digest,
            "transcript_digest": entry.transcript_digest,
            "outcome_digest": entry.outcome_digest,
            "state_snapshot_digest": entry.state_snapshot_digest,
            "previous_entry_digest": entry.previous_entry_digest,
        },
    )


class SqlitePrivateAnalysisRunStore:
    """Thread-safe durable run store for one trusted local server profile."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        admission_validator: PrivateAnalysisRunAdmissionValidator,
        admission_fence: PrivateAnalysisRunAdmissionFence = nullcontext,
    ) -> None:
        if not callable(admission_validator):
            raise TypeError("admission_validator must be callable")
        if not callable(admission_fence):
            raise TypeError("admission_fence must be callable")
        raw_path = str(database_path)
        database_uri = False
        schema_lock_path: Path | None = None
        if raw_path != ":memory:":
            path = Path(database_path).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            raw_path = str(path)
            schema_lock_path = path.with_name(f".{path.name}.schema.lock")
        else:
            raw_path = (
                "file:router-dump-analyzer-private-analysis-"
                f"{uuid4().hex}?mode=memory&cache=shared"
            )
            database_uri = True
        self._database_path = raw_path
        self._database_uri = database_uri
        self._admission_validator = admission_validator
        self._admission_fence = admission_fence
        self._lock = threading.RLock()
        self._closed = False
        self._installation_id = ""
        self._connection = self._open_connection()
        try:
            if schema_lock_path is None:
                with self._lock:
                    self._initialize_schema()
            else:
                with exclusive_file_lock(schema_lock_path), self._lock:
                    self._initialize_schema()
        except BaseException:
            self._connection.close()
            raise

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            isolation_level=None,
            check_same_thread=False,
            timeout=30.0,
            uri=self._database_uri,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def _initialize_schema(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, _SCHEMA_VERSION}:
            raise PrivateAnalysisRunStoreError(
                f"unsupported private-analysis run-store schema version {version}"
            )
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS private_analysis_runs (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                state TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                request_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                execution_id TEXT,
                lease_expires_at_ns INTEGER,
                cancellation_requested_at_ns INTEGER,
                evidence_ledger_digest TEXT NOT NULL,
                budget_json TEXT NOT NULL,
                outcome_json TEXT,
                outcome_digest TEXT,
                transcript_json TEXT,
                transcript_digest TEXT,
                created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
                completed_at_ns INTEGER,
                audit_root_digest TEXT NOT NULL,
                audit_tip_sequence INTEGER NOT NULL CHECK (audit_tip_sequence > 0),
                audit_tip_digest TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, workspace_id, run_id),
                CHECK ((state IN ('running', 'cancel_requested')) =
                       (execution_id IS NOT NULL)),
                CHECK ((state IN ('running', 'cancel_requested')) =
                       (lease_expires_at_ns IS NOT NULL)),
                CHECK ((state IN ('completed', 'cancelled')) =
                       (outcome_json IS NOT NULL)),
                CHECK ((state IN ('completed', 'cancelled')) =
                       (outcome_digest IS NOT NULL)),
                CHECK ((state IN ('completed', 'cancelled')) =
                       (completed_at_ns IS NOT NULL))
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_revisions (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                fixture_id TEXT NOT NULL,
                fixture_content_sha256 TEXT NOT NULL,
                node_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                revision_identity_sha256 TEXT NOT NULL,
                plan_basis_revision_id TEXT NOT NULL,
                execution_plan_digest TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, project_id, workspace_id, run_id, ordinal
                ),
                UNIQUE (
                    tenant_id, project_id, workspace_id, run_id,
                    node_id, revision_id
                ),
                FOREIGN KEY (tenant_id, project_id, workspace_id, run_id)
                    REFERENCES private_analysis_runs(
                        tenant_id, project_id, workspace_id, run_id
                    ) ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_disclosures (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                reference_digest TEXT NOT NULL,
                reference_json TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, project_id, workspace_id, run_id,
                    reference_digest
                ),
                FOREIGN KEY (tenant_id, project_id, workspace_id, run_id)
                    REFERENCES private_analysis_runs(
                        tenant_id, project_id, workspace_id, run_id
                    ) ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_audit (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK (sequence > 0),
                run_version INTEGER NOT NULL CHECK (run_version > 0),
                reason TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                execution_id TEXT,
                created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                request_digest TEXT NOT NULL,
                evidence_ledger_digest TEXT NOT NULL,
                transcript_digest TEXT,
                outcome_digest TEXT,
                state_snapshot_digest TEXT NOT NULL,
                previous_entry_digest TEXT NOT NULL,
                entry_digest TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, project_id, workspace_id, run_id, sequence
                ),
                FOREIGN KEY (tenant_id, project_id, workspace_id, run_id)
                    REFERENCES private_analysis_runs(
                        tenant_id, project_id, workspace_id, run_id
                    ) ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_admissions (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                run_id TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, project_id, workspace_id, idempotency_key
                ),
                UNIQUE (
                    tenant_id, project_id, workspace_id, run_id
                )
            ) STRICT;

            -- This independent guard deliberately has no foreign key to the
            -- mutable run head.  A torn or out-of-band head deletion must
            -- remain observable instead of cascading away the evidence that
            -- catalog retention uses to fail closed.  Normal retention
            -- removes the guard in the same transaction that creates the
            -- payload-free tombstone and deletes the run.
            CREATE TABLE IF NOT EXISTS private_analysis_active_run_guards (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, workspace_id, run_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_tombstones (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                idempotency_key_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                evidence_ledger_digest TEXT NOT NULL,
                transcript_digest TEXT,
                outcome_digest TEXT NOT NULL,
                audit_root_digest TEXT NOT NULL,
                audit_tip_sequence INTEGER NOT NULL,
                audit_tip_digest TEXT NOT NULL,
                purged_at_ns INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project_id, workspace_id, run_id),
                UNIQUE (
                    tenant_id, project_id, workspace_id,
                    idempotency_key_digest
                )
            ) STRICT;

            CREATE TABLE IF NOT EXISTS private_analysis_run_retention_journal (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                inventory_digest TEXT NOT NULL,
                inventory_json TEXT NOT NULL,
                purged_run_ids_json TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                result_digest TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, project_id, workspace_id, operation_id
                )
            ) STRICT;

            CREATE INDEX IF NOT EXISTS private_analysis_runs_scope_created
            ON private_analysis_runs(
                tenant_id, project_id, workspace_id, created_at_ns, run_id
            );
            CREATE INDEX IF NOT EXISTS private_analysis_runs_scope_completed
            ON private_analysis_runs(
                tenant_id, project_id, workspace_id, completed_at_ns, run_id
            );
            CREATE INDEX IF NOT EXISTS private_analysis_runs_expiring
            ON private_analysis_runs(state, lease_expires_at_ns);
            CREATE INDEX IF NOT EXISTS private_analysis_admissions_scope_run
            ON private_analysis_run_admissions(
                tenant_id, project_id, workspace_id, run_id
            );
            CREATE INDEX IF NOT EXISTS private_analysis_active_guards_scope
            ON private_analysis_active_run_guards(
                tenant_id, project_id, workspace_id, run_id
            );

            CREATE TABLE IF NOT EXISTS private_analysis_run_store_metadata (
                metadata_key TEXT PRIMARY KEY,
                metadata_value TEXT NOT NULL
            ) STRICT;
            """
        )
        metadata = self._connection.execute(
            """
            SELECT metadata_value FROM private_analysis_run_store_metadata
            WHERE metadata_key = ?
            """,
            (_STORE_METADATA_KEY,),
        ).fetchone()
        if metadata is None:
            installation_id = uuid4().hex
            self._connection.execute(
                """
                INSERT INTO private_analysis_run_store_metadata(
                    metadata_key, metadata_value
                ) VALUES (?, ?)
                """,
                (_STORE_METADATA_KEY, installation_id),
            )
        else:
            installation_id = _identity(
                metadata["metadata_value"], "stored installation_id"
            )
        self._installation_id = installation_id
        self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    @property
    def installation_id(self) -> str:
        """Return the opaque identity bound to this durable database file."""

        with self._lock:
            self._require_open()
            return self._installation_id

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise PrivateAnalysisRunStoreError("private-analysis run store is closed")

    @contextmanager
    def _read_cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            self._require_open()
            cursor = self._connection.cursor()
            try:
                # One record is reconstructed from its head, revision vector,
                # disclosure ledger, and audit chain.  A real read transaction
                # keeps those statements on one WAL snapshot when another
                # process commits concurrently.
                cursor.execute("BEGIN")
                yield cursor
                cursor.execute("COMMIT")
            except BaseException as error:
                try:
                    if self._connection.in_transaction:
                        cursor.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    self._closed = True
                    self._connection.close()
                if isinstance(error, sqlite3.DatabaseError):
                    raise PrivateAnalysisRunStoreError(
                        "private-analysis run storage failed"
                    ) from error
                raise
            finally:
                cursor.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            self._require_open()
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                yield cursor
                cursor.execute("COMMIT")
            except BaseException as error:
                rollback_failed = False
                try:
                    if self._connection.in_transaction:
                        cursor.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    rollback_failed = True
                finally:
                    cursor.close()
                if rollback_failed:
                    old_connection = self._connection
                    try:
                        replacement = self._open_connection()
                    except BaseException:  # noqa: BLE001 - connection recovery boundary.
                        self._closed = True
                        old_connection.close()
                    else:
                        self._connection = replacement
                        old_connection.close()
                if isinstance(error, sqlite3.IntegrityError):
                    raise PrivateAnalysisRunConflict(
                        "private-analysis run conflicts with durable state"
                    ) from error
                if isinstance(error, sqlite3.DatabaseError):
                    raise PrivateAnalysisRunStoreError(
                        "private-analysis run storage failed"
                    ) from error
                raise
            else:
                cursor.close()

    @staticmethod
    def _scope_values(scope: EvidenceScope) -> tuple[str, str, str]:
        return (scope.tenant_id, scope.project_id, scope.workspace_id)

    @staticmethod
    def _require_run_row(
        cursor: sqlite3.Cursor,
        scope: EvidenceScope,
        run_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM private_analysis_runs
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND run_id = ?
            """,
            (*SqlitePrivateAnalysisRunStore._scope_values(scope), run_id),
        ).fetchone()
        if row is None:
            raise PrivateAnalysisRunNotFound("private-analysis run was not found")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _audit_root(
        scope: EvidenceScope,
        run_id: str,
        request_digest: str,
    ) -> str:
        return _digest(
            "private_analysis_run_audit_root",
            {
                "contract_version": _RUN_STORE_CONTRACT_VERSION,
                "scope": {
                    "tenant_id": scope.tenant_id,
                    "project_id": scope.project_id,
                    "workspace_id": scope.workspace_id,
                },
                "run_id": run_id,
                "request_digest": request_digest,
            },
        )

    @staticmethod
    def _audit_entry_from_row(
        scope: EvidenceScope,
        row: sqlite3.Row,
    ) -> PrivateAnalysisRunAuditEntry:
        try:
            reason = PrivateAnalysisRunAuditReason(row["reason"])
            from_state = (
                PrivateAnalysisRunState(row["from_state"])
                if row["from_state"] is not None
                else None
            )
            to_state = PrivateAnalysisRunState(row["to_state"])
            entry = PrivateAnalysisRunAuditEntry(
                scope=scope,
                run_id=_identity(row["run_id"], "stored run_id"),
                sequence=_bounded_integer(
                    row["sequence"],
                    "stored audit sequence",
                    minimum=1,
                    maximum=_MAX_SIGNED_64,
                ),
                run_version=_bounded_integer(
                    row["run_version"],
                    "stored audit run version",
                    minimum=1,
                    maximum=_MAX_SIGNED_64,
                ),
                reason=reason,
                from_state=from_state,
                to_state=to_state,
                actor_id=_identity(row["actor_id"], "stored audit actor"),
                execution_id=(
                    _identity(row["execution_id"], "stored execution_id")
                    if row["execution_id"] is not None
                    else None
                ),
                created_at_ns=_bounded_integer(
                    row["created_at_ns"],
                    "stored audit timestamp",
                    minimum=0,
                    maximum=_MAX_SIGNED_64,
                ),
                request_digest=validate_prefixed_lowercase_sha256(
                    row["request_digest"], "stored audit request digest"
                ),
                evidence_ledger_digest=validate_prefixed_lowercase_sha256(
                    row["evidence_ledger_digest"],
                    "stored audit evidence ledger digest",
                ),
                transcript_digest=(
                    validate_prefixed_lowercase_sha256(
                        row["transcript_digest"], "stored audit transcript digest"
                    )
                    if row["transcript_digest"] is not None
                    else None
                ),
                outcome_digest=(
                    validate_prefixed_lowercase_sha256(
                        row["outcome_digest"], "stored audit outcome digest"
                    )
                    if row["outcome_digest"] is not None
                    else None
                ),
                state_snapshot_digest=validate_prefixed_lowercase_sha256(
                    row["state_snapshot_digest"],
                    "stored audit state snapshot digest",
                ),
                previous_entry_digest=validate_prefixed_lowercase_sha256(
                    row["previous_entry_digest"],
                    "stored audit previous digest",
                ),
                entry_digest=validate_prefixed_lowercase_sha256(
                    row["entry_digest"], "stored audit entry digest"
                ),
            )
        except (TypeError, ValueError, KeyError) as error:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit is invalid"
            ) from error
        if entry.sequence != entry.run_version:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit sequence is not contiguous"
            )
        if _audit_entry_digest(entry) != entry.entry_digest:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit digest does not match"
            )
        return entry

    def _audit_entries(
        self,
        cursor: sqlite3.Cursor,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_root: str,
        expected_tip_sequence: int,
        expected_tip_digest: str,
    ) -> tuple[PrivateAnalysisRunAuditEntry, ...]:
        if expected_tip_sequence > _MAX_AUDIT_ENTRIES_PER_RUN:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit exceeds its safety bound"
            )
        rows = cursor.execute(
            """
            SELECT * FROM private_analysis_run_audit
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND run_id = ?
            ORDER BY sequence
            LIMIT ?
            """,
            (
                *self._scope_values(scope),
                run_id,
                _MAX_AUDIT_ENTRIES_PER_RUN + 1,
            ),
        ).fetchall()
        if len(rows) != expected_tip_sequence:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit is incomplete"
            )
        previous = expected_root
        entries: list[PrivateAnalysisRunAuditEntry] = []
        for expected_sequence, row in enumerate(rows, 1):
            entry = self._audit_entry_from_row(scope, row)
            if entry.sequence != expected_sequence:
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis run audit sequence is not contiguous"
                )
            if entry.previous_entry_digest != previous:
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis run audit predecessor does not match"
                )
            previous = entry.entry_digest
            entries.append(entry)
        if previous != expected_tip_digest:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run audit tip does not match"
            )
        return tuple(entries)

    def _record_from_row(
        self,
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        *,
        verify_audit: bool = True,
    ) -> PrivateAnalysisRunRecord:
        try:
            scope = EvidenceScope(
                row["tenant_id"], row["project_id"], row["workspace_id"]
            )
            run_id = _identity(row["run_id"], "stored run_id")
            state = PrivateAnalysisRunState(row["state"])
            version = _bounded_integer(
                row["version"],
                "stored run version",
                minimum=1,
                maximum=_MAX_SIGNED_64,
            )
            request = private_analysis_request_from_json(row["request_json"])
            if (
                request.scope != scope
                or request.request_digest != row["request_digest"]
            ):
                raise ValueError("stored request binding conflicts")
            revision_rows = cursor.execute(
                """
                SELECT * FROM private_analysis_run_revisions
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND run_id = ?
                ORDER BY ordinal
                """,
                (*self._scope_values(scope), run_id),
            ).fetchall()
            revisions = tuple(
                EvidenceRevisionBinding(
                    fixture_id=item["fixture_id"],
                    fixture_content_sha256=item["fixture_content_sha256"],
                    node_id=item["node_id"],
                    revision_id=item["revision_id"],
                    revision_identity_sha256=item["revision_identity_sha256"],
                    plan_basis_revision_id=item["plan_basis_revision_id"],
                    execution_plan_digest=item["execution_plan_digest"],
                )
                for item in revision_rows
            )
            if any(
                item["ordinal"] != index for index, item in enumerate(revision_rows)
            ):
                raise ValueError("stored revision vector is not contiguous")
            if revisions != request.revisions:
                raise ValueError("stored revision vector conflicts with request")
            reference_rows = cursor.execute(
                """
                SELECT reference_digest, reference_json
                FROM private_analysis_run_disclosures
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND run_id = ?
                ORDER BY reference_digest
                """,
                (*self._scope_values(scope), run_id),
            ).fetchall()
            references = tuple(
                _reference_from_json(item["reference_json"]) for item in reference_rows
            )
            if any(
                item["reference_digest"] != reference.reference_digest
                for item, reference in zip(reference_rows, references, strict=True)
            ):
                raise ValueError("stored reference digest conflicts")
            ledger_digest = validate_prefixed_lowercase_sha256(
                row["evidence_ledger_digest"], "stored evidence ledger digest"
            )
            if evidence_snapshot_digest(references) != ledger_digest:
                raise ValueError("stored evidence ledger digest conflicts")
            budget = _budget_from_json(row["budget_json"])
            _validate_accounting(request, references, budget)
            outcome = (
                private_analysis_outcome_from_json(row["outcome_json"])
                if row["outcome_json"] is not None
                else None
            )
            if outcome is not None and outcome.outcome_digest != row["outcome_digest"]:
                raise ValueError("stored outcome digest conflicts")
            transcript = (
                private_analysis_transcript_summary_from_json(row["transcript_json"])
                if row["transcript_json"] is not None
                else None
            )
            if (
                transcript is not None
                and transcript.summary_digest != row["transcript_digest"]
            ):
                raise ValueError("stored transcript digest conflicts")
            execution_id = (
                _identity(row["execution_id"], "stored execution_id")
                if row["execution_id"] is not None
                else None
            )
            lease_expires_at_ns = (
                _bounded_integer(
                    row["lease_expires_at_ns"],
                    "stored lease expiry",
                    minimum=0,
                    maximum=_MAX_SIGNED_64,
                )
                if row["lease_expires_at_ns"] is not None
                else None
            )
            cancellation_requested_at_ns = (
                _bounded_integer(
                    row["cancellation_requested_at_ns"],
                    "stored cancellation timestamp",
                    minimum=0,
                    maximum=_MAX_SIGNED_64,
                )
                if row["cancellation_requested_at_ns"] is not None
                else None
            )
            created_at_ns = _bounded_integer(
                row["created_at_ns"],
                "stored creation timestamp",
                minimum=0,
                maximum=_MAX_SIGNED_64,
            )
            updated_at_ns = _bounded_integer(
                row["updated_at_ns"],
                "stored update timestamp",
                minimum=created_at_ns,
                maximum=_MAX_SIGNED_64,
            )
            completed_at_ns = (
                _bounded_integer(
                    row["completed_at_ns"],
                    "stored completion timestamp",
                    minimum=created_at_ns,
                    maximum=_MAX_SIGNED_64,
                )
                if row["completed_at_ns"] is not None
                else None
            )
            audit_root = validate_prefixed_lowercase_sha256(
                row["audit_root_digest"], "stored audit root digest"
            )
            if audit_root != self._audit_root(scope, run_id, request.request_digest):
                raise ValueError("stored audit root conflicts")
            audit_tip_sequence = _bounded_integer(
                row["audit_tip_sequence"],
                "stored audit tip sequence",
                minimum=1,
                maximum=_MAX_AUDIT_ENTRIES_PER_RUN,
            )
            audit_tip_digest = validate_prefixed_lowercase_sha256(
                row["audit_tip_digest"], "stored audit tip digest"
            )
        except (TypeError, ValueError, KeyError) as error:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run state is invalid"
            ) from error
        if version != audit_tip_sequence:
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run version and audit tip disagree"
            )
        record = PrivateAnalysisRunRecord(
            scope=scope,
            run_id=run_id,
            state=state,
            version=version,
            request=request,
            execution_id=execution_id,
            lease_expires_at_ns=lease_expires_at_ns,
            cancellation_requested_at_ns=cancellation_requested_at_ns,
            disclosed_references=references,
            evidence_ledger_digest=ledger_digest,
            budget_state=budget,
            outcome=outcome,
            transcript_summary=transcript,
            created_at_ns=created_at_ns,
            updated_at_ns=updated_at_ns,
            completed_at_ns=completed_at_ns,
            audit_root_digest=audit_root,
            audit_tip_sequence=audit_tip_sequence,
            audit_tip_digest=audit_tip_digest,
        )
        self._validate_record_shape(record)
        if verify_audit:
            entries = self._audit_entries(
                cursor,
                scope,
                run_id,
                expected_root=audit_root,
                expected_tip_sequence=audit_tip_sequence,
                expected_tip_digest=audit_tip_digest,
            )
            final = entries[-1]
            transcript_digest = (
                transcript.summary_digest if transcript is not None else None
            )
            outcome_digest = outcome.outcome_digest if outcome is not None else None
            expected_snapshot = _state_snapshot_digest(
                state=state,
                version=version,
                execution_id=execution_id,
                lease_expires_at_ns=lease_expires_at_ns,
                cancellation_requested_at_ns=cancellation_requested_at_ns,
                evidence_ledger_digest=ledger_digest,
                budget_state=budget,
                transcript_digest=transcript_digest,
                outcome_digest=outcome_digest,
                created_at_ns=created_at_ns,
                updated_at_ns=updated_at_ns,
                completed_at_ns=completed_at_ns,
            )
            if (
                final.to_state is not state
                or final.run_version != version
                or final.created_at_ns != updated_at_ns
                or final.request_digest != request.request_digest
                or final.evidence_ledger_digest != ledger_digest
                or final.transcript_digest != transcript_digest
                or final.outcome_digest != outcome_digest
                or final.state_snapshot_digest != expected_snapshot
            ):
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis run audit tip does not describe run state"
                )
        return record

    @staticmethod
    def _validate_record_shape(record: PrivateAnalysisRunRecord) -> None:
        active = record.state in {
            PrivateAnalysisRunState.RUNNING,
            PrivateAnalysisRunState.CANCEL_REQUESTED,
        }
        if active is not (
            record.execution_id is not None and record.lease_expires_at_ns is not None
        ):
            raise PrivateAnalysisRunCorruptionError(
                "private-analysis run execution fence is inconsistent"
            )
        if record.state is PrivateAnalysisRunState.CANCEL_REQUESTED:
            if record.cancellation_requested_at_ns is None:
                raise PrivateAnalysisRunCorruptionError(
                    "cancel-requested run lacks its timestamp"
                )
        elif (
            record.state
            in {
                PrivateAnalysisRunState.QUEUED,
                PrivateAnalysisRunState.RUNNING,
            }
            and record.cancellation_requested_at_ns is not None
        ):
            raise PrivateAnalysisRunCorruptionError(
                "run carries an unexpected cancellation timestamp"
            )
        if record.state.is_terminal:
            if record.outcome is None or record.completed_at_ns is None:
                raise PrivateAnalysisRunCorruptionError(
                    "terminal private-analysis run is incomplete"
                )
            if _terminal_state(record.outcome) is not record.state:
                raise PrivateAnalysisRunCorruptionError(
                    "terminal private-analysis state conflicts with outcome"
                )
        elif (
            record.outcome is not None
            or record.transcript_summary is not None
            or record.completed_at_ns is not None
        ):
            raise PrivateAnalysisRunCorruptionError(
                "nonterminal private-analysis run carries terminal data"
            )

    @staticmethod
    def _new_audit_entry(
        *,
        record: PrivateAnalysisRunRecord,
        reason: PrivateAnalysisRunAuditReason,
        from_state: PrivateAnalysisRunState | None,
        to_state: PrivateAnalysisRunState,
        actor_id: str,
        execution_id: str | None,
        audit_execution_id: str | None,
        created_at_ns: int,
        version: int,
        lease_expires_at_ns: int | None,
        cancellation_requested_at_ns: int | None,
        evidence_ledger_digest: str,
        budget_state: PrivateAnalysisToolBudgetState,
        transcript_digest: str | None,
        outcome_digest: str | None,
        completed_at_ns: int | None,
    ) -> PrivateAnalysisRunAuditEntry:
        snapshot = _state_snapshot_digest(
            state=to_state,
            version=version,
            execution_id=execution_id,
            lease_expires_at_ns=lease_expires_at_ns,
            cancellation_requested_at_ns=cancellation_requested_at_ns,
            evidence_ledger_digest=evidence_ledger_digest,
            budget_state=budget_state,
            transcript_digest=transcript_digest,
            outcome_digest=outcome_digest,
            created_at_ns=record.created_at_ns,
            updated_at_ns=created_at_ns,
            completed_at_ns=completed_at_ns,
        )
        provisional = PrivateAnalysisRunAuditEntry(
            scope=record.scope,
            run_id=record.run_id,
            sequence=version,
            run_version=version,
            reason=reason,
            from_state=from_state,
            to_state=to_state,
            actor_id=actor_id,
            execution_id=audit_execution_id,
            created_at_ns=created_at_ns,
            request_digest=record.request_digest,
            evidence_ledger_digest=evidence_ledger_digest,
            transcript_digest=transcript_digest,
            outcome_digest=outcome_digest,
            state_snapshot_digest=snapshot,
            previous_entry_digest=record.audit_tip_digest,
            entry_digest=_ZERO_DIGEST,
        )
        return PrivateAnalysisRunAuditEntry(
            scope=provisional.scope,
            run_id=provisional.run_id,
            sequence=provisional.sequence,
            run_version=provisional.run_version,
            reason=provisional.reason,
            from_state=provisional.from_state,
            to_state=provisional.to_state,
            actor_id=provisional.actor_id,
            execution_id=provisional.execution_id,
            created_at_ns=provisional.created_at_ns,
            request_digest=provisional.request_digest,
            evidence_ledger_digest=provisional.evidence_ledger_digest,
            transcript_digest=provisional.transcript_digest,
            outcome_digest=provisional.outcome_digest,
            state_snapshot_digest=provisional.state_snapshot_digest,
            previous_entry_digest=provisional.previous_entry_digest,
            entry_digest=_audit_entry_digest(provisional),
        )

    @staticmethod
    def _insert_audit(
        cursor: sqlite3.Cursor, entry: PrivateAnalysisRunAuditEntry
    ) -> None:
        cursor.execute(
            """
            INSERT INTO private_analysis_run_audit(
                tenant_id, project_id, workspace_id, run_id, sequence,
                run_version, reason, from_state, to_state, actor_id,
                execution_id, created_at_ns, request_digest,
                evidence_ledger_digest, transcript_digest, outcome_digest,
                state_snapshot_digest, previous_entry_digest, entry_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.scope.tenant_id,
                entry.scope.project_id,
                entry.scope.workspace_id,
                entry.run_id,
                entry.sequence,
                entry.run_version,
                entry.reason.value,
                entry.from_state.value if entry.from_state is not None else None,
                entry.to_state.value,
                entry.actor_id,
                entry.execution_id,
                entry.created_at_ns,
                entry.request_digest,
                entry.evidence_ledger_digest,
                entry.transcript_digest,
                entry.outcome_digest,
                entry.state_snapshot_digest,
                entry.previous_entry_digest,
                entry.entry_digest,
            ),
        )

    def _persist_transition(
        self,
        cursor: sqlite3.Cursor,
        prior: PrivateAnalysisRunRecord,
        desired: PrivateAnalysisRunRecord,
        *,
        reason: PrivateAnalysisRunAuditReason,
        actor_id: str,
    ) -> PrivateAnalysisRunRecord:
        if desired.version != prior.version + 1:
            raise AssertionError("run transition must increment version exactly once")
        if desired.scope != prior.scope or desired.run_id != prior.run_id:
            raise AssertionError("run transition cannot change durable identity")
        if desired.request != prior.request:
            raise AssertionError("run transition cannot change its request")
        if desired.created_at_ns != prior.created_at_ns:
            raise AssertionError("run transition cannot change its creation time")
        if desired.updated_at_ns < prior.updated_at_ns:
            raise ValueError("run transition timestamp cannot move backwards")
        if prior.audit_tip_sequence >= _MAX_AUDIT_ENTRIES_PER_RUN:
            raise PrivateAnalysisRunConflict(
                "private-analysis run audit safety bound reached"
            )
        if (
            desired.state is PrivateAnalysisRunState.CANCEL_REQUESTED
            and prior.audit_tip_sequence >= _MAX_AUDIT_ENTRIES_PER_RUN - 1
        ):
            raise PrivateAnalysisRunConflict(
                "private-analysis run audit terminal reserve reached"
            )
        if (
            not desired.state.is_terminal
            and desired.state is not PrivateAnalysisRunState.CANCEL_REQUESTED
            and prior.audit_tip_sequence >= _MAX_AUDIT_ENTRIES_PER_RUN - 2
        ):
            raise PrivateAnalysisRunConflict(
                "private-analysis run audit terminal reserve reached"
            )
        if (
            desired.completed_at_ns is not None
            and desired.completed_at_ns < desired.updated_at_ns
        ):
            raise ValueError("run completion timestamp cannot predate its update")
        transcript_digest = (
            desired.transcript_summary.summary_digest
            if desired.transcript_summary is not None
            else None
        )
        outcome_digest = (
            desired.outcome.outcome_digest if desired.outcome is not None else None
        )
        entry = self._new_audit_entry(
            record=prior,
            reason=reason,
            from_state=prior.state,
            to_state=desired.state,
            actor_id=actor_id,
            execution_id=desired.execution_id,
            audit_execution_id=(
                prior.execution_id
                if desired.state.is_terminal and prior.execution_id is not None
                else desired.execution_id
            ),
            created_at_ns=desired.updated_at_ns,
            version=desired.version,
            lease_expires_at_ns=desired.lease_expires_at_ns,
            cancellation_requested_at_ns=desired.cancellation_requested_at_ns,
            evidence_ledger_digest=desired.evidence_ledger_digest,
            budget_state=desired.budget_state,
            transcript_digest=transcript_digest,
            outcome_digest=outcome_digest,
            completed_at_ns=desired.completed_at_ns,
        )
        desired = replace(
            desired,
            audit_tip_sequence=entry.sequence,
            audit_tip_digest=entry.entry_digest,
        )
        self._validate_record_shape(desired)
        updated = cursor.execute(
            """
            UPDATE private_analysis_runs
            SET state = ?, version = ?, execution_id = ?,
                lease_expires_at_ns = ?, cancellation_requested_at_ns = ?,
                evidence_ledger_digest = ?, budget_json = ?,
                outcome_json = ?, outcome_digest = ?,
                transcript_json = ?, transcript_digest = ?,
                updated_at_ns = ?, completed_at_ns = ?,
                audit_tip_sequence = ?, audit_tip_digest = ?
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND run_id = ? AND version = ?
            """,
            (
                desired.state.value,
                desired.version,
                desired.execution_id,
                desired.lease_expires_at_ns,
                desired.cancellation_requested_at_ns,
                desired.evidence_ledger_digest,
                _budget_json(desired.budget_state),
                (
                    private_analysis_outcome_json(desired.outcome)
                    if desired.outcome is not None
                    else None
                ),
                outcome_digest,
                (
                    private_analysis_transcript_summary_json(desired.transcript_summary)
                    if desired.transcript_summary is not None
                    else None
                ),
                transcript_digest,
                desired.updated_at_ns,
                desired.completed_at_ns,
                entry.sequence,
                entry.entry_digest,
                *self._scope_values(desired.scope),
                desired.run_id,
                prior.version,
            ),
        )
        if updated.rowcount != 1:
            raise PrivateAnalysisRunStaleVersion(
                "private-analysis run changed concurrently"
            )
        if desired.disclosed_references != prior.disclosed_references:
            cursor.execute(
                """
                DELETE FROM private_analysis_run_disclosures
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND run_id = ?
                """,
                (*self._scope_values(desired.scope), desired.run_id),
            )
            cursor.executemany(
                """
                INSERT INTO private_analysis_run_disclosures(
                    tenant_id, project_id, workspace_id, run_id,
                    reference_digest, reference_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                tuple(
                    (
                        *self._scope_values(desired.scope),
                        desired.run_id,
                        reference.reference_digest,
                        _reference_json(reference),
                    )
                    for reference in desired.disclosed_references
                ),
            )
        self._insert_audit(cursor, entry)
        return desired

    def create_run(
        self,
        request: PrivateAnalysisRequest,
        *,
        actor_id: str,
        idempotency_key: str,
        run_id: str | None = None,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Admit one exact request after trusted scope/revision revalidation."""

        if type(request) is not PrivateAnalysisRequest:
            raise TypeError("request must be an exact PrivateAnalysisRequest")
        request = private_analysis_request_from_json(
            private_analysis_request_json(request)
        )
        actor = _identity(actor_id, "actor_id")
        key = _identity(idempotency_key, "idempotency_key")
        selected_run_id = _identity(run_id or uuid4().hex, "run_id")
        created_at = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        # The validator is deployment-owned trusted composition.  It must
        # compare every request binding with the durable catalog, not merely
        # accept a syntactically valid request.
        scope = request.scope
        budget = empty_private_analysis_budget_state(request)
        references: tuple[EvidenceReference, ...] = ()
        ledger_digest = evidence_snapshot_digest(references)
        audit_root = self._audit_root(scope, selected_run_id, request.request_digest)
        provisional = PrivateAnalysisRunRecord(
            scope=scope,
            run_id=selected_run_id,
            state=PrivateAnalysisRunState.QUEUED,
            version=1,
            request=request,
            execution_id=None,
            lease_expires_at_ns=None,
            cancellation_requested_at_ns=None,
            disclosed_references=references,
            evidence_ledger_digest=ledger_digest,
            budget_state=budget,
            outcome=None,
            transcript_summary=None,
            created_at_ns=created_at,
            updated_at_ns=created_at,
            completed_at_ns=None,
            audit_root_digest=audit_root,
            audit_tip_sequence=0,
            audit_tip_digest=audit_root,
        )
        initial = self._new_audit_entry(
            record=provisional,
            reason=PrivateAnalysisRunAuditReason.ADMITTED,
            from_state=None,
            to_state=PrivateAnalysisRunState.QUEUED,
            actor_id=actor,
            execution_id=None,
            audit_execution_id=None,
            created_at_ns=created_at,
            version=1,
            lease_expires_at_ns=None,
            cancellation_requested_at_ns=None,
            evidence_ledger_digest=ledger_digest,
            budget_state=budget,
            transcript_digest=None,
            outcome_digest=None,
            completed_at_ns=None,
        )
        record = replace(
            provisional,
            audit_tip_sequence=1,
            audit_tip_digest=initial.entry_digest,
        )
        try:
            with self._admission_fence():
                try:
                    self._admission_validator(request)
                except PrivateAnalysisRunStoreError:
                    raise
                except Exception as error:
                    raise PrivateAnalysisRunConflict(
                        "private-analysis request does not match durable scope and revisions"
                    ) from error
                with self._transaction() as cursor:
                    prior = cursor.execute(
                        """
                    SELECT request_digest, run_id
                    FROM private_analysis_run_admissions
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND idempotency_key = ?
                    """,
                        (*self._scope_values(scope), key),
                    ).fetchone()
                    if prior is not None:
                        if prior["request_digest"] != request.request_digest:
                            raise PrivateAnalysisRunConflict(
                                "private-analysis admission idempotency key conflicts"
                            )
                        try:
                            prior_row = self._require_run_row(
                                cursor, scope, prior["run_id"]
                            )
                        except PrivateAnalysisRunNotFound as error:
                            raise PrivateAnalysisRunConflict(
                                "private-analysis admission was already retained"
                            ) from error
                        return self._record_from_row(cursor, prior_row)
                    retained_key = cursor.execute(
                        """
                    SELECT request_digest FROM private_analysis_run_tombstones
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND idempotency_key_digest = ?
                    """,
                        (
                            *self._scope_values(scope),
                            _idempotency_key_digest(scope, key),
                        ),
                    ).fetchone()
                    if retained_key is not None:
                        if retained_key["request_digest"] != request.request_digest:
                            raise PrivateAnalysisRunConflict(
                                "private-analysis admission idempotency key conflicts"
                            )
                        raise PrivateAnalysisRunConflict(
                            "private-analysis admission was already retained"
                        )
                    retained_id = cursor.execute(
                        """
                    SELECT 1 FROM private_analysis_run_tombstones
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ?
                    """,
                        (*self._scope_values(scope), selected_run_id),
                    ).fetchone()
                    if retained_id is not None:
                        raise PrivateAnalysisRunConflict(
                            "private-analysis run id was already retained"
                        )
                    beyond_reference_bound = cursor.execute(
                        """
                    SELECT 1 FROM private_analysis_active_run_guards
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                    ORDER BY run_id
                    LIMIT 1 OFFSET ?
                    """,
                        (
                            *self._scope_values(scope),
                            _MAX_REFERENCE_PROTECTION_RUNS - 1,
                        ),
                    ).fetchone()
                    if beyond_reference_bound is not None:
                        raise PrivateAnalysisRunConflict(
                            "private-analysis active-run safety bound reached"
                        )
                    cursor.execute(
                        """
                    INSERT INTO private_analysis_runs(
                        tenant_id, project_id, workspace_id, run_id, state,
                        version, request_json, request_digest, execution_id,
                        lease_expires_at_ns, cancellation_requested_at_ns,
                        evidence_ledger_digest, budget_json, outcome_json,
                        outcome_digest, transcript_json, transcript_digest,
                        created_at_ns, updated_at_ns, completed_at_ns,
                        audit_root_digest, audit_tip_sequence, audit_tip_digest
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?,
                        NULL, NULL, NULL, NULL, ?, ?, NULL, ?, ?, ?
                    )
                    """,
                        (
                            *self._scope_values(scope),
                            selected_run_id,
                            record.state.value,
                            record.version,
                            private_analysis_request_json(request),
                            request.request_digest,
                            ledger_digest,
                            _budget_json(budget),
                            created_at,
                            created_at,
                            audit_root,
                            initial.sequence,
                            initial.entry_digest,
                        ),
                    )
                    cursor.executemany(
                        """
                    INSERT INTO private_analysis_run_revisions(
                        tenant_id, project_id, workspace_id, run_id, ordinal,
                        fixture_id, fixture_content_sha256, node_id,
                        revision_id, revision_identity_sha256,
                        plan_basis_revision_id, execution_plan_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        tuple(
                            (
                                *self._scope_values(scope),
                                selected_run_id,
                                index,
                                revision.fixture_id,
                                revision.fixture_content_sha256,
                                revision.node_id,
                                revision.revision_id,
                                revision.revision_identity_sha256,
                                revision.plan_basis_revision_id,
                                revision.execution_plan_digest,
                            )
                            for index, revision in enumerate(request.revisions)
                        ),
                    )
                    self._insert_audit(cursor, initial)
                    cursor.execute(
                        """
                    INSERT INTO private_analysis_active_run_guards(
                        tenant_id, project_id, workspace_id, run_id,
                        request_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                        (
                            *self._scope_values(scope),
                            selected_run_id,
                            request.request_digest,
                        ),
                    )
                    cursor.execute(
                        """
                    INSERT INTO private_analysis_run_admissions(
                        tenant_id, project_id, workspace_id, idempotency_key,
                        request_digest, run_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (
                            *self._scope_values(scope),
                            key,
                            request.request_digest,
                            selected_run_id,
                        ),
                    )
        except sqlite3.IntegrityError as error:
            raise PrivateAnalysisRunConflict(
                "private-analysis run conflicts with durable state"
            ) from error
        return record

    def get_run(
        self,
        scope: EvidenceScope,
        run_id: str,
    ) -> PrivateAnalysisRunRecord:
        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        with self._read_cursor() as cursor:
            return self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
            )

    def list_runs(
        self,
        scope: EvidenceScope,
        *,
        limit: int = 100,
        after_created_at_ns: int | None = None,
        after_run_id: str | None = None,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        selected_scope = _scope(scope)
        selected_limit = _bounded_integer(
            limit, "limit", minimum=1, maximum=_MAX_LIST_LIMIT
        )
        if (after_created_at_ns is None) is not (after_run_id is None):
            raise ValueError("run list cursor fields must be provided together")
        if after_created_at_ns is not None:
            after_time = _bounded_integer(
                after_created_at_ns,
                "after_created_at_ns",
                minimum=0,
                maximum=_MAX_SIGNED_64,
            )
            after_id = _identity(after_run_id, "after_run_id")
        else:
            after_time = -1
            after_id = ""
        with self._read_cursor() as cursor:
            rows = cursor.execute(
                """
                SELECT * FROM private_analysis_runs
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND (created_at_ns > ? OR
                       (created_at_ns = ? AND run_id > ?))
                ORDER BY created_at_ns, run_id
                LIMIT ?
                """,
                (
                    *self._scope_values(selected_scope),
                    after_time,
                    after_time,
                    after_id,
                    selected_limit,
                ),
            ).fetchall()
            return tuple(self._record_from_row(cursor, row) for row in rows)

    @staticmethod
    def _require_expected_version(
        record: PrivateAnalysisRunRecord,
        expected_version: int,
    ) -> None:
        selected = _bounded_integer(
            expected_version,
            "expected_version",
            minimum=1,
            maximum=_MAX_SIGNED_64,
        )
        if record.version != selected:
            raise PrivateAnalysisRunStaleVersion(
                "private-analysis run version is stale"
            )

    @staticmethod
    def _lease_expiry(now_ns: int, lease_duration_ns: int) -> int:
        duration = _bounded_integer(
            lease_duration_ns,
            "lease_duration_ns",
            minimum=1,
            maximum=_MAX_LEASE_NS,
        )
        if now_ns > _MAX_SIGNED_64 - duration:
            raise ValueError("lease expiry exceeds its signed 64-bit domain")
        return now_ns + duration

    def claim_run(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
        lease_duration_ns: int,
        execution_id: str | None = None,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Fence and lease one queued run; claims never retry a prior attempt."""

        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        actor = _identity(actor_id, "actor_id")
        attempt = _identity(execution_id or uuid4().hex, "execution_id")
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        expires = self._lease_expiry(now, lease_duration_ns)
        # Re-check the durable revision vector immediately before claiming.
        # The ControlPlane composition wraps admission/claim with the shared
        # catalog-retention fence, closing the cross-database race.
        with self._admission_fence():
            request = self.get_run(selected_scope, selected_run_id).request
            try:
                self._admission_validator(request)
            except Exception as error:
                raise PrivateAnalysisRunConflict(
                    "private-analysis request no longer matches durable revisions"
                ) from error
            with self._transaction() as cursor:
                prior = self._record_from_row(
                    cursor,
                    self._require_run_row(cursor, selected_scope, selected_run_id),
                )
                self._require_expected_version(prior, expected_version)
                if prior.state is not PrivateAnalysisRunState.QUEUED:
                    raise PrivateAnalysisRunConflict(
                        "only a queued private-analysis run can be claimed"
                    )
                desired = replace(
                    prior,
                    state=PrivateAnalysisRunState.RUNNING,
                    version=prior.version + 1,
                    execution_id=attempt,
                    lease_expires_at_ns=expires,
                    updated_at_ns=now,
                )
                return self._persist_transition(
                    cursor,
                    prior,
                    desired,
                    reason=PrivateAnalysisRunAuditReason.CLAIMED,
                    actor_id=actor,
                )

    def renew_lease(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        execution_id: str,
        actor_id: str,
        lease_duration_ns: int,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        attempt = _identity(execution_id, "execution_id")
        actor = _identity(actor_id, "actor_id")
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        expires = self._lease_expiry(now, lease_duration_ns)
        with self._transaction() as cursor:
            prior = self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
            )
            self._require_expected_version(prior, expected_version)
            if prior.state not in {
                PrivateAnalysisRunState.RUNNING,
                PrivateAnalysisRunState.CANCEL_REQUESTED,
            }:
                raise PrivateAnalysisRunConflict("run has no renewable lease")
            if prior.execution_id != attempt:
                raise PrivateAnalysisRunConflict("execution fence does not match")
            if prior.lease_expires_at_ns is None or prior.lease_expires_at_ns < now:
                raise PrivateAnalysisRunConflict("private-analysis lease has expired")
            if expires <= prior.lease_expires_at_ns:
                raise PrivateAnalysisRunConflict(
                    "private-analysis lease renewal must extend the lease"
                )
            desired = replace(
                prior,
                version=prior.version + 1,
                lease_expires_at_ns=expires,
                updated_at_ns=now,
            )
            return self._persist_transition(
                cursor,
                prior,
                desired,
                reason=PrivateAnalysisRunAuditReason.LEASE_RENEWED,
                actor_id=actor,
            )

    def commit_accounting(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        execution_id: str,
        references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
        actor_id: str,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Durably publish a complete ledger/budget before model disclosure."""

        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        attempt = _identity(execution_id, "execution_id")
        actor = _identity(actor_id, "actor_id")
        detached_references = _detached_references(references)
        detached_budget = detached_private_analysis_budget_state(budget_state)
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        with self._transaction() as cursor:
            prior = self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
            )
            self._require_expected_version(prior, expected_version)
            if prior.state not in {
                PrivateAnalysisRunState.RUNNING,
                PrivateAnalysisRunState.CANCEL_REQUESTED,
            }:
                raise PrivateAnalysisRunConflict(
                    "accounting requires an active private-analysis run"
                )
            if prior.execution_id != attempt:
                raise PrivateAnalysisRunConflict("execution fence does not match")
            if prior.lease_expires_at_ns is None or prior.lease_expires_at_ns < now:
                raise PrivateAnalysisRunConflict("private-analysis lease has expired")
            _validate_accounting(prior.request, detached_references, detached_budget)
            old = {item.reference_digest: item for item in prior.disclosed_references}
            new = {item.reference_digest: item for item in detached_references}
            if not old.keys() <= new.keys() or any(
                new[key] != value for key, value in old.items()
            ):
                raise PrivateAnalysisRunConflict(
                    "durable disclosure ledger cannot lose or replace references"
                )
            old_budget = prior.budget_state
            if (
                detached_budget.tool_calls_consumed < old_budget.tool_calls_consumed
                or detached_budget.evidence_items_disclosed
                < old_budget.evidence_items_disclosed
                or detached_budget.evidence_bytes_disclosed
                < old_budget.evidence_bytes_disclosed
            ):
                raise PrivateAnalysisRunConflict(
                    "durable private-analysis accounting cannot move backwards"
                )
            desired = replace(
                prior,
                version=prior.version + 1,
                disclosed_references=detached_references,
                evidence_ledger_digest=evidence_snapshot_digest(detached_references),
                budget_state=detached_budget,
                updated_at_ns=now,
            )
            return self._persist_transition(
                cursor,
                prior,
                desired,
                reason=PrivateAnalysisRunAuditReason.ACCOUNTING_COMMITTED,
                actor_id=actor,
            )

    def request_cancellation(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        actor_id: str,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Linearize a one-way cancellation request against completion."""

        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        actor = _identity(actor_id, "actor_id")
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        with self._transaction() as cursor:
            prior = self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
            )
            self._require_expected_version(prior, expected_version)
            if prior.state is PrivateAnalysisRunState.CANCEL_REQUESTED:
                return prior
            if prior.state is PrivateAnalysisRunState.CANCELLED:
                return prior
            if prior.state is PrivateAnalysisRunState.COMPLETED:
                raise PrivateAnalysisRunConflict("completed run cannot be cancelled")
            if prior.state is PrivateAnalysisRunState.QUEUED:
                outcome = _cancelled_outcome(prior.request_digest)
                desired = replace(
                    prior,
                    state=PrivateAnalysisRunState.CANCELLED,
                    version=prior.version + 1,
                    cancellation_requested_at_ns=now,
                    outcome=outcome,
                    updated_at_ns=now,
                    completed_at_ns=now,
                )
                reason = PrivateAnalysisRunAuditReason.CANCELLED_BEFORE_START
            else:
                desired = replace(
                    prior,
                    state=PrivateAnalysisRunState.CANCEL_REQUESTED,
                    version=prior.version + 1,
                    cancellation_requested_at_ns=now,
                    updated_at_ns=now,
                )
                reason = PrivateAnalysisRunAuditReason.CANCELLATION_REQUESTED
            return self._persist_transition(
                cursor,
                prior,
                desired,
                reason=reason,
                actor_id=actor,
            )

    def complete_run(
        self,
        scope: EvidenceScope,
        run_id: str,
        *,
        expected_version: int,
        execution_id: str,
        outcome: PrivateAnalysisOutcome,
        transcript_summary: PrivateAnalysisTranscriptSummary,
        references: tuple[EvidenceReference, ...],
        budget_state: PrivateAnalysisToolBudgetState,
        actor_id: str,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRecord:
        """Atomically seal one exact terminal receipt and its durable ledger."""

        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        attempt = _identity(execution_id, "execution_id")
        actor = _identity(actor_id, "actor_id")
        if type(outcome) is not PrivateAnalysisOutcome:
            raise TypeError("outcome must be an exact PrivateAnalysisOutcome")
        detached_outcome = private_analysis_outcome_from_json(
            private_analysis_outcome_json(outcome)
        )
        if type(transcript_summary) is not PrivateAnalysisTranscriptSummary:
            raise TypeError(
                "transcript_summary must be an exact PrivateAnalysisTranscriptSummary"
            )
        detached_transcript = private_analysis_transcript_summary_from_json(
            private_analysis_transcript_summary_json(transcript_summary)
        )
        detached_references = _detached_references(references)
        detached_budget = detached_private_analysis_budget_state(budget_state)
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        with self._transaction() as cursor:
            prior = self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
            )
            if detached_outcome.kind is PrivateAnalysisOutcomeKind.RESULT:
                assert detached_outcome.result is not None
                try:
                    # Terminal persistence is an authority boundary of its
                    # own.  Reapply the request-specific result contract here
                    # even when the runner already validated its output: the
                    # exact durable ledger, output budget, claim budget, and
                    # proposal budget are the values that must authorize the
                    # receipt being sealed.
                    validate_private_analysis_result(
                        detached_outcome.result,
                        prior.request,
                        detached_references,
                    )
                except (TypeError, ValueError) as error:
                    raise PrivateAnalysisRunConflict(
                        "terminal result violates the private-analysis contract"
                    ) from error
            if prior.state.is_terminal:
                if expected_version not in {prior.version, prior.version - 1}:
                    raise PrivateAnalysisRunStaleVersion(
                        "private-analysis run version is stale"
                    )
                final_audit = self._audit_entries(
                    cursor,
                    prior.scope,
                    prior.run_id,
                    expected_root=prior.audit_root_digest,
                    expected_tip_sequence=prior.audit_tip_sequence,
                    expected_tip_digest=prior.audit_tip_digest,
                )[-1]
                if (
                    final_audit.execution_id == attempt
                    and prior.outcome == detached_outcome
                    and prior.transcript_summary == detached_transcript
                    and prior.disclosed_references == detached_references
                    and prior.budget_state == detached_budget
                ):
                    return prior
                raise PrivateAnalysisRunConflict("terminal run receipt conflicts")
            self._require_expected_version(prior, expected_version)
            if prior.state not in {
                PrivateAnalysisRunState.RUNNING,
                PrivateAnalysisRunState.CANCEL_REQUESTED,
            }:
                raise PrivateAnalysisRunConflict(
                    "only an active private-analysis run can complete"
                )
            if prior.execution_id != attempt:
                raise PrivateAnalysisRunConflict("execution fence does not match")
            if prior.lease_expires_at_ns is None or prior.lease_expires_at_ns < now:
                raise PrivateAnalysisRunConflict("private-analysis lease has expired")
            outcome_request_digest: str | None
            if detached_outcome.kind is PrivateAnalysisOutcomeKind.RESULT:
                assert detached_outcome.result is not None
                outcome_request_digest = detached_outcome.result.request_digest
            else:
                assert detached_outcome.error is not None
                outcome_request_digest = detached_outcome.error.request_digest
            if outcome_request_digest != prior.request_digest:
                raise PrivateAnalysisRunConflict("outcome request digest conflicts")
            if (
                prior.state is PrivateAnalysisRunState.CANCEL_REQUESTED
                and _terminal_state(detached_outcome)
                is not PrivateAnalysisRunState.CANCELLED
            ):
                raise PrivateAnalysisRunConflict(
                    "cancel-requested run requires a cancelled outcome"
                )
            _validate_accounting(prior.request, detached_references, detached_budget)
            if (
                detached_references != prior.disclosed_references
                or detached_budget != prior.budget_state
            ):
                raise PrivateAnalysisRunConflict(
                    "terminal receipt was not committed to the write-ahead ledger"
                )
            if (
                detached_transcript.request_digest != prior.request_digest
                or detached_transcript.catalog_digest
                != prior.request.tool_catalog_digest
                or detached_transcript.instruction_profile_digest
                != prior.request.instruction_profile_digest
                or detached_transcript.runner_configuration_digest
                != prior.request.runner.configuration_digest
                or detached_transcript.transport is not prior.request.runner.transport
                or detached_transcript.evidence_ledger_digest
                != prior.evidence_ledger_digest
                or detached_transcript.budget_state != prior.budget_state
                or detached_transcript.outcome_digest != detached_outcome.outcome_digest
            ):
                raise PrivateAnalysisRunConflict(
                    "terminal transcript does not bind the durable run"
                )
            state = _terminal_state(detached_outcome)
            desired = replace(
                prior,
                state=state,
                version=prior.version + 1,
                execution_id=None,
                lease_expires_at_ns=None,
                outcome=detached_outcome,
                transcript_summary=detached_transcript,
                updated_at_ns=now,
                completed_at_ns=now,
            )
            reason = (
                PrivateAnalysisRunAuditReason.CANCELLED_DURING_RUN
                if state is PrivateAnalysisRunState.CANCELLED
                else PrivateAnalysisRunAuditReason.COMPLETED
            )
            return self._persist_transition(
                cursor,
                prior,
                desired,
                reason=reason,
                actor_id=actor,
            )

    def recover_expired_runs(
        self,
        *,
        actor_id: str,
        now_ns: int | None = None,
        limit: int = 100,
    ) -> tuple[PrivateAnalysisRunRecord, ...]:
        """Terminalize expired fenced attempts without automatic retry."""

        actor = _identity(actor_id, "actor_id")
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        selected_limit = _bounded_integer(
            limit, "limit", minimum=1, maximum=_MAX_LIST_LIMIT
        )
        recovered: list[PrivateAnalysisRunRecord] = []
        with self._transaction() as cursor:
            rows = cursor.execute(
                """
                SELECT * FROM private_analysis_runs
                WHERE state IN ('running', 'cancel_requested')
                  AND lease_expires_at_ns < ?
                ORDER BY lease_expires_at_ns, tenant_id, project_id,
                         workspace_id, run_id
                LIMIT ?
                """,
                (now, selected_limit),
            ).fetchall()
            for row in rows:
                prior = self._record_from_row(cursor, row)
                cancelled = prior.state is PrivateAnalysisRunState.CANCEL_REQUESTED
                outcome = (
                    _cancelled_outcome(prior.request_digest)
                    if cancelled
                    else _expired_outcome(prior.request_digest)
                )
                desired = replace(
                    prior,
                    state=(
                        PrivateAnalysisRunState.CANCELLED
                        if cancelled
                        else PrivateAnalysisRunState.COMPLETED
                    ),
                    version=prior.version + 1,
                    execution_id=None,
                    lease_expires_at_ns=None,
                    outcome=outcome,
                    transcript_summary=None,
                    updated_at_ns=now,
                    completed_at_ns=now,
                )
                recovered.append(
                    self._persist_transition(
                        cursor,
                        prior,
                        desired,
                        reason=(
                            PrivateAnalysisRunAuditReason.EXPIRED_CANCELLED
                            if cancelled
                            else PrivateAnalysisRunAuditReason.EXPIRED_RUNNER_FAILED
                        ),
                        actor_id=actor,
                    )
                )
        return tuple(recovered)

    def list_audit(
        self,
        scope: EvidenceScope,
        run_id: str,
    ) -> tuple[PrivateAnalysisRunAuditEntry, ...]:
        selected_scope = _scope(scope)
        selected_run_id = _identity(run_id, "run_id")
        with self._read_cursor() as cursor:
            record = self._record_from_row(
                cursor,
                self._require_run_row(cursor, selected_scope, selected_run_id),
                verify_audit=False,
            )
            return self._audit_entries(
                cursor,
                selected_scope,
                selected_run_id,
                expected_root=record.audit_root_digest,
                expected_tip_sequence=record.audit_tip_sequence,
                expected_tip_digest=record.audit_tip_digest,
            )

    def referenced_revision_ids(
        self,
        scope: EvidenceScope,
    ) -> tuple[str, ...]:
        """Return every revision retained by active proprietary run data."""

        selected_scope = _scope(scope)
        with self._read_cursor() as cursor:
            guards = cursor.execute(
                """
                SELECT * FROM private_analysis_active_run_guards
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                ORDER BY run_id
                LIMIT ?
                """,
                (
                    *self._scope_values(selected_scope),
                    _MAX_REFERENCE_PROTECTION_RUNS + 1,
                ),
            ).fetchall()
            if len(guards) > _MAX_REFERENCE_PROTECTION_RUNS:
                raise PrivateAnalysisRunCorruptionError(
                    "active private-analysis runs exceed the catalog-protection bound"
                )
            admissions = cursor.execute(
                """
                SELECT run_id, request_digest
                FROM private_analysis_run_admissions
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                ORDER BY run_id
                LIMIT ?
                """,
                (
                    *self._scope_values(selected_scope),
                    _MAX_REFERENCE_PROTECTION_RUNS + 1,
                ),
            ).fetchall()
            if len(admissions) > _MAX_REFERENCE_PROTECTION_RUNS:
                raise PrivateAnalysisRunCorruptionError(
                    "live private-analysis admissions exceed the protection bound"
                )
            missing_guard = cursor.execute(
                """
                SELECT runs.run_id
                FROM private_analysis_runs AS runs
                LEFT JOIN private_analysis_active_run_guards AS guards
                  ON guards.tenant_id = runs.tenant_id
                 AND guards.project_id = runs.project_id
                 AND guards.workspace_id = runs.workspace_id
                 AND guards.run_id = runs.run_id
                WHERE runs.tenant_id = ? AND runs.project_id = ?
                  AND runs.workspace_id = ? AND guards.run_id IS NULL
                LIMIT 1
                """,
                self._scope_values(selected_scope),
            ).fetchone()
            if missing_guard is not None:
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis run is missing its active guard"
                )
            guard_digests = {
                guard["run_id"]: guard["request_digest"] for guard in guards
            }
            admission_digests = {
                admission["run_id"]: admission["request_digest"]
                for admission in admissions
            }
            if guard_digests != admission_digests:
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis active guards and admissions disagree"
                )
            # Catalog retention is a safety-critical consumer.  Reconstruct
            # every bounded active guard into its full record.  The guard is
            # independent of the run head, so a torn/out-of-band whole-row
            # deletion remains visible instead of cascading all evidence of
            # the protected references away.
            revision_ids: set[str] = set()
            for guard in guards:
                row = cursor.execute(
                    """
                    SELECT * FROM private_analysis_runs
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ?
                    """,
                    (*self._scope_values(selected_scope), guard["run_id"]),
                ).fetchone()
                if row is None:
                    raise PrivateAnalysisRunCorruptionError(
                        "private-analysis active guard has no run head"
                    )
                record = self._record_from_row(cursor, row)
                if record.request_digest != guard["request_digest"]:
                    raise PrivateAnalysisRunCorruptionError(
                        "private-analysis active guard digest does not match"
                    )
                revision_ids.update(
                    revision.revision_id for revision in record.request.revisions
                )
            return tuple(sorted(revision_ids))

    def quick_check(self) -> None:
        """Fail closed if SQLite reports physical database corruption."""

        with self._read_cursor() as cursor:
            rows = cursor.execute("PRAGMA quick_check").fetchall()
            if not rows or any(row[0] != "ok" for row in rows):
                raise PrivateAnalysisRunCorruptionError(
                    "private-analysis run database integrity check failed"
                )

    @staticmethod
    def _retention_policy_document(
        policy: PrivateAnalysisRunRetentionPolicy,
    ) -> dict[str, object]:
        return {
            "contract_version": _RETENTION_VERSION,
            "enabled": policy.enabled,
            "completed_before_ns": str(policy.completed_before_ns),
            "max_runs": policy.max_runs,
        }

    @staticmethod
    def _retention_candidate_document(
        candidate: PrivateAnalysisRunRetentionCandidate,
    ) -> dict[str, object]:
        return {
            "run_id": candidate.run_id,
            "state": candidate.state.value,
            "completed_at_ns": str(candidate.completed_at_ns),
            "request_digest": candidate.request_digest,
            "evidence_ledger_digest": candidate.evidence_ledger_digest,
            "transcript_digest": candidate.transcript_digest,
            "outcome_digest": candidate.outcome_digest,
            "audit_tip_digest": candidate.audit_tip_digest,
        }

    @classmethod
    def _retention_inventory_document(
        cls,
        inventory: PrivateAnalysisRunRetentionInventory,
    ) -> dict[str, object]:
        return {
            "contract_version": _RETENTION_VERSION,
            "scope": {
                "tenant_id": inventory.scope.tenant_id,
                "project_id": inventory.scope.project_id,
                "workspace_id": inventory.scope.workspace_id,
            },
            "policy": cls._retention_policy_document(inventory.policy),
            "candidates": [
                cls._retention_candidate_document(item) for item in inventory.candidates
            ],
        }

    @classmethod
    def _retention_inventory_from_document(
        cls,
        value: object,
        *,
        expected_digest: str,
    ) -> PrivateAnalysisRunRetentionInventory:
        if type(value) is not dict or set(value) != {
            "contract_version",
            "scope",
            "policy",
            "candidates",
        }:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention inventory is invalid"
            )
        if value["contract_version"] != _RETENTION_VERSION:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention version is unsupported"
            )
        scope_value = value["scope"]
        policy_value = value["policy"]
        candidates_value = value["candidates"]
        if type(scope_value) is not dict or set(scope_value) != {
            "tenant_id",
            "project_id",
            "workspace_id",
        }:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention scope is invalid"
            )
        if type(policy_value) is not dict or set(policy_value) != {
            "contract_version",
            "enabled",
            "completed_before_ns",
            "max_runs",
        }:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention policy is invalid"
            )
        if policy_value["contract_version"] != _RETENTION_VERSION:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention policy version is unsupported"
            )
        if type(candidates_value) is not list:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention candidates are invalid"
            )
        try:
            scope = EvidenceScope(**scope_value)
            completed_text = policy_value["completed_before_ns"]
            completed_before_ns = parse_canonical_decimal_integer(
                completed_text,
                "stored retention completed_before_ns",
                minimum=0,
                maximum=_MAX_SIGNED_64,
            )
            policy = PrivateAnalysisRunRetentionPolicy(
                enabled=policy_value["enabled"],
                completed_before_ns=completed_before_ns,
                max_runs=policy_value["max_runs"],
            )
            candidates: list[PrivateAnalysisRunRetentionCandidate] = []
            expected_fields = {
                "run_id",
                "state",
                "completed_at_ns",
                "request_digest",
                "evidence_ledger_digest",
                "transcript_digest",
                "outcome_digest",
                "audit_tip_digest",
            }
            for item in candidates_value:
                if type(item) is not dict or set(item) != expected_fields:
                    raise ValueError("invalid retention candidate")
                completed_at = item["completed_at_ns"]
                parsed_completed_at = parse_canonical_decimal_integer(
                    completed_at,
                    "stored retention candidate completed_at_ns",
                    minimum=0,
                    maximum=_MAX_SIGNED_64,
                )
                candidate = PrivateAnalysisRunRetentionCandidate(
                    run_id=_identity(item["run_id"], "stored retention run_id"),
                    state=PrivateAnalysisRunState(item["state"]),
                    completed_at_ns=parsed_completed_at,
                    request_digest=validate_prefixed_lowercase_sha256(
                        item["request_digest"], "stored retention request digest"
                    ),
                    evidence_ledger_digest=validate_prefixed_lowercase_sha256(
                        item["evidence_ledger_digest"],
                        "stored retention ledger digest",
                    ),
                    transcript_digest=(
                        validate_prefixed_lowercase_sha256(
                            item["transcript_digest"],
                            "stored retention transcript digest",
                        )
                        if item["transcript_digest"] is not None
                        else None
                    ),
                    outcome_digest=validate_prefixed_lowercase_sha256(
                        item["outcome_digest"], "stored retention outcome digest"
                    ),
                    audit_tip_digest=validate_prefixed_lowercase_sha256(
                        item["audit_tip_digest"], "stored retention audit digest"
                    ),
                )
                if not candidate.state.is_terminal:
                    raise ValueError("nonterminal retention candidate")
                candidates.append(candidate)
        except (TypeError, ValueError, KeyError) as error:
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention inventory is invalid"
            ) from error
        if tuple(
            sorted(candidates, key=lambda item: (item.completed_at_ns, item.run_id))
        ) != tuple(candidates):
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention candidates are not canonical"
            )
        inventory = PrivateAnalysisRunRetentionInventory(
            scope=scope,
            policy=policy,
            candidates=tuple(candidates),
            inventory_digest=expected_digest,
        )
        if (
            _digest(
                "private_analysis_run_retention_inventory",
                cls._retention_inventory_document(inventory),
            )
            != expected_digest
        ):
            raise PrivateAnalysisRunCorruptionError(
                "stored run-retention inventory digest does not match"
            )
        return inventory

    def _retention_inventory(
        self,
        cursor: sqlite3.Cursor,
        scope: EvidenceScope,
        policy: PrivateAnalysisRunRetentionPolicy,
    ) -> PrivateAnalysisRunRetentionInventory:
        rows = cursor.execute(
            """
            SELECT * FROM private_analysis_runs
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
              AND state IN ('completed', 'cancelled')
              AND completed_at_ns < ?
            ORDER BY completed_at_ns, run_id
            LIMIT ?
            """,
            (*self._scope_values(scope), policy.completed_before_ns, policy.max_runs),
        ).fetchall()
        candidates: list[PrivateAnalysisRunRetentionCandidate] = []
        for row in rows:
            record = self._record_from_row(cursor, row)
            if record.completed_at_ns is None or record.outcome is None:
                raise PrivateAnalysisRunCorruptionError(
                    "terminal retention candidate is incomplete"
                )
            candidates.append(
                PrivateAnalysisRunRetentionCandidate(
                    run_id=record.run_id,
                    state=record.state,
                    completed_at_ns=record.completed_at_ns,
                    request_digest=record.request_digest,
                    evidence_ledger_digest=record.evidence_ledger_digest,
                    transcript_digest=(
                        record.transcript_summary.summary_digest
                        if record.transcript_summary is not None
                        else None
                    ),
                    outcome_digest=record.outcome.outcome_digest,
                    audit_tip_digest=record.audit_tip_digest,
                )
            )
        provisional = PrivateAnalysisRunRetentionInventory(
            scope=scope,
            policy=policy,
            candidates=tuple(candidates),
            inventory_digest=_ZERO_DIGEST,
        )
        digest = _digest(
            "private_analysis_run_retention_inventory",
            self._retention_inventory_document(provisional),
        )
        return replace(provisional, inventory_digest=digest)

    def inventory_retention(
        self,
        scope: EvidenceScope,
        policy: PrivateAnalysisRunRetentionPolicy | None = None,
    ) -> PrivateAnalysisRunRetentionInventory:
        selected_scope = _scope(scope)
        selected_policy = policy or PrivateAnalysisRunRetentionPolicy()
        if type(selected_policy) is not PrivateAnalysisRunRetentionPolicy:
            raise TypeError("policy must be an exact PrivateAnalysisRunRetentionPolicy")
        with self._read_cursor() as cursor:
            return self._retention_inventory(cursor, selected_scope, selected_policy)

    @classmethod
    def _retention_result_digest(
        cls,
        *,
        inventory_digest: str,
        operation_id: str,
        purged_run_ids: tuple[str, ...],
        actor_id: str,
        created_at_ns: int,
    ) -> str:
        return _digest(
            "private_analysis_run_retention_result",
            {
                "contract_version": _RETENTION_VERSION,
                "inventory_digest": inventory_digest,
                "operation_id": operation_id,
                "purged_run_ids": list(purged_run_ids),
                "actor_id": actor_id,
                "created_at_ns": str(created_at_ns),
            },
        )

    def _purge_deleted_content(self) -> None:
        """Remove logically deleted proprietary bytes from live DB/WAL files."""

        with self._lock:
            self._require_open()
            try:
                # ``secure_delete=ON`` zeros deleted cells within the bounded
                # candidate transaction.  A full-database VACUUM would make a
                # one-run retention request scale with every unrelated run, so
                # it is deliberately excluded from this online operation.
                # Truncating the WAL removes the pre-delete frames; a busy
                # checkpoint is not called a purge, and the committed journal
                # makes the operation safely retryable.
                row = self._connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
            except sqlite3.DatabaseError as error:
                raise PrivateAnalysisRunStoreError(
                    "private-analysis run physical cleanup failed"
                ) from error
            if (
                row is None
                or len(row) != 3
                or row[0] != 0
                or row[1] != 0
                or row[2] != 0
            ):
                raise PrivateAnalysisRunStoreError(
                    "private-analysis run physical cleanup is incomplete"
                )

    def run_retention(
        self,
        scope: EvidenceScope,
        policy: PrivateAnalysisRunRetentionPolicy,
        *,
        actor_id: str,
        operation_id: str,
        expected_inventory_digest: str | None = None,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRetentionResult:
        """Purge terminal run data and remove its live DB/WAL payload bytes."""

        result = self._run_retention_transaction(
            scope,
            policy,
            actor_id=actor_id,
            operation_id=operation_id,
            expected_inventory_digest=expected_inventory_digest,
            now_ns=now_ns,
        )
        if result.purged_run_ids:
            self._purge_deleted_content()
        return result

    def _run_retention_transaction(
        self,
        scope: EvidenceScope,
        policy: PrivateAnalysisRunRetentionPolicy,
        *,
        actor_id: str,
        operation_id: str,
        expected_inventory_digest: str | None = None,
        now_ns: int | None = None,
    ) -> PrivateAnalysisRunRetentionResult:
        """Commit one idempotent logical purge and its durable commitments."""

        selected_scope = _scope(scope)
        if type(policy) is not PrivateAnalysisRunRetentionPolicy:
            raise TypeError("policy must be an exact PrivateAnalysisRunRetentionPolicy")
        if not policy.enabled:
            raise PrivateAnalysisRunRetentionDisabled(
                "private-analysis run retention is disabled"
            )
        actor = _identity(actor_id, "actor_id")
        operation = _identity(operation_id, "operation_id")
        if expected_inventory_digest is not None:
            validate_prefixed_lowercase_sha256(
                expected_inventory_digest, "expected_inventory_digest"
            )
        now = _bounded_integer(
            time.time_ns() if now_ns is None else now_ns,
            "now_ns",
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
        policy_json = strict_canonical_json(self._retention_policy_document(policy))
        with self._transaction() as cursor:
            prior = cursor.execute(
                """
                SELECT * FROM private_analysis_run_retention_journal
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND operation_id = ?
                """,
                (*self._scope_values(selected_scope), operation),
            ).fetchone()
            if prior is not None:
                if prior["policy_json"] != policy_json or prior["actor_id"] != actor:
                    raise PrivateAnalysisRunConflict(
                        "run-retention operation id conflicts"
                    )
                try:
                    document = json.loads(prior["inventory_json"])
                    inventory = self._retention_inventory_from_document(
                        document,
                        expected_digest=prior["inventory_digest"],
                    )
                    purged_value = json.loads(prior["purged_run_ids_json"])
                    if type(purged_value) is not list or any(
                        type(item) is not str for item in purged_value
                    ):
                        raise ValueError("invalid purged IDs")
                    purged = tuple(purged_value)
                    if purged != tuple(item.run_id for item in inventory.candidates):
                        raise ValueError("retention result conflicts with inventory")
                    expected_result = self._retention_result_digest(
                        inventory_digest=inventory.inventory_digest,
                        operation_id=operation,
                        purged_run_ids=purged,
                        actor_id=actor,
                        created_at_ns=prior["created_at_ns"],
                    )
                    if expected_result != prior["result_digest"]:
                        raise ValueError("retention result digest conflicts")
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise PrivateAnalysisRunCorruptionError(
                        "stored run-retention journal is invalid"
                    ) from error
                return PrivateAnalysisRunRetentionResult(
                    inventory=inventory,
                    operation_id=operation,
                    purged_run_ids=purged,
                    result_digest=expected_result,
                )
            inventory = self._retention_inventory(cursor, selected_scope, policy)
            if (
                expected_inventory_digest is not None
                and inventory.inventory_digest != expected_inventory_digest
            ):
                raise PrivateAnalysisRunConflict(
                    "run-retention inventory changed before execution"
                )
            purged = tuple(item.run_id for item in inventory.candidates)
            for candidate in inventory.candidates:
                record = self._record_from_row(
                    cursor,
                    self._require_run_row(cursor, selected_scope, candidate.run_id),
                )
                if not record.state.is_terminal:
                    raise PrivateAnalysisRunConflict("nonterminal run cannot be purged")
                if now < record.updated_at_ns:
                    raise PrivateAnalysisRunConflict(
                        "run-retention timestamp cannot predate a candidate"
                    )
                admission = cursor.execute(
                    """
                    SELECT idempotency_key, request_digest
                    FROM private_analysis_run_admissions
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ?
                    """,
                    (*self._scope_values(selected_scope), record.run_id),
                ).fetchone()
                if (
                    admission is None
                    or admission["request_digest"] != record.request_digest
                ):
                    raise PrivateAnalysisRunCorruptionError(
                        "retained run is missing its exact admission"
                    )
                idempotency_key_digest = _idempotency_key_digest(
                    selected_scope,
                    _identity(
                        admission["idempotency_key"],
                        "stored idempotency_key",
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO private_analysis_run_tombstones(
                        tenant_id, project_id, workspace_id, run_id,
                        idempotency_key_digest,
                        request_digest, evidence_ledger_digest,
                        transcript_digest, outcome_digest, audit_root_digest,
                        audit_tip_sequence, audit_tip_digest, purged_at_ns,
                        operation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *self._scope_values(selected_scope),
                        record.run_id,
                        idempotency_key_digest,
                        record.request_digest,
                        record.evidence_ledger_digest,
                        (
                            record.transcript_summary.summary_digest
                            if record.transcript_summary is not None
                            else None
                        ),
                        record.outcome.outcome_digest if record.outcome else None,
                        record.audit_root_digest,
                        record.audit_tip_sequence,
                        record.audit_tip_digest,
                        now,
                        operation,
                    ),
                )
                deleted = cursor.execute(
                    """
                    DELETE FROM private_analysis_runs
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ? AND state IN ('completed', 'cancelled')
                    """,
                    (*self._scope_values(selected_scope), record.run_id),
                )
                if deleted.rowcount != 1:
                    raise PrivateAnalysisRunConflict("run changed during retention")
                guard_deleted = cursor.execute(
                    """
                    DELETE FROM private_analysis_active_run_guards
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ? AND request_digest = ?
                    """,
                    (
                        *self._scope_values(selected_scope),
                        record.run_id,
                        record.request_digest,
                    ),
                )
                if guard_deleted.rowcount != 1:
                    raise PrivateAnalysisRunCorruptionError(
                        "retained run is missing its exact active guard"
                    )
                admission_deleted = cursor.execute(
                    """
                    DELETE FROM private_analysis_run_admissions
                    WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                      AND run_id = ? AND request_digest = ?
                    """,
                    (
                        *self._scope_values(selected_scope),
                        record.run_id,
                        record.request_digest,
                    ),
                )
                if admission_deleted.rowcount != 1:
                    raise PrivateAnalysisRunCorruptionError(
                        "retained run admission changed during retention"
                    )
            result_digest = self._retention_result_digest(
                inventory_digest=inventory.inventory_digest,
                operation_id=operation,
                purged_run_ids=purged,
                actor_id=actor,
                created_at_ns=now,
            )
            inventory_json = strict_canonical_json(
                self._retention_inventory_document(inventory)
            )
            cursor.execute(
                """
                INSERT INTO private_analysis_run_retention_journal(
                    tenant_id, project_id, workspace_id, operation_id,
                    policy_json, inventory_digest, inventory_json,
                    purged_run_ids_json, actor_id, created_at_ns, result_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *self._scope_values(selected_scope),
                    operation,
                    policy_json,
                    inventory.inventory_digest,
                    inventory_json,
                    strict_canonical_json(list(purged)),
                    actor,
                    now,
                    result_digest,
                ),
            )
            return PrivateAnalysisRunRetentionResult(
                inventory=inventory,
                operation_id=operation,
                purged_run_ids=purged,
                result_digest=result_digest,
            )

    def list_retention_journal(
        self,
        scope: EvidenceScope,
        *,
        limit: int = 100,
    ) -> tuple[PrivateAnalysisRunRetentionJournalEntry, ...]:
        selected_scope = _scope(scope)
        selected_limit = _bounded_integer(
            limit, "limit", minimum=1, maximum=_MAX_LIST_LIMIT
        )
        with self._read_cursor() as cursor:
            rows = cursor.execute(
                """
                SELECT * FROM private_analysis_run_retention_journal
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                ORDER BY created_at_ns, operation_id
                LIMIT ?
                """,
                (*self._scope_values(selected_scope), selected_limit),
            ).fetchall()
            result: list[PrivateAnalysisRunRetentionJournalEntry] = []
            for row in rows:
                try:
                    purged_value = json.loads(row["purged_run_ids_json"])
                    if type(purged_value) is not list or any(
                        type(item) is not str for item in purged_value
                    ):
                        raise ValueError("invalid purged IDs")
                    purged = tuple(
                        _identity(item, "stored purged run ID") for item in purged_value
                    )
                    entry = PrivateAnalysisRunRetentionJournalEntry(
                        scope=selected_scope,
                        operation_id=_identity(
                            row["operation_id"], "stored operation_id"
                        ),
                        inventory_digest=validate_prefixed_lowercase_sha256(
                            row["inventory_digest"],
                            "stored retention inventory digest",
                        ),
                        purged_run_ids=purged,
                        actor_id=_identity(row["actor_id"], "stored actor_id"),
                        created_at_ns=_bounded_integer(
                            row["created_at_ns"],
                            "stored retention timestamp",
                            minimum=0,
                            maximum=_MAX_SIGNED_64,
                        ),
                        result_digest=validate_prefixed_lowercase_sha256(
                            row["result_digest"], "stored retention result digest"
                        ),
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise PrivateAnalysisRunCorruptionError(
                        "stored run-retention journal is invalid"
                    ) from error
                expected = self._retention_result_digest(
                    inventory_digest=entry.inventory_digest,
                    operation_id=entry.operation_id,
                    purged_run_ids=entry.purged_run_ids,
                    actor_id=entry.actor_id,
                    created_at_ns=entry.created_at_ns,
                )
                if expected != entry.result_digest:
                    raise PrivateAnalysisRunCorruptionError(
                        "stored run-retention result digest does not match"
                    )
                result.append(entry)
            return tuple(result)


__all__ = [
    "PrivateAnalysisRunAdmissionFence",
    "PrivateAnalysisRunAdmissionValidator",
    "PrivateAnalysisRunAuditEntry",
    "PrivateAnalysisRunAuditReason",
    "PrivateAnalysisRunConflict",
    "PrivateAnalysisRunCorruptionError",
    "PrivateAnalysisRunNotFound",
    "PrivateAnalysisRunRecord",
    "PrivateAnalysisRunRetentionCandidate",
    "PrivateAnalysisRunRetentionDisabled",
    "PrivateAnalysisRunRetentionInventory",
    "PrivateAnalysisRunRetentionJournalEntry",
    "PrivateAnalysisRunRetentionPolicy",
    "PrivateAnalysisRunRetentionResult",
    "PrivateAnalysisRunStaleVersion",
    "PrivateAnalysisRunState",
    "PrivateAnalysisRunStoreError",
    "SqlitePrivateAnalysisRunStore",
]
