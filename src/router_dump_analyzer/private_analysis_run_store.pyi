from .private_analysis import EvidenceReference, EvidenceScope, PrivateAnalysisOutcome, PrivateAnalysisRequest
from .private_analysis_runner_support import PrivateAnalysisTranscriptSummary
from .private_analysis_tool_service import PrivateAnalysisToolBudgetState
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Self

__all__ = ['PrivateAnalysisRunStoreError', 'PrivateAnalysisRunConflict', 'PrivateAnalysisRunNotFound', 'PrivateAnalysisRunStaleVersion', 'PrivateAnalysisRunCorruptionError', 'PrivateAnalysisRunRetentionDisabled', 'PrivateAnalysisRunCleanupPending', 'PrivateAnalysisRunState', 'PrivateAnalysisRunAuditReason', 'PrivateAnalysisRunCleanupFence', 'PrivateAnalysisRunRecord', 'PrivateAnalysisRunAuditEntry', 'PrivateAnalysisRunRetentionPolicy', 'PrivateAnalysisRunRetentionCandidate', 'PrivateAnalysisRunRetentionInventory', 'PrivateAnalysisRunRetentionResult', 'PrivateAnalysisRunRetentionJournalEntry', 'PrivateAnalysisRunAdmissionValidator', 'PrivateAnalysisRunAdmissionFence', 'SqlitePrivateAnalysisRunStore']

class PrivateAnalysisRunStoreError(RuntimeError): ...
class PrivateAnalysisRunConflict(PrivateAnalysisRunStoreError): ...
class PrivateAnalysisRunNotFound(PrivateAnalysisRunStoreError): ...
class PrivateAnalysisRunStaleVersion(PrivateAnalysisRunConflict): ...
class PrivateAnalysisRunCorruptionError(PrivateAnalysisRunStoreError): ...
class PrivateAnalysisRunRetentionDisabled(PrivateAnalysisRunStoreError): ...
class PrivateAnalysisRunCleanupPending(PrivateAnalysisRunConflict): ...

class PrivateAnalysisRunState(StrEnum):
    QUEUED = 'queued'
    RUNNING = 'running'
    CANCEL_REQUESTED = 'cancel_requested'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'
    @property
    def is_terminal(self) -> bool: ...

class PrivateAnalysisRunAuditReason(StrEnum):
    ADMITTED = 'admitted'
    CLAIMED = 'claimed'
    LEASE_RENEWED = 'lease_renewed'
    ACCOUNTING_COMMITTED = 'accounting_committed'
    CANCELLATION_REQUESTED = 'cancellation_requested'
    CANCELLED_BEFORE_START = 'cancelled_before_start'
    COMPLETED = 'completed'
    CANCELLED_DURING_RUN = 'cancelled_during_run'
    CANCELLED_BEFORE_RUNNER = 'cancelled_before_runner'
    FAILED_BEFORE_RUNNER = 'failed_before_runner'
    EXPIRED_RUNNER_FAILED = 'expired_runner_failed'
    EXPIRED_CANCELLED = 'expired_cancelled'

@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunCleanupFence:
    scope: EvidenceScope
    run_id: str
    execution_id: str
    created_at_ns: int
    last_attempt_at_ns: int
    attempt_count: int

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
    cleanup_pending: bool
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
    def request_digest(self) -> str: ...

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
    enabled: bool = ...
    completed_before_ns: int = ...
    max_runs: int = ...
    def __post_init__(self) -> None: ...

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

class SqlitePrivateAnalysisRunStore:
    def __init__(self, database_path: str | Path, *, admission_validator: PrivateAnalysisRunAdmissionValidator, admission_fence: PrivateAnalysisRunAdmissionFence = ...) -> None: ...
    @property
    def installation_id(self) -> str: ...
    def close(self) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *exc_info: object) -> None: ...
    def create_run(self, request: PrivateAnalysisRequest, *, actor_id: str, idempotency_key: str, run_id: str | None = None, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def get_run(self, scope: EvidenceScope, run_id: str) -> PrivateAnalysisRunRecord: ...
    def get_cleanup_fence(self, scope: EvidenceScope, run_id: str) -> PrivateAnalysisRunCleanupFence | None: ...
    def cleanup_fence_matches(self, scope: EvidenceScope, run_id: str, *, execution_id: str, cleanup_capability: str) -> bool | None: ...
    def list_cleanup_fences(self, scope: EvidenceScope, *, limit: int = 100) -> tuple[PrivateAnalysisRunCleanupFence, ...]: ...
    def begin_cleanup_fence(self, scope: EvidenceScope, run_id: str, *, execution_id: str, cleanup_capability: str, now_ns: int | None = None) -> PrivateAnalysisRunCleanupFence: ...
    def note_cleanup_attempt(self, scope: EvidenceScope, run_id: str, *, execution_id: str, cleanup_capability: str, now_ns: int | None = None) -> PrivateAnalysisRunCleanupFence: ...
    def list_runs(self, scope: EvidenceScope, *, limit: int = 100, after_created_at_ns: int | None = None, after_run_id: str | None = None) -> tuple[PrivateAnalysisRunRecord, ...]: ...
    def claim_run(self, scope: EvidenceScope, run_id: str, *, expected_version: int, actor_id: str, lease_duration_ns: int, execution_id: str | None = None, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def renew_lease(self, scope: EvidenceScope, run_id: str, *, expected_version: int, execution_id: str, actor_id: str, lease_duration_ns: int, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def commit_accounting(self, scope: EvidenceScope, run_id: str, *, expected_version: int, execution_id: str, references: tuple[EvidenceReference, ...], budget_state: PrivateAnalysisToolBudgetState, actor_id: str, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def request_cancellation(self, scope: EvidenceScope, run_id: str, *, expected_version: int, actor_id: str, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def finalize_unstarted_attempt(self, scope: EvidenceScope, run_id: str, *, expected_version: int, execution_id: str, actor_id: str, cleanup_capability: str | None = None, timed_out: bool = False, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def complete_run(self, scope: EvidenceScope, run_id: str, *, expected_version: int, execution_id: str, outcome: PrivateAnalysisOutcome, transcript_summary: PrivateAnalysisTranscriptSummary, references: tuple[EvidenceReference, ...], budget_state: PrivateAnalysisToolBudgetState, actor_id: str, cleanup_capability: str | None = None, now_ns: int | None = None) -> PrivateAnalysisRunRecord: ...
    def recover_expired_runs(self, *, actor_id: str, now_ns: int | None = None, limit: int = 100, scope: EvidenceScope | None = None) -> tuple[PrivateAnalysisRunRecord, ...]: ...
    def list_audit(self, scope: EvidenceScope, run_id: str) -> tuple[PrivateAnalysisRunAuditEntry, ...]: ...
    def referenced_revision_ids(self, scope: EvidenceScope) -> tuple[str, ...]: ...
    def quick_check(self) -> None: ...
    def inventory_retention(self, scope: EvidenceScope, policy: PrivateAnalysisRunRetentionPolicy | None = None) -> PrivateAnalysisRunRetentionInventory: ...
    def run_retention(self, scope: EvidenceScope, policy: PrivateAnalysisRunRetentionPolicy, *, actor_id: str, operation_id: str, expected_inventory_digest: str | None = None, now_ns: int | None = None) -> PrivateAnalysisRunRetentionResult: ...
    def list_retention_journal(self, scope: EvidenceScope, *, limit: int = 100) -> tuple[PrivateAnalysisRunRetentionJournalEntry, ...]: ...
