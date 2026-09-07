from .capability_router import CapabilityProviderRegistry
from .ingestion_contracts import CatalogExecutionTimeoutError as CatalogExecutionTimeoutError, CatalogPublisherProcessBootstrap as CatalogPublisherProcessBootstrap, ImportScope as ImportScope, IngestionPipelineError as IngestionPipelineError, PublisherCallContext as PublisherCallContext, RevisionCatalogPublisher as RevisionCatalogPublisher
from .plugin_composition import PluginCompositionPolicy
from .plugin_execution_plan import MAX_EXECUTION_IDENTITY_LENGTH, PluginExecutionPlan
from .plugin_registration import PluginCandidate as PluginCandidate, PluginRegistry as PluginRegistry, RegisteredPlugin as RegisteredPlugin
from collections.abc import Iterable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

__all__ = ['CatalogExecutionTimeoutError', 'ImportScope', 'IngestionPipelineError', 'PublisherCallContext', 'RevisionCatalogPublisher', 'PluginCandidate', 'PluginRegistry', 'RegisteredPlugin', 'IngestionStateRootPathError', 'validate_ingestion_state_root', 'PluginExecutionTimeoutError', 'PluginExecutionProcessError', 'CatalogExecutionProcessError', 'ImportNotFoundError', 'ImportConflictError', 'ImportQuotaExceededError', 'ImportState', 'RetentionHostInventoryCoverage', 'PluginExecutionMode', 'PipelineLimits', 'RetentionPolicy', 'RetentionReport', 'RetentionAuditRecord', 'WorkerHealthSnapshot', 'QueueHealthSnapshot', 'inspect_durable_queue', 'ImportDescriptor', 'ImportEvent', 'NullRevisionCatalogPublisher', 'DurableIngestionPipeline', 'validate_import_metadata']

MAX_NODE_HINT_LENGTH = MAX_EXECUTION_IDENTITY_LENGTH

class IngestionStateRootPathError(IngestionPipelineError): ...

def validate_ingestion_state_root(root: str | Path) -> Path: ...

class PluginExecutionTimeoutError(IngestionPipelineError): ...

class PluginExecutionProcessError(IngestionPipelineError):
    private_exception_type: str | None
    private_exception_message: str | None
    def __init__(self, message: str, *, private_exception_type: str | None = None, private_exception_message: str | None = None) -> None: ...

class CatalogExecutionProcessError(IngestionPipelineError):
    private_exception_type: str | None
    private_exception_message: str | None
    def __init__(self, message: str, *, private_exception_type: str | None = None, private_exception_message: str | None = None) -> None: ...

class ImportNotFoundError(KeyError): ...
class ImportConflictError(IngestionPipelineError): ...
class ImportQuotaExceededError(ImportConflictError): ...

class ImportState(StrEnum):
    ADMITTING = 'admitting'
    QUEUED = 'queued'
    PROBING = 'probing'
    AWAITING_SELECTION = 'awaiting_selection'
    READY = 'ready'
    INGESTING = 'ingesting'
    PUBLISHING = 'publishing'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    @property
    def terminal(self) -> bool: ...

class _RetentionArtifactKind(StrEnum):
    BLOB = 'blob'
    DATASET = 'dataset'

class _RetentionCleanupState(StrEnum):
    CLEANUP_PENDING = 'cleanup_pending'
    COMPLETED = 'completed'
    DELETED = 'deleted'
    FAILED = 'failed'
    SKIPPED = 'skipped'

class RetentionHostInventoryCoverage(StrEnum):
    NOT_OBSERVED = 'not_observed'
    BOUNDED_HOST_SCAN = 'bounded_host_scan'

class PluginExecutionMode(StrEnum):
    INLINE = 'inline'
    PROCESS = 'process'

@dataclass(frozen=True, slots=True)
class PipelineLimits:
    max_upload_bytes: int = ...
    upload_chunk_bytes: int = ...
    max_workers: int = ...
    lease_seconds: int = ...
    poll_interval_seconds: float = ...
    max_attempts: int = ...
    max_active_imports_per_workspace: int = ...
    plugin_execution_mode: PluginExecutionMode = ...
    publisher_execution_mode: PluginExecutionMode | None = ...
    plugin_execution_timeout_seconds: float = ...
    publisher_execution_timeout_seconds: float | None = ...
    stalled_import_seconds: float = ...
    max_concurrent_uploads: int = ...
    max_staging_bytes: int = ...
    def __post_init__(self) -> None: ...
    @property
    def effective_publisher_execution_timeout_seconds(self) -> float: ...
    @property
    def effective_publisher_execution_mode(self) -> PluginExecutionMode: ...

@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    enabled: bool = ...
    terminal_import_grace_seconds: int = ...
    idempotency_replay_seconds: int = ...
    orphan_artifact_grace_seconds: int = ...
    stale_partial_seconds: int = ...
    max_delete_batch: int = ...
    max_scan_entries: int = ...
    max_tenant_bytes: int | None = ...
    max_workspace_bytes: int | None = ...
    max_tenant_imports: int | None = ...
    max_workspace_imports: int | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class RetentionReport:
    scope: ImportScope
    evaluated_at_ns: int
    executed: bool
    policy_enabled: bool
    host_storage_orphan_inventory: RetentionHostInventoryCoverage
    eligible_imports: int = ...
    candidate_events: int = ...
    candidate_plugin_rows: int = ...
    expired_idempotency_receipts: int = ...
    expired_retention_audits: int = ...
    fixture_views: int = ...
    content_blobs: int = ...
    revision_datasets: int = ...
    stale_partials: int = ...
    estimated_bytes: int = ...
    deleted_imports: int = ...
    deleted_retention_audits: int = ...
    deleted_files: int = ...
    deleted_bytes: int = ...
    deletion_failures: int = ...
    failure_details: tuple[str, ...] = ...
    truncated: bool = ...
    audit_id: str | None = ...
    def as_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class RetentionAuditRecord:
    audit_id: str
    scope: ImportScope
    created_at_ns: int
    report: Mapping[str, Any]
    actor: str | None = ...
    operation_id: str | None = ...
    request_digest: str | None = ...
    effective_now_ns: int | None = ...
    state: str = ...

@dataclass(frozen=True, slots=True)
class WorkerHealthSnapshot:
    started: bool
    live_workers: int
    total_claim_errors: int
    consecutive_claim_errors: int
    last_claim_error_at_ns: int | None
    last_claim_error: str | None
    total_iteration_errors: int
    consecutive_iteration_errors: int
    last_iteration_error_at_ns: int | None
    last_iteration_error: str | None
    pending_imports: int = ...
    awaiting_selection_imports: int = ...
    stalled_imports: int = ...
    oldest_pending_updated_at_ns: int | None = ...
    stall_after_seconds: float = ...
    queue_evaluated_at_ns: int | None = ...
    state_counts: tuple[tuple[str, int], ...] = ...
    queue_observation_error: str | None = ...
    unexpected_worker_exits: int = ...
    last_worker_exit_at_ns: int | None = ...
    last_worker_exit: str | None = ...
    catalog_attention_imports: int = ...

@dataclass(frozen=True, slots=True)
class QueueHealthSnapshot:
    pending_imports: int
    awaiting_selection_imports: int
    stalled_imports: int
    oldest_pending_updated_at_ns: int | None
    stall_after_seconds: float
    evaluated_at_ns: int
    state_counts: tuple[tuple[str, int], ...]
    observation_error: str | None = ...
    catalog_attention_imports: int = ...

def inspect_durable_queue(database_path: str | Path, *, stall_after_seconds: float = 900.0, now_ns: int | None = None) -> QueueHealthSnapshot: ...

@dataclass(frozen=True, slots=True)
class _RetentionPlan:
    report: RetentionReport
    import_ids: tuple[str, ...]
    receipt_rowids: tuple[int, ...]
    audit_ids: tuple[str, ...]
    fixture_directories: tuple[Path, ...]
    blob_files: tuple[tuple[str, Path], ...]
    dataset_files: tuple[tuple[str, Path], ...]
    stale_partials: tuple[Path, ...]
    shard_directories: tuple[tuple[str, Path], ...]
    host_cursors: tuple[tuple[str, str], ...]
    host_identities: tuple[tuple[str, str, tuple[int, int, int, int, int, int]], ...] = ...
    path_sizes: tuple[tuple[Path, int], ...] = ...
    truncations: tuple[_RetentionTruncation, ...] = ...

@dataclass(frozen=True, slots=True)
class _RetentionTruncation:
    source: str
    limit: int
    observed_at_least: int

@dataclass(slots=True)
class _RetentionTelemetryContext:
    run_id: str
    started_monotonic_ns: int
    phase: str = ...
    audit_id: str | None = ...
    mutation_started: bool = ...

@dataclass(frozen=True, slots=True)
class _RetentionWorkItem:
    sequence: int
    action: str
    root: str
    reference: str | None
    relative_path: str
    planned_bytes: int
    expected_identity: tuple[int, int, int, int, int, int] | None = ...

@dataclass(frozen=True, slots=True)
class _HostRetentionCandidate:
    root_name: str
    relative_path: str
    path: Path
    action: str
    reference: str | None
    is_directory: bool
    identity: tuple[int, int, int, int, int, int]

@dataclass(frozen=True, slots=True)
class _HostRetentionScan:
    candidates: tuple[_HostRetentionCandidate, ...]
    next_cursors: tuple[tuple[str, str], ...]
    truncated: bool
    truncations: tuple[_RetentionTruncation, ...] = ...

@dataclass(frozen=True, slots=True)
class _PreparedContentFile:
    target: Path
    candidate: Path
    content_root: Path
    install_lock: Path
    shard_gate: Path
    activity_lock: Path
    activity_lock_stack: ExitStack
    expected_sha256: str
    expected_bytes: int
    observed_target_identity: tuple[int, int, int, int, int, int] | None
    observed_target_valid: bool

@dataclass(frozen=True, slots=True)
class _PreparedFixtureView:
    fixture_directory: Path
    staging_directory: Path
    input_relative: Path

@dataclass(frozen=True, slots=True)
class ImportDescriptor:
    import_id: str
    scope: ImportScope
    fixture_id: str
    state: ImportState
    version: int
    original_name: str
    content_type: str
    node_hint: str | None
    metadata: Mapping[str, Any]
    byte_count: int
    content_sha256: str
    probe_set_hash: str | None
    plugin_composition_policy_digest: str
    selected_plugin_id: str | None
    selected_plugin_version: str | None
    revision_id: str | None
    node_id: str | None
    attempt_count: int
    max_attempts: int
    auto_select: bool
    error_code: str | None
    error_message: str | None
    created_at_ns: int
    updated_at_ns: int
    @property
    def attempts_remaining(self) -> int: ...
    @property
    def retryable(self) -> bool: ...
    def as_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class ImportEvent:
    sequence: int
    import_id: str
    state: ImportState
    event_type: str
    message: str
    payload: Mapping[str, Any]
    created_at_ns: int
    def as_dict(self) -> dict[str, Any]: ...

class _PublisherExecutionPlanSupport(StrEnum):
    ABSENT = 'absent'
    EXPLICIT_KEYWORD = 'explicit_keyword'
    VAR_KEYWORD = 'var_keyword'

class NullRevisionCatalogPublisher:
    def admit_fixture(self, scope: ImportScope, **values: Any) -> None: ...
    def publish_revision(self, scope: ImportScope, **values: Any) -> str | None: ...

@dataclass(frozen=True, slots=True)
class _StagedChildIngestion:
    revision_id: str
    node_id: str
    dataset_sha256: str
    dataset_bytes: int
    event_count: int
    source_record_count: int
    resource_count: int
    execution_plan: PluginExecutionPlan

class DurableIngestionPipeline:
    root: Path
    database_path: Path
    blob_root: Path
    dataset_root: Path
    fixture_root: Path
    spool_root: Path
    lock_root: Path
    content_lock_root: Path
    registry: PluginRegistry
    allow_inline_only: bool
    requires_inline_execution: bool
    capability_providers: CapabilityProviderRegistry
    composition_policy: PluginCompositionPolicy
    publisher: RevisionCatalogPublisher
    publisher_process_bootstrap: CatalogPublisherProcessBootstrap
    limits: PipelineLimits
    retention_policy: RetentionPolicy
    worker_id: str
    def __init__(self, root: Path, *, registry: PluginRegistry, publisher: RevisionCatalogPublisher | None = None, publisher_module_target: str | None = None, limits: PipelineLimits | None = None, retention_policy: RetentionPolicy | None = None, composition_policy: PluginCompositionPolicy | None = None, capability_providers: CapabilityProviderRegistry | None = None, worker_id: str | None = None, allow_inline_only: bool = False) -> None: ...
    def start(self) -> None: ...
    def close(self, *, timeout: float = 30.0) -> None: ...
    def worker_health(self) -> WorkerHealthSnapshot: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, *exc_info: object) -> None: ...
    def submit_bytes(self, scope: ImportScope, content: bytes, *, original_name: str, content_type: str = 'application/octet-stream', idempotency_key: str | None = None, auto_select: bool = True, preferred_plugin_id: str | None = None, node_hint: str | None = None, metadata: Mapping[str, Any] | None = None) -> ImportDescriptor: ...
    def submit_chunks(self, scope: ImportScope, chunks: Iterable[bytes], *, original_name: str, content_type: str = 'application/octet-stream', idempotency_key: str | None = None, auto_select: bool = True, preferred_plugin_id: str | None = None, node_hint: str | None = None, metadata: Mapping[str, Any] | None = None, expected_bytes: int | None = None) -> ImportDescriptor: ...
    def retention_inventory(self, scope: ImportScope, *, now_ns: int | None = None) -> RetentionReport: ...
    def run_retention(self, scope: ImportScope, *, dry_run: bool = True, now_ns: int | None = None, actor: str = 'system', operation_id: str | None = None) -> RetentionReport: ...
    def list_retention_audits(self, scope: ImportScope, *, limit: int = 100) -> tuple[RetentionAuditRecord, ...]: ...
    def release_artifact_pin(self, scope: ImportScope, *, artifact_kind: str, artifact_ref: str, owner_operation_id: str) -> bool: ...
    def get_import(self, scope: ImportScope, import_id: str) -> ImportDescriptor: ...
    def list_imports(self, scope: ImportScope, *, limit: int = 100, before_created_at_ns: int | None = None, before_import_id: str | None = None) -> tuple[ImportDescriptor, ...]: ...
    def candidates(self, scope: ImportScope, import_id: str) -> tuple[PluginCandidate, ...]: ...
    def events(self, scope: ImportScope, import_id: str, *, after_sequence: int = 0, limit: int = 200) -> tuple[ImportEvent, ...]: ...
    def select_plugin(self, scope: ImportScope, import_id: str, *, probe_set_hash: str, plugin_id: str, plugin_version: str, package_hash: str, idempotency_key: str, instance_id: str | None = None, registered_execution_identity: str | None = None) -> ImportDescriptor: ...
    def resume(self, scope: ImportScope, import_id: str) -> ImportDescriptor: ...
    def cancel(self, scope: ImportScope, import_id: str, *, expected_version: int) -> ImportDescriptor: ...
    def wait(self, scope: ImportScope, import_id: str, *, timeout: float, stop_at_selection: bool = True) -> ImportDescriptor: ...

def validate_import_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]: ...

# Preserve the original typed import paths for moved bootstrap records.
from .plugin_registration import (
    _IdentityBoundTraceDecoder as _IdentityBoundTraceDecoder,
    _PinnedManifestPlugin as _PinnedManifestPlugin,
    _PluginProcessBootstrap as _PluginProcessBootstrap,
    _ProcessTargetIdentityUnavailable as _ProcessTargetIdentityUnavailable,
    _ProcessTargetKind as _ProcessTargetKind,
)
