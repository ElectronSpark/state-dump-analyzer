"""Durable, tenant-scoped upload and ingestion coordination.

The parser contract in :mod:`router_dump_analyzer.ingestion` deliberately
handles one admitted input at a time.  This module owns the production control
plane around that pure operation:

* bounded, content-addressed uploads;
* a durable SQLite job queue with restart recovery and leases;
* deterministic plug-in probing and optimistic plug-in selection;
* publication through a caller-supplied revision catalog; and
* status/event projections suitable for HTTP, CLI, and CI callers.

The SQLite profile is intended for a single-host deployment. Queue claims are
transactional and safe across processes sharing the same database. Direct
local/test pipelines may execute plug-ins inline; production composition uses
bounded child processes while the parent retains lease ownership and durable
publication. A distributed deployment can replace this class without changing
the catalog or plug-in contracts.
"""

from __future__ import annotations

import errno
import hashlib
import heapq
import inspect
import json
import math
import multiprocessing
import os
import random
import re
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Self
from uuid import uuid4

from .artifact_core import ArtifactLimits
from .canonical import canonical_json
from .contract_validation import validate_bounded_json_value
from .filesystem_lock import (
    exclusive_file_lock,
    try_exclusive_file_lock,
    try_existing_exclusive_file_lock,
)
from .ingestion import (
    IngestionCoordinator,
    IngestionError,
    IngestionLimits,
    IngestionResult,
    _bind_primary_ingestion_perspectives,
    snapshot_ingestion_result_for_publication,
)
from .ingestion_contracts import (
    MAX_SCOPE_ID_LENGTH as MAX_SCOPE_ID_LENGTH,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    CatalogExecutionTimeoutError as CatalogExecutionTimeoutError,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    CatalogPublisherProcessBootstrap as CatalogPublisherProcessBootstrap,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    ImportScope as ImportScope,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    IngestionPipelineError as IngestionPipelineError,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    PublisherCallContext as PublisherCallContext,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    RevisionCatalogPublisher as RevisionCatalogPublisher,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    _bounded_identifier as _bounded_identifier,  # noqa: PLC0414 - compatibility export
)
from .ingestion_contracts import (
    _normalized_explicit_bootstrap_target as _normalized_explicit_bootstrap_target,  # noqa: PLC0414 - compatibility export
)
from .operational_logging import emit_operational_event
from .plugin_api import (
    MAX_PROBE_DETECTED_TEXT_LENGTH,
    MAX_PROBE_REASON_LENGTH,
    CaptureRange,
    PluginCapability,
    ProbeMatchKind,
    ProbeResult,
    Provenance,
    Quality,
    TimelineTimeBasis,
    WorldBasis,
    WorldBasisKind,
    validate_probe_result,
)
from .plugin_composition import (
    DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST,
    REVISION_CONSISTENCY_ROLE,
    REVISION_RELATIONSHIP_PROJECTION_ROLE,
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from .plugin_execution_plan import (
    MAX_EXECUTION_IDENTITY_LENGTH,
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
    plugin_execution_plan_dict,
    plugin_execution_plan_from_dict,
    plugin_execution_plan_is_executable,
    primary_parser_execution_pin,
    validate_execution_identity,
)
from .plugin_loading import load_process_bootstrap_target
from .plugin_registration import (
    _ACTIVE_DECODER_IDENTITY as _ACTIVE_DECODER_IDENTITY,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _ARTIFACT_LIMIT_BOOTSTRAP_FIELDS as _ARTIFACT_LIMIT_BOOTSTRAP_FIELDS,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _DEFAULT_PLUGIN_CONFIGURATION_DIGEST as _DEFAULT_PLUGIN_CONFIGURATION_DIGEST,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _INGESTION_LIMIT_BOOTSTRAP_FIELDS as _INGESTION_LIMIT_BOOTSTRAP_FIELDS,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _INLINE_ONLY_PROCESS_COMPATIBILITY as _INLINE_ONLY_PROCESS_COMPATIBILITY,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _MANIFEST_PROCESS_BOOTSTRAP_ERROR as _MANIFEST_PROCESS_BOOTSTRAP_ERROR,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _PACKAGE_HASH_PATTERN as _PACKAGE_HASH_PATTERN,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR as _PROCESS_TARGET_PROCESS_BOOTSTRAP_ERROR,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    MAX_PLUGIN_CANDIDATES as MAX_PLUGIN_CANDIDATES,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    PluginCandidate as PluginCandidate,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    PluginRegistry as PluginRegistry,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    RegisteredPlugin as RegisteredPlugin,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _bootstrap_class_target as _bootstrap_class_target,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _current_process_target_executable_identities as _current_process_target_executable_identities,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _IdentityBoundTraceDecoder as _IdentityBoundTraceDecoder,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _ingestion_limits_from_snapshot as _ingestion_limits_from_snapshot,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _PinnedManifestPlugin as _PinnedManifestPlugin,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _plugin_process_bootstrap_digest as _plugin_process_bootstrap_digest,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _plugin_process_bootstrap_identity_material as _plugin_process_bootstrap_identity_material,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _PluginProcessBootstrap as _PluginProcessBootstrap,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _process_target_executable_identity as _process_target_executable_identity,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _process_target_identity_subject as _process_target_identity_subject,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _ProcessTargetIdentityUnavailable as _ProcessTargetIdentityUnavailable,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _ProcessTargetKind as _ProcessTargetKind,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _registered_ingestion_limits as _registered_ingestion_limits,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _registered_plugin_is_process_capable as _registered_plugin_is_process_capable,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _registered_plugin_is_trusted_inline_capable as _registered_plugin_is_trusted_inline_capable,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _registered_plugin_uses_inline_only_compatibility as _registered_plugin_uses_inline_only_compatibility,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _registered_plugins_require_inline_execution as _registered_plugins_require_inline_execution,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _require_no_inline_only_plugin_compatibility as _require_no_inline_only_plugin_compatibility,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _revalidate_process_target_executable_identities as _revalidate_process_target_executable_identities,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _snapshot_decoder_identity as _snapshot_decoder_identity,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _snapshot_ingestion_limit_bootstrap as _snapshot_ingestion_limit_bootstrap,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _snapshot_plugin_manifest as _snapshot_plugin_manifest,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    _validated_allow_inline_only as _validated_allow_inline_only,  # noqa: PLC0414 - compatibility export
)
from .plugin_registration import (
    registered_plugin_matches_execution_pin as registered_plugin_matches_execution_pin,  # noqa: PLC0414 - compatibility export
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .revision_world import IngestionRevisionWorld
from .value_core import parse_canonical_decimal_integer

if TYPE_CHECKING:
    from .capability_router import CapabilityProviderRegistry

MAX_IMPORT_ID_LENGTH = 128
MAX_FILENAME_LENGTH = 512
MAX_CONTENT_TYPE_LENGTH = 256
MAX_NODE_HINT_LENGTH = MAX_EXECUTION_IDENTITY_LENGTH
MAX_IMPORT_METADATA_BYTES = 65_536
MAX_EVENT_MESSAGE_LENGTH = 2_048
MAX_IDEMPOTENCY_KEY_LENGTH = 256
MAX_IMPORT_EVENTS_PAGE = 1_000
MAX_PLUGIN_CHILD_MESSAGE_BYTES = 1024 * 1024
PLUGIN_CHILD_REAP_SECONDS = 2.0
MAX_RETENTION_BATCH = 10_000
MAX_RETENTION_SCAN_ENTRIES = 100_000
MAX_RETENTION_ACTOR_LENGTH = 256
MAX_RETENTION_OPERATION_ID_LENGTH = 256
RETENTION_REQUEST_VERSION = 1
RETENTION_PLAN_VERSION = 2
RETENTION_CLEANUP_FENCE_BATCH = 32
HOST_RETENTION_ROOT_NAMES = ("spool", "blob", "dataset", "fixture")
MAX_HOST_RETENTION_CURSOR_LENGTH = 4_096
MAX_PRIVATE_FAILURE_TYPE_LENGTH = 512
MAX_PRIVATE_FAILURE_MESSAGE_LENGTH = 65_536
_ARTIFACT_PIN_BACKFILL_REQUIRED_MARKER = "2026-07-31-artifact-pin-backfill-required-v1"
_ARTIFACT_PIN_BACKFILL_MIGRATION = "2026-07-31-artifact-pin-backfill-v1"
_EXECUTION_PLAN_REQUIRED = 1
_EXECUTION_PLAN_LEGACY_OPTIONAL = 0
_MAX_STAGED_INGESTION_ENVELOPE_BYTES = 4 * 1024 * 1024

# Core deliberately uses the legacy-compatible Windows pathname budget on every
# Windows host rather than depending on registry, manifest, child-process, or
# filesystem-specific long-path support. Keep the limit in UTF-16 code units:
# one astral character takes two WCHARs even though ``len(text)`` reports one
# Python code point.
WINDOWS_MAX_USABLE_PATH_UNITS = 259
_WINDOWS_DATASET_STAGING_RELATIVE = PureWindowsPath(
    "revisions",
    "00",
    "00",
    f".{'0' * 64}.json.{'0' * 32}.partial",
)
WINDOWS_DATASET_STAGING_RESERVE_UNITS = (
    1 + len(str(_WINDOWS_DATASET_STAGING_RELATIVE).encode("utf-16-le")) // 2
)
WINDOWS_MAX_STATE_ROOT_UNITS = (
    WINDOWS_MAX_USABLE_PATH_UNITS - WINDOWS_DATASET_STAGING_RESERVE_UNITS
)
_WINDOWS_FIXTURE_STAGING_DIRECTORY = PureWindowsPath(
    "fixtures",
    f".fixture-{'0' * 32}.{'0' * 32}.partial",
)
# Include both the separator below the state root and the separator before the
# caller-supplied basename.
WINDOWS_FIXTURE_STAGING_PREFIX_RESERVE_UNITS = (
    2 + len(str(_WINDOWS_FIXTURE_STAGING_DIRECTORY).encode("utf-16-le")) // 2
)

PUBLIC_INGESTION_FAILURE_MESSAGES: Mapping[str, str] = MappingProxyType(
    {
        "plugin_execution_timeout": (
            "Plug-in execution exceeded the configured time limit."
        ),
        "plugin_execution_failed": ("Plug-in execution failed in an isolated worker."),
        "catalog_execution_timeout": (
            "Catalog publication exceeded the configured time limit; its "
            "idempotent outcome must be reconciled before cleanup."
        ),
        "catalog_execution_failed": (
            "Catalog publication failed in its isolated worker."
        ),
        "ingestion_rejected": (
            "The input or plug-in output did not satisfy the ingestion contract."
        ),
        "worker_failure": ("The ingestion worker could not complete this attempt."),
    }
)


class IngestionStateRootPathError(IngestionPipelineError):
    """The durable state root cannot fit core-owned Windows paths."""


def _windows_path_units(value: str | Path) -> int:
    """Return the number of UTF-16 code units consumed by a Windows path."""

    return len(str(value).encode("utf-16-le")) // 2


def _validate_ingestion_state_root(
    root: str | Path,
    *,
    platform_name: str,
) -> Path:
    """Resolve and preflight one durable ingestion state directory.

    The deepest fixed, core-owned pathname is the private dataset publication
    candidate. Core enforces a legacy-compatible Windows budget regardless of
    optional host long-path support; its 128-unit suffix leaves 131 UTF-16 code
    units for the resolved state root. POSIX hosts are deliberately not
    constrained by this Windows-only budget.

    ``platform_name`` is explicit so cross-platform conformance tests can
    exercise both branches. Production callers use the public wrapper below.
    """

    try:
        resolved = Path(root).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as error:
        raise IngestionStateRootPathError(
            "durable state directory could not be resolved safely; choose an "
            "accessible, shorter --state-dir"
        ) from error
    if platform_name != "nt":
        return resolved
    actual_units = _windows_path_units(resolved)
    if actual_units > WINDOWS_MAX_STATE_ROOT_UNITS:
        raise IngestionStateRootPathError(
            "durable state directory is too long for ingestion on Windows: "
            f"resolved length {actual_units} UTF-16 code units exceeds the "
            f"supported maximum of {WINDOWS_MAX_STATE_ROOT_UNITS}; core-owned "
            f"staging paths reserve {WINDOWS_DATASET_STAGING_RESERVE_UNITS} "
            f"units within the {WINDOWS_MAX_USABLE_PATH_UNITS}-unit path "
            "budget; choose a shorter --state-dir"
        )
    return resolved


def validate_ingestion_state_root(root: str | Path) -> Path:
    """Resolve and validate a state root for the current operating system."""

    return _validate_ingestion_state_root(root, platform_name=os.name)


class PluginExecutionTimeoutError(IngestionPipelineError):
    """A plug-in stage exceeded its configured execution deadline."""


class PluginExecutionProcessError(IngestionPipelineError):
    """A process-isolated plug-in stage failed or exited without a result."""

    def __init__(
        self,
        message: str,
        *,
        private_exception_type: str | None = None,
        private_exception_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.private_exception_type: str | None = private_exception_type
        self.private_exception_message: str | None = private_exception_message


class CatalogExecutionProcessError(IngestionPipelineError):
    """A process-isolated catalog call failed or returned invalid metadata."""

    def __init__(
        self,
        message: str,
        *,
        private_exception_type: str | None = None,
        private_exception_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.private_exception_type: str | None = private_exception_type
        self.private_exception_message: str | None = private_exception_message


class ImportNotFoundError(KeyError):
    """The import is absent or outside the caller's tenant scope."""


class ImportConflictError(IngestionPipelineError):
    """An optimistic or idempotency precondition was not satisfied."""


class ImportQuotaExceededError(ImportConflictError):
    """A tenant or workspace storage admission quota was exhausted."""


class ImportState(StrEnum):
    """Durable state machine for one upload/import."""

    ADMITTING = "admitting"
    QUEUED = "queued"
    PROBING = "probing"
    AWAITING_SELECTION = "awaiting_selection"
    READY = "ready"
    INGESTING = "ingesting"
    PUBLISHING = "publishing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {
            ImportState.COMPLETED,
            ImportState.FAILED,
            ImportState.CANCELLED,
        }


_OBSERVABLE_QUEUE_STATES = tuple(state for state in ImportState if not state.terminal)


class _RetentionArtifactKind(StrEnum):
    BLOB = "blob"
    DATASET = "dataset"


class _RetentionCleanupState(StrEnum):
    CLEANUP_PENDING = "cleanup_pending"
    COMPLETED = "completed"
    DELETED = "deleted"
    FAILED = "failed"
    SKIPPED = "skipped"


class RetentionHostInventoryCoverage(StrEnum):
    """Whether one report observed the host-global orphan inventory."""

    NOT_OBSERVED = "not_observed"
    BOUNDED_HOST_SCAN = "bounded_host_scan"


_TERMINAL_RETENTION_CLEANUP_STATES = frozenset(
    {
        _RetentionCleanupState.DELETED,
        _RetentionCleanupState.FAILED,
        _RetentionCleanupState.SKIPPED,
    }
)


class PluginExecutionMode(StrEnum):
    """How durable workers invoke externally supplied execution."""

    INLINE = "inline"
    PROCESS = "process"


@dataclass(frozen=True, slots=True)
class PipelineLimits:
    """Resource limits applied before untrusted input reaches a plug-in."""

    max_upload_bytes: int = 8 * 1024 * 1024 * 1024
    upload_chunk_bytes: int = 1024 * 1024
    max_workers: int = 2
    lease_seconds: int = 300
    poll_interval_seconds: float = 0.2
    max_attempts: int = 3
    max_active_imports_per_workspace: int = 1_000
    plugin_execution_mode: PluginExecutionMode = PluginExecutionMode.PROCESS
    publisher_execution_mode: PluginExecutionMode | None = None
    plugin_execution_timeout_seconds: float = 300.0
    publisher_execution_timeout_seconds: float | None = None
    stalled_import_seconds: float = 900.0

    def __post_init__(self) -> None:
        if self.max_upload_bytes < 1:
            raise ValueError("max_upload_bytes must be positive")
        if not 4_096 <= self.upload_chunk_bytes <= 16 * 1024 * 1024:
            raise ValueError("upload_chunk_bytes must be between 4096 and 16777216")
        if not 1 <= self.max_workers <= 64:
            raise ValueError("max_workers must be between 1 and 64")
        if not 5 <= self.lease_seconds <= 86_400:
            raise ValueError("lease_seconds must be between 5 and 86400")
        if not 0.01 <= self.poll_interval_seconds <= 60:
            raise ValueError("poll_interval_seconds must be between 0.01 and 60")
        if not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if not 1 <= self.max_active_imports_per_workspace <= 1_000_000:
            raise ValueError(
                "max_active_imports_per_workspace must be between 1 and 1000000"
            )
        try:
            execution_mode = PluginExecutionMode(self.plugin_execution_mode)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "plugin_execution_mode must be 'inline' or 'process'"
            ) from error
        object.__setattr__(self, "plugin_execution_mode", execution_mode)
        publisher_execution_mode = self.publisher_execution_mode
        if publisher_execution_mode is not None:
            try:
                publisher_execution_mode = PluginExecutionMode(publisher_execution_mode)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    "publisher_execution_mode must be null, 'inline', or 'process'"
                ) from error
            object.__setattr__(
                self,
                "publisher_execution_mode",
                publisher_execution_mode,
            )
        timeout = self.plugin_execution_timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0.05 <= float(timeout) <= 86_400
        ):
            raise ValueError(
                "plugin_execution_timeout_seconds must be finite and "
                "between 0.05 and 86400"
            )
        object.__setattr__(
            self,
            "plugin_execution_timeout_seconds",
            float(timeout),
        )
        publisher_timeout = self.publisher_execution_timeout_seconds
        effective_publisher_timeout = float(timeout)
        if publisher_timeout is not None:
            if (
                isinstance(publisher_timeout, bool)
                or not isinstance(publisher_timeout, (int, float))
                or not math.isfinite(float(publisher_timeout))
                or not 0.05 <= float(publisher_timeout) <= 86_400
            ):
                raise ValueError(
                    "publisher_execution_timeout_seconds must be null or "
                    "finite and between 0.05 and 86400"
                )
            effective_publisher_timeout = float(publisher_timeout)
            object.__setattr__(
                self,
                "publisher_execution_timeout_seconds",
                effective_publisher_timeout,
            )
        stalled = self.stalled_import_seconds
        heartbeat_interval = max(0.25, min(5.0, self.lease_seconds / 3))
        # Health measures stage progress, not lease liveness.  Leave enough
        # room for the longest bounded plug-in call plus two heartbeat periods
        # before treating an otherwise live worker as stalled.
        minimum_stall_seconds = max(
            5.0,
            max(float(timeout), effective_publisher_timeout) + heartbeat_interval * 2,
        )
        if (
            isinstance(stalled, bool)
            or not isinstance(stalled, (int, float))
            or not math.isfinite(float(stalled))
            or not minimum_stall_seconds <= float(stalled) <= 7 * 24 * 60 * 60
        ):
            raise ValueError(
                "stalled_import_seconds must be finite, at least the plug-in "
                "execution timeout plus two lease heartbeats or the publisher "
                "execution timeout plus two lease heartbeats "
                f"({minimum_stall_seconds:g}), and at most 604800"
            )
        object.__setattr__(self, "stalled_import_seconds", float(stalled))

    @property
    def effective_publisher_execution_timeout_seconds(self) -> float:
        configured = self.publisher_execution_timeout_seconds
        return (
            self.plugin_execution_timeout_seconds if configured is None else configured
        )

    @property
    def effective_publisher_execution_mode(self) -> PluginExecutionMode:
        """Return the explicit publisher mode or inherit the plug-in mode."""

        configured = self.publisher_execution_mode
        return self.plugin_execution_mode if configured is None else configured


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Opt-in retention plus independently configurable admission quotas.

    Quota bytes are logical admitted upload bytes, not filesystem allocation;
    identical content is charged once per retained import.  Destructive
    workspace retention remains disabled unless ``enabled`` is true. Pipeline
    construction is always non-destructive. An explicit destructive run may
    additionally invoke the bounded host-global staging/content janitor.
    """

    enabled: bool = False
    terminal_import_grace_seconds: int = 7 * 24 * 60 * 60
    idempotency_replay_seconds: int = 30 * 24 * 60 * 60
    orphan_artifact_grace_seconds: int = 24 * 60 * 60
    stale_partial_seconds: int = 24 * 60 * 60
    max_delete_batch: int = 1_000
    max_scan_entries: int = 10_000
    max_tenant_bytes: int | None = None
    max_workspace_bytes: int | None = None
    max_tenant_imports: int | None = None
    max_workspace_imports: int | None = None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("retention enabled must be a boolean")
        for label, value in (
            ("terminal_import_grace_seconds", self.terminal_import_grace_seconds),
            ("idempotency_replay_seconds", self.idempotency_replay_seconds),
            ("orphan_artifact_grace_seconds", self.orphan_artifact_grace_seconds),
            ("stale_partial_seconds", self.stale_partial_seconds),
        ):
            if type(value) is not int or not 0 <= value <= 10 * 365 * 24 * 60 * 60:
                raise ValueError(f"{label} must be between 0 and ten years")
        if (
            type(self.max_delete_batch) is not int
            or not 1 <= self.max_delete_batch <= MAX_RETENTION_BATCH
        ):
            raise ValueError(
                f"max_delete_batch must be between 1 and {MAX_RETENTION_BATCH}"
            )
        if (
            type(self.max_scan_entries) is not int
            or not 1 <= self.max_scan_entries <= MAX_RETENTION_SCAN_ENTRIES
        ):
            raise ValueError(
                f"max_scan_entries must be between 1 and {MAX_RETENTION_SCAN_ENTRIES}"
            )
        for label, optional_value in (
            ("max_tenant_bytes", self.max_tenant_bytes),
            ("max_workspace_bytes", self.max_workspace_bytes),
            ("max_tenant_imports", self.max_tenant_imports),
            ("max_workspace_imports", self.max_workspace_imports),
        ):
            if optional_value is not None and (
                type(optional_value) is not int or not 1 <= optional_value <= 2**63 - 1
            ):
                raise ValueError(f"{label} must be a positive integer or None")


@dataclass(frozen=True, slots=True)
class RetentionReport:
    """Bounded inventory or execution result for one workspace."""

    scope: ImportScope
    evaluated_at_ns: int
    executed: bool
    policy_enabled: bool
    host_storage_orphan_inventory: RetentionHostInventoryCoverage
    eligible_imports: int = 0
    candidate_events: int = 0
    candidate_plugin_rows: int = 0
    expired_idempotency_receipts: int = 0
    expired_retention_audits: int = 0
    fixture_views: int = 0
    content_blobs: int = 0
    revision_datasets: int = 0
    stale_partials: int = 0
    estimated_bytes: int = 0
    deleted_imports: int = 0
    deleted_retention_audits: int = 0
    deleted_files: int = 0
    deleted_bytes: int = 0
    deletion_failures: int = 0
    failure_details: tuple[str, ...] = ()
    truncated: bool = False
    audit_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": {
                "tenant_id": self.scope.tenant_id,
                "project_id": self.scope.project_id,
                "workspace_id": self.scope.workspace_id,
            },
            "evaluated_at_ns": str(self.evaluated_at_ns),
            "executed": self.executed,
            "policy_enabled": self.policy_enabled,
            "host_storage_orphan_inventory": (self.host_storage_orphan_inventory.value),
            "eligible_imports": self.eligible_imports,
            "candidate_events": self.candidate_events,
            "candidate_plugin_rows": self.candidate_plugin_rows,
            "expired_idempotency_receipts": self.expired_idempotency_receipts,
            "expired_retention_audits": self.expired_retention_audits,
            "fixture_views": self.fixture_views,
            "content_blobs": self.content_blobs,
            "revision_datasets": self.revision_datasets,
            "stale_partials": self.stale_partials,
            "estimated_bytes": self.estimated_bytes,
            "deleted_imports": self.deleted_imports,
            "deleted_retention_audits": self.deleted_retention_audits,
            "deleted_files": self.deleted_files,
            "deleted_bytes": self.deleted_bytes,
            "deletion_failures": self.deletion_failures,
            "failure_details": list(self.failure_details),
            "truncated": self.truncated,
            "audit_id": self.audit_id,
        }


@dataclass(frozen=True, slots=True)
class RetentionAuditRecord:
    audit_id: str
    scope: ImportScope
    created_at_ns: int
    report: Mapping[str, Any]
    actor: str | None = None
    operation_id: str | None = None
    request_digest: str | None = None
    effective_now_ns: int | None = None
    state: str = "completed"


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
    pending_imports: int = 0
    awaiting_selection_imports: int = 0
    stalled_imports: int = 0
    oldest_pending_updated_at_ns: int | None = None
    stall_after_seconds: float = 0.0
    queue_evaluated_at_ns: int | None = None
    state_counts: tuple[tuple[str, int], ...] = ()
    queue_observation_error: str | None = None
    unexpected_worker_exits: int = 0
    last_worker_exit_at_ns: int | None = None
    last_worker_exit: str | None = None
    catalog_attention_imports: int = 0


@dataclass(frozen=True, slots=True)
class QueueHealthSnapshot:
    """Read-only durable queue age/depth projection."""

    pending_imports: int
    awaiting_selection_imports: int
    stalled_imports: int
    oldest_pending_updated_at_ns: int | None
    stall_after_seconds: float
    evaluated_at_ns: int
    state_counts: tuple[tuple[str, int], ...]
    observation_error: str | None = None
    catalog_attention_imports: int = 0


def inspect_durable_queue(
    database_path: str | Path,
    *,
    stall_after_seconds: float = 900.0,
    now_ns: int | None = None,
) -> QueueHealthSnapshot:
    """Inspect queue state through a read-only SQLite connection.

    This is shared by in-process worker health and the headless health CLI.
    It never initializes or migrates a state directory.
    """

    if (
        isinstance(stall_after_seconds, bool)
        or not isinstance(stall_after_seconds, (int, float))
        or not math.isfinite(float(stall_after_seconds))
        or not 5 <= float(stall_after_seconds) <= 7 * 24 * 60 * 60
    ):
        raise ValueError("stall_after_seconds must be finite and between 5 and 604800")
    if now_ns is None:
        evaluated_at_ns = time.time_ns()
    elif type(now_ns) is not int or not 0 <= now_ns <= 2**63 - 1:
        raise ValueError("now_ns must be a non-negative signed 64-bit integer")
    else:
        evaluated_at_ns = now_ns
    cutoff_ns = evaluated_at_ns - int(float(stall_after_seconds) * 1_000_000_000)
    path = Path(database_path).expanduser().resolve()
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        timeout=1,
        isolation_level=None,
        uri=True,
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 1000")
        placeholders = ", ".join("?" for _state in _OBSERVABLE_QUEUE_STATES)
        rows = connection.execute(
            """
            SELECT state, COUNT(*) AS item_count,
                   MIN(updated_at_ns) AS oldest_updated_at_ns,
                   SUM(
                       CASE WHEN updated_at_ns < ? THEN 1 ELSE 0 END
                   ) AS stalled_count
            FROM ingestion_imports
            WHERE state IN ("""
            + placeholders
            + """ )
            GROUP BY state
            ORDER BY state
            """,
            (
                cutoff_ns,
                *(state.value for state in _OBSERVABLE_QUEUE_STATES),
            ),
        ).fetchall()
        # Detect corrupt/foreign state vocabulary with a bounded number of
        # indexed range probes.  A DISTINCT scan would traverse terminal
        # history even though health otherwise reads only active queue rows.
        known_state_values = tuple(sorted(state.value for state in ImportState))
        unknown_state = connection.execute(
            "SELECT 1 FROM ingestion_imports WHERE state IS NULL LIMIT 1"
        ).fetchone()
        if unknown_state is None:
            unknown_state = connection.execute(
                "SELECT 1 FROM ingestion_imports WHERE state < ? LIMIT 1",
                (known_state_values[0],),
            ).fetchone()
        if unknown_state is None:
            for index in range(len(known_state_values) - 1):
                lower = known_state_values[index]
                upper = known_state_values[index + 1]
                unknown_state = connection.execute(
                    "SELECT 1 FROM ingestion_imports "
                    "WHERE state > ? AND state < ? LIMIT 1",
                    (lower, upper),
                ).fetchone()
                if unknown_state is not None:
                    break
        if unknown_state is None:
            unknown_state = connection.execute(
                "SELECT 1 FROM ingestion_imports WHERE state > ? LIMIT 1",
                (known_state_values[-1],),
            ).fetchone()
        table_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(ingestion_imports)"
            ).fetchall()
        }
        catalog_attention_count = 0
        if "error_code" in table_columns:
            catalog_attention_row = connection.execute(
                """
                SELECT COUNT(*) AS item_count
                FROM ingestion_imports
                WHERE state = ? AND error_code = ?
                """,
                (
                    ImportState.FAILED.value,
                    "catalog_execution_timeout",
                ),
            ).fetchone()
            catalog_attention_count = int(catalog_attention_row["item_count"])
    finally:
        connection.close()
    pending_imports = 0
    awaiting_selection_imports = 0
    stalled_imports = 0
    oldest_pending_updated_at_ns: int | None = None
    state_counts: list[tuple[str, int]] = []
    observation_error = "unknown_import_state" if unknown_state is not None else None
    for row in rows:
        state = str(row["state"])
        count = int(row["item_count"])
        state_counts.append((state, count))
        if state == ImportState.AWAITING_SELECTION.value:
            awaiting_selection_imports += count
            continue
        pending_imports += count
        stalled_imports += int(row["stalled_count"] or 0)
        candidate_oldest = int(row["oldest_updated_at_ns"])
        if (
            oldest_pending_updated_at_ns is None
            or candidate_oldest < oldest_pending_updated_at_ns
        ):
            oldest_pending_updated_at_ns = candidate_oldest
    return QueueHealthSnapshot(
        pending_imports=pending_imports,
        awaiting_selection_imports=awaiting_selection_imports,
        stalled_imports=stalled_imports,
        oldest_pending_updated_at_ns=oldest_pending_updated_at_ns,
        stall_after_seconds=float(stall_after_seconds),
        evaluated_at_ns=evaluated_at_ns,
        state_counts=tuple(state_counts),
        observation_error=observation_error,
        catalog_attention_imports=catalog_attention_count,
    )


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
    host_identities: tuple[
        tuple[str, str, tuple[int, int, int, int, int, int]], ...
    ] = ()
    path_sizes: tuple[tuple[Path, int], ...] = ()
    truncations: tuple[_RetentionTruncation, ...] = ()


@dataclass(frozen=True, slots=True)
class _RetentionTruncation:
    source: str
    limit: int
    observed_at_least: int


@dataclass(slots=True)
class _RetentionTelemetryContext:
    run_id: str
    started_monotonic_ns: int
    phase: str = "validation"
    audit_id: str | None = None
    mutation_started: bool = False


@dataclass(frozen=True, slots=True)
class _RetentionWorkItem:
    sequence: int
    action: str
    root: str
    reference: str | None
    relative_path: str
    planned_bytes: int
    expected_identity: tuple[int, int, int, int, int, int] | None = None


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
    truncations: tuple[_RetentionTruncation, ...] = ()


@dataclass(frozen=True, slots=True)
class _PreparedContentFile:
    """Private, verified candidate awaiting atomic content publication."""

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
    """Private fixture directory awaiting one atomic root-level rename."""

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
    def attempts_remaining(self) -> int:
        """Return the configured retry budget that remains for this import."""

        return max(0, self.max_attempts - self.attempt_count)

    @property
    def retryable(self) -> bool:
        """Whether another claimed queue attempt is still permitted."""

        return self.state is ImportState.FAILED and self.attempts_remaining > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "import_id": self.import_id,
            "tenant_id": self.scope.tenant_id,
            "project_id": self.scope.project_id,
            "workspace_id": self.scope.workspace_id,
            "fixture_id": self.fixture_id,
            "state": self.state.value,
            "terminal": self.state.terminal,
            "version": self.version,
            "original_name": self.original_name,
            "content_type": self.content_type,
            "node_hint": self.node_hint,
            "metadata": dict(self.metadata),
            "byte_count": self.byte_count,
            "content_sha256": self.content_sha256,
            "probe_set_hash": self.probe_set_hash,
            "plugin_composition_policy_digest": (self.plugin_composition_policy_digest),
            "selected_plugin_id": self.selected_plugin_id,
            "selected_plugin_version": self.selected_plugin_version,
            "revision_id": self.revision_id,
            "node_id": self.node_id,
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "attempts_remaining": self.attempts_remaining,
            "auto_select": self.auto_select,
            "error": (
                {
                    "code": self.error_code,
                    "message": self.error_message,
                    "retryable": self.retryable,
                    "attempts_remaining": self.attempts_remaining,
                }
                if self.error_code
                else None
            ),
            "created_at_ns": str(self.created_at_ns),
            "updated_at_ns": str(self.updated_at_ns),
        }


@dataclass(frozen=True, slots=True)
class ImportEvent:
    sequence: int
    import_id: str
    state: ImportState
    event_type: str
    message: str
    payload: Mapping[str, Any]
    created_at_ns: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "import_id": self.import_id,
            "state": self.state.value,
            "event_type": self.event_type,
            "message": self.message,
            "payload": dict(self.payload),
            "created_at_ns": str(self.created_at_ns),
        }


class _PublisherExecutionPlanSupport(StrEnum):
    ABSENT = "absent"
    EXPLICIT_KEYWORD = "explicit_keyword"
    VAR_KEYWORD = "var_keyword"


def _publisher_execution_plan_support(
    publisher: Any,
) -> _PublisherExecutionPlanSupport:
    """Inspect the publication contract before any side-effecting call.

    Pre-contract publishers remain valid for genuine legacy planless replay.
    A planful publication may never silently discard its execution identity.
    """

    try:
        publish_revision = publisher.publish_revision
        parameters = inspect.signature(publish_revision).parameters.values()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            "revision publisher contract could not be inspected"
        ) from error
    if any(
        parameter.name == "execution_plan"
        and parameter.kind is inspect.Parameter.POSITIONAL_ONLY
        for parameter in parameters
    ):
        return _PublisherExecutionPlanSupport.ABSENT
    if any(
        (
            parameter.name == "execution_plan"
            and parameter.kind
            in {
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            }
        )
        for parameter in parameters
    ):
        return _PublisherExecutionPlanSupport.EXPLICIT_KEYWORD
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters):
        return _PublisherExecutionPlanSupport.VAR_KEYWORD
    return _PublisherExecutionPlanSupport.ABSENT


class NullRevisionCatalogPublisher:
    """No-op publisher useful for isolated queue tests."""

    def admit_fixture(self, scope: ImportScope, **values: Any) -> None:
        del scope, values

    def publish_revision(
        self,
        scope: ImportScope,
        **values: Any,
    ) -> str | None:
        del scope, values
        return None


def _catalog_publisher_process_bootstrap(
    publisher: RevisionCatalogPublisher,
    *,
    module_target: str | None,
) -> CatalogPublisherProcessBootstrap:
    """Freeze process construction without pickling the publisher object."""

    from .session_catalog_publisher import SessionCatalogPublisher

    if type(publisher) is NullRevisionCatalogPublisher:
        return CatalogPublisherProcessBootstrap(loader_kind="core_null")
    if type(publisher) is SessionCatalogPublisher:
        try:
            bootstrap = publisher.process_bootstrap()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "session catalog process bootstrap could not be frozen"
            ) from error
        if type(bootstrap) is not CatalogPublisherProcessBootstrap:
            raise IngestionPipelineError(
                "session catalog returned an invalid process bootstrap"
            )
        return bootstrap
    if module_target is not None:
        return CatalogPublisherProcessBootstrap(
            loader_kind="module_attribute",
            target=_normalized_explicit_bootstrap_target(
                module_target,
                "publisher_module_target",
            ),
        )
    return CatalogPublisherProcessBootstrap(
        loader_kind="class_constructor",
        target=_bootstrap_class_target(publisher, "catalog publisher"),
    )


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


def _registered_execution_pin(
    registered: RegisteredPlugin,
    *,
    schema_digest: str,
    roles: tuple[str, ...],
    process_authority: bool,
    allow_inline_only: bool = False,
) -> PluginExecutionPin:
    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if type(process_authority) is not bool:
        raise TypeError("process_authority must be an exact boolean")
    if not allow_inline_only:
        _require_no_inline_only_plugin_compatibility(
            (registered,),
            boundary=(
                "plug-in execution pins require PROCESS-capable plug-ins unless "
                "trusted INLINE-only execution is explicit"
            ),
        )
    return PluginExecutionPin(
        instance_id=registered.instance_id,
        plugin_id=registered.plugin_id,
        plugin_version=registered.plugin_version,
        core_api_version=registered.core_api_version,
        artifact=PluginArtifactIdentity(
            distribution_name=registered.distribution_name,
            distribution_version=registered.distribution_version,
            package_hash=registered.package_hash,
            entry_point_name=registered.entry_point_name,
            module_target=registered.module_target,
        ),
        configuration_digest=registered.configuration_digest,
        schema_digest=schema_digest,
        registered_execution_identity=registered.registered_execution_identity,
        process_bootstrap_digest=(
            registered.process_bootstrap_digest if process_authority else None
        ),
        schema_versions=registered.schema_versions,
        capabilities=registered.capabilities,
        roles=roles,
    )


def _auxiliary_execution_pin(
    capability_providers: CapabilityProviderRegistry,
    selection: PluginParticipationSelection,
    *,
    process_authority: bool,
    allow_inline_only: bool = False,
) -> PluginExecutionPin:
    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if type(process_authority) is not bool:
        raise TypeError("process_authority must be an exact boolean")
    try:
        registered = capability_providers.get_by_execution_identity(
            selection.instance_id,
            selection.registered_execution_identity,
        )
        if not allow_inline_only:
            _require_no_inline_only_plugin_compatibility(
                (registered,),
                boundary=(
                    "durable ingestion requires PROCESS-capable auxiliary plug-ins "
                    "unless trusted INLINE-only execution is explicit"
                ),
            )
        PluginRegistry.revalidate_registered_identity(registered)
        if not _registered_plugin_is_process_capable(registered) and not (
            allow_inline_only
            and _registered_plugin_is_trusted_inline_capable(registered)
        ):
            raise IngestionPipelineError(
                "an auxiliary plug-in requires a validated process bootstrap"
            )
        if registered.decoder_identity is not None:
            raise IngestionPipelineError(
                "an auxiliary plug-in cannot bind a trace decoder"
            )
        schema_digest = capability_providers.schema_digest_by_execution_identity(
            selection.instance_id,
            selection.registered_execution_identity,
        )
        PluginRegistry.revalidate_registered_identity(registered)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except IngestionPipelineError:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            "auxiliary plug-in identity or schema could not be frozen"
        ) from error
    return _registered_execution_pin(
        registered,
        schema_digest=schema_digest,
        roles=selection.roles,
        process_authority=process_authority,
        allow_inline_only=allow_inline_only,
    )


def _selected_composition_records(
    registered: RegisteredPlugin,
    *,
    capability_providers: CapabilityProviderRegistry | None,
    composition_policy: PluginCompositionPolicy | None,
) -> tuple[RegisteredPlugin, ...]:
    """Resolve the exact live records selected for one primary execution."""

    if type(registered) is not RegisteredPlugin:
        raise TypeError("registered must be an exact RegisteredPlugin")
    selected_policy = (
        PluginCompositionPolicy() if composition_policy is None else composition_policy
    )
    if type(selected_policy) is not PluginCompositionPolicy:
        raise TypeError("composition_policy must be PluginCompositionPolicy or None")
    selections = selected_policy.auxiliaries_for(
        primary_instance_id=registered.instance_id,
        primary_registered_execution_identity=(
            registered.registered_execution_identity
        ),
    )
    if selections and capability_providers is None:
        raise IngestionPipelineError(
            "an auxiliary plug-in composition requires the exact capability "
            "provider registry"
        )
    auxiliaries: list[RegisteredPlugin] = []
    for selection in selections:
        assert capability_providers is not None
        try:
            auxiliary = capability_providers.get_by_execution_identity(
                selection.instance_id,
                selection.registered_execution_identity,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "an auxiliary plug-in selected by the composition policy is "
                "not registered"
            ) from error
        auxiliaries.append(auxiliary)
    return (registered, *auxiliaries)


def _execution_plan_authority_for_mode(
    records: Iterable[RegisteredPlugin],
    *,
    execution_mode: PluginExecutionMode,
    allow_inline_only: bool,
) -> PluginExecutionPlanAuthority:
    """Derive the closed durable authority from the actual execution branch."""

    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if type(execution_mode) is not PluginExecutionMode:
        raise TypeError("execution_mode must be an exact PluginExecutionMode")
    selected = tuple(records)
    if not selected or any(type(record) is not RegisteredPlugin for record in selected):
        raise TypeError("execution authority requires registered plug-ins")
    contains_inline_only = _registered_plugins_require_inline_execution(selected)
    if contains_inline_only and not allow_inline_only:
        _require_no_inline_only_plugin_compatibility(
            selected,
            boundary=(
                "durable ingestion requires PROCESS-capable plug-ins unless "
                "trusted INLINE-only execution is explicit"
            ),
        )
    if execution_mode is PluginExecutionMode.PROCESS:
        if contains_inline_only:
            raise IngestionPipelineError(
                "PROCESS execution cannot use an INLINE-only plug-in"
            )
        return PluginExecutionPlanAuthority.PROCESS
    if any(record.package_hash.startswith("manifest-sha256:") for record in selected):
        return PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST
    return PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED


def _frozen_auxiliary_execution_pins(
    capability_providers: CapabilityProviderRegistry,
    selections: tuple[PluginParticipationSelection, ...],
) -> tuple[PluginExecutionPin, ...]:
    """Project child-safe auxiliary pins from admission-frozen coordinates.

    Auxiliary providers do not execute during primary parsing.  Sending their
    Python objects through Windows spawn would invoke arbitrary pickle hooks in
    the parent before the child deadline exists.  The child therefore receives
    only these exact primitive/data-class pins.  The parent revalidates each
    live auxiliary executable and manifest immediately before freezing its
    child pin, with the same checks used by inline composition.
    """

    pins: list[PluginExecutionPin] = []
    for selection in selections:
        try:
            registered = capability_providers.get_by_execution_identity(
                selection.instance_id,
                selection.registered_execution_identity,
            )
            _require_no_inline_only_plugin_compatibility(
                (registered,),
                boundary=(
                    "durable ingestion requires PROCESS-capable auxiliary plug-ins"
                ),
            )
            PluginRegistry.revalidate_registered_identity(registered)
            if (
                not _registered_plugin_is_process_capable(registered)
                or registered.decoder_identity is not None
            ):
                raise IngestionPipelineError(
                    "auxiliary plug-in frozen identity is not eligible for composition"
                )
            schema_digest = capability_providers.schema_digest_by_execution_identity(
                selection.instance_id,
                selection.registered_execution_identity,
            )
            PluginRegistry.revalidate_registered_identity(registered)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except IngestionPipelineError:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "auxiliary plug-in identity or schema could not be frozen"
            ) from error
        pins.append(
            _registered_execution_pin(
                registered,
                schema_digest=schema_digest,
                roles=selection.roles,
                process_authority=True,
            )
        )
    return tuple(pins)


def _frozen_auxiliary_process_bootstraps(
    capability_providers: CapabilityProviderRegistry,
    selections: tuple[PluginParticipationSelection, ...],
) -> tuple[_PluginProcessBootstrap, ...]:
    """Freeze child-safe executable descriptors for selected auxiliaries.

    The existing execution pins remain the parent-owned authority recorded in
    the immutable plan.  Scheduled post-parse materialization hooks also need
    each selected auxiliary implementation inside the killable ingestion
    child. Only core-owned scalar bootstrap descriptors cross the spawn
    boundary; plug-in objects and bound methods never do. An auxiliary carrying
    both scheduled roles is loaded exactly once.
    """

    bootstraps: list[_PluginProcessBootstrap] = []
    for selection in selections:
        consistency_selected = REVISION_CONSISTENCY_ROLE in selection.roles
        relationship_projection_selected = (
            REVISION_RELATIONSHIP_PROJECTION_ROLE in selection.roles
        )
        if not consistency_selected and not relationship_projection_selected:
            continue
        try:
            registered = capability_providers.get_by_execution_identity(
                selection.instance_id,
                selection.registered_execution_identity,
            )
            if (
                consistency_selected
                and PluginCapability.CONSISTENCY_CHECK.value
                not in registered.capabilities
            ):
                raise IngestionPipelineError(
                    "a revision consistency auxiliary does not declare "
                    "CONSISTENCY_CHECK"
                )
            if (
                relationship_projection_selected
                and PluginCapability.RELATIONSHIP_PROJECTION.value
                not in registered.capabilities
            ):
                raise IngestionPipelineError(
                    "a revision relationship-projection auxiliary does not "
                    "declare RELATIONSHIP_PROJECTION"
                )
            _require_no_inline_only_plugin_compatibility(
                (registered,),
                boundary=(
                    "PROCESS post-parse materialization requires "
                    "PROCESS-capable auxiliary plug-ins"
                ),
            )
            PluginRegistry.revalidate_registered_identity(registered)
            if (
                not _registered_plugin_is_process_capable(registered)
                or registered.decoder_identity is not None
            ):
                raise IngestionPipelineError(
                    "an auxiliary materialization provider is not eligible "
                    "for PROCESS execution"
                )
            bootstrap = registered.process_bootstrap
            PluginRegistry.revalidate_registered_identity(registered)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except IngestionPipelineError:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "auxiliary materialization provider bootstrap could not be frozen"
            ) from error
        bootstraps.append(bootstrap)
    return tuple(bootstraps)


def _validated_materialization_process_bootstraps(
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...],
    auxiliary_bootstraps: tuple[_PluginProcessBootstrap, ...],
    expected_parent_bootstrap_digests: tuple[str, ...],
) -> tuple[_PluginProcessBootstrap, ...]:
    """Validate the exact materialization-only child load set.

    The parent freezes all policy-selected auxiliary pins because the complete
    composition remains part of the revision plan. The ingestion child needs
    executable implementations only for pins carrying a reserved scheduled
    materialization role. Validate that union entirely from scalar coordinates
    before importing any auxiliary target, so injected, duplicated, or stale
    spawn payloads cannot make the child load unrelated plug-in code.
    """

    if type(frozen_auxiliary_pins) is not tuple or any(
        type(pin) is not PluginExecutionPin for pin in frozen_auxiliary_pins
    ):
        raise IngestionPipelineError("frozen auxiliary execution pins are invalid")
    if type(auxiliary_bootstraps) is not tuple or any(
        type(bootstrap) is not _PluginProcessBootstrap
        for bootstrap in auxiliary_bootstraps
    ):
        raise IngestionPipelineError(
            "materialization auxiliary process bootstraps are invalid"
        )
    if type(expected_parent_bootstrap_digests) is not tuple or any(
        type(digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        for digest in expected_parent_bootstrap_digests
    ):
        raise IngestionPipelineError(
            "materialization auxiliary parent bootstrap authority is invalid"
        )
    if len(expected_parent_bootstrap_digests) != len(auxiliary_bootstraps):
        raise IngestionPipelineError(
            "materialization auxiliary parent bootstrap authority does not "
            "match the child bootstrap vector"
        )

    expected: list[PluginExecutionPin] = []
    for pin in frozen_auxiliary_pins:
        consistency_selected = REVISION_CONSISTENCY_ROLE in pin.roles
        relationship_projection_selected = (
            REVISION_RELATIONSHIP_PROJECTION_ROLE in pin.roles
        )
        if not consistency_selected and not relationship_projection_selected:
            continue
        if (
            consistency_selected
            and PluginCapability.CONSISTENCY_CHECK.value not in pin.capabilities
        ):
            raise IngestionPipelineError(
                "a revision consistency auxiliary does not declare CONSISTENCY_CHECK"
            )
        if (
            relationship_projection_selected
            and PluginCapability.RELATIONSHIP_PROJECTION.value not in pin.capabilities
        ):
            raise IngestionPipelineError(
                "a revision relationship-projection auxiliary does not declare "
                "RELATIONSHIP_PROJECTION"
            )
        expected.append(pin)
    if len(expected) != len(auxiliary_bootstraps):
        raise IngestionPipelineError(
            "materialization auxiliary bootstraps do not match the frozen plan pins"
        )
    if len(expected) != len({pin.instance_id for pin in expected}):
        raise IngestionPipelineError(
            "materialization auxiliary plan pins contain duplicate instances"
        )

    for pin, bootstrap, parent_digest in zip(
        expected,
        auxiliary_bootstraps,
        expected_parent_bootstrap_digests,
        strict=True,
    ):
        try:
            bootstrap_digest = _plugin_process_bootstrap_digest(bootstrap)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "materialization auxiliary process bootstrap is invalid"
            ) from error
        artifact = pin.artifact
        if (
            bootstrap.decoder_identity_values is not None
            or pin.process_bootstrap_digest is None
            or bootstrap_digest != pin.process_bootstrap_digest
            or bootstrap_digest != parent_digest
            or bootstrap.instance_id != pin.instance_id
            or bootstrap.expected_registered_execution_identity
            != pin.registered_execution_identity
            or bootstrap.package_hash != artifact.package_hash
            or bootstrap.distribution_name != artifact.distribution_name
            or bootstrap.distribution_version != artifact.distribution_version
            or bootstrap.entry_point_name != artifact.entry_point_name
            or bootstrap.module_target != artifact.module_target
            or bootstrap.configuration_digest != pin.configuration_digest
        ):
            raise IngestionPipelineError(
                "materialization auxiliary bootstrap does not match its frozen plan pin"
            )
    return auxiliary_bootstraps


def _validated_child_composition_authority(
    primary_bootstrap: _PluginProcessBootstrap,
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...],
    composition_policy: PluginCompositionPolicy | None,
) -> tuple[PluginCompositionPolicy, tuple[PluginExecutionPin, ...]]:
    """Bind a child auxiliary vector to policy before importing its code."""

    if type(primary_bootstrap) is not _PluginProcessBootstrap:
        raise IngestionPipelineError("primary process bootstrap is invalid")
    if type(frozen_auxiliary_pins) is not tuple or any(
        type(pin) is not PluginExecutionPin for pin in frozen_auxiliary_pins
    ):
        raise IngestionPipelineError("frozen auxiliary execution pins are invalid")
    if composition_policy is None:
        selected_policy = PluginCompositionPolicy()
    else:
        if type(composition_policy) is not PluginCompositionPolicy:
            raise IngestionPipelineError("plug-in composition policy is invalid")
        try:
            selected_policy = PluginCompositionPolicy(
                rules=composition_policy.rules,
                contract_version=composition_policy.contract_version,
                policy_digest=composition_policy.policy_digest,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "plug-in composition policy is invalid"
            ) from error
    try:
        selections = selected_policy.auxiliaries_for(
            primary_instance_id=primary_bootstrap.instance_id,
            primary_registered_execution_identity=(
                primary_bootstrap.expected_registered_execution_identity
            ),
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise IngestionPipelineError(
            "plug-in composition policy could not be resolved"
        ) from error
    if len(frozen_auxiliary_pins) != len(selections) or any(
        pin.instance_id != selection.instance_id
        or pin.registered_execution_identity
        != selection.registered_execution_identity
        or pin.roles != selection.roles
        for pin, selection in zip(
            frozen_auxiliary_pins,
            selections,
            strict=True,
        )
    ):
        raise IngestionPipelineError(
            "frozen auxiliary pins do not match the composition policy"
        )
    return selected_policy, frozen_auxiliary_pins


def _execution_plan_for_result(
    registered: RegisteredPlugin,
    result: IngestionResult,
    *,
    capability_providers: CapabilityProviderRegistry | None = None,
    composition_policy: PluginCompositionPolicy | None = None,
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...] | None = None,
    allow_inline_only: bool = False,
    execution_plan_authority: PluginExecutionPlanAuthority,
) -> PluginExecutionPlan:
    """Freeze the executable interpretation that produced one result."""

    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if type(execution_plan_authority) is not PluginExecutionPlanAuthority:
        raise TypeError(
            "execution_plan_authority must be an exact PluginExecutionPlanAuthority"
        )
    decoder_identity = _ACTIVE_DECODER_IDENTITY.get()
    _ACTIVE_DECODER_IDENTITY.set(None)
    if decoder_identity is not None:
        try:
            decoder_matches = decoder_identity == registered.decoder_identity
            executed_decoder_identity = _snapshot_decoder_identity(decoder_identity)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "executed trace decoder identity could not be validated"
            ) from error
        if not decoder_matches:
            raise IngestionPipelineError(
                "executed trace decoder does not match the registered identity"
            )
    else:
        executed_decoder_identity = None
    schema = result.dataset.get("schema")
    if not isinstance(schema, Mapping):
        raise IngestionPipelineError("normalized dataset lacks its plug-in schema")
    schema_digest = (
        "sha256:"
        + hashlib.sha256(canonical_json(dict(schema)).encode("utf-8")).hexdigest()
    )
    primary_pin = _registered_execution_pin(
        registered,
        schema_digest=schema_digest,
        roles=("primary_parser",),
        process_authority=(
            execution_plan_authority is PluginExecutionPlanAuthority.PROCESS
        ),
        allow_inline_only=allow_inline_only,
    )
    selected_policy = (
        PluginCompositionPolicy() if composition_policy is None else composition_policy
    )
    if type(selected_policy) is not PluginCompositionPolicy:
        raise TypeError("composition_policy must be PluginCompositionPolicy or None")
    auxiliary_selections = selected_policy.auxiliaries_for(
        primary_instance_id=registered.instance_id,
        primary_registered_execution_identity=(
            registered.registered_execution_identity
        ),
    )
    if (
        auxiliary_selections
        and capability_providers is None
        and frozen_auxiliary_pins is None
    ):
        raise IngestionPipelineError(
            "an auxiliary plug-in composition requires the exact capability "
            "provider registry"
        )
    if frozen_auxiliary_pins is not None:
        if type(frozen_auxiliary_pins) is not tuple or any(
            type(pin) is not PluginExecutionPin for pin in frozen_auxiliary_pins
        ):
            raise TypeError("frozen_auxiliary_pins must contain execution pins")
        if len(frozen_auxiliary_pins) != len(auxiliary_selections) or any(
            pin.instance_id != selection.instance_id
            or pin.registered_execution_identity
            != selection.registered_execution_identity
            or pin.roles != selection.roles
            for pin, selection in zip(
                frozen_auxiliary_pins,
                auxiliary_selections,
                strict=True,
            )
        ):
            raise IngestionPipelineError(
                "frozen auxiliary pins do not match the composition policy"
            )
        auxiliary_pins = frozen_auxiliary_pins
    else:
        auxiliary_pins = (
            tuple(
                _auxiliary_execution_pin(
                    capability_providers,
                    selection,
                    process_authority=(
                        execution_plan_authority is PluginExecutionPlanAuthority.PROCESS
                    ),
                    allow_inline_only=allow_inline_only,
                )
                for selection in auxiliary_selections
            )
            if capability_providers is not None
            else ()
        )
    return PluginExecutionPlan(
        node_id=result.node_id,
        basis_revision_id=result.revision_id,
        plugins=(primary_pin, *auxiliary_pins),
        decoder=executed_decoder_identity,
        composition_policy_digest=selected_policy.policy_digest,
        execution_plan_authority=execution_plan_authority,
    )


def _revision_world_basis(result: IngestionResult) -> WorldBasis:
    """Describe the observed status capture without inventing common time.

    Each artifact/clock-domain pair remains an independent capture range. The
    world therefore stays honest for dumps whose clocks are unrelated or whose
    collection intervals do not overlap. Artifacts that emitted no state are
    retained as unbounded ranges so the basis still describes the complete
    admitted inventory.
    """

    ranges: dict[
        tuple[Any, str | None],
        tuple[int | None, int | None, bool],
    ] = {}
    observations = (*result.snapshots, *result.relationship_observations)
    for observation in observations:
        evidence = observation.evidence
        key = (evidence.artifact_id, evidence.clock_domain)
        minimum = observation.observed_at_min_ns
        maximum = observation.observed_at_max_ns
        current_minimum, current_maximum, has_unbounded = ranges.get(
            key,
            (None, None, False),
        )
        if minimum is None or maximum is None:
            ranges[key] = (current_minimum, current_maximum, True)
            continue
        ranges[key] = (
            minimum if current_minimum is None else min(current_minimum, minimum),
            maximum if current_maximum is None else max(current_maximum, maximum),
            has_unbounded,
        )

    inventory_ids = {item.artifact_id for item in result.inventory.artifacts}
    observed_ids = {artifact_id for artifact_id, _clock in ranges}
    for artifact_id in inventory_ids - observed_ids:
        ranges[(artifact_id, None)] = (None, None, True)

    capture_ranges = tuple(
        CaptureRange(
            scope=(
                f"node:{result.node_id}/artifact:{artifact_id}/clock:"
                f"{clock_domain or 'unspecified'}"
            ),
            observed_at_min_ns=None if bounds[2] else bounds[0],
            observed_at_max_ns=None if bounds[2] else bounds[1],
            evidence=(),
            clock_domain=clock_domain,
        )
        for (artifact_id, clock_domain), bounds in sorted(
            ranges.items(),
            key=lambda item: (
                item[0][0].bytes,
                item[0][1] is None,
                item[0][1] or "",
            ),
        )
    )
    qualities = {observation.quality for observation in observations}
    quality = Quality.EXACT
    for candidate in (Quality.UNKNOWN, Quality.AMBIGUOUS, Quality.BEST_EFFORT):
        if candidate in qualities:
            quality = candidate
            break
    if not observations:
        quality = Quality.UNKNOWN
    return WorldBasis(
        kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
        requested_time_ns=None,
        resolved_at_min_ns=None,
        resolved_at_max_ns=None,
        capture_ranges=capture_ranges,
        provenance=Provenance.OBSERVED,
        quality=quality,
        clock_domain=None,
    )


def _dataset_with_execution_plan(
    registered: RegisteredPlugin,
    result: IngestionResult,
    *,
    capability_providers: CapabilityProviderRegistry | None = None,
    composition_policy: PluginCompositionPolicy | None = None,
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...] | None = None,
    frozen_process_providers: tuple[RegisteredPlugin, ...] | None = None,
    allow_inline_only: bool = False,
    execution_plan_authority: PluginExecutionPlanAuthority,
) -> tuple[bytes, PluginExecutionPlan]:
    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    plan = _execution_plan_for_result(
        registered,
        result,
        capability_providers=capability_providers,
        composition_policy=composition_policy,
        frozen_auxiliary_pins=frozen_auxiliary_pins,
        allow_inline_only=allow_inline_only,
        execution_plan_authority=execution_plan_authority,
    )
    primary_pin = primary_parser_execution_pin(plan)
    result = _bind_primary_ingestion_perspectives(
        result,
        plugin_id=registered.plugin_id,
        primary_plugin_instance_id=primary_pin.instance_id,
        primary_schema_digest=primary_pin.schema_digest,
        timeline_time_basis=TimelineTimeBasis(registered.timeline_time_basis),
        timeline_clock_domain=registered.timeline_clock_domain,
    )
    # Materialization is a later pipeline stage, loaded only after parser
    # normalization has produced an admitted result.
    from .consistency_materialization import (
        materialize_revision_consistency,
        not_applicable_consistency_materialization,
        revision_consistency_selected_pins,
    )
    from .relationship_projection_materialization import (
        materialize_revision_relationship_projection,
        not_applicable_relationship_projection_materialization,
        revision_relationship_projection_selected_pins,
        validate_relationship_projection_dataset_fragment,
    )

    projection_pins = revision_relationship_projection_selected_pins(plan)
    consistency_pins = revision_consistency_selected_pins(plan)
    required_instance_ids = {
        pin.instance_id for pin in (*projection_pins, *consistency_pins)
    }
    required_pins = tuple(
        pin for pin in plan.plugins if pin.instance_id in required_instance_ids
    )
    if required_pins:
        if capability_providers is None:
            if frozen_process_providers is None:
                raise IngestionPipelineError(
                    "scheduled materialization requires the exact plan-bound "
                    "capability provider registry"
                )
            from .capability_router import (
                CapabilityProviderRegistry as ProviderRegistry,
            )

            capability_providers = ProviderRegistry._from_frozen_process_execution_plan(
                frozen_process_providers,
                plan,
                required_pins,
            )
        elif frozen_process_providers is not None:
            raise IngestionPipelineError(
                "scheduled materialization received conflicting provider sources"
            )
    base_world = IngestionRevisionWorld(
        basis=_revision_world_basis(result),
        snapshots=result.snapshots,
        relationship_observations=result.relationship_observations,
        undirected_relationship_types=frozenset(
            item.relation_type
            for item in result.schema.relationship_types
            if not item.directed
        ),
        primary_plugin_instance_id=primary_pin.instance_id,
        primary_schema_digest=primary_pin.schema_digest,
    )
    if not projection_pins:
        relationship_projection = (
            not_applicable_relationship_projection_materialization(plan)
        )
    else:
        assert capability_providers is not None
        from .capability_router import PlanBoundCapabilityRouter

        projection_router = PlanBoundCapabilityRouter._for_required_pins(
            capability_providers,
            plan,
            catalog_revision_id=result.revision_id,
            member_id=result.revision_id,
            required_pins=projection_pins,
            allow_inline_only=allow_inline_only,
        )
        relationship_projection = materialize_revision_relationship_projection(
            plan=plan,
            router=projection_router,
            world=base_world,
            primary_schema=result.schema,
            artifact_ids=tuple(
                artifact.artifact_id for artifact in result.inventory.artifacts
            ),
        )
    projection_fragment = relationship_projection.dataset_fragment()
    validate_relationship_projection_dataset_fragment(
        projection_fragment,
        plan=plan,
        world=base_world,
        primary_schema=result.schema,
        artifact_ids=tuple(
            artifact.artifact_id for artifact in result.inventory.artifacts
        ),
    )

    augmented_world = IngestionRevisionWorld(
        basis=base_world.basis,
        snapshots=result.snapshots,
        relationship_observations=result.relationship_observations,
        projected_relationships=relationship_projection.augmented_relationships,
        undirected_relationship_types=frozenset(
            item.relation_type
            for item in result.schema.relationship_types
            if not item.directed
        ),
        primary_plugin_instance_id=primary_pin.instance_id,
        primary_schema_digest=primary_pin.schema_digest,
    )
    if not consistency_pins:
        consistency = not_applicable_consistency_materialization(plan)
    else:
        assert capability_providers is not None
        from .capability_router import PlanBoundCapabilityRouter

        consistency_router = PlanBoundCapabilityRouter._for_required_pins(
            capability_providers,
            plan,
            catalog_revision_id=result.revision_id,
            member_id=result.revision_id,
            required_pins=consistency_pins,
            allow_inline_only=allow_inline_only,
        )
        consistency = materialize_revision_consistency(
            plan=plan,
            router=consistency_router,
            world=augmented_world,
            artifact_ids=tuple(
                artifact.artifact_id for artifact in result.inventory.artifacts
            ),
        )

    dataset = dict(result.dataset)
    raw_ingestion = dataset.get("_ingestion")
    if not isinstance(raw_ingestion, Mapping):
        raise IngestionPipelineError("normalized dataset lacks ingestion metadata")
    ingestion_metadata = dict(raw_ingestion)
    ingestion_metadata["mode"] = "core-ingestion-v3"
    ingestion_metadata["plugin_execution_plan_digest"] = plan.plan_digest
    ingestion_metadata["relationship_projection_materialization_status"] = (
        relationship_projection.status.value
    )
    ingestion_metadata["consistency_materialization_status"] = consistency.status.value
    dataset["_ingestion"] = ingestion_metadata
    inventory = dataset.get("inventory")
    if not isinstance(inventory, Mapping):
        raise IngestionPipelineError("normalized dataset inventory is invalid")
    detached_inventory = dict(inventory)
    detached_inventory["mode"] = "core-ingestion-v3"
    dataset["inventory"] = detached_inventory
    dataset.update(projection_fragment)
    fragment = consistency.dataset_fragment()
    dataset["findings"] = fragment["findings"]
    consistency_diagnostics = fragment["consistency_diagnostics"]
    dataset["consistency_diagnostics"] = consistency_diagnostics
    dataset["consistency_materialization"] = fragment["consistency_materialization"]
    raw_diagnostics = dataset.get("diagnostics")
    if not isinstance(raw_diagnostics, list):
        raise IngestionPipelineError("normalized dataset diagnostics are invalid")
    projection_diagnostics = projection_fragment[
        "relationship_projection_diagnostics"
    ]
    dataset["diagnostics"] = [
        *raw_diagnostics,
        *projection_diagnostics,
        *consistency_diagnostics,
    ]
    raw_summary = dataset.get("summary")
    if not isinstance(raw_summary, Mapping):
        raise IngestionPipelineError("normalized dataset summary is invalid")
    summary = dict(raw_summary)
    summary["relationship_projection"] = {
        "status": relationship_projection.status.value,
        "declaration_count": len(relationship_projection.declarations),
        "resolved_edge_count": len(relationship_projection.resolved_relationships),
        "diagnostic_count": len(relationship_projection.diagnostics),
        "semantic_conflict_groups": (
            relationship_projection.semantic_conflict_groups
        ),
    }
    summary["consistency"] = fragment["consistency_summary"]
    dataset["summary"] = summary
    return canonical_json(dataset).encode("utf-8"), plan


def _snapshot_coordinator_result(
    value: object,
    *,
    registered: RegisteredPlugin,
    expected_node_id: str | None,
) -> IngestionResult:
    """Admit one coordinator handoff without trusting class or JSON aliases."""

    try:
        return snapshot_ingestion_result_for_publication(
            value,
            limits=_registered_ingestion_limits(registered),
            plugin_id=registered.plugin_id,
            timeline_time_basis=TimelineTimeBasis(
                registered.timeline_time_basis
            ),
            timeline_clock_domain=registered.timeline_clock_domain,
            expected_node_id=expected_node_id,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except IngestionError as error:
        if str(error) == (
            "ingestion coordinator dataset is not bound to its typed result"
        ):
            raise IngestionPipelineError(str(error)) from error
        raise IngestionPipelineError(
            "ingestion coordinator returned an invalid result"
        ) from error
    except (TypeError, ValueError) as error:
        raise IngestionPipelineError(
            "ingestion coordinator returned an invalid result"
        ) from error
    except BaseException as error:
        raise IngestionPipelineError(
            "ingestion coordinator result could not be validated"
        ) from error


def _execution_plan_matches_registration(
    plan: PluginExecutionPlan,
    registered: RegisteredPlugin,
) -> bool:
    try:
        if not plugin_execution_plan_is_executable(plan):
            return False
    except (TypeError, ValueError):
        return False
    try:
        pin = primary_parser_execution_pin(plan)
    except (TypeError, ValueError):
        return False
    return (
        registered_plugin_matches_execution_pin(pin, registered)
        and pin.roles == ("primary_parser",)
        and (plan.decoder is None or plan.decoder == registered.decoder_identity)
    )


def _execution_plan_matches_composition(
    plan: PluginExecutionPlan,
    registered: RegisteredPlugin,
    *,
    capability_providers: CapabilityProviderRegistry,
    composition_policy: PluginCompositionPolicy,
    allow_inline_only: bool = False,
    expected_execution_plan_authority: PluginExecutionPlanAuthority,
) -> bool:
    """Re-admit a child-produced plan against the exact parent policy.

    The child may calculate the normalized-data schema digest, but it never
    chooses participating providers or roles. Those are parent-owned durable
    composition facts and every auxiliary coordinate is revalidated here
    before the plan can be staged.
    """

    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if type(expected_execution_plan_authority) is not PluginExecutionPlanAuthority:
        raise TypeError(
            "expected_execution_plan_authority must be an exact "
            "PluginExecutionPlanAuthority"
        )
    if plan.execution_plan_authority is not expected_execution_plan_authority:
        return False
    trusted_inline_plan = plan.execution_plan_authority in (
        PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED,
        PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST,
    )
    if trusted_inline_plan and not _registered_plugin_is_trusted_inline_capable(
        registered
    ):
        return False
    if (
        trusted_inline_plan
        and not _registered_plugin_is_process_capable(registered)
        and not allow_inline_only
    ):
        return False
    if (
        plan.execution_plan_authority is PluginExecutionPlanAuthority.PROCESS
        and not _registered_plugin_is_process_capable(registered)
    ):
        return False
    try:
        if not allow_inline_only:
            _require_no_inline_only_plugin_compatibility(
                (registered,),
                boundary=(
                    "durable ingestion requires PROCESS-capable primary plug-ins "
                    "unless trusted INLINE-only execution is explicit"
                ),
            )
        PluginRegistry.revalidate_registered_identity(registered)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - fail-closed parent trust boundary.
        return False
    if not _execution_plan_matches_registration(plan, registered):
        return False
    if plan.composition_policy_digest != composition_policy.policy_digest:
        return False
    if plan.plugins[0].roles != ("primary_parser",):
        return False
    selections = composition_policy.auxiliaries_for(
        primary_instance_id=registered.instance_id,
        primary_registered_execution_identity=(
            registered.registered_execution_identity
        ),
    )
    if len(plan.plugins) != 1 + len(selections):
        return False
    revalidated_auxiliaries: list[RegisteredPlugin] = []
    for pin, selection in zip(plan.plugins[1:], selections, strict=True):
        if pin.roles != selection.roles:
            return False
        try:
            auxiliary = capability_providers.get_by_execution_identity(
                selection.instance_id,
                selection.registered_execution_identity,
            )
            if (
                plan.execution_plan_authority is PluginExecutionPlanAuthority.PROCESS
                and not _registered_plugin_is_process_capable(auxiliary)
            ):
                return False
            if trusted_inline_plan and not _registered_plugin_is_trusted_inline_capable(
                auxiliary
            ):
                return False
            if not allow_inline_only:
                _require_no_inline_only_plugin_compatibility(
                    (auxiliary,),
                    boundary=(
                        "durable ingestion requires PROCESS-capable auxiliary "
                        "plug-ins unless trusted INLINE-only execution is explicit"
                    ),
                )
            PluginRegistry.revalidate_registered_identity(auxiliary)
            if (
                (
                    not _registered_plugin_is_process_capable(auxiliary)
                    and not (
                        allow_inline_only
                        and _registered_plugin_is_trusted_inline_capable(auxiliary)
                    )
                )
                or auxiliary.decoder_identity is not None
                or not registered_plugin_matches_execution_pin(pin, auxiliary)
            ):
                return False
            PluginRegistry.revalidate_registered_identity(auxiliary)
            auxiliary_schema_digest = (
                capability_providers.schema_digest_by_execution_identity(
                    selection.instance_id,
                    selection.registered_execution_identity,
                )
            )
            PluginRegistry.revalidate_registered_identity(auxiliary)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - fail-closed parent trust boundary.
            return False
        if pin.schema_digest != auxiliary_schema_digest:
            return False
        revalidated_auxiliaries.append(auxiliary)
    try:
        # A multi-provider readmission can spend time checking later entries.
        # Revalidate the complete selected set once more at the acceptance
        # edge so no earlier provider is admitted only on a stale live check.
        for auxiliary in revalidated_auxiliaries:
            PluginRegistry.revalidate_registered_identity(auxiliary)
        PluginRegistry.revalidate_registered_identity(registered)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - fail-closed parent trust boundary.
        return False
    return True


def _ingest_registered_plugin(
    registered: RegisteredPlugin,
    input_path: Path,
    *,
    capability_providers: CapabilityProviderRegistry | None = None,
    composition_policy: PluginCompositionPolicy | None = None,
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...] | None = None,
    frozen_process_providers: tuple[RegisteredPlugin, ...] | None = None,
    allow_inline_only: bool = False,
    execution_mode: PluginExecutionMode,
    node_hint: str | None,
    metadata: Mapping[str, Any],
) -> tuple[IngestionResult, bytes, PluginExecutionPlan]:
    """Execute and bind the identities revalidated for this exact run."""

    allow_inline_only = _validated_allow_inline_only(allow_inline_only)
    if frozen_process_providers is not None:
        if (
            type(frozen_process_providers) is not tuple
            or not frozen_process_providers
            or any(
                type(provider) is not RegisteredPlugin
                for provider in frozen_process_providers
            )
        ):
            raise TypeError(
                "frozen_process_providers must contain exact registered plug-ins"
            )
        if (
            execution_mode is not PluginExecutionMode.PROCESS
            or capability_providers is not None
        ):
            raise IngestionPipelineError(
                "frozen process providers are valid only inside PROCESS ingestion"
            )
    if frozen_auxiliary_pins is not None and capability_providers is None:
        if execution_mode is not PluginExecutionMode.PROCESS or any(
            pin.artifact.package_hash.startswith("manifest-sha256:")
            for pin in frozen_auxiliary_pins
        ):
            raise IngestionPipelineError(
                "frozen auxiliary pins are valid only for PROCESS execution"
            )
        selected_records: tuple[RegisteredPlugin, ...] = (registered,)
    else:
        selected_records = _selected_composition_records(
            registered,
            capability_providers=capability_providers,
            composition_policy=composition_policy,
        )
    execution_plan_authority = _execution_plan_authority_for_mode(
        selected_records,
        execution_mode=execution_mode,
        allow_inline_only=allow_inline_only,
    )
    token = _ACTIVE_DECODER_IDENTITY.set(None)
    try:
        PluginRegistry.revalidate_registered_identity(registered)
        result = _snapshot_coordinator_result(
            registered.coordinator.ingest(
                registered.execution_plugin,
                input_path,
                node_hint=node_hint,
                metadata=metadata,
            ),
            registered=registered,
            expected_node_id=node_hint,
        )
        PluginRegistry.revalidate_registered_identity(registered)
        dataset_json, execution_plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=capability_providers,
            composition_policy=composition_policy,
            frozen_auxiliary_pins=frozen_auxiliary_pins,
            frozen_process_providers=frozen_process_providers,
            allow_inline_only=allow_inline_only,
            execution_plan_authority=execution_plan_authority,
        )
        if not _execution_plan_matches_registration(execution_plan, registered):
            raise IngestionPipelineError(
                "execution plan does not match the registered execution identity"
            )
        return result, dataset_json, execution_plan
    finally:
        _ACTIVE_DECODER_IDENTITY.reset(token)


def _send_isolated_child_message(
    connection: Any,
    payload: Mapping[str, Any],
) -> None:
    encoded = canonical_json(dict(payload)).encode("utf-8")
    if len(encoded) > MAX_PLUGIN_CHILD_MESSAGE_BYTES:
        encoded = canonical_json(
            {
                "ok": False,
                "error_type": "PluginExecutionProcessError",
                "message": "plug-in child result exceeded the IPC metadata limit",
            }
        ).encode("utf-8")
    connection.send_bytes(encoded)


def _load_process_bootstrap_target(
    loader_kind: str,
    target: str,
    *,
    label: str,
) -> Any:
    """Resolve one module-level child object entirely inside the child."""

    if loader_kind not in {"module_attribute", "class_constructor"}:
        raise IngestionPipelineError(f"unknown {label} process loader kind")
    normalized = _normalized_explicit_bootstrap_target(target, f"{label}_target")
    return load_process_bootstrap_target(
        normalized,
        construct_class=loader_kind == "class_constructor",
    )


def _ingestion_limits_from_process_bootstrap(
    bootstrap: _PluginProcessBootstrap,
) -> IngestionLimits:
    if (
        type(bootstrap.ingestion_limit_values) is not tuple
        or len(bootstrap.ingestion_limit_values)
        != len(_INGESTION_LIMIT_BOOTSTRAP_FIELDS)
        or type(bootstrap.artifact_limit_values) is not tuple
        or len(bootstrap.artifact_limit_values) != len(_ARTIFACT_LIMIT_BOOTSTRAP_FIELDS)
        or any(
            type(value) is not int
            for value in (
                *bootstrap.ingestion_limit_values,
                *bootstrap.artifact_limit_values,
            )
        )
    ):
        raise IngestionPipelineError("plug-in process limit bootstrap is invalid")
    artifact_limits = ArtifactLimits(
        **dict(
            zip(
                _ARTIFACT_LIMIT_BOOTSTRAP_FIELDS,
                bootstrap.artifact_limit_values,
                strict=True,
            )
        )
    )
    return IngestionLimits(
        **dict(
            zip(
                _INGESTION_LIMIT_BOOTSTRAP_FIELDS,
                bootstrap.ingestion_limit_values,
                strict=True,
            )
        ),
        artifact_limits=artifact_limits,
    )


def _register_process_bootstrap(
    registry: PluginRegistry,
    bootstrap: _PluginProcessBootstrap,
    *,
    defer_executable_attestation: bool = False,
) -> RegisteredPlugin:
    """Reconstruct one exact child registration.

    The process entry points defer executable attestation to their immediate
    probe/ingestion boundary; direct conformance callers keep eager validation.
    """

    if type(defer_executable_attestation) is not bool:
        raise TypeError("defer_executable_attestation must be a boolean")
    if (
        type(bootstrap) is not _PluginProcessBootstrap
        or bootstrap.schema_version
        != "router_dump_analyzer.plugin_process_bootstrap.v2"
        or type(bootstrap.verify_package_bytes) is not bool
    ):
        raise IngestionPipelineError("plug-in process bootstrap is invalid")
    plugin = _load_process_bootstrap_target(
        bootstrap.plugin_loader_kind,
        bootstrap.plugin_target,
        label="plug-in",
    )
    limits = _ingestion_limits_from_process_bootstrap(bootstrap)
    if bootstrap.decoder_loader_kind == "none":
        if bootstrap.decoder_target is not None:
            raise IngestionPipelineError("decoder process bootstrap is invalid")
        decoder = None
    else:
        if type(bootstrap.decoder_target) is not str:
            raise IngestionPipelineError("decoder process bootstrap is invalid")
        decoder = _load_process_bootstrap_target(
            bootstrap.decoder_loader_kind,
            bootstrap.decoder_target,
            label="decoder",
        )
    if bootstrap.coordinator_loader_kind == "core_default":
        if bootstrap.coordinator_target is not None:
            raise IngestionPipelineError("coordinator process bootstrap is invalid")
        coordinator = IngestionCoordinator(
            trace_decoder=decoder,
            limits=limits,
        )
    else:
        if type(bootstrap.coordinator_target) is not str:
            raise IngestionPipelineError("coordinator process bootstrap is invalid")
        coordinator = _load_process_bootstrap_target(
            bootstrap.coordinator_loader_kind,
            bootstrap.coordinator_target,
            label="coordinator",
        )
        if not isinstance(coordinator, IngestionCoordinator):
            raise IngestionPipelineError(
                "coordinator process target did not produce an IngestionCoordinator"
            )
        coordinator.trace_decoder = decoder
        coordinator.limits = limits
    decoder_identity = (
        DecoderIdentity(*bootstrap.decoder_identity_values)
        if bootstrap.decoder_identity_values is not None
        else None
    )
    registered = registry._register(
        plugin,
        coordinator=coordinator,
        package_hash=(
            None if bootstrap.verify_package_bytes else bootstrap.package_hash
        ),
        instance_id=bootstrap.instance_id,
        distribution_name=bootstrap.distribution_name,
        distribution_version=bootstrap.distribution_version,
        entry_point_name=bootstrap.entry_point_name,
        module_target=bootstrap.module_target,
        configuration_digest=bootstrap.configuration_digest,
        decoder_identity=decoder_identity,
        plugin_process_module_target=bootstrap.plugin_target,
        plugin_process_construct_class=(
            bootstrap.plugin_loader_kind == "class_constructor"
        ),
        coordinator_module_target=(
            bootstrap.coordinator_target
            if bootstrap.coordinator_loader_kind == "module_attribute"
            else None
        ),
        decoder_module_target=(
            bootstrap.decoder_target
            if bootstrap.decoder_loader_kind == "module_attribute"
            else None
        ),
        _deferred_process_bootstrap=(
            bootstrap if defer_executable_attestation else None
        ),
    )
    # The deferred child path only materializes the frozen record here. Its
    # probe/ingestion boundary performs the one full package/target attestation
    # immediately before invoking plug-in code. Direct callers retain the
    # eager attestation used by conformance and drift checks.
    child_bootstrap = registered._process_bootstrap
    if type(child_bootstrap) is not _PluginProcessBootstrap:
        raise IngestionPipelineError(
            "child plug-in bootstrap is unavailable after registration"
        )
    if (
        registered.package_hash != bootstrap.package_hash
        or registered.verify_package_bytes != bootstrap.verify_package_bytes
        or child_bootstrap.plugin_target_executable_identity
        != bootstrap.plugin_target_executable_identity
        or child_bootstrap.coordinator_target_executable_identity
        != bootstrap.coordinator_target_executable_identity
        or child_bootstrap.decoder_target_executable_identity
        != bootstrap.decoder_target_executable_identity
        or registered.registered_execution_identity
        != bootstrap.expected_registered_execution_identity
    ):
        raise IngestionPipelineError(
            "child plug-in bootstrap does not match the registered execution identity"
        )
    return registered


def _registry_from_process_bootstraps(
    bootstraps: tuple[_PluginProcessBootstrap, ...],
) -> PluginRegistry:
    if (
        type(bootstraps) is not tuple
        or not bootstraps
        or len(bootstraps) > MAX_PLUGIN_CANDIDATES
        or any(type(item) is not _PluginProcessBootstrap for item in bootstraps)
    ):
        raise IngestionPipelineError("plug-in registry process bootstrap is invalid")
    registry = PluginRegistry(require_executable_identity=True)
    for bootstrap in bootstraps:
        _register_process_bootstrap(
            registry,
            bootstrap,
            defer_executable_attestation=True,
        )
    return registry


def _probe_plugin_child(
    connection: Any,
    bootstraps: tuple[_PluginProcessBootstrap, ...],
    input_path: str,
    node_hint: str | None,
    metadata: dict[str, Any],
) -> None:
    try:
        registry = _registry_from_process_bootstraps(bootstraps)
        candidates = registry.probe(
            Path(input_path),
            node_hint=node_hint,
            metadata=metadata,
        )
        _send_isolated_child_message(
            connection,
            {
                "ok": True,
                "kind": "probe",
                "candidates": [candidate.as_dict() for candidate in candidates],
            },
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:  # noqa: BLE001 - child fault boundary.
        _send_isolated_child_message(
            connection,
            {
                "ok": False,
                "error_type": type(error).__name__,
                "message": _private_exception_message(error),
            },
        )
    finally:
        connection.close()


def _ingest_plugin_child(
    connection: Any,
    bootstrap: _PluginProcessBootstrap,
    expected_primary_process_bootstrap_digest: str,
    expected_auxiliary_process_bootstrap_digests: tuple[str, ...],
    input_path: str,
    node_hint: str | None,
    metadata: dict[str, Any],
    staged_path: str,
    frozen_auxiliary_pins: tuple[PluginExecutionPin, ...] = (),
    composition_policy: PluginCompositionPolicy | None = None,
    auxiliary_bootstraps: tuple[_PluginProcessBootstrap, ...] = (),
) -> None:
    try:
        if (
            type(expected_primary_process_bootstrap_digest) is not str
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                expected_primary_process_bootstrap_digest,
            )
            is None
            or _plugin_process_bootstrap_digest(bootstrap)
            != expected_primary_process_bootstrap_digest
        ):
            raise IngestionPipelineError(
                "primary process bootstrap does not match its parent authority"
            )
        selected_policy, authorized_auxiliary_pins = (
            _validated_child_composition_authority(
                bootstrap,
                frozen_auxiliary_pins,
                composition_policy,
            )
        )
        selected_auxiliary_bootstraps = _validated_materialization_process_bootstraps(
            authorized_auxiliary_pins,
            auxiliary_bootstraps,
            expected_auxiliary_process_bootstrap_digests,
        )
        if any(
            auxiliary.instance_id == bootstrap.instance_id
            or auxiliary.expected_registered_execution_identity
            == bootstrap.expected_registered_execution_identity
            for auxiliary in selected_auxiliary_bootstraps
        ):
            raise IngestionPipelineError(
                "primary and auxiliary process bootstraps must be distinct"
            )
        registry = _registry_from_process_bootstraps(
            (bootstrap, *selected_auxiliary_bootstraps)
        )
        registered = registry.get_by_execution_identity(
            bootstrap.instance_id,
            bootstrap.expected_registered_execution_identity,
        )
        result, dataset_json, execution_plan = _ingest_registered_plugin(
            registered,
            Path(input_path),
            frozen_auxiliary_pins=authorized_auxiliary_pins,
            frozen_process_providers=registry.records(),
            composition_policy=selected_policy,
            execution_mode=PluginExecutionMode.PROCESS,
            node_hint=node_hint,
            metadata=metadata,
        )
        dataset_sha256 = hashlib.sha256(dataset_json).hexdigest()
        output = Path(staged_path)
        with output.open("xb") as stream:
            stream.write(dataset_json)
            stream.flush()
            os.fsync(stream.fileno())
        _send_isolated_child_message(
            connection,
            {
                "ok": True,
                "kind": "ingest",
                "revision_id": result.revision_id,
                "node_id": result.node_id,
                "dataset_sha256": dataset_sha256,
                "dataset_bytes": len(dataset_json),
                "event_count": len(result.events),
                "source_record_count": len(result.source_records),
                "resource_count": len(result.dataset.get("resources", ())),
                "execution_plan": plugin_execution_plan_dict(execution_plan),
            },
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:  # noqa: BLE001 - child fault boundary.
        _send_isolated_child_message(
            connection,
            {
                "ok": False,
                "error_type": type(error).__name__,
                "message": _private_exception_message(error),
            },
        )
    finally:
        connection.close()


def _catalog_publisher_child(
    connection: Any,
    bootstrap: CatalogPublisherProcessBootstrap,
    stage: str,
    scope: ImportScope,
    values: dict[str, Any],
) -> None:
    """Run one catalog boundary call in a disposable child process."""

    try:
        publisher = _catalog_publisher_from_process_bootstrap(bootstrap)
        if stage == "admission":
            publisher.admit_fixture(scope, **values)
            result: str | None = None
        elif stage == "publication":
            result = publisher.publish_revision(scope, **values)
            if result is not None and not isinstance(result, str):
                raise TypeError("catalog publisher returned a non-string revision ID")
        else:
            raise ValueError("unknown catalog publisher stage")
        _send_isolated_child_message(
            connection,
            {
                "ok": True,
                "kind": f"catalog_{stage}",
                "revision_id": result,
            },
        )
    except BaseException as error:  # noqa: BLE001 - child fault boundary.
        _send_isolated_child_message(
            connection,
            {
                "ok": False,
                "error_type": type(error).__name__,
                "message": _private_exception_message(error),
            },
        )
    finally:
        connection.close()


def _catalog_publisher_from_process_bootstrap(
    bootstrap: CatalogPublisherProcessBootstrap,
) -> RevisionCatalogPublisher:
    if type(bootstrap) is not CatalogPublisherProcessBootstrap:
        raise IngestionPipelineError("catalog process bootstrap is invalid")
    if bootstrap.loader_kind == "core_null":
        publisher: Any = NullRevisionCatalogPublisher()
    elif bootstrap.loader_kind == "core_sqlite_session":
        from .session_catalog_publisher import SessionCatalogPublisher
        from .session_store import SqliteSessionStore

        publisher = SessionCatalogPublisher(
            SqliteSessionStore(bootstrap.constructor_args[0])
        )
    else:
        assert bootstrap.target is not None
        publisher = load_process_bootstrap_target(
            bootstrap.target,
            construct_class=bootstrap.loader_kind == "class_constructor",
        )
    if not callable(getattr(publisher, "admit_fixture", None)) or not callable(
        getattr(publisher, "publish_revision", None)
    ):
        raise IngestionPipelineError(
            "catalog process target does not implement the publisher contract"
        )
    return publisher


def _terminate_isolated_child(
    process: Any,
    *,
    process_error: type[PluginExecutionProcessError | CatalogExecutionProcessError],
    subject: str,
) -> None:
    if process.is_alive():
        process.terminate()
        process.join(PLUGIN_CHILD_REAP_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(PLUGIN_CHILD_REAP_SECONDS)
    if process.is_alive():
        raise process_error(f"{subject} child {process.name!r} could not be reaped")


def _run_isolated_child(
    target: Callable[..., None],
    args: tuple[Any, ...],
    *,
    timeout_seconds: float,
    stage: str,
    expected_kind: str,
    subject: str,
    process_name_prefix: str,
    timeout_error: type[PluginExecutionTimeoutError | CatalogExecutionTimeoutError],
    process_error: type[PluginExecutionProcessError | CatalogExecutionProcessError],
    reported_timeout_types: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Run one bounded child call and validate its small JSON result."""

    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=target,
        args=(sender, *args),
        name=f"{process_name_prefix}-{stage}-{uuid4().hex[:12]}",
        daemon=False,
    )
    deadline = time.monotonic() + timeout_seconds
    started = False
    try:
        try:
            process.start()
            started = True
        except Exception as error:
            raise process_error(
                f"could not start process-isolated {subject} {stage}: "
                f"{type(error).__name__}: {error}"
            ) from error
        finally:
            sender.close()
        if not receiver.poll(max(0.0, deadline - time.monotonic())):
            raise timeout_error(
                f"{subject} {stage} exceeded {timeout_seconds:g} seconds"
            )
        try:
            encoded = receiver.recv_bytes(MAX_PLUGIN_CHILD_MESSAGE_BYTES)
        except EOFError as error:
            raise process_error(
                f"{subject} {stage} child exited without a result"
            ) from error
        except OSError as error:
            raise process_error(
                f"{subject} {stage} child returned invalid or oversized metadata"
            ) from error
        process.join(max(0.0, deadline - time.monotonic()))
        if process.is_alive():
            raise timeout_error(
                f"{subject} {stage} exceeded {timeout_seconds:g} seconds"
            )
        if process.exitcode != 0:
            raise process_error(
                f"{subject} {stage} child exited with code {process.exitcode}"
            )
        try:
            payload = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise process_error(
                f"{subject} {stage} child returned invalid JSON metadata"
            ) from error
        if not isinstance(payload, dict):
            raise process_error(f"{subject} {stage} child returned a non-object result")
        if payload.get("ok") is not True:
            error_type = payload.get("error_type")
            message = payload.get("message")
            if (
                not isinstance(error_type, str)
                or not error_type
                or len(error_type) > 256
                or not isinstance(message, str)
                or not message
                or len(message) > MAX_PRIVATE_FAILURE_MESSAGE_LENGTH
            ):
                raise process_error(
                    f"{subject} {stage} child returned malformed error metadata"
                )
            if error_type in reported_timeout_types:
                raise timeout_error(
                    f"{subject} {stage} reported that its deadline expired"
                )
            raise process_error(
                f"{subject} {stage} failed in its isolated process",
                private_exception_type=error_type,
                private_exception_message=message,
            )
        if payload.get("kind") != expected_kind:
            raise process_error(
                f"{subject} {stage} child returned the wrong result kind"
            )
        return payload
    finally:
        receiver.close()
        if started or process.pid is not None:
            _terminate_isolated_child(
                process,
                process_error=process_error,
                subject=subject,
            )
            process.close()
        else:
            try:
                process.close()
            except ValueError:
                pass


def _run_plugin_child(
    target: Callable[..., None],
    args: tuple[Any, ...],
    *,
    timeout_seconds: float,
    stage: str,
) -> dict[str, Any]:
    _validate_plugin_child_spawn_args(args)
    return _run_isolated_child(
        target,
        args,
        timeout_seconds=timeout_seconds,
        stage=stage,
        expected_kind=stage,
        subject="plug-in",
        process_name_prefix="rda-plugin",
        timeout_error=PluginExecutionTimeoutError,
        process_error=PluginExecutionProcessError,
    )


def _validate_plugin_child_spawn_args(args: tuple[Any, ...]) -> None:
    """Reject live deployment objects before Windows spawn can pickle them."""

    remaining = [200_000]

    def visit(value: Any, depth: int) -> None:
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 32:
            raise PluginExecutionProcessError(
                "plug-in child bootstrap exceeds the safe value boundary"
            )
        if value is None or type(value) in {bool, int, str}:
            return
        if type(value) is float:
            if math.isfinite(value):
                return
            raise PluginExecutionProcessError(
                "plug-in child bootstrap contains a non-finite float"
            )
        if type(value) in {tuple, list}:
            for item in value:
                visit(item, depth + 1)
            return
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise PluginExecutionProcessError(
                        "plug-in child bootstrap mappings require string keys"
                    )
                visit(item, depth + 1)
            return
        if type(value) is _PluginProcessBootstrap:
            visit(
                (
                    value.schema_version,
                    value.plugin_loader_kind,
                    value.plugin_target,
                    value.plugin_target_executable_identity,
                    value.coordinator_loader_kind,
                    value.coordinator_target,
                    value.coordinator_target_executable_identity,
                    value.decoder_loader_kind,
                    value.decoder_target,
                    value.decoder_target_executable_identity,
                    value.ingestion_limit_values,
                    value.artifact_limit_values,
                    value.package_hash,
                    value.verify_package_bytes,
                    value.instance_id,
                    value.distribution_name,
                    value.distribution_version,
                    value.entry_point_name,
                    value.module_target,
                    value.configuration_digest,
                    value.decoder_identity_values,
                    value.expected_registered_execution_identity,
                ),
                depth + 1,
            )
            return
        if type(value) is PluginArtifactIdentity:
            visit(
                (
                    value.distribution_name,
                    value.distribution_version,
                    value.package_hash,
                    value.entry_point_name,
                    value.module_target,
                ),
                depth + 1,
            )
            return
        if type(value) is PluginExecutionPin:
            visit(
                (
                    value.instance_id,
                    value.plugin_id,
                    value.plugin_version,
                    value.core_api_version,
                    value.artifact,
                    value.configuration_digest,
                    value.schema_digest,
                    value.registered_execution_identity,
                    value.process_bootstrap_digest,
                    value.schema_versions,
                    value.capabilities,
                    value.roles,
                ),
                depth + 1,
            )
            return
        if type(value) is PluginParticipationSelection:
            visit(
                (
                    value.instance_id,
                    value.registered_execution_identity,
                    value.roles,
                ),
                depth + 1,
            )
            return
        if type(value) is PluginCompositionRule:
            visit(
                (
                    value.primary_instance_id,
                    value.primary_registered_execution_identity,
                    value.auxiliaries,
                ),
                depth + 1,
            )
            return
        if type(value) is PluginCompositionPolicy:
            visit(
                (value.rules, value.contract_version, value.policy_digest),
                depth + 1,
            )
            return
        raise PluginExecutionProcessError(
            "plug-in child bootstrap contains a live or unsupported object"
        )

    if type(args) is not tuple:
        raise PluginExecutionProcessError(
            "plug-in child bootstrap arguments must be an exact tuple"
        )
    visit(args, 0)


def _run_catalog_publisher_child(
    bootstrap: CatalogPublisherProcessBootstrap,
    *,
    stage: str,
    scope: ImportScope,
    values: dict[str, Any],
    timeout_seconds: float,
) -> str | None:
    if type(bootstrap) is not CatalogPublisherProcessBootstrap:
        raise CatalogExecutionProcessError(
            "catalog publisher process bootstrap is invalid"
        )
    bootstrap = CatalogPublisherProcessBootstrap(
        loader_kind=bootstrap.loader_kind,
        target=bootstrap.target,
        constructor_args=bootstrap.constructor_args,
        schema_version=bootstrap.schema_version,
    )
    payload = _run_isolated_child(
        _catalog_publisher_child,
        (bootstrap, stage, scope, values),
        timeout_seconds=timeout_seconds,
        stage=stage,
        expected_kind=f"catalog_{stage}",
        subject="catalog publisher",
        process_name_prefix="rda-catalog",
        timeout_error=CatalogExecutionTimeoutError,
        process_error=CatalogExecutionProcessError,
        reported_timeout_types=frozenset({"CatalogExecutionTimeoutError"}),
    )
    revision_id = payload.get("revision_id")
    if revision_id is not None and not isinstance(revision_id, str):
        raise CatalogExecutionProcessError(
            f"catalog publisher {stage} child returned an invalid revision ID"
        )
    return revision_id


def _run_plugin_inline(
    operation: Callable[[], Any],
    *,
    stage: str,
) -> Any:
    """Run trusted local/test plug-in code synchronously.

    CPython cannot safely cancel an arbitrary thread.  Running the operation
    on a disposable daemon thread would therefore turn each apparent timeout
    into a permanently live execution.  Inline mode is deliberately honest:
    it is synchronous and has no hard-deadline guarantee.  Durable and
    production callers use the default process mode, whose child can be
    terminated and reaped.
    """

    try:
        return operation()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        # Ordinary domain failures retain the existing worker classification;
        # the caller's established ingestion boundary contains them.
        raise
    except BaseException as error:
        raise PluginExecutionProcessError(
            f"plug-in {stage} failed during trusted inline execution",
            private_exception_type=type(error).__name__,
            private_exception_message=_private_exception_message(error),
        ) from error


class DurableIngestionPipeline:
    """Single-host durable import queue and content-addressed artifact store."""

    def __init__(
        self,
        root: Path,
        *,
        registry: PluginRegistry,
        publisher: RevisionCatalogPublisher | None = None,
        publisher_module_target: str | None = None,
        limits: PipelineLimits | None = None,
        retention_policy: RetentionPolicy | None = None,
        composition_policy: PluginCompositionPolicy | None = None,
        capability_providers: CapabilityProviderRegistry | None = None,
        worker_id: str | None = None,
        allow_inline_only: bool = False,
    ) -> None:
        if type(registry) is not PluginRegistry:
            raise TypeError("registry must be an exact PluginRegistry")
        if type(allow_inline_only) is not bool:
            raise TypeError("allow_inline_only must be an exact boolean")
        selected_registry = registry._sealed_snapshot()
        selected_records = selected_registry.records()
        if allow_inline_only:
            for record in selected_records:
                PluginRegistry.revalidate_registered_identity(record)
                if not _registered_plugin_is_process_capable(
                    record
                ) and not _registered_plugin_is_trusted_inline_capable(record):
                    raise ValueError(
                        "trusted INLINE-only durable ingestion requires registered "
                        "attested execution identities"
                    )
        else:
            selected_registry.require_executable_identities()
            for record in selected_records:
                if not _registered_plugin_is_process_capable(record):
                    raise ValueError(
                        record._process_bootstrap_error
                        or "durable ingestion requires validated process bootstraps"
                    )
        selected_limits = limits or PipelineLimits()
        if (
            allow_inline_only
            and selected_limits.plugin_execution_mode is PluginExecutionMode.INLINE
            and selected_limits.publisher_execution_mode is None
        ):
            # Trusted-inline plug-in consent must not silently weaken the
            # independent catalog publication boundary.
            selected_limits = replace(
                selected_limits,
                publisher_execution_mode=PluginExecutionMode.PROCESS,
            )
        self.root: Path = validate_ingestion_state_root(root)
        self.database_path: Path = self.root / "control-plane.sqlite3"
        self.blob_root: Path = self.root / "blobs"
        self.dataset_root: Path = self.root / "revisions"
        self.fixture_root: Path = self.root / "fixtures"
        self.spool_root: Path = self.root / "spool"
        self.lock_root: Path = self.root / "locks"
        self.content_lock_root: Path = self.lock_root / "content"
        self._spool_namespace_lock_path = self.lock_root / "spool-namespace.lock"
        self.registry: PluginRegistry = selected_registry
        # Import lazily: capability_router consumes RegisteredPlugin and the
        # registry primitives from this module.  Construction occurs only
        # after both modules are fully initialized.
        from .capability_router import CapabilityProviderRegistry as ProviderRegistry

        if capability_providers is None:
            candidate_capability_providers = ProviderRegistry.from_primary_registry(
                selected_registry,
            )
        elif type(capability_providers) is not ProviderRegistry:
            raise TypeError(
                "capability_providers must be an exact "
                "CapabilityProviderRegistry or None"
            )
        else:
            candidate_capability_providers = capability_providers
        selected_capability_providers = (
            candidate_capability_providers._sealed_snapshot()
        )
        selected_provider_records = selected_capability_providers.records()
        if not allow_inline_only:
            _require_no_inline_only_plugin_compatibility(
                selected_provider_records,
                boundary=(
                    "durable ingestion requires PROCESS-capable auxiliary plug-ins"
                ),
            )
            for record in selected_provider_records:
                if not _registered_plugin_is_process_capable(record):
                    raise ValueError(
                        record._process_bootstrap_error
                        or "durable ingestion requires validated auxiliary process "
                        "bootstraps"
                    )
        elif any(
            not _registered_plugin_is_process_capable(record)
            and not _registered_plugin_is_trusted_inline_capable(record)
            for record in selected_provider_records
        ):
            raise ValueError(
                "trusted INLINE-only capability providers require registered "
                "attested execution identities"
            )
        requires_inline_execution = _registered_plugins_require_inline_execution(
            (*selected_records, *selected_provider_records)
        )
        if (
            requires_inline_execution
            and selected_limits.plugin_execution_mode is not PluginExecutionMode.INLINE
        ):
            raise ValueError(
                "trusted INLINE-only durable ingestion requires "
                "PipelineLimits(plugin_execution_mode='inline')"
            )
        self.allow_inline_only: bool = allow_inline_only
        self.requires_inline_execution: bool = requires_inline_execution
        self.capability_providers: CapabilityProviderRegistry = (
            selected_capability_providers
        )
        selected_composition_policy = (
            PluginCompositionPolicy()
            if composition_policy is None
            else composition_policy
        )
        if type(selected_composition_policy) is not PluginCompositionPolicy:
            raise TypeError(
                "composition_policy must be PluginCompositionPolicy or None"
            )
        self.composition_policy: PluginCompositionPolicy = PluginCompositionPolicy(
            rules=selected_composition_policy.rules,
            contract_version=selected_composition_policy.contract_version,
            policy_digest=selected_composition_policy.policy_digest,
        )
        self.publisher: RevisionCatalogPublisher = (
            publisher or NullRevisionCatalogPublisher()
        )
        self.publisher_process_bootstrap: CatalogPublisherProcessBootstrap = (
            _catalog_publisher_process_bootstrap(
                self.publisher,
                module_target=publisher_module_target,
            )
        )
        self.limits: PipelineLimits = selected_limits
        if self.limits.plugin_execution_mode is PluginExecutionMode.PROCESS:
            # Materialize the inert descriptors now so a configured object
            # cannot remain apparently registered until the first queued job
            # silently reconstructs a default instance in a child.
            self.registry.process_bootstraps()
        self.retention_policy: RetentionPolicy = retention_policy or RetentionPolicy()
        self.worker_id: str = worker_id or f"worker-{uuid4().hex}"
        _bounded_identifier(self.worker_id, "worker_id", 256)
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._maintenance_lock_path = self.root / ".retention.lock"
        self._schema_lock_path = self.root / ".schema.lock"
        # Retention executions need a durable, cross-process order of their
        # cursor reads and commits.  Keep that order separate from the short
        # publication fence so a bounded directory walk cannot stall uploads.
        self._retention_operation_lock_path = self.root / ".retention-operation.lock"
        self._total_claim_errors = 0
        self._consecutive_claim_errors = 0
        self._last_claim_error_at_ns: int | None = None
        self._last_claim_error: str | None = None
        self._total_iteration_errors = 0
        self._consecutive_iteration_errors = 0
        self._last_iteration_error_at_ns: int | None = None
        self._last_iteration_error: str | None = None
        self._unexpected_worker_exits = 0
        self._last_worker_exit_at_ns: int | None = None
        self._last_worker_exit: str | None = None
        self._last_worker_log_at = {
            "claim": float("-inf"),
            "iteration": float("-inf"),
        }
        for directory in (
            self.root,
            self.blob_root,
            self.dataset_root,
            self.fixture_root,
            self.spool_root,
            self.content_lock_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        # Schema upgrades use read-then-ALTER checks.  Serialize initialization
        # across processes so two first-start instances cannot both observe a
        # missing legacy column and race the same ALTER TABLE statement.
        with exclusive_file_lock(self._schema_lock_path):
            self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.database_path,
            timeout=30,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            # Capture the upgrade origin before CREATE TABLE can erase the
            # distinction. Databases opened by the earlier pin-aware build
            # normally ran its compatibility backfill, while a missing pin in
            # such a database can represent a deliberate release. The old
            # build had no release tombstones, so a crash partway through its
            # non-transactional backfill is indistinguishable from a release;
            # preserve absence rather than resurrect ownership. A genuinely
            # pre-pin schema requires the one-time backfill. Persisting that
            # intent first makes a crash between schema creation and migration
            # retryable.
            artifact_pin_schema_existed = (
                connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'ingestion_artifact_pins'
                    """
                ).fetchone()
                is not None
            )
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ingestion_schema_migrations (
                        migration_id TEXT PRIMARY KEY,
                        applied_at_ns INTEGER NOT NULL
                    )
                    """
                )
                if not artifact_pin_schema_existed:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO ingestion_schema_migrations (
                            migration_id, applied_at_ns
                        ) VALUES (?, ?)
                        """,
                        (
                            _ARTIFACT_PIN_BACKFILL_REQUIRED_MARKER,
                            time.time_ns(),
                        ),
                    )
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ingestion_imports (
                    import_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    fixture_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    node_hint TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    byte_count INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    blob_ref TEXT NOT NULL,
                    input_ref TEXT NOT NULL,
                    composition_policy_digest TEXT NOT NULL,
                    probe_set_hash TEXT,
                    selected_plugin_id TEXT,
                    selected_plugin_version TEXT,
                    selected_package_hash TEXT,
                    selected_execution_identity TEXT,
                    revision_id TEXT,
                    node_id TEXT,
                    admission_operation_id TEXT,
                    catalog_fixture_admitted INTEGER NOT NULL DEFAULT 0,
                    publication_operation_id TEXT,
                    staged_source_revision_id TEXT,
                    staged_node_id TEXT,
                    staged_dataset_ref TEXT,
                    staged_dataset_sha256 TEXT,
                    staged_event_count INTEGER,
                    staged_source_record_count INTEGER,
                    staged_resource_count INTEGER,
                    staged_execution_plan_json TEXT,
                    staged_execution_plan_digest TEXT,
                    execution_plan_required INTEGER NOT NULL DEFAULT 1
                        CHECK (execution_plan_required IN (0, 1)),
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    auto_select INTEGER NOT NULL,
                    preferred_plugin_id TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    idempotency_key TEXT,
                    lease_owner TEXT,
                    lease_expires_ns INTEGER,
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL,
                    UNIQUE (
                        tenant_id,
                        project_id,
                        workspace_id,
                        idempotency_key
                    )
                );
                CREATE INDEX IF NOT EXISTS ingestion_import_scope
                    ON ingestion_imports (
                        tenant_id, project_id, workspace_id, created_at_ns
                    );
                CREATE INDEX IF NOT EXISTS ingestion_import_queue
                    ON ingestion_imports (
                        state, lease_expires_ns, created_at_ns
                    );
                CREATE INDEX IF NOT EXISTS ingestion_import_health
                    ON ingestion_imports (state, updated_at_ns);
                CREATE INDEX IF NOT EXISTS ingestion_catalog_attention
                    ON ingestion_imports (error_code, state)
                    WHERE error_code IS NOT NULL;
                CREATE TABLE IF NOT EXISTS ingestion_candidates (
                    import_id TEXT NOT NULL REFERENCES ingestion_imports(
                        import_id
                    ) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    plugin_id TEXT NOT NULL,
                    plugin_version TEXT NOT NULL,
                    package_hash TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    registered_execution_identity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    match_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (import_id, ordinal),
                    UNIQUE (
                        import_id, plugin_id, plugin_version, package_hash,
                        instance_id, registered_execution_identity
                    )
                );
                CREATE TABLE IF NOT EXISTS ingestion_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    import_id TEXT NOT NULL REFERENCES ingestion_imports(
                        import_id
                    ) ON DELETE CASCADE,
                    state TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ingestion_event_stream
                    ON ingestion_events (import_id, sequence);
                CREATE TABLE IF NOT EXISTS ingestion_failure_diagnostics (
                    diagnostic_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    import_id TEXT NOT NULL REFERENCES ingestion_imports(
                        import_id
                    ) ON DELETE CASCADE,
                    attempt_number INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    public_error_code TEXT NOT NULL,
                    exception_type TEXT NOT NULL,
                    exception_message TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    UNIQUE (import_id, source_kind, source_id)
                );
                CREATE INDEX IF NOT EXISTS ingestion_failure_diagnostic_import
                    ON ingestion_failure_diagnostics (
                        import_id, diagnostic_id
                    );
                CREATE TABLE IF NOT EXISTS ingestion_idempotency (
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    import_id TEXT NOT NULL REFERENCES ingestion_imports(
                        import_id
                    ) ON DELETE CASCADE,
                    created_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (
                        tenant_id, project_id, workspace_id,
                        operation, idempotency_key
                    )
                );
                CREATE INDEX IF NOT EXISTS ingestion_idempotency_expiry
                    ON ingestion_idempotency (
                        tenant_id, project_id, workspace_id, created_at_ns
                    );
                CREATE TABLE IF NOT EXISTS ingestion_artifact_pins (
                    artifact_kind TEXT NOT NULL,
                    artifact_ref TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    owner_operation_id TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (
                        artifact_kind, artifact_ref,
                        tenant_id, project_id, workspace_id,
                        owner_operation_id
                    )
                );
                CREATE TABLE IF NOT EXISTS ingestion_retention_audit (
                    audit_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    actor TEXT,
                    operation_id TEXT,
                    request_digest TEXT,
                    effective_now_ns INTEGER,
                    plan_json TEXT,
                    cleanup_progress_json TEXT NOT NULL DEFAULT '{}',
                    state TEXT NOT NULL DEFAULT 'completed'
                );
                CREATE TABLE IF NOT EXISTS ingestion_retention_cleanup_progress (
                    audit_id TEXT NOT NULL REFERENCES ingestion_retention_audit(
                        audit_id
                    ) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    deleted_bytes INTEGER NOT NULL,
                    detail TEXT,
                    updated_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (audit_id, sequence)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS ingestion_retention_audit_scope
                    ON ingestion_retention_audit (
                        tenant_id, project_id, workspace_id, created_at_ns
                    );
                CREATE TABLE IF NOT EXISTS ingestion_host_retention_cursor (
                    root_name TEXT PRIMARY KEY,
                    cursor TEXT NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                );
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(ingestion_imports)"
                ).fetchall()
            }
            if "node_hint" not in columns:
                connection.execute(
                    "ALTER TABLE ingestion_imports ADD COLUMN node_hint TEXT"
                )
            if "metadata_json" not in columns:
                connection.execute(
                    "ALTER TABLE ingestion_imports ADD COLUMN "
                    "metadata_json TEXT NOT NULL DEFAULT '{}'"
                )
            staged_columns = {
                "composition_policy_digest": (
                    "TEXT NOT NULL DEFAULT "
                    f"'{DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST}'"
                ),
                "selected_execution_identity": "TEXT",
                "admission_operation_id": "TEXT",
                "catalog_fixture_admitted": "INTEGER NOT NULL DEFAULT 0",
                "publication_operation_id": "TEXT",
                "staged_source_revision_id": "TEXT",
                "staged_node_id": "TEXT",
                "staged_dataset_ref": "TEXT",
                "staged_dataset_sha256": "TEXT",
                "staged_event_count": "INTEGER",
                "staged_source_record_count": "INTEGER",
                "staged_resource_count": "INTEGER",
                "staged_execution_plan_json": "TEXT",
                "staged_execution_plan_digest": "TEXT",
                "execution_plan_required": (
                    "INTEGER NOT NULL DEFAULT 0 "
                    "CHECK (execution_plan_required IN (0, 1))"
                ),
            }
            for name, sql_type in staged_columns.items():
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE ingestion_imports ADD COLUMN {name} {sql_type}"
                    )
            candidate_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(ingestion_candidates)"
                ).fetchall()
            }
            expected_candidate_unique = (
                "import_id",
                "plugin_id",
                "plugin_version",
                "package_hash",
                "instance_id",
                "registered_execution_identity",
            )
            candidate_unique_indexes = tuple(
                tuple(
                    str(column["name"])
                    for column in connection.execute(
                        f"PRAGMA index_info({str(index['name'])!r})"
                    ).fetchall()
                )
                for index in connection.execute(
                    "PRAGMA index_list(ingestion_candidates)"
                ).fetchall()
                if bool(index["unique"])
            )
            if (
                "instance_id" not in candidate_columns
                or "registered_execution_identity" not in candidate_columns
                or expected_candidate_unique not in candidate_unique_indexes
            ):
                instance_projection = (
                    "instance_id" if "instance_id" in candidate_columns else "''"
                )
                execution_projection = (
                    "registered_execution_identity"
                    if "registered_execution_identity" in candidate_columns
                    else "''"
                )
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        CREATE TABLE ingestion_candidates_upgrade (
                            import_id TEXT NOT NULL REFERENCES ingestion_imports(
                                import_id
                            ) ON DELETE CASCADE,
                            ordinal INTEGER NOT NULL,
                            plugin_id TEXT NOT NULL,
                            plugin_version TEXT NOT NULL,
                            package_hash TEXT NOT NULL,
                            instance_id TEXT NOT NULL,
                            registered_execution_identity TEXT NOT NULL,
                            confidence REAL NOT NULL,
                            match_kind TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            PRIMARY KEY (import_id, ordinal),
                            UNIQUE (
                                import_id, plugin_id, plugin_version, package_hash,
                                instance_id, registered_execution_identity
                            )
                        )
                        """
                    )
                    connection.execute(
                        f"""
                        INSERT INTO ingestion_candidates_upgrade (
                            import_id, ordinal, plugin_id, plugin_version,
                            package_hash, instance_id,
                            registered_execution_identity, confidence,
                            match_kind, payload_json
                        )
                        SELECT import_id, ordinal, plugin_id, plugin_version,
                               package_hash, {instance_projection},
                               {execution_projection}, confidence,
                               match_kind, payload_json
                        FROM ingestion_candidates
                        """
                    )
                    connection.execute("DROP TABLE ingestion_candidates")
                    connection.execute(
                        "ALTER TABLE ingestion_candidates_upgrade "
                        "RENAME TO ingestion_candidates"
                    )
                except BaseException:
                    connection.rollback()
                    raise
                else:
                    connection.commit()
            connection.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_composition_policy_immutable
                BEFORE UPDATE OF composition_policy_digest ON ingestion_imports
                WHEN NEW.composition_policy_digest
                         IS NOT OLD.composition_policy_digest
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'plug-in composition policy is immutable'
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_execution_plan_contract_no_downgrade
                BEFORE UPDATE OF execution_plan_required ON ingestion_imports
                WHEN OLD.execution_plan_required = 1
                     AND NEW.execution_plan_required != 1
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'execution-plan contract cannot be downgraded'
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_execution_plan_required_insert
                BEFORE INSERT ON ingestion_imports
                WHEN NEW.execution_plan_required = 1
                     AND NEW.publication_operation_id IS NOT NULL
                     AND (
                         NEW.staged_execution_plan_json IS NULL
                         OR NEW.staged_execution_plan_json = ''
                         OR NEW.staged_execution_plan_digest IS NULL
                         OR NEW.staged_execution_plan_digest = ''
                     )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'execution plan is required for this import'
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_execution_plan_required_update
                BEFORE UPDATE ON ingestion_imports
                WHEN NEW.execution_plan_required = 1
                     AND NEW.publication_operation_id IS NOT NULL
                     AND (
                         NEW.staged_execution_plan_json IS NULL
                         OR NEW.staged_execution_plan_json = ''
                         OR NEW.staged_execution_plan_digest IS NULL
                         OR NEW.staged_execution_plan_digest = ''
                     )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'execution plan is required for this import'
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_staged_publication_immutable
                BEFORE UPDATE OF
                    publication_operation_id,
                    staged_source_revision_id,
                    staged_node_id,
                    staged_dataset_ref,
                    staged_dataset_sha256,
                    staged_event_count,
                    staged_source_record_count,
                    staged_resource_count,
                    staged_execution_plan_json,
                    staged_execution_plan_digest,
                    selected_plugin_id,
                    selected_plugin_version,
                    selected_package_hash,
                    selected_execution_identity
                ON ingestion_imports
                WHEN OLD.publication_operation_id IS NOT NULL
                     AND (
                         NEW.publication_operation_id
                             IS NOT OLD.publication_operation_id
                         OR NEW.staged_source_revision_id
                             IS NOT OLD.staged_source_revision_id
                         OR NEW.staged_node_id IS NOT OLD.staged_node_id
                         OR NEW.staged_dataset_ref IS NOT OLD.staged_dataset_ref
                         OR NEW.staged_dataset_sha256
                             IS NOT OLD.staged_dataset_sha256
                         OR NEW.staged_event_count IS NOT OLD.staged_event_count
                         OR NEW.staged_source_record_count
                             IS NOT OLD.staged_source_record_count
                         OR NEW.staged_resource_count
                             IS NOT OLD.staged_resource_count
                         OR NEW.staged_execution_plan_json
                             IS NOT OLD.staged_execution_plan_json
                         OR NEW.staged_execution_plan_digest
                             IS NOT OLD.staged_execution_plan_digest
                         OR NEW.selected_plugin_id IS NOT OLD.selected_plugin_id
                         OR NEW.selected_plugin_version
                             IS NOT OLD.selected_plugin_version
                         OR NEW.selected_package_hash
                             IS NOT OLD.selected_package_hash
                         OR NEW.selected_execution_identity
                             IS NOT OLD.selected_execution_identity
                     )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'staged publication payload is immutable'
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS
                    ingestion_staged_scope_immutable
                BEFORE UPDATE OF
                    tenant_id,
                    project_id,
                    workspace_id,
                    fixture_id
                ON ingestion_imports
                WHEN OLD.publication_operation_id IS NOT NULL
                     AND (
                         NEW.tenant_id IS NOT OLD.tenant_id
                         OR NEW.project_id IS NOT OLD.project_id
                         OR NEW.workspace_id IS NOT OLD.workspace_id
                         OR NEW.fixture_id IS NOT OLD.fixture_id
                     )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'staged publication scope is immutable'
                    );
                END;
                """
            )
            retention_audit_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(ingestion_retention_audit)"
                ).fetchall()
            }
            retention_audit_upgrades = {
                "actor": "TEXT",
                "operation_id": "TEXT",
                "request_digest": "TEXT",
                "effective_now_ns": "INTEGER",
                "plan_json": "TEXT",
                "cleanup_progress_json": "TEXT NOT NULL DEFAULT '{}'",
                "state": "TEXT NOT NULL DEFAULT 'completed'",
            }
            for name, sql_type in retention_audit_upgrades.items():
                if name not in retention_audit_columns:
                    connection.execute(
                        "ALTER TABLE ingestion_retention_audit "
                        f"ADD COLUMN {name} {sql_type}"
                    )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS
                    ingestion_retention_audit_operation
                ON ingestion_retention_audit (
                    tenant_id, project_id, workspace_id, operation_id
                )
                WHERE operation_id IS NOT NULL
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            try:
                # The policy digest is immutable after admission.  A legacy
                # pre-contract row is the sole exception: while this schema
                # transaction clears its obsolete probe/selection authority,
                # bind the policy explicitly active for the re-probe.  Drop
                # and recreate the trigger inside the same write transaction
                # so no externally visible state ever lacks the guard.
                connection.execute(
                    "DROP TRIGGER IF EXISTS ingestion_composition_policy_immutable"
                )
                self._migrate_legacy_execution_selections(connection)
                self._migrate_legacy_artifact_pins(connection)
                self._migrate_legacy_public_failures(connection)
                connection.execute(
                    """
                    CREATE TRIGGER ingestion_composition_policy_immutable
                    BEFORE UPDATE OF composition_policy_digest
                        ON ingestion_imports
                    WHEN NEW.composition_policy_digest
                             IS NOT OLD.composition_policy_digest
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'plug-in composition policy is immutable'
                        );
                    END
                    """
                )
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
        self._recover_expired_jobs()

    def _migrate_legacy_execution_selections(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Re-probe unfinished pre-contract jobs before binding a full identity."""

        reprobe_states = (
            ImportState.QUEUED.value,
            ImportState.PROBING.value,
            ImportState.AWAITING_SELECTION.value,
            ImportState.READY.value,
            ImportState.INGESTING.value,
            ImportState.FAILED.value,
        )
        placeholders = ", ".join("?" for _ in reprobe_states)
        rows = connection.execute(
            f"""
            SELECT import_id, state
            FROM ingestion_imports
            WHERE execution_plan_required = 0
              AND publication_operation_id IS NULL
              AND state IN ({placeholders})
            """,
            reprobe_states,
        ).fetchall()
        if not rows:
            # ADMITTING rows have not probed and can adopt the contract in place.
            connection.execute(
                """
                UPDATE ingestion_imports
                SET composition_policy_digest = ?,
                    execution_plan_required = 1
                WHERE execution_plan_required = 0
                  AND publication_operation_id IS NULL
                  AND state = ?
                """,
                (
                    self.composition_policy.policy_digest,
                    ImportState.ADMITTING.value,
                ),
            )
            return
        import_ids = tuple(str(row["import_id"]) for row in rows)
        id_placeholders = ", ".join("?" for _ in import_ids)
        connection.execute(
            f"DELETE FROM ingestion_candidates WHERE import_id IN ({id_placeholders})",
            import_ids,
        )
        connection.execute(
            f"""
            UPDATE ingestion_imports
            SET state = CASE WHEN state = ? THEN state ELSE ? END,
                probe_set_hash = NULL,
                selected_plugin_id = NULL,
                selected_plugin_version = NULL,
                selected_package_hash = NULL,
                selected_execution_identity = NULL,
                lease_owner = NULL,
                lease_expires_ns = NULL,
                composition_policy_digest = ?,
                execution_plan_required = 1
            WHERE import_id IN ({id_placeholders})
            """,
            (
                ImportState.FAILED.value,
                ImportState.QUEUED.value,
                self.composition_policy.policy_digest,
                *import_ids,
            ),
        )
        connection.execute(
            """
            UPDATE ingestion_imports
            SET composition_policy_digest = ?,
                execution_plan_required = 1
            WHERE execution_plan_required = 0
              AND publication_operation_id IS NULL
              AND state = ?
            """,
            (
                self.composition_policy.policy_digest,
                ImportState.ADMITTING.value,
            ),
        )

    def _migrate_legacy_artifact_pins(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Backfill pre-pin catalog ownership exactly once.

        The migration marker and both pin projections share the caller's
        transaction.  Once catalog retention deliberately releases a pin,
        later process construction observes the marker and cannot reconstruct
        that ownership from the historical import row.
        """

        applied = connection.execute(
            """
            SELECT 1 FROM ingestion_schema_migrations
            WHERE migration_id = ?
            """,
            (_ARTIFACT_PIN_BACKFILL_MIGRATION,),
        ).fetchone()
        if applied is not None:
            return
        backfill_required = (
            connection.execute(
                """
                SELECT 1 FROM ingestion_schema_migrations
                WHERE migration_id = ?
                """,
                (_ARTIFACT_PIN_BACKFILL_REQUIRED_MARKER,),
            ).fetchone()
            is not None
        )
        if backfill_required:
            # Conservative pre-pin upgrade: artifacts already acknowledged by
            # the external catalog remain pinned even after queue history is
            # later pruned. Fresh databases contain no imports at this point.
            connection.execute(
                """
                INSERT OR IGNORE INTO ingestion_artifact_pins (
                    artifact_kind, artifact_ref,
                    tenant_id, project_id, workspace_id,
                    owner_operation_id, created_at_ns
                )
                SELECT 'blob', blob_ref,
                       tenant_id, project_id, workspace_id,
                       admission_operation_id, updated_at_ns
                FROM ingestion_imports
                WHERE catalog_fixture_admitted = 1
                  AND admission_operation_id IS NOT NULL
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO ingestion_artifact_pins (
                    artifact_kind, artifact_ref,
                    tenant_id, project_id, workspace_id,
                    owner_operation_id, created_at_ns
                )
                SELECT 'dataset', staged_dataset_ref,
                       tenant_id, project_id, workspace_id,
                       publication_operation_id, updated_at_ns
                FROM ingestion_imports
                WHERE state = ? AND staged_dataset_ref IS NOT NULL
                  AND publication_operation_id IS NOT NULL
                """,
                (ImportState.COMPLETED.value,),
            )
        connection.execute(
            """
            INSERT INTO ingestion_schema_migrations (
                migration_id, applied_at_ns
            ) VALUES (?, ?)
            """,
            (_ARTIFACT_PIN_BACKFILL_MIGRATION, self._now_ns()),
        )

    def _migrate_legacy_public_failures(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Move legacy free-form failures behind the private DB boundary."""

        import_rows = connection.execute(
            """
            SELECT import_id, state, attempt_count, error_code,
                   error_message, updated_at_ns
            FROM ingestion_imports
            WHERE error_code IS NOT NULL OR error_message IS NOT NULL
            """
        ).fetchall()
        for row in import_rows:
            raw_code = str(row["error_code"]) if row["error_code"] is not None else None
            raw_message = (
                str(row["error_message"]) if row["error_message"] is not None else None
            )
            is_failed = str(row["state"]) == ImportState.FAILED.value
            public_code = (
                _normalized_public_failure_code(raw_code) if is_failed else None
            )
            public_message = (
                PUBLIC_INGESTION_FAILURE_MESSAGES[public_code]
                if public_code is not None
                else None
            )
            if raw_code != public_code or raw_message != public_message:
                diagnostic_text = canonical_json(
                    {
                        "legacy_error_code": raw_code,
                        "legacy_error_message": raw_message,
                    }
                )
                self._insert_failure_diagnostic(
                    connection,
                    import_id=str(row["import_id"]),
                    attempt_number=max(0, int(row["attempt_count"])),
                    stage="legacy",
                    public_error_code=public_code or "worker_failure",
                    exception_type="LegacyPublicFailure",
                    exception_message=diagnostic_text,
                    source_kind="legacy_import",
                    source_id="public-row-v1",
                    created_at_ns=int(row["updated_at_ns"]),
                )
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET error_code = ?, error_message = ?
                    WHERE import_id = ?
                    """,
                    (public_code, public_message, row["import_id"]),
                )

        event_rows = connection.execute(
            """
            SELECT events.sequence, events.import_id, events.message,
                   events.payload_json, events.created_at_ns,
                   imports.attempt_count, imports.error_code
            FROM ingestion_events AS events
            JOIN ingestion_imports AS imports
              ON imports.import_id = events.import_id
            WHERE events.event_type = 'import_failed'
            """
        ).fetchall()
        for row in event_rows:
            raw_payload_text = str(row["payload_json"])
            try:
                raw_payload = json.loads(raw_payload_text)
            except json.JSONDecodeError:
                raw_payload = None
            payload_code = (
                raw_payload.get("error_code") if isinstance(raw_payload, dict) else None
            )
            public_code = _normalized_public_failure_code(
                payload_code
                if isinstance(payload_code, str)
                else (str(row["error_code"]) if row["error_code"] is not None else None)
            )
            public_message = PUBLIC_INGESTION_FAILURE_MESSAGES[public_code]
            public_payload = canonical_json({"error_code": public_code})
            raw_message = str(row["message"])
            if raw_message == public_message and raw_payload_text == public_payload:
                continue
            self._insert_failure_diagnostic(
                connection,
                import_id=str(row["import_id"]),
                attempt_number=max(0, int(row["attempt_count"])),
                stage="legacy",
                public_error_code=public_code,
                exception_type="LegacyPublicFailureEvent",
                exception_message=canonical_json(
                    {
                        "legacy_event_message": raw_message,
                        "legacy_event_payload": raw_payload_text,
                    }
                ),
                source_kind="legacy_event",
                source_id=str(row["sequence"]),
                created_at_ns=int(row["created_at_ns"]),
            )
            connection.execute(
                """
                UPDATE ingestion_events
                SET message = ?, payload_json = ?
                WHERE sequence = ?
                """,
                (public_message, public_payload, row["sequence"]),
            )

    @staticmethod
    def _insert_failure_diagnostic(
        connection: sqlite3.Connection,
        *,
        import_id: str,
        attempt_number: int,
        stage: str,
        public_error_code: str,
        exception_type: str,
        exception_message: str,
        source_kind: str,
        source_id: str,
        created_at_ns: int,
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO ingestion_failure_diagnostics (
                import_id, attempt_number, stage, public_error_code,
                exception_type, exception_message, source_kind,
                source_id, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                attempt_number,
                stage,
                public_error_code,
                _truncate_text(
                    exception_type,
                    maximum=MAX_PRIVATE_FAILURE_TYPE_LENGTH,
                ),
                _truncate_text(
                    exception_message,
                    maximum=MAX_PRIVATE_FAILURE_MESSAGE_LENGTH,
                ),
                source_kind,
                source_id,
                created_at_ns,
            ),
        )

    @staticmethod
    def _now_ns() -> int:
        return time.time_ns()

    @staticmethod
    def _scope_predicate(scope: ImportScope) -> tuple[str, str, str]:
        return (scope.tenant_id, scope.project_id, scope.workspace_id)

    def _enforce_admission_quotas(
        self,
        connection: sqlite3.Connection,
        scope: ImportScope,
        *,
        incoming_bytes: int,
    ) -> None:
        """Apply logical tenant/workspace quotas in the caller transaction."""

        policy = self.retention_policy
        tenant = connection.execute(
            """
            SELECT COUNT(*) AS import_count,
                   COALESCE(SUM(byte_count), 0) AS stored_bytes
            FROM ingestion_imports WHERE tenant_id = ?
            """,
            (scope.tenant_id,),
        ).fetchone()
        workspace = connection.execute(
            """
            SELECT COUNT(*) AS import_count,
                   COALESCE(SUM(byte_count), 0) AS stored_bytes
            FROM ingestion_imports
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
            """,
            self._scope_predicate(scope),
        ).fetchone()
        assert tenant is not None and workspace is not None
        checks = (
            (
                "tenant import-row",
                int(tenant["import_count"]) + 1,
                policy.max_tenant_imports,
            ),
            (
                "workspace import-row",
                int(workspace["import_count"]) + 1,
                policy.max_workspace_imports,
            ),
            (
                "tenant byte",
                int(tenant["stored_bytes"]) + incoming_bytes,
                policy.max_tenant_bytes,
            ),
            (
                "workspace byte",
                int(workspace["stored_bytes"]) + incoming_bytes,
                policy.max_workspace_bytes,
            ),
        )
        for label, proposed, maximum in checks:
            if maximum is not None and proposed > maximum:
                raise ImportQuotaExceededError(
                    f"{label} quota exceeded ({proposed} > {maximum})"
                )

    def _recover_expired_jobs(self) -> None:
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_expired_jobs_locked(connection, now=now)
            connection.commit()

    def _recover_expired_jobs_locked(
        self,
        connection: sqlite3.Connection,
        *,
        now: int,
    ) -> int:
        """Recover expired work inside the caller's immediate transaction."""

        rows = connection.execute(
            """
            SELECT import_id, state
            FROM ingestion_imports
            WHERE state IN (?, ?, ?, ?)
              AND lease_owner IS NOT NULL
              AND (lease_expires_ns IS NULL OR lease_expires_ns < ?)
            ORDER BY created_at_ns, import_id
            """,
            (
                ImportState.ADMITTING.value,
                ImportState.PROBING.value,
                ImportState.INGESTING.value,
                ImportState.PUBLISHING.value,
                now,
            ),
        ).fetchall()
        for row in rows:
            recovered = {
                ImportState.ADMITTING.value: ImportState.ADMITTING,
                ImportState.PROBING.value: ImportState.QUEUED,
                ImportState.INGESTING.value: ImportState.READY,
                ImportState.PUBLISHING.value: ImportState.PUBLISHING,
            }[str(row["state"])]
            updated = connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ? AND state = ?
                  AND lease_owner IS NOT NULL
                  AND (lease_expires_ns IS NULL OR lease_expires_ns < ?)
                """,
                (
                    recovered.value,
                    now,
                    row["import_id"],
                    row["state"],
                    now,
                ),
            ).rowcount
            if updated != 1:
                continue
            self._append_event(
                connection,
                str(row["import_id"]),
                recovered,
                "job_recovered",
                "Recovered an expired in-progress queue lease.",
                {},
                now=now,
            )
        return len(rows)

    def _renew_lease(
        self,
        import_id: str,
        state: ImportState,
        lease_token: str,
    ) -> bool:
        now = self._now_ns()
        lease_expires = now + self.limits.lease_seconds * 1_000_000_000
        with self._connect() as connection:
            updated = connection.execute(
                """
                UPDATE ingestion_imports
                SET lease_expires_ns = ?
                WHERE import_id = ? AND state = ? AND lease_owner = ?
                """,
                (
                    lease_expires,
                    import_id,
                    state.value,
                    lease_token,
                ),
            ).rowcount
        return updated == 1

    @contextmanager
    def _lease_heartbeat(
        self,
        row: sqlite3.Row,
    ) -> Iterator[None]:
        import_id = str(row["import_id"])
        state = ImportState(str(row["state"]))
        lease_token = str(row["lease_owner"])
        stopped = threading.Event()
        interval = max(
            0.25,
            min(5.0, self.limits.lease_seconds / 3),
        )

        def heartbeat() -> None:
            while not stopped.wait(interval):
                try:
                    if not self._renew_lease(
                        import_id,
                        state,
                        lease_token,
                    ):
                        return
                except sqlite3.Error:
                    # A transient busy/IO error must not terminate renewal
                    # permanently. Ownership checks at publication still
                    # prevent stale workers from committing results.
                    continue

        thread = threading.Thread(
            target=heartbeat,
            name=f"router-dump-lease-{import_id}",
            daemon=True,
        )
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join(timeout=max(1.0, interval + 0.5))

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._stop.clear()
            self._threads = [
                threading.Thread(
                    target=self._worker_entrypoint,
                    name=f"router-dump-ingestion-{index + 1}",
                    daemon=True,
                )
                for index in range(self.limits.max_workers)
            ]
            self._started = True
            for thread in self._threads:
                thread.start()
            self._wake.set()

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            if not self._started:
                return
            threads = tuple(self._threads)
            self._stop.set()
            self._wake.set()
        deadline = time.monotonic() + max(0.0, timeout)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        alive = [thread for thread in threads if thread.is_alive()]
        with self._lock:
            self._threads = alive
            self._started = bool(alive)
        if alive:
            raise TimeoutError(
                f"{len(alive)} ingestion worker(s) did not stop before "
                "the close timeout"
            )

    def worker_health(self) -> WorkerHealthSnapshot:
        """Return observable coordination health without exposing internals."""

        queue_health = QueueHealthSnapshot(
            pending_imports=0,
            awaiting_selection_imports=0,
            stalled_imports=0,
            oldest_pending_updated_at_ns=None,
            stall_after_seconds=self.limits.stalled_import_seconds,
            evaluated_at_ns=self._now_ns(),
            state_counts=(),
            catalog_attention_imports=0,
        )
        queue_observation_error: str | None = None
        try:
            queue_health = inspect_durable_queue(
                self.database_path,
                stall_after_seconds=self.limits.stalled_import_seconds,
                now_ns=self._now_ns(),
            )
            queue_observation_error = queue_health.observation_error
        except Exception as error:  # noqa: BLE001 - health stays bounded/available.
            queue_observation_error = self._worker_error_label(error)

        with self._lock:
            return WorkerHealthSnapshot(
                started=self._started,
                live_workers=sum(thread.is_alive() for thread in self._threads),
                total_claim_errors=self._total_claim_errors,
                consecutive_claim_errors=self._consecutive_claim_errors,
                last_claim_error_at_ns=self._last_claim_error_at_ns,
                last_claim_error=self._last_claim_error,
                total_iteration_errors=self._total_iteration_errors,
                consecutive_iteration_errors=(self._consecutive_iteration_errors),
                last_iteration_error_at_ns=(self._last_iteration_error_at_ns),
                last_iteration_error=self._last_iteration_error,
                pending_imports=queue_health.pending_imports,
                awaiting_selection_imports=(queue_health.awaiting_selection_imports),
                stalled_imports=queue_health.stalled_imports,
                oldest_pending_updated_at_ns=(
                    queue_health.oldest_pending_updated_at_ns
                ),
                stall_after_seconds=queue_health.stall_after_seconds,
                queue_evaluated_at_ns=queue_health.evaluated_at_ns,
                state_counts=queue_health.state_counts,
                queue_observation_error=queue_observation_error,
                unexpected_worker_exits=self._unexpected_worker_exits,
                last_worker_exit_at_ns=self._last_worker_exit_at_ns,
                last_worker_exit=self._last_worker_exit,
                catalog_attention_imports=(queue_health.catalog_attention_imports),
            )

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    @staticmethod
    def _contained_path(
        root: Path,
        relative: Path,
        *,
        label: str,
    ) -> Path:
        if relative.is_absolute() or not relative.parts:
            raise IngestionPipelineError(f"{label} must be a relative path")
        resolved_root = root.resolve()
        candidate = (resolved_root / relative).resolve(strict=False)
        try:
            root_comparison = _path_for_containment_comparison(resolved_root)
            candidate_comparison = _path_for_containment_comparison(candidate)
            common = os.path.commonpath((root_comparison, candidate_comparison))
        except (OSError, ValueError) as error:
            raise IngestionPipelineError(
                f"{label} escapes its configured storage root"
            ) from error
        if common != root_comparison:
            raise IngestionPipelineError(f"{label} escapes its configured storage root")
        if candidate_comparison == root_comparison:
            raise IngestionPipelineError(
                f"{label} must identify a file below its storage root"
            )
        return candidate

    @staticmethod
    def _verify_content_file(
        path: Path,
        *,
        expected_sha256: str,
        expected_bytes: int,
    ) -> None:
        if path.is_symlink() or not path.is_file():
            raise IngestionPipelineError(
                "content-addressed object is not a regular file"
            )
        if path.stat().st_size != expected_bytes:
            raise IngestionPipelineError(
                "content-addressed object has a conflicting byte count"
            )
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        if digest.hexdigest() != expected_sha256:
            raise IngestionPipelineError(
                "content-addressed object failed digest verification"
            )

    @staticmethod
    def _verified_dataset_ingestion_envelope(
        path: Path,
        *,
        expected_sha256: str,
    ) -> dict[str, Any]:
        """Verify staged bytes and read the bounded canonical ingestion envelope."""

        if len(expected_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_sha256
        ):
            raise IngestionPipelineError("staged dataset digest is invalid")
        if path.is_symlink() or not path.is_file():
            raise IngestionPipelineError("staged dataset is not a regular file")
        digest = hashlib.sha256()
        prefix = bytearray()
        try:
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
                    remaining = _MAX_STAGED_INGESTION_ENVELOPE_BYTES - len(prefix)
                    if remaining > 0:
                        prefix.extend(block[:remaining])
        except OSError as error:
            raise IngestionPipelineError(
                "staged dataset could not be verified"
            ) from error
        if digest.hexdigest() != expected_sha256:
            raise IngestionPipelineError("staged dataset failed digest verification")
        try:
            document_prefix = bytes(prefix).decode("utf-8")
            envelope_prefix = '{"_ingestion":'
            if not document_prefix.startswith(envelope_prefix):
                raise ValueError("canonical ingestion envelope is not first")
            ingestion, _ = json.JSONDecoder().raw_decode(
                document_prefix[len(envelope_prefix) :]
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise IngestionPipelineError(
                "staged dataset has an invalid or oversized ingestion envelope"
            ) from error
        if not isinstance(ingestion, dict):
            raise IngestionPipelineError("staged dataset ingestion envelope is invalid")
        return ingestion

    @classmethod
    def _verified_dataset_execution_plan_digest(
        cls,
        path: Path,
        *,
        expected_sha256: str,
    ) -> str | None:
        ingestion = cls._verified_dataset_ingestion_envelope(
            path,
            expected_sha256=expected_sha256,
        )
        value = ingestion.get("plugin_execution_plan_digest")
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in value[7:])
        ):
            raise IngestionPipelineError(
                "staged dataset execution-plan digest is invalid"
            )
        return value

    @classmethod
    def _validate_staged_timeline_binding(
        cls,
        path: Path,
        *,
        staged: _StagedChildIngestion,
        registered: RegisteredPlugin,
    ) -> None:
        """Attest child-emitted clock semantics against the frozen manifest."""

        ingestion = cls._verified_dataset_ingestion_envelope(
            path,
            expected_sha256=staged.dataset_sha256,
        )
        if (
            ingestion.get("plugin_execution_plan_digest")
            != staged.execution_plan.plan_digest
        ):
            raise IngestionPipelineError(
                "staged dataset execution-plan digest does not match child metadata"
            )
        if (
            ingestion.get("timeline_time_basis") != registered.timeline_time_basis
            or ingestion.get("timeline_clock_domain")
            != registered.timeline_clock_domain
        ):
            raise IngestionPipelineError(
                "staged dataset timeline declaration does not match the registered "
                "plug-in manifest"
            )
        try:
            from .private_analysis_revision_evidence import (
                validate_private_analysis_timeline_metadata,
            )

            validate_private_analysis_timeline_metadata({"_ingestion": ingestion})
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise IngestionPipelineError(
                "staged dataset timeline metadata is invalid"
            ) from error

    @staticmethod
    def _content_file_identity(
        path: Path,
    ) -> tuple[int, int, int, int, int, int]:
        """Return a cheap identity used after an out-of-lock verification."""

        details = path.lstat()
        return (
            details.st_dev,
            details.st_ino,
            details.st_mode,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )

    def _content_lock_coordinates(
        self,
        root: Path,
        digest: str,
    ) -> tuple[Path, Path]:
        """Return stable namespace and per-address locks outside data shards."""

        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise IngestionPipelineError("content digest is not canonical")
        resolved_root = root.resolve()
        blob_root = getattr(self, "blob_root", None)
        dataset_root = getattr(self, "dataset_root", None)
        if blob_root is not None and resolved_root == blob_root.resolve():
            kind = "blob"
        elif (
            dataset_root is not None and resolved_root == dataset_root.resolve()
        ) or root.name == "revisions":
            kind = "dataset"
        elif blob_root is None and dataset_root is None:
            # Private low-level embeddings that construct only the content
            # installer retain a deterministic lock namespace beside their
            # supplied root. Production instances always take the branches
            # above.
            kind = "blob"
        else:
            raise IngestionPipelineError("unsupported content storage root")
        base = getattr(
            self,
            "content_lock_root",
            resolved_root.parent / "locks" / "content",
        )
        shard = digest[:2]
        return (
            base / kind / f"{shard}.gate.lock",
            base / kind / shard / f"{digest}.install.lock",
        )

    def _content_shard_gate(
        self,
        root_name: str,
        path: Path,
    ) -> tuple[Path, Path]:
        root = self.blob_root if root_name == "blob" else self.dataset_root
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise IngestionPipelineError("content shard escapes its root") from error
        if root_name not in {"blob", "dataset"} or not relative.parts:
            raise IngestionPipelineError("content shard root is invalid")
        first = relative.parts[0]
        if (
            len(first) != 2
            or first != first.lower()
            or any(character not in "0123456789abcdef" for character in first)
        ):
            raise IngestionPipelineError("content shard is not canonical")
        return root, self.content_lock_root / root_name / f"{first}.gate.lock"

    def _content_cleanup_gate(self, root_name: str, path: Path) -> Path:
        root = self.blob_root if root_name == "blob" else self.dataset_root
        try:
            first = path.relative_to(root).parts[0]
        except (ValueError, IndexError) as error:
            raise IngestionPipelineError(
                "content cleanup path escapes its root"
            ) from error
        if (
            len(first) == 2
            and first == first.lower()
            and all(character in "0123456789abcdef" for character in first)
        ):
            return self.content_lock_root / root_name / f"{first}.gate.lock"
        return self.content_lock_root / root_name / "namespace.gate.lock"

    @staticmethod
    def _canonical_shard_relative(relative: str) -> bool:
        parts = PurePosixPath(relative).parts
        return 1 <= len(parts) <= 2 and all(
            len(part) == 2
            and part == part.lower()
            and all(character in "0123456789abcdef" for character in part)
            for part in parts
        )

    @contextmanager
    def _spool_active_file_lock(self, lock_path: Path) -> Iterator[None]:
        """Hold and retire one dynamic spool lock under a stable gate."""

        child_context: Any | None = None
        while child_context is None:
            # Never wait for the dynamic child while holding the namespace
            # gate.  Its current owner needs that gate to close and unlink the
            # child atomically; blocking here would deadlock the hand-off.
            with exclusive_file_lock(self._spool_namespace_lock_path):
                if lock_path.exists():
                    existing_candidate = try_existing_exclusive_file_lock(lock_path)
                    if existing_candidate.__enter__():
                        child_context = existing_candidate
                    else:
                        existing_candidate.__exit__(None, None, None)
                else:
                    new_candidate = exclusive_file_lock(lock_path)
                    new_candidate.__enter__()
                    child_context = new_candidate
            if child_context is None:
                time.sleep(0.001)
        try:
            yield
        finally:
            with exclusive_file_lock(self._spool_namespace_lock_path):
                assert child_context is not None
                child_context.__exit__(None, None, None)
                lock_path.unlink(missing_ok=True)

    @staticmethod
    def _prune_empty_content_shards(root: Path, leaf_parent: Path) -> int:
        """Remove only exact empty two-level lowercase-hex shard ancestors."""

        removed = 0
        resolved_root = root.resolve()
        candidates = (leaf_parent, leaf_parent.parent)
        for expected_depth, directory in ((2, candidates[0]), (1, candidates[1])):
            try:
                relative = directory.relative_to(resolved_root)
            except ValueError:
                break
            if (
                len(relative.parts) != expected_depth
                or any(
                    len(part) != 2
                    or part != part.lower()
                    or any(character not in "0123456789abcdef" for character in part)
                    for part in relative.parts
                )
                or directory.is_symlink()
            ):
                break
            try:
                directory.rmdir()
            except FileNotFoundError:
                continue
            except OSError as error:
                if error.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                    break
                raise
            else:
                removed += 1
                _fsync_directory(directory.parent)
        return removed

    def _prepare_content_file(
        self,
        temporary: Path,
        *,
        root: Path,
        relative: Path,
        expected_sha256: str,
        expected_bytes: int,
    ) -> _PreparedContentFile:
        """Verify and stage content without holding the maintenance lock.

        A private candidate is always prepared.  That keeps final publication
        bounded to identity checks and atomic renames even when retention or
        another publisher changes the digest address after this preparation.
        """

        target = self._contained_path(
            root,
            relative,
            label="content-addressed reference",
        )
        shard_gate, install_lock = self._content_lock_coordinates(
            root,
            expected_sha256,
        )
        observed_target_identity: tuple[int, int, int, int, int, int] | None = None
        observed_target_valid = False
        candidate_token = uuid4().hex
        candidate = target.with_name(f".{target.name}.{candidate_token}.partial")
        # A private staging candidate can outlive the shard gate while a large
        # fallback copy is in progress.  Hold a candidate-specific advisory
        # lock in the stable external lock namespace for the complete
        # prepare/publish lifetime.  Retention can then distinguish a crashed
        # writer (OS lock released) from a slow live writer without trusting
        # age alone or pinning the data shard with another lock file.
        activity_lock = (
            shard_gate.parent
            / "staging"
            / self._content_staging_activity_lock_name(
                shard_gate.parent.name,
                expected_sha256,
                candidate_token,
            )
        )
        activity_lock_stack = ExitStack()
        try:
            self._verify_content_file(
                temporary,
                expected_sha256=expected_sha256,
                expected_bytes=expected_bytes,
            )
            copied_candidate = False
            with exclusive_file_lock(shard_gate):
                activity_lock_stack.enter_context(exclusive_file_lock(activity_lock))
                target.parent.mkdir(parents=True, exist_ok=True)
                target = self._contained_path(
                    root,
                    relative,
                    label="content-addressed reference",
                )
                with exclusive_file_lock(install_lock):
                    if target.exists() or target.is_symlink():
                        try:
                            self._verify_content_file(
                                target,
                                expected_sha256=expected_sha256,
                                expected_bytes=expected_bytes,
                            )
                        except IngestionPipelineError:
                            observed_target_identity = self._content_file_identity(
                                target
                            )
                        else:
                            observed_target_identity = self._content_file_identity(
                                target
                            )
                            observed_target_valid = True
                try:
                    os.link(temporary, candidate)
                except OSError:
                    # Reserve the pathname while the shard gate is held. The
                    # empty candidate keeps the directory non-empty while the
                    # potentially large fallback copy happens outside it.
                    with candidate.open("xb"):
                        pass
                    copied_candidate = True
            if copied_candidate:
                # Some Windows policies and filesystems disable hard links.
                # Copy only to the private candidate, never to the final name.
                with (
                    temporary.open("rb") as source,
                    candidate.open("r+b") as output,
                ):
                    output.truncate(0)
                    shutil.copyfileobj(
                        source,
                        output,
                        length=self.limits.upload_chunk_bytes,
                    )
                    output.flush()
                    os.fsync(output.fileno())
            # A hard link references the already-verified upload inode.  A
            # copied candidate must be verified independently before it can be
            # made reachable at the digest address.
            if copied_candidate:
                self._verify_content_file(
                    candidate,
                    expected_sha256=expected_sha256,
                    expected_bytes=expected_bytes,
                )
        except BaseException:
            # Close and retire the dynamic activity lock under the same stable
            # namespace gate used by the janitor.  This preserves one POSIX
            # inode lock domain across close/unlink and prevents a Windows
            # opener from racing the retirement.
            with exclusive_file_lock(shard_gate):
                candidate.unlink(missing_ok=True)
                activity_lock_stack.close()
                activity_lock.unlink(missing_ok=True)
                self._prune_empty_content_shards(root, target.parent)
            raise
        return _PreparedContentFile(
            target=target,
            candidate=candidate,
            content_root=root,
            install_lock=install_lock,
            shard_gate=shard_gate,
            activity_lock=activity_lock,
            activity_lock_stack=activity_lock_stack,
            expected_sha256=expected_sha256,
            expected_bytes=expected_bytes,
            observed_target_identity=observed_target_identity,
            observed_target_valid=observed_target_valid,
        )

    def _publish_prepared_content_file(
        self,
        prepared: _PreparedContentFile,
    ) -> Path:
        """Atomically publish a verified candidate inside the global lock.

        No bytes are hashed or copied here. An unchanged, previously verified
        target is reused. An unchanged invalid target is quarantined. A target
        changed by a concurrent writer is atomically replaced by this caller's
        own verified candidate, avoiding any trust based only on file size.
        """

        target = prepared.target
        with exclusive_file_lock(prepared.shard_gate):
            target.parent.mkdir(parents=True, exist_ok=True)
            with exclusive_file_lock(prepared.install_lock):
                target_exists = target.exists() or target.is_symlink()
                if target_exists:
                    current_identity = self._content_file_identity(target)
                    if (
                        prepared.observed_target_valid
                        and current_identity == prepared.observed_target_identity
                    ):
                        return target
                    if current_identity == prepared.observed_target_identity:
                        quarantine = target.with_name(
                            f".{target.name}.corrupt-{uuid4().hex}"
                        )
                        os.replace(target, quarantine)
                        _fsync_directory(target.parent)

                os.replace(prepared.candidate, target)
                _fsync_directory(target.parent)
                return target

    def _discard_prepared_content_file(
        self,
        prepared: _PreparedContentFile | None,
    ) -> None:
        if prepared is not None:
            with exclusive_file_lock(prepared.shard_gate):
                prepared.candidate.unlink(missing_ok=True)
                prepared.activity_lock_stack.close()
                prepared.activity_lock.unlink(missing_ok=True)
                self._prune_empty_content_shards(
                    prepared.content_root,
                    prepared.target.parent,
                )

    def _install_content_file(
        self,
        temporary: Path,
        *,
        root: Path,
        relative: Path,
        expected_sha256: str,
        expected_bytes: int,
    ) -> Path:
        """Verify, stage, and atomically publish one repairable object.

        Queue admission uses the two explicit prepare/publish methods so its
        host-global lock covers only publication and catalog references. This
        wrapper preserves the independently useful per-address operation.
        """

        prepared: _PreparedContentFile | None = None
        try:
            prepared = self._prepare_content_file(
                temporary,
                root=root,
                relative=relative,
                expected_sha256=expected_sha256,
                expected_bytes=expected_bytes,
            )
            return self._publish_prepared_content_file(prepared)
        finally:
            self._discard_prepared_content_file(prepared)

    def _prepare_fixture_view(
        self,
        source_path: Path,
        *,
        fixture_id: str,
        safe_name: str,
    ) -> _PreparedFixtureView:
        """Build a complete private fixture view outside the global lock."""

        fixture_relative = Path(fixture_id)
        fixture_directory = self._contained_path(
            self.fixture_root,
            fixture_relative,
            label="fixture reference",
        )
        staging_relative = Path(f".{fixture_id}.{uuid4().hex}.partial")
        staging_directory = self._contained_path(
            self.fixture_root,
            staging_relative,
            label="fixture staging reference",
        )
        staging_directory.mkdir(parents=True, exist_ok=False)
        try:
            staging_input = staging_directory / safe_name
            try:
                os.link(source_path, staging_input)
            except OSError:
                with (
                    source_path.open("rb") as source,
                    staging_input.open("xb") as output,
                ):
                    shutil.copyfileobj(
                        source,
                        output,
                        length=self.limits.upload_chunk_bytes,
                    )
                    output.flush()
                    os.fsync(output.fileno())
            _fsync_directory(staging_directory)
        except BaseException:
            self._remove_fixture_view(staging_directory)
            raise
        return _PreparedFixtureView(
            fixture_directory=fixture_directory,
            staging_directory=staging_directory,
            input_relative=fixture_relative / safe_name,
        )

    def _validate_fixture_basename_path_budget(self, safe_name: str) -> None:
        """Reject a Windows fixture basename before creating upload artifacts."""

        if os.name != "nt":
            return
        maximum_units = (
            WINDOWS_MAX_USABLE_PATH_UNITS
            - _windows_path_units(self.root)
            - WINDOWS_FIXTURE_STAGING_PREFIX_RESERVE_UNITS
        )
        actual_units = _windows_path_units(safe_name)
        if actual_units > maximum_units:
            raise IngestionPipelineError(
                "upload basename is too long for the configured Windows state "
                f"directory: length {actual_units} UTF-16 code units exceeds "
                f"the supported maximum of {maximum_units}; choose a shorter "
                "filename or --state-dir"
            )

    def _publish_prepared_fixture_view(
        self,
        prepared: _PreparedFixtureView,
    ) -> tuple[Path, Path]:
        """Atomically expose a prepared fixture inside the global lock."""

        if (
            prepared.fixture_directory.exists()
            or prepared.fixture_directory.is_symlink()
        ):
            raise IngestionPipelineError(
                "fixture identifier already has a materialized view"
            )
        os.replace(
            prepared.staging_directory,
            prepared.fixture_directory,
        )
        _fsync_directory(self.fixture_root)
        return prepared.fixture_directory, prepared.input_relative

    def _discard_prepared_fixture_view(
        self,
        prepared: _PreparedFixtureView | None,
    ) -> None:
        if prepared is not None:
            self._remove_fixture_view(prepared.staging_directory)

    @staticmethod
    def _validate_idempotent_upload(
        existing: sqlite3.Row,
        *,
        content_sha256: str,
        original_name: str,
        content_type: str,
        node_hint: str | None,
        metadata_json: str,
        auto_select: bool,
        preferred_plugin_id: str | None,
    ) -> None:
        if (
            existing["content_sha256"] != content_sha256
            or existing["original_name"] != original_name
            or existing["content_type"] != content_type
            or existing["node_hint"] != node_hint
            or existing["metadata_json"] != metadata_json
            or bool(existing["auto_select"]) != auto_select
            or existing["preferred_plugin_id"] != preferred_plugin_id
        ):
            raise ImportConflictError(
                "idempotency key was already used for a different import request"
            )

    @staticmethod
    def _remove_fixture_view(directory: Path | None) -> None:
        if directory is not None and directory.exists():
            shutil.rmtree(directory)

    def submit_bytes(
        self,
        scope: ImportScope,
        content: bytes,
        *,
        original_name: str,
        content_type: str = "application/octet-stream",
        idempotency_key: str | None = None,
        auto_select: bool = True,
        preferred_plugin_id: str | None = None,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ImportDescriptor:
        return self.submit_chunks(
            scope,
            (content,),
            original_name=original_name,
            content_type=content_type,
            idempotency_key=idempotency_key,
            auto_select=auto_select,
            preferred_plugin_id=preferred_plugin_id,
            node_hint=node_hint,
            metadata=metadata,
        )

    def submit_chunks(
        self,
        scope: ImportScope,
        chunks: Iterable[bytes],
        *,
        original_name: str,
        content_type: str = "application/octet-stream",
        idempotency_key: str | None = None,
        auto_select: bool = True,
        preferred_plugin_id: str | None = None,
        node_hint: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ImportDescriptor:
        original_name = _bounded_text(
            original_name,
            "original_name",
            MAX_FILENAME_LENGTH,
        )
        content_type = _bounded_text(
            content_type or "application/octet-stream",
            "content_type",
            MAX_CONTENT_TYPE_LENGTH,
        )
        if idempotency_key is not None:
            idempotency_key = _bounded_text(
                idempotency_key,
                "idempotency_key",
                MAX_IDEMPOTENCY_KEY_LENGTH,
            )
        if preferred_plugin_id is not None:
            _bounded_identifier(
                preferred_plugin_id,
                "preferred_plugin_id",
            )
        if not isinstance(auto_select, bool):
            raise TypeError("auto_select must be a boolean")
        if node_hint is not None:
            node_hint = validate_execution_identity(
                node_hint,
                "node_hint",
                maximum=MAX_NODE_HINT_LENGTH,
            )
        metadata_json = _import_metadata_json(metadata)

        safe_name = Path(original_name.replace("\\", "/")).name
        if safe_name in {"", ".", ".."}:
            safe_name = "upload.bin"
        # An exact idempotent replay never creates another fixture view. Allow
        # it to survive relocation of an existing state tree to a longer (but
        # still supported) root; the request-sensitive check after hashing
        # below will still reject any semantic mismatch. New keys validate
        # before even a private spool file is created.
        defer_fixture_basename_validation = False
        if idempotency_key is not None:
            with self._connect() as connection:
                defer_fixture_basename_validation = (
                    connection.execute(
                        """
                        SELECT 1 FROM ingestion_imports
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND idempotency_key = ?
                        """,
                        (*self._scope_predicate(scope), idempotency_key),
                    ).fetchone()
                    is not None
                )
        if not defer_fixture_basename_validation:
            self._validate_fixture_basename_path_budget(safe_name)

        temporary = self.spool_root / f"{uuid4().hex}.partial"
        temporary_lock = temporary.with_name(f".{temporary.name}.active.lock")
        digest = hashlib.sha256()
        byte_count = 0
        fixture_directory: Path | None = None
        prepared_content: _PreparedContentFile | None = None
        prepared_fixture: _PreparedFixtureView | None = None
        replayed_row: sqlite3.Row | None = None
        operation_stack = ExitStack()
        try:
            operation_stack.enter_context(self._spool_active_file_lock(temporary_lock))
            with temporary.open("xb") as stream:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise TypeError("upload chunks must be bytes")
                    if not chunk:
                        continue
                    byte_count += len(chunk)
                    if byte_count > self.limits.max_upload_bytes:
                        raise IngestionPipelineError(
                            "upload exceeds the configured byte limit"
                        )
                    digest.update(chunk)
                    stream.write(chunk)
                if byte_count == 0:
                    raise IngestionPipelineError("upload must not be empty")
                stream.flush()
                os.fsync(stream.fileno())
            content_sha256 = digest.hexdigest()
            blob_relative = (
                Path(content_sha256[:2]) / content_sha256[2:4] / content_sha256
            )

            # Fast idempotent replays avoid building a throwaway fixture view.
            # The same check is repeated in the write transaction to close the
            # race with another process admitting the request concurrently.
            if idempotency_key is not None:
                with self._connect() as connection:
                    existing = connection.execute(
                        """
                        SELECT *
                        FROM ingestion_imports
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND idempotency_key = ?
                        """,
                        (
                            *self._scope_predicate(scope),
                            idempotency_key,
                        ),
                    ).fetchone()
                if existing is not None:
                    self._validate_idempotent_upload(
                        existing,
                        content_sha256=content_sha256,
                        original_name=original_name,
                        content_type=content_type,
                        node_hint=node_hint,
                        metadata_json=metadata_json,
                        auto_select=auto_select,
                        preferred_plugin_id=preferred_plugin_id,
                    )
                    return self._descriptor(existing)
                # A stale/out-of-band preliminary observation must never let a
                # genuinely new fixture bypass the pathname budget.
                if defer_fixture_basename_validation:
                    self._validate_fixture_basename_path_budget(safe_name)

            # Fail obvious quota exhaustion before publishing filesystem
            # artifacts.  The check is repeated under BEGIN IMMEDIATE below.
            with self._connect() as connection:
                self._enforce_admission_quotas(
                    connection,
                    scope,
                    incoming_bytes=byte_count,
                )

            import_id = f"import-{uuid4().hex}"
            fixture_id = f"fixture-{uuid4().hex}"
            admission_operation_id = f"admission:{import_id}"
            # Hashing, copy fallback, and fixture construction can scale with
            # upload size. Complete all of them while the host-global
            # maintenance lock remains available to unrelated workspaces.
            prepared_content = self._prepare_content_file(
                temporary,
                root=self.blob_root,
                relative=blob_relative,
                expected_sha256=content_sha256,
                expected_bytes=byte_count,
            )
            prepared_fixture = self._prepare_fixture_view(
                temporary,
                fixture_id=fixture_id,
                safe_name=safe_name,
            )

            # Retention can delete an unreferenced final object, so expose the
            # prepared paths and commit their catalog references as one short
            # host-global critical section.
            with exclusive_file_lock(self._maintenance_lock_path):
                self._publish_prepared_content_file(prepared_content)
                fixture_directory, input_relative = self._publish_prepared_fixture_view(
                    prepared_fixture
                )
                now = self._now_ns()
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        if idempotency_key is not None:
                            existing = connection.execute(
                                """
                                SELECT *
                                FROM ingestion_imports
                                WHERE tenant_id = ? AND project_id = ?
                                  AND workspace_id = ? AND idempotency_key = ?
                                """,
                                (
                                    *self._scope_predicate(scope),
                                    idempotency_key,
                                ),
                            ).fetchone()
                            if existing is not None:
                                self._validate_idempotent_upload(
                                    existing,
                                    content_sha256=content_sha256,
                                    original_name=original_name,
                                    content_type=content_type,
                                    node_hint=node_hint,
                                    metadata_json=metadata_json,
                                    auto_select=auto_select,
                                    preferred_plugin_id=preferred_plugin_id,
                                )
                                connection.rollback()
                                replayed_row = existing

                        if replayed_row is None:
                            self._enforce_admission_quotas(
                                connection,
                                scope,
                                incoming_bytes=byte_count,
                            )
                            active_count = int(
                                connection.execute(
                                    """
                                    SELECT COUNT(*)
                                    FROM ingestion_imports
                                    WHERE tenant_id = ? AND project_id = ?
                                      AND workspace_id = ?
                                      AND state NOT IN (?, ?, ?)
                                    """,
                                    (
                                        *self._scope_predicate(scope),
                                        ImportState.COMPLETED.value,
                                        ImportState.FAILED.value,
                                        ImportState.CANCELLED.value,
                                    ),
                                ).fetchone()[0]
                            )
                            if (
                                active_count
                                >= self.limits.max_active_imports_per_workspace
                            ):
                                raise ImportConflictError(
                                    "workspace active import limit reached "
                                    f"({self.limits.max_active_imports_per_workspace})"
                                )

                            connection.execute(
                                """
                                INSERT INTO ingestion_imports (
                                    import_id, tenant_id, project_id,
                                    workspace_id, fixture_id, state, version,
                                    original_name, content_type, node_hint,
                                    metadata_json, byte_count, content_sha256,
                                    blob_ref, input_ref,
                                    composition_policy_digest,
                                    admission_operation_id,
                                    catalog_fixture_admitted, attempt_count,
                                    auto_select, preferred_plugin_id,
                                    idempotency_key, created_at_ns,
                                    updated_at_ns, execution_plan_required
                                ) VALUES (
                                    ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?,
                                    ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, 1
                                )
                                """,
                                (
                                    import_id,
                                    scope.tenant_id,
                                    scope.project_id,
                                    scope.workspace_id,
                                    fixture_id,
                                    ImportState.ADMITTING.value,
                                    original_name,
                                    content_type,
                                    node_hint,
                                    metadata_json,
                                    byte_count,
                                    content_sha256,
                                    blob_relative.as_posix(),
                                    input_relative.as_posix(),
                                    self.composition_policy.policy_digest,
                                    admission_operation_id,
                                    int(auto_select),
                                    preferred_plugin_id,
                                    idempotency_key,
                                    now,
                                    now,
                                ),
                            )
                            self._append_event(
                                connection,
                                import_id,
                                ImportState.ADMITTING,
                                "upload_staged",
                                "Upload stored and staged for catalog admission.",
                                {
                                    "operation_id": admission_operation_id,
                                    "byte_count": byte_count,
                                    "content_sha256": content_sha256,
                                    "node_hint": node_hint,
                                },
                                now=now,
                            )
                            admitted_row = connection.execute(
                                "SELECT * FROM ingestion_imports WHERE import_id = ?",
                                (import_id,),
                            ).fetchone()
                            assert admitted_row is not None
                            connection.commit()
                    except Exception:
                        connection.rollback()
                        raise

            if replayed_row is not None:
                self._remove_fixture_view(fixture_directory)
                fixture_directory = None
                return self._descriptor(replayed_row)
        except Exception:
            # A commit response can be lost after SQLite made the row durable.
            # Never remove a fixture view that a reconciled catalog row owns.
            fixture_is_referenced = False
            if fixture_directory is not None:
                try:
                    with self._connect() as connection:
                        fixture_is_referenced = (
                            connection.execute(
                                """
                                SELECT 1 FROM ingestion_imports
                                WHERE import_id = ? AND fixture_id = ?
                                """,
                                (import_id, fixture_id),
                            ).fetchone()
                            is not None
                        )
                except (NameError, sqlite3.Error):
                    # Preserve the view when catalog reconciliation itself is
                    # unavailable; a janitor can later prove it unreferenced.
                    fixture_is_referenced = True
            if not fixture_is_referenced:
                self._remove_fixture_view(fixture_directory)
            raise
        finally:
            self._discard_prepared_fixture_view(prepared_fixture)
            self._discard_prepared_content_file(prepared_content)
            temporary.unlink(missing_ok=True)
            operation_stack.close()
        self._wake.set()
        return self._descriptor(admitted_row)

    @staticmethod
    def _path_bytes(path: Path) -> int:
        try:
            if path.is_symlink() or path.is_file():
                return path.stat().st_size
            if path.is_dir():
                return sum(
                    item.stat().st_size
                    for item in path.rglob("*")
                    if item.is_file() and not item.is_symlink()
                )
        except OSError:
            return 0
        return 0

    @staticmethod
    def _count_child_rows(
        connection: sqlite3.Connection,
        table: str,
        import_ids: tuple[str, ...],
    ) -> int:
        if table not in {"ingestion_events", "ingestion_candidates"}:
            raise ValueError("unsupported retention child table")
        total = 0
        for offset in range(0, len(import_ids), 500):
            batch = import_ids[offset : offset + 500]
            placeholders = ",".join("?" for _item in batch)
            total += int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE import_id IN ({placeholders})",
                    batch,
                ).fetchone()[0]
            )
        return total

    def _host_retention_root(self, root_name: str) -> Path:
        roots = {
            "spool": self.spool_root,
            "blob": self.blob_root,
            "dataset": self.dataset_root,
            "fixture": self.fixture_root,
        }
        try:
            return roots[root_name]
        except KeyError as error:
            raise IngestionPipelineError(
                "stored host-retention cursor has an invalid root"
            ) from error

    @staticmethod
    def _validate_host_cursor(value: object) -> str:
        if not isinstance(value, str) or len(value) > MAX_HOST_RETENTION_CURSOR_LENGTH:
            raise IngestionPipelineError("stored host-retention cursor is invalid")
        if not value:
            return value
        relative = PurePosixPath(value)
        if (
            relative.is_absolute()
            or "\\" in value
            or any(part in {"", ".", ".."} or ":" in part for part in relative.parts)
        ):
            raise IngestionPipelineError("stored host-retention cursor is invalid")
        return value

    def _host_retention_cursors(self) -> dict[str, str]:
        cursors = {root_name: "" for root_name in HOST_RETENTION_ROOT_NAMES}
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT root_name, cursor FROM ingestion_host_retention_cursor"
            ).fetchall()
        for row in rows:
            root_name = str(row["root_name"])
            if root_name not in cursors:
                raise IngestionPipelineError(
                    "stored host-retention cursor has an invalid root"
                )
            cursors[root_name] = self._validate_host_cursor(row["cursor"])
        return cursors

    @staticmethod
    def _sorted_directory_entries(directory: Path) -> tuple[os.DirEntry[str], ...]:
        try:
            with os.scandir(directory) as entries:
                return tuple(sorted(entries, key=lambda entry: entry.name))
        except FileNotFoundError:
            return ()

    def _walk_host_root(
        self,
        root: Path,
        *,
        recursive: bool,
    ) -> Iterator[tuple[str, Path, bool, int]]:
        """Yield one globally lexical filesystem projection.

        A depth-first walk is deterministic but not ordered by the POSIX
        relative strings persisted as cursors: for example ``.foo-bar`` sorts
        before ``.foo/z`` even though DFS visits the child first.  A lexical
        frontier makes traversal order and cursor comparison the same total
        order without materializing the whole tree.
        """

        pending: list[tuple[str, int, os.DirEntry[str]]] = []
        sequence = 0
        for entry in self._sorted_directory_entries(root):
            heapq.heappush(pending, (entry.name, sequence, entry))
            sequence += 1
        while pending:
            relative, _sequence, entry = heapq.heappop(pending)
            path = Path(entry.path)
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
                modified_ns = entry.stat(follow_symlinks=False).st_mtime_ns
            except FileNotFoundError:
                continue
            yield relative, path, is_directory, modified_ns
            if recursive and is_directory:
                for child in self._sorted_directory_entries(path):
                    child_relative = f"{relative}/{child.name}"
                    heapq.heappush(
                        pending,
                        (child_relative, sequence, child),
                    )
                    sequence += 1

    @staticmethod
    def _content_reference(root_name: str, relative: str) -> str | None:
        parts = PurePosixPath(relative).parts
        if len(parts) != 3:
            return None
        leaf = parts[2]
        if root_name == "dataset":
            if not leaf.endswith(".json"):
                return None
            digest = leaf[:-5]
        elif root_name == "blob":
            digest = leaf
        else:
            return None
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
            or parts[0] != digest[:2]
            or parts[1] != digest[2:4]
        ):
            return None
        return relative

    @staticmethod
    def _content_transient_reference(
        root_name: str,
        relative: str,
    ) -> tuple[str, str, str] | None:
        """Recognize only core-owned crash-recoverable content filenames.

        The result is ``(kind, digest, token)`` where ``kind`` is ``partial``
        or ``corrupt``.  Arbitrary dotfiles, malformed tokens, paths outside an
        exact two-level digest shard, and filenames whose digest disagrees with
        their shard are deliberately excluded from retention.
        """

        parts = PurePosixPath(relative).parts
        if len(parts) != 3 or root_name not in {"blob", "dataset"}:
            return None
        name = parts[2]
        if not name.startswith("."):
            return None
        body = name[1:]
        if body.endswith(".partial"):
            target_leaf, separator, token = body[: -len(".partial")].rpartition(".")
            kind = "partial"
        else:
            target_leaf, separator, token = body.rpartition(".corrupt-")
            kind = "corrupt"
        if (
            not separator
            or len(token) != 32
            or token != token.lower()
            or any(character not in "0123456789abcdef" for character in token)
        ):
            return None
        if root_name == "dataset":
            if not target_leaf.endswith(".json"):
                return None
            digest = target_leaf[: -len(".json")]
        else:
            digest = target_leaf
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
            or parts[0] != digest[:2]
            or parts[1] != digest[2:4]
        ):
            return None
        return kind, digest, token

    @staticmethod
    def _content_staging_activity_lock_name(
        root_name: str,
        digest: str,
        token: str,
    ) -> str:
        if root_name not in {"blob", "dataset"}:
            raise IngestionPipelineError("content staging lock root is invalid")
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
            or len(token) != 32
            or token != token.lower()
            or any(character not in "0123456789abcdef" for character in token)
        ):
            raise IngestionPipelineError("content staging lock identity is invalid")
        # The candidate filename already carries the complete digest and UUID.
        # Repeating both in the external lock leaf made this the longest
        # core-owned pathname and exceeded legacy Windows MAX_PATH at realistic
        # state-root depths. A 128-bit, domain-separated projection retains the
        # UUID's collision budget while keeping the lock path substantially
        # shorter than the candidate it protects.
        projected_identity = hashlib.sha256(
            f"router-dump-analyzer:staging:{root_name}:{digest}:{token}".encode("ascii")
        ).hexdigest()[:32]
        return f"{projected_identity}.active.lock"

    def _content_staging_activity_lock(
        self,
        root_name: str,
        digest: str,
        token: str,
    ) -> Path:
        return (
            self.content_lock_root
            / root_name
            / "staging"
            / self._content_staging_activity_lock_name(root_name, digest, token)
        )

    @staticmethod
    def _content_activity_lock_exists(path: Path) -> bool:
        """Check a dynamic lock without ``Path.exists()`` fail-open behavior.

        ``Path.exists()`` suppresses some Windows path-resolution errors and
        reports ``False``.  The retention caller holds the stable shard gate,
        so an exact parent-directory enumeration cannot race lock retirement.
        Errors other than a genuinely absent lock directory propagate and
        therefore stop deletion.  The bounded activity-lock pathname is also
        shorter than the content candidate whose existence led us here.
        """

        try:
            with os.scandir(path.parent) as entries:
                return any(entry.name == path.name for entry in entries)
        except FileNotFoundError:
            return False

    @staticmethod
    def _fixture_reference(relative: str) -> str | None:
        parts = PurePosixPath(relative).parts
        if len(parts) != 1:
            return None
        fixture_id = parts[0]
        suffix = fixture_id.removeprefix("fixture-")
        if (
            not fixture_id.startswith("fixture-")
            or len(suffix) != 32
            or suffix != suffix.lower()
            or any(character not in "0123456789abcdef" for character in suffix)
        ):
            return None
        return fixture_id

    def _fixture_is_referenced(
        self,
        fixture_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        if connection is None:
            with self._connect() as owned_connection:
                return self._fixture_is_referenced(
                    fixture_id,
                    connection=owned_connection,
                )
        return (
            connection.execute(
                "SELECT 1 FROM ingestion_imports WHERE fixture_id = ? LIMIT 1",
                (fixture_id,),
            ).fetchone()
            is not None
        )

    def _host_retention_candidate(
        self,
        root_name: str,
        *,
        relative: str,
        path: Path,
        is_directory: bool,
        modified_ns: int,
        stale_cutoff_ns: int,
        orphan_cutoff_ns: int,
        connection: sqlite3.Connection | None = None,
    ) -> tuple[str, str | None] | None:
        if root_name == "fixture":
            fixture_id = self._fixture_reference(relative) if is_directory else None
            if (
                fixture_id is None
                or modified_ns > orphan_cutoff_ns
                or self._fixture_is_referenced(
                    fixture_id,
                    connection=connection,
                )
            ):
                return None
            return "fixture", fixture_id
        if is_directory:
            if (
                root_name in {"blob", "dataset"}
                and modified_ns <= orphan_cutoff_ns
                and self._canonical_shard_relative(relative)
                and not path.is_symlink()
            ):
                try:
                    with os.scandir(path) as entries:
                        empty = next(entries, None) is None
                except FileNotFoundError:
                    return None
                if empty:
                    return "shard", None
            return None
        name = path.name
        if root_name == "spool":
            is_partial = name.endswith(".partial")
            is_active_lock = name.startswith(".") and name.endswith(
                ".partial.active.lock"
            )
            if (not is_partial and not is_active_lock) or modified_ns > stale_cutoff_ns:
                return None
            if is_active_lock:
                partial_name = name[1 : -len(".active.lock")]
                if (self.spool_root / partial_name).exists():
                    # The paired partial owns cleanup of this lock.
                    return None
            return "partial", None

        if (
            name.startswith(".")
            and name.endswith(".install.lock")
            and modified_ns <= stale_cutoff_ns
        ):
            return "partial", None
        transient = self._content_transient_reference(root_name, relative)
        if transient is not None and modified_ns <= stale_cutoff_ns:
            return "partial", None
        reference = self._content_reference(root_name, relative)
        if (
            reference is None
            or modified_ns > orphan_cutoff_ns
            or self._artifact_is_referenced(
                root_name,
                reference,
                connection=connection,
            )
        ):
            return None
        return root_name, reference

    def _scan_host_cleanup(
        self,
        *,
        now_ns: int,
        connection: sqlite3.Connection | None = None,
    ) -> _HostRetentionScan:
        """Discover bounded host work without occupying the upload fence.

        Each root advances monotonically from its durable cursor to lexical
        end-of-file.  Reaching EOF completes that root's cycle and resets its
        cursor; it does not wrap within the same call.  Consequently a root
        larger than ``max_scan_entries`` eventually reports a completed empty
        cycle instead of remaining permanently truncated.

        The returned observations are advisory until revalidated under the
        maintenance fence.  Their file identities are also journalled so a
        crash/restart cannot delete a replacement that appeared at the same
        path.
        """

        if connection is None:
            with self._connect() as owned_connection:
                return DurableIngestionPipeline._scan_host_cleanup(
                    self,
                    now_ns=now_ns,
                    connection=owned_connection,
                )
        policy = self.retention_policy
        stale_cutoff_ns = now_ns - policy.stale_partial_seconds * 1_000_000_000
        orphan_cutoff_ns = now_ns - policy.orphan_artifact_grace_seconds * 1_000_000_000
        prior_cursors = self._host_retention_cursors()
        candidates: list[_HostRetentionCandidate] = []
        next_cursors: list[tuple[str, str]] = []
        truncations: list[_RetentionTruncation] = []
        any_truncated = False

        for root_name in HOST_RETENTION_ROOT_NAMES:
            root = self._host_retention_root(root_name)
            prior_cursor = prior_cursors[root_name]
            scanned = 0
            selected = 0
            last_relative = ""
            stopped = False
            scan_limit_reached = False
            delete_limit_reached = False
            for relative, path, is_directory, modified_ns in self._walk_host_root(
                root,
                # A fixture view is one atomic top-level directory. Its
                # children are neither independent cleanup candidates nor
                # useful cursor entries.
                recursive=root_name not in {"spool", "fixture"},
            ):
                if relative <= prior_cursor:
                    continue
                # Stop only when another unvisited entry proves that the
                # budget truncated this cycle.  Hitting a limit exactly at
                # EOF is a complete scan, not a truncated one.
                scan_limit_reached = scanned >= policy.max_scan_entries
                delete_limit_reached = selected >= policy.max_delete_batch
                if scan_limit_reached or delete_limit_reached:
                    stopped = True
                    break
                scanned += 1
                last_relative = relative
                candidate = self._host_retention_candidate(
                    root_name,
                    relative=relative,
                    path=path,
                    is_directory=is_directory,
                    modified_ns=modified_ns,
                    stale_cutoff_ns=stale_cutoff_ns,
                    orphan_cutoff_ns=orphan_cutoff_ns,
                    connection=connection,
                )
                if candidate is None:
                    continue
                action, reference = candidate
                try:
                    identity = self._content_file_identity(path)
                except FileNotFoundError:
                    continue
                candidates.append(
                    _HostRetentionCandidate(
                        root_name=root_name,
                        relative_path=relative,
                        path=path,
                        action=action,
                        reference=reference,
                        is_directory=is_directory,
                        identity=identity,
                    )
                )
                selected += 1
            next_cursors.append((root_name, last_relative if stopped else ""))
            any_truncated = any_truncated or stopped
            if scan_limit_reached:
                truncations.append(
                    _RetentionTruncation(
                        source=f"host_{root_name}_scan",
                        limit=policy.max_scan_entries,
                        # The unvisited entry that triggered the stop proves
                        # that this root contains at least one more entry.
                        observed_at_least=scanned + 1,
                    )
                )
            if delete_limit_reached:
                truncations.append(
                    _RetentionTruncation(
                        source=f"host_{root_name}_delete",
                        limit=policy.max_delete_batch,
                        observed_at_least=selected,
                    )
                )

        return _HostRetentionScan(
            candidates=tuple(candidates),
            next_cursors=tuple(next_cursors),
            truncated=any_truncated,
            truncations=tuple(truncations),
        )

    def _revalidate_host_cleanup(
        self,
        scan: _HostRetentionScan,
        *,
        now_ns: int,
        connection: sqlite3.Connection | None = None,
    ) -> tuple[
        tuple[Path, ...],
        tuple[tuple[str, Path], ...],
        tuple[tuple[str, Path], ...],
        tuple[tuple[str, Path], ...],
        tuple[tuple[str, Path], ...],
        tuple[tuple[str, str, tuple[int, int, int, int, int, int]], ...],
    ]:
        """Revalidate out-of-fence observations inside the upload fence."""

        if connection is None:
            with self._connect() as owned_connection:
                return DurableIngestionPipeline._revalidate_host_cleanup(
                    self,
                    scan,
                    now_ns=now_ns,
                    connection=owned_connection,
                )
        policy = self.retention_policy
        stale_cutoff_ns = now_ns - policy.stale_partial_seconds * 1_000_000_000
        orphan_cutoff_ns = now_ns - policy.orphan_artifact_grace_seconds * 1_000_000_000
        stale_paths: list[Path] = []
        blob_files: list[tuple[str, Path]] = []
        dataset_files: list[tuple[str, Path]] = []
        fixture_directories: list[tuple[str, Path]] = []
        shard_directories: list[tuple[str, Path]] = []
        identities: list[tuple[str, str, tuple[int, int, int, int, int, int]]] = []
        for observed in scan.candidates:
            try:
                current_identity = self._content_file_identity(observed.path)
            except FileNotFoundError:
                continue
            if current_identity != observed.identity:
                continue
            candidate = self._host_retention_candidate(
                observed.root_name,
                relative=observed.relative_path,
                path=observed.path,
                is_directory=observed.is_directory,
                modified_ns=current_identity[4],
                stale_cutoff_ns=stale_cutoff_ns,
                orphan_cutoff_ns=orphan_cutoff_ns,
                connection=connection,
            )
            if candidate != (observed.action, observed.reference):
                continue
            if observed.action == "partial":
                stale_paths.append(observed.path)
            elif observed.action == "shard":
                shard_directories.append((observed.root_name, observed.path))
            elif observed.action == "blob":
                assert observed.reference is not None
                blob_files.append((observed.reference, observed.path))
            elif observed.action == "fixture":
                assert observed.reference is not None
                fixture_directories.append((observed.reference, observed.path))
            else:
                assert observed.action == "dataset"
                assert observed.reference is not None
                dataset_files.append((observed.reference, observed.path))
            identities.append(
                (
                    observed.root_name,
                    observed.relative_path,
                    current_identity,
                )
            )
        return (
            tuple(stale_paths),
            tuple(blob_files),
            tuple(dataset_files),
            tuple(fixture_directories),
            tuple(shard_directories),
            tuple(identities),
        )

    def _build_retention_plan(
        self,
        scope: ImportScope,
        *,
        now_ns: int,
        host_scan: _HostRetentionScan | None = None,
        precomputed_path_sizes: Mapping[Path, int] | None = None,
        measure_path_sizes: bool = True,
    ) -> _RetentionPlan:
        policy = self.retention_policy
        terminal_age = max(
            policy.terminal_import_grace_seconds,
            policy.idempotency_replay_seconds,
        )
        terminal_cutoff = now_ns - terminal_age * 1_000_000_000
        receipt_cutoff = now_ns - policy.idempotency_replay_seconds * 1_000_000_000
        # The audit row is also the idempotency receipt for destructive
        # retention, so it shares the configured replay window.
        audit_cutoff = receipt_cutoff
        batch_limit = policy.max_delete_batch
        truncations: list[_RetentionTruncation] = []
        with self._connect() as connection:
            eligible = connection.execute(
                """
                SELECT candidate.import_id, candidate.fixture_id,
                       candidate.blob_ref, candidate.staged_dataset_ref
                FROM ingestion_imports AS candidate
                WHERE candidate.tenant_id = ? AND candidate.project_id = ?
                  AND candidate.workspace_id = ?
                  AND candidate.state IN (?, ?, ?)
                  AND candidate.updated_at_ns <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM ingestion_artifact_pins AS blob_pin
                      WHERE blob_pin.artifact_kind = 'blob'
                        AND blob_pin.artifact_ref = candidate.blob_ref
                  )
                  AND (
                      candidate.staged_dataset_ref IS NULL OR NOT EXISTS (
                          SELECT 1
                          FROM ingestion_artifact_pins AS dataset_pin
                          WHERE dataset_pin.artifact_kind = 'dataset'
                            AND dataset_pin.artifact_ref =
                                candidate.staged_dataset_ref
                      )
                  )
                ORDER BY candidate.updated_at_ns, candidate.import_id
                LIMIT ?
                """,
                (
                    *self._scope_predicate(scope),
                    ImportState.COMPLETED.value,
                    ImportState.FAILED.value,
                    ImportState.CANCELLED.value,
                    terminal_cutoff,
                    batch_limit + 1,
                ),
            ).fetchall()
            truncated = len(eligible) > batch_limit
            if truncated:
                truncations.append(
                    _RetentionTruncation(
                        source="imports",
                        limit=batch_limit,
                        observed_at_least=batch_limit + 1,
                    )
                )
            eligible = eligible[:batch_limit]
            import_ids = tuple(str(row["import_id"]) for row in eligible)
            receipt_rows = connection.execute(
                """
                SELECT rowid FROM ingestion_idempotency
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND created_at_ns <= ?
                ORDER BY created_at_ns, rowid LIMIT ?
                """,
                (
                    *self._scope_predicate(scope),
                    receipt_cutoff,
                    batch_limit + 1,
                ),
            ).fetchall()
            if len(receipt_rows) > batch_limit:
                truncated = True
                truncations.append(
                    _RetentionTruncation(
                        source="idempotency_receipts",
                        limit=batch_limit,
                        observed_at_least=batch_limit + 1,
                    )
                )
            receipt_rowids = tuple(
                int(row["rowid"]) for row in receipt_rows[:batch_limit]
            )
            audit_rows = connection.execute(
                """
                SELECT audit_id FROM ingestion_retention_audit
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                  AND state = 'completed' AND created_at_ns <= ?
                ORDER BY created_at_ns, audit_id LIMIT ?
                """,
                (
                    *self._scope_predicate(scope),
                    audit_cutoff,
                    batch_limit + 1,
                ),
            ).fetchall()
            if len(audit_rows) > batch_limit:
                truncated = True
                truncations.append(
                    _RetentionTruncation(
                        source="retention_audits",
                        limit=batch_limit,
                        observed_at_least=batch_limit + 1,
                    )
                )
            audit_ids = tuple(str(row["audit_id"]) for row in audit_rows[:batch_limit])
            event_count = self._count_child_rows(
                connection,
                "ingestion_events",
                import_ids,
            )
            candidate_count = self._count_child_rows(
                connection,
                "ingestion_candidates",
                import_ids,
            )
            planned = set(import_ids)
            remaining_rows = connection.execute(
                """
                SELECT import_id, blob_ref, staged_dataset_ref
                FROM ingestion_imports
                """
            ).fetchall()
            remaining_blobs = {
                str(row["blob_ref"])
                for row in remaining_rows
                if str(row["import_id"]) not in planned
            }
            remaining_datasets = {
                str(row["staged_dataset_ref"])
                for row in remaining_rows
                if str(row["import_id"]) not in planned
                and row["staged_dataset_ref"] is not None
            }
            pin_rows = connection.execute(
                "SELECT artifact_kind, artifact_ref FROM ingestion_artifact_pins"
            ).fetchall()
            pinned_blobs: set[str] = set()
            pinned_datasets: set[str] = set()
            for row in pin_rows:
                try:
                    artifact_kind = _RetentionArtifactKind(str(row["artifact_kind"]))
                except ValueError as error:
                    raise IngestionPipelineError(
                        "stored retention artifact kind is invalid"
                    ) from error
                if artifact_kind is _RetentionArtifactKind.BLOB:
                    pinned_blobs.add(str(row["artifact_ref"]))
                elif artifact_kind is _RetentionArtifactKind.DATASET:
                    pinned_datasets.add(str(row["artifact_ref"]))

        stale_paths: tuple[Path, ...] = ()
        host_blob_files: tuple[tuple[str, Path], ...] = ()
        host_dataset_files: tuple[tuple[str, Path], ...] = ()
        host_fixture_directories: tuple[tuple[str, Path], ...] = ()
        host_shard_directories: tuple[tuple[str, Path], ...] = ()
        host_cursors: tuple[tuple[str, str], ...] = ()
        host_identities: tuple[
            tuple[str, str, tuple[int, int, int, int, int, int]], ...
        ] = ()
        if host_scan is not None:
            (
                stale_paths,
                host_blob_files,
                host_dataset_files,
                host_fixture_directories,
                host_shard_directories,
                host_identities,
            ) = self._revalidate_host_cleanup(host_scan, now_ns=now_ns)
            host_cursors = host_scan.next_cursors
            truncated = truncated or host_scan.truncated
            truncations.extend(host_scan.truncations)

        fixture_paths: dict[str, Path] = {}
        blob_paths: dict[str, Path] = {}
        dataset_paths: dict[str, Path] = {}
        for row in eligible:
            fixture_id = str(row["fixture_id"])
            fixture = self.fixture_root / fixture_id
            if fixture.exists() or fixture.is_symlink():
                fixture_paths[fixture_id] = fixture
            blob_ref = str(row["blob_ref"])
            blob = self.blob_root / Path(blob_ref)
            if (
                blob_ref not in remaining_blobs
                and blob_ref not in pinned_blobs
                and (blob.exists() or blob.is_symlink())
            ):
                blob_paths[blob_ref] = blob
            dataset_ref = row["staged_dataset_ref"]
            if dataset_ref is not None:
                dataset_key = str(dataset_ref)
                dataset = self.dataset_root / Path(dataset_key)
                if (
                    dataset_key not in remaining_datasets
                    and dataset_key not in pinned_datasets
                    and (dataset.exists() or dataset.is_symlink())
                ):
                    dataset_paths[dataset_key] = dataset
        for reference, path in host_blob_files:
            blob_paths.setdefault(reference, path)
        for reference, path in host_dataset_files:
            dataset_paths.setdefault(reference, path)
        for fixture_id, path in host_fixture_directories:
            fixture_paths.setdefault(fixture_id, path)

        all_paths = {
            *(fixture_paths.values()),
            *(blob_paths.values()),
            *(dataset_paths.values()),
            *stale_paths,
            *(path for _root_name, path in host_shard_directories),
        }
        path_sizes: dict[Path, int] = {}
        supplied_sizes = precomputed_path_sizes or {}
        for path in all_paths:
            supplied = supplied_sizes.get(path)
            if supplied is not None:
                path_sizes[path] = supplied
            elif measure_path_sizes:
                path_sizes[path] = self._path_bytes(path)
            else:
                # A path can join the authoritative plan after the advisory
                # out-of-fence sizing pass only through a concurrent metadata
                # change. Files have a bounded stat cost; a newly discovered
                # directory is conservatively reported as zero rather than
                # recursively walked while publication is fenced.
                try:
                    path_sizes[path] = (
                        path.stat().st_size
                        if path.is_file() or path.is_symlink()
                        else 0
                    )
                except OSError:
                    path_sizes[path] = 0
        report = RetentionReport(
            scope=scope,
            evaluated_at_ns=now_ns,
            executed=False,
            policy_enabled=policy.enabled,
            host_storage_orphan_inventory=(
                RetentionHostInventoryCoverage.BOUNDED_HOST_SCAN
                if host_scan is not None
                else RetentionHostInventoryCoverage.NOT_OBSERVED
            ),
            eligible_imports=len(import_ids),
            candidate_events=event_count,
            candidate_plugin_rows=candidate_count,
            expired_idempotency_receipts=len(receipt_rowids),
            expired_retention_audits=len(audit_ids),
            fixture_views=len(fixture_paths),
            content_blobs=len(blob_paths),
            revision_datasets=len(dataset_paths),
            stale_partials=len(stale_paths),
            estimated_bytes=sum(path_sizes.values()),
            truncated=truncated,
        )
        return _RetentionPlan(
            report=report,
            import_ids=import_ids,
            receipt_rowids=receipt_rowids,
            audit_ids=audit_ids,
            fixture_directories=tuple(fixture_paths.values()),
            blob_files=tuple(blob_paths.items()),
            dataset_files=tuple(dataset_paths.items()),
            stale_partials=stale_paths,
            shard_directories=host_shard_directories,
            host_cursors=host_cursors,
            host_identities=host_identities,
            path_sizes=tuple(path_sizes.items()),
            truncations=tuple(truncations),
        )

    def retention_inventory(
        self,
        scope: ImportScope,
        *,
        now_ns: int | None = None,
    ) -> RetentionReport:
        """Return a bounded dry-run inventory without deleting anything."""

        effective_now = self._now_ns() if now_ns is None else now_ns
        if type(effective_now) is not int or effective_now < 0:
            raise ValueError("now_ns must be a non-negative integer or None")
        # Inventory is advisory and non-mutating. Recursive size measurement
        # intentionally stays outside the publication fence.
        return self._build_retention_plan(
            scope,
            now_ns=effective_now,
        ).report

    def _artifact_is_referenced(
        self,
        kind: str,
        reference: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        column = "blob_ref" if kind == "blob" else "staged_dataset_ref"
        if connection is None:
            with self._connect() as owned_connection:
                return self._artifact_is_referenced(
                    kind,
                    reference,
                    connection=owned_connection,
                )
        row = connection.execute(
            f"SELECT 1 FROM ingestion_imports WHERE {column} = ? LIMIT 1",
            (reference,),
        ).fetchone()
        pin = connection.execute(
            """
            SELECT 1 FROM ingestion_artifact_pins
            WHERE artifact_kind = ? AND artifact_ref = ?
            """,
            (kind, reference),
        ).fetchone()
        return row is not None or pin is not None

    @staticmethod
    def _delete_path(path: Path) -> tuple[bool, int]:
        if not path.exists() and not path.is_symlink():
            return False, 0
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            shutil.rmtree(path)
        # Retention reports use the immutable plan's out-of-fence size. Do
        # not recursively walk a directory again while publication is fenced.
        return True, 0

    @staticmethod
    def _retention_identity_matches(
        current: tuple[int, int, int, int, int, int],
        expected: tuple[int, int, int, int, int, int],
        *,
        lock_initialized: bool = False,
    ) -> bool:
        if current == expected:
            return True
        # The Windows advisory-lock primitive must write its first lock byte
        # when an empty abandoned lock is opened.  Treat only that mutation of
        # the same device/inode/mode as identity-preserving; all replacements
        # and every other size transition still fail closed.
        return (
            lock_initialized
            and expected[3] == 0
            and current[3] == 1
            and current[:3] == expected[:3]
        )

    def _delete_artifact_if_unreferenced(
        self,
        kind: str,
        reference: str,
        path: Path,
        *,
        expected_identity: tuple[int, int, int, int, int, int] | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> tuple[bool, int]:
        root = self.blob_root if kind == "blob" else self.dataset_root
        canonical_reference = self._content_reference(kind, reference)
        if canonical_reference != reference:
            raise IngestionPipelineError("retention artifact reference is invalid")
        digest = path.name.removesuffix(".json") if kind == "dataset" else path.name
        shard_gate, lock_path = self._content_lock_coordinates(root, digest)
        with exclusive_file_lock(shard_gate):
            if self._artifact_is_referenced(
                kind,
                reference,
                connection=connection,
            ):
                return False, 0
            with exclusive_file_lock(lock_path):
                exists = path.exists() or path.is_symlink()
                if expected_identity is not None and exists:
                    current_identity = self._content_file_identity(path)
                    if current_identity != expected_identity:
                        return False, 0
                deleted = self._delete_path(path) if exists else (True, 0)
            self._prune_empty_content_shards(root, path.parent)
            # Per-address locks live in a stable namespace outside the data
            # tree and are intentionally persistent.  Never unlink an
            # advisory lock pathname after releasing its inode lock.
            return deleted

    def _delete_empty_shard_directory(
        self,
        root_name: str,
        path: Path,
        *,
        expected_identity: tuple[int, int, int, int, int, int] | None,
    ) -> bool:
        root, shard_gate = self._content_shard_gate(root_name, path)
        with exclusive_file_lock(shard_gate):
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError as error:
                raise IngestionPipelineError(
                    "shard cleanup path escapes its storage root"
                ) from error
            if not self._canonical_shard_relative(relative) or path.is_symlink():
                raise IngestionPipelineError(
                    "shard cleanup path is not a canonical directory"
                )
            if not path.exists():
                return True
            if not path.is_dir():
                return False
            if expected_identity is not None:
                current_identity = self._content_file_identity(path)
                if current_identity != expected_identity:
                    return False
            try:
                path.rmdir()
            except FileNotFoundError:
                return True
            except OSError as error:
                if error.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                    return False
                raise
            _fsync_directory(path.parent)
            if len(PurePosixPath(relative).parts) == 2:
                self._prune_empty_content_shards(root, path)
            return True

    def _delete_content_transient(
        self,
        item: _RetentionWorkItem,
        path: Path,
    ) -> bool:
        """Delete one exact crashed staging/quarantine file if it is inactive."""

        parsed = self._content_transient_reference(item.root, item.relative_path)
        if parsed is None:
            raise IngestionPipelineError(
                "retention content-transient reference is invalid"
            )
        transient_kind, digest, token = parsed
        root = self._retention_root(item.root)
        shard_gate, install_lock = self._content_lock_coordinates(root, digest)

        def delete_if_unchanged() -> bool:
            if not path.exists() and not path.is_symlink():
                return True
            if item.expected_identity is not None:
                current_identity = self._content_file_identity(path)
                if current_identity != item.expected_identity:
                    return False
            deleted, _size = self._delete_path(path)
            return deleted

        with exclusive_file_lock(shard_gate):
            if transient_kind == "partial":
                activity_lock = self._content_staging_activity_lock(
                    item.root,
                    digest,
                    token,
                )
                # Accept the pre-bounded-name lock during rolling upgrades.
                # Exact parent enumeration keeps even an over-length legacy
                # leaf visible without relying on Path.exists(). If opening
                # such a lock fails, the non-acquisition remains fail-closed.
                legacy_activity_lock = activity_lock.with_name(
                    f"{digest}.{token}.active.lock"
                )
                activity_locks = tuple(
                    candidate_lock
                    for candidate_lock in (activity_lock, legacy_activity_lock)
                    if self._content_activity_lock_exists(candidate_lock)
                )
                if activity_locks:
                    with ExitStack() as lock_stack:
                        for candidate_lock in activity_locks:
                            acquired = lock_stack.enter_context(
                                try_existing_exclusive_file_lock(candidate_lock)
                            )
                            if not acquired:
                                return False
                        deleted = delete_if_unchanged()
                    # The stable shard gate prevents close/unlink from splitting
                    # the activity lock domain while a new opener arrives.
                    for candidate_lock in activity_locks:
                        candidate_lock.unlink(missing_ok=True)
                else:
                    # Candidates written by older versions have no activity
                    # lock. Their exact syntax, age, and journalled identity are
                    # still sufficient to reclaim them fail-closed.
                    deleted = delete_if_unchanged()
            else:
                # Quarantine creation is serialized by the per-address install
                # lock. A non-blocking acquisition avoids waiting behind a live
                # publisher while preserving the same lock ordering as publish.
                with try_exclusive_file_lock(install_lock) as acquired:
                    if not acquired:
                        return False
                    deleted = delete_if_unchanged()
            if deleted:
                self._prune_empty_content_shards(root, path.parent)
            return deleted

    @staticmethod
    def _retention_policy_payload(policy: RetentionPolicy) -> dict[str, Any]:
        return {
            "enabled": policy.enabled,
            "terminal_import_grace_seconds": (policy.terminal_import_grace_seconds),
            "idempotency_replay_seconds": policy.idempotency_replay_seconds,
            "orphan_artifact_grace_seconds": (policy.orphan_artifact_grace_seconds),
            "stale_partial_seconds": policy.stale_partial_seconds,
            "max_delete_batch": policy.max_delete_batch,
            "max_scan_entries": policy.max_scan_entries,
            "max_tenant_bytes": policy.max_tenant_bytes,
            "max_workspace_bytes": policy.max_workspace_bytes,
            "max_tenant_imports": policy.max_tenant_imports,
            "max_workspace_imports": policy.max_workspace_imports,
        }

    def _retention_request_digest(
        self,
        scope: ImportScope,
        *,
        actor: str,
        operation_id: str,
        requested_now_ns: int | None,
    ) -> str:
        payload = {
            "version": RETENTION_REQUEST_VERSION,
            "scope": {
                "tenant_id": scope.tenant_id,
                "project_id": scope.project_id,
                "workspace_id": scope.workspace_id,
            },
            "actor": actor,
            "operation_id": operation_id,
            "dry_run": False,
            # Preserve whether the caller requested a fixed clock.  A retry of
            # an implicit-clock operation therefore reuses the persisted
            # effective clock instead of hashing a new wall-clock value.
            "requested_now_ns": (
                None if requested_now_ns is None else str(requested_now_ns)
            ),
            "policy": self._retention_policy_payload(self.retention_policy),
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _relative_retention_path(path: Path, root: Path) -> str:
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise IngestionPipelineError(
                "retention plan path escapes its configured storage root"
            ) from error
        value = relative.as_posix()
        if not value or value == ".":
            raise IngestionPipelineError(
                "retention plan path must identify a stored artifact"
            )
        return value

    def _serialize_retention_plan(self, plan: _RetentionPlan) -> str:
        work_items: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        path_sizes = dict(plan.path_sizes)
        host_identities = {
            (root_name, relative_path): identity
            for root_name, relative_path, identity in plan.host_identities
        }

        def append_item(
            *,
            action: str,
            root_name: str,
            root: Path,
            path: Path,
            reference: str | None,
        ) -> None:
            relative = self._relative_retention_path(path, root)
            identity = (root_name, relative)
            if identity in seen:
                return
            seen.add(identity)
            expected_identity = host_identities.get(identity)
            if expected_identity is None:
                try:
                    expected_identity = self._content_file_identity(path)
                except FileNotFoundError:
                    pass
            work_items.append(
                {
                    "sequence": len(work_items),
                    "action": action,
                    "root": root_name,
                    "reference": reference,
                    "relative_path": relative,
                    "planned_bytes": path_sizes.get(path, 0),
                    "expected_identity": (
                        None if expected_identity is None else list(expected_identity)
                    ),
                }
            )

        for path in plan.fixture_directories:
            append_item(
                action="fixture",
                root_name="fixture",
                root=self.fixture_root,
                path=path,
                reference=path.name,
            )
        for reference, path in plan.blob_files:
            append_item(
                action="blob",
                root_name="blob",
                root=self.blob_root,
                path=path,
                reference=reference,
            )
        for reference, path in plan.dataset_files:
            append_item(
                action="dataset",
                root_name="dataset",
                root=self.dataset_root,
                path=path,
                reference=reference,
            )
        roots = (
            ("spool", self.spool_root),
            ("blob", self.blob_root),
            ("dataset", self.dataset_root),
            ("fixture", self.fixture_root),
        )
        for path in plan.stale_partials:
            for root_name, root in roots:
                try:
                    path.relative_to(root)
                except ValueError:
                    continue
                append_item(
                    action="partial",
                    root_name=root_name,
                    root=root,
                    path=path,
                    reference=None,
                )
                break
            else:
                raise IngestionPipelineError(
                    "stale partial escapes configured storage roots"
                )
        for root_name, path in plan.shard_directories:
            root = self._host_retention_root(root_name)
            append_item(
                action="shard",
                root_name=root_name,
                root=root,
                path=path,
                reference=None,
            )
        return canonical_json(
            {
                "version": RETENTION_PLAN_VERSION,
                "policy": self._retention_policy_payload(self.retention_policy),
                "import_ids": list(plan.import_ids),
                "receipt_rowids": list(plan.receipt_rowids),
                "audit_ids": list(plan.audit_ids),
                "host_cursors": {
                    root_name: cursor for root_name, cursor in plan.host_cursors
                },
                "work_items": work_items,
            }
        )

    def _retention_root(self, name: str) -> Path:
        roots = {
            "spool": self.spool_root,
            "blob": self.blob_root,
            "dataset": self.dataset_root,
            "fixture": self.fixture_root,
        }
        try:
            return roots[name]
        except KeyError as error:
            raise IngestionPipelineError(
                "persisted retention plan has an invalid storage root"
            ) from error

    def _deserialize_retention_work_items(
        self,
        value: str,
    ) -> tuple[_RetentionWorkItem, ...]:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError) as error:
            raise IngestionPipelineError(
                "persisted retention plan is not valid JSON"
            ) from error
        if not isinstance(payload, dict) or payload.get("version") not in {
            1,
            RETENTION_PLAN_VERSION,
        }:
            raise IngestionPipelineError(
                "persisted retention plan has an unsupported version"
            )
        raw_items = payload.get("work_items")
        if not isinstance(raw_items, list) or len(raw_items) > (
            MAX_RETENTION_SCAN_ENTRIES + MAX_RETENTION_BATCH * 3
        ):
            raise IngestionPipelineError(
                "persisted retention plan has invalid work items"
            )
        items: list[_RetentionWorkItem] = []
        for expected_sequence, raw in enumerate(raw_items):
            if not isinstance(raw, dict):
                raise IngestionPipelineError(
                    "persisted retention plan has an invalid work item"
                )
            sequence = raw.get("sequence")
            action = raw.get("action")
            root_name = raw.get("root")
            reference = raw.get("reference")
            relative_value = raw.get("relative_path")
            planned_bytes = raw.get("planned_bytes")
            raw_expected_identity = raw.get("expected_identity")
            if (
                type(sequence) is not int
                or sequence != expected_sequence
                or action
                not in {
                    "fixture",
                    "blob",
                    "dataset",
                    "partial",
                    "shard",
                }
                or root_name not in {"spool", "blob", "dataset", "fixture"}
                or not isinstance(relative_value, str)
                or not relative_value
                or "\\" in relative_value
                or type(planned_bytes) is not int
                or not 0 <= planned_bytes <= 2**63 - 1
            ):
                raise IngestionPipelineError(
                    "persisted retention plan has an invalid work item"
                )
            relative = PurePosixPath(relative_value)
            if relative.is_absolute() or any(
                part in {"", ".", ".."} or ":" in part for part in relative.parts
            ):
                raise IngestionPipelineError(
                    "persisted retention plan contains an unsafe path"
                )
            expected_identity: tuple[int, int, int, int, int, int] | None
            if raw_expected_identity is None:
                expected_identity = None
            elif (
                isinstance(raw_expected_identity, list)
                and len(raw_expected_identity) == 6
                and all(
                    type(component) is int and 0 <= component <= 2**63 - 1
                    for component in raw_expected_identity
                )
            ):
                expected_identity = tuple(raw_expected_identity)  # type: ignore[assignment]
            else:
                raise IngestionPipelineError(
                    "persisted retention plan has an invalid file identity"
                )
            if action == "fixture":
                valid_reference = (
                    root_name == "fixture"
                    and isinstance(reference, str)
                    and reference == relative.parts[0]
                )
            elif action in {"blob", "dataset"}:
                valid_reference = (
                    root_name == action
                    and isinstance(reference, str)
                    and reference == relative_value
                )
            elif action == "partial":
                valid_reference = reference is None
            else:
                valid_reference = (
                    payload.get("version") == RETENTION_PLAN_VERSION
                    and root_name in {"blob", "dataset"}
                    and reference is None
                    and self._canonical_shard_relative(relative_value)
                )
            if not valid_reference:
                raise IngestionPipelineError(
                    "persisted retention plan has invalid reference metadata"
                )
            items.append(
                _RetentionWorkItem(
                    sequence=sequence,
                    action=action,
                    root=root_name,
                    reference=reference,
                    relative_path=relative_value,
                    planned_bytes=planned_bytes,
                    expected_identity=expected_identity,
                )
            )
        return tuple(items)

    @staticmethod
    def _retention_report_from_mapping(
        scope: ImportScope,
        value: Mapping[str, Any],
    ) -> RetentionReport:
        def integer(name: str) -> int:
            try:
                return parse_canonical_decimal_integer(
                    value.get(name, 0),
                    name,
                    minimum=0,
                    maximum=2**63 - 1,
                )
            except ValueError as error:
                raise IngestionPipelineError(
                    "persisted retention report has an invalid integer"
                ) from error

        def boolean(name: str) -> bool:
            raw = value.get(name, False)
            if type(raw) is not bool:
                raise IngestionPipelineError(
                    "persisted retention report has an invalid boolean"
                )
            return raw

        raw_failures = value.get("failure_details", [])
        if (
            not isinstance(raw_failures, list)
            or len(raw_failures) > 100
            or any(
                not isinstance(item, str) or len(item) > 512 for item in raw_failures
            )
        ):
            raise IngestionPipelineError(
                "persisted retention report has invalid failure details"
            )
        audit_id = value.get("audit_id")
        if audit_id is not None and not isinstance(audit_id, str):
            raise IngestionPipelineError(
                "persisted retention report has an invalid audit identifier"
            )
        raw_host_inventory = value.get(
            "host_storage_orphan_inventory",
            # Only destructive reports are journalled. Legacy journals were
            # produced after the bounded host scan, before this coverage field
            # was added to their serialized report.
            RetentionHostInventoryCoverage.BOUNDED_HOST_SCAN.value,
        )
        try:
            host_inventory = RetentionHostInventoryCoverage(raw_host_inventory)
        except (TypeError, ValueError) as error:
            raise IngestionPipelineError(
                "persisted retention report has invalid inventory coverage"
            ) from error
        return RetentionReport(
            scope=scope,
            evaluated_at_ns=integer("evaluated_at_ns"),
            executed=boolean("executed"),
            policy_enabled=boolean("policy_enabled"),
            host_storage_orphan_inventory=host_inventory,
            eligible_imports=integer("eligible_imports"),
            candidate_events=integer("candidate_events"),
            candidate_plugin_rows=integer("candidate_plugin_rows"),
            expired_idempotency_receipts=integer("expired_idempotency_receipts"),
            expired_retention_audits=integer("expired_retention_audits"),
            fixture_views=integer("fixture_views"),
            content_blobs=integer("content_blobs"),
            revision_datasets=integer("revision_datasets"),
            stale_partials=integer("stale_partials"),
            estimated_bytes=integer("estimated_bytes"),
            deleted_imports=integer("deleted_imports"),
            deleted_retention_audits=integer("deleted_retention_audits"),
            deleted_files=integer("deleted_files"),
            deleted_bytes=integer("deleted_bytes"),
            deletion_failures=integer("deletion_failures"),
            failure_details=tuple(raw_failures),
            truncated=boolean("truncated"),
            audit_id=audit_id,
        )

    def _process_retention_work_item(
        self,
        item: _RetentionWorkItem,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> tuple[_RetentionCleanupState, int, str | None]:
        root = self._retention_root(item.root)
        relative = PurePosixPath(item.relative_path)
        path = root.joinpath(*relative.parts)
        if (
            not path.exists()
            and not path.is_symlink()
            and item.action not in {"blob", "dataset", "shard"}
        ):
            # Every journalled candidate existed when its immutable plan was
            # committed.  Absence while resuming therefore represents a
            # completed deletion whose outcome update was interrupted.
            return _RetentionCleanupState.DELETED, item.planned_bytes, None
        try:
            if item.action == "fixture":
                assert item.reference is not None
                if connection is None:
                    with self._connect() as owned_connection:
                        referenced = owned_connection.execute(
                            "SELECT 1 FROM ingestion_imports "
                            "WHERE fixture_id = ? LIMIT 1",
                            (item.reference,),
                        ).fetchone()
                else:
                    referenced = connection.execute(
                        "SELECT 1 FROM ingestion_imports WHERE fixture_id = ? LIMIT 1",
                        (item.reference,),
                    ).fetchone()
                if referenced is not None:
                    return _RetentionCleanupState.SKIPPED, 0, None
                if item.expected_identity is not None:
                    try:
                        current_identity = self._content_file_identity(path)
                    except FileNotFoundError:
                        return _RetentionCleanupState.DELETED, item.planned_bytes, None
                    if current_identity != item.expected_identity:
                        return _RetentionCleanupState.SKIPPED, 0, None
                self._delete_path(path)
            elif item.action in {"blob", "dataset"}:
                assert item.reference is not None
                deleted, _size = self._delete_artifact_if_unreferenced(
                    item.action,
                    item.reference,
                    path,
                    expected_identity=item.expected_identity,
                    connection=connection,
                )
                if not deleted and (path.exists() or path.is_symlink()):
                    return _RetentionCleanupState.SKIPPED, 0, None
            elif item.action == "shard":
                deleted = self._delete_empty_shard_directory(
                    item.root,
                    path,
                    expected_identity=item.expected_identity,
                )
                if not deleted:
                    return _RetentionCleanupState.SKIPPED, 0, None
            else:
                transient = (
                    None
                    if item.root == "spool"
                    else self._content_transient_reference(
                        item.root,
                        item.relative_path,
                    )
                )
                if transient is not None:
                    deleted = self._delete_content_transient(item, path)
                    if not deleted:
                        return _RetentionCleanupState.SKIPPED, 0, None
                    return _RetentionCleanupState.DELETED, item.planned_bytes, None
                if item.root == "spool":
                    gate = self._spool_namespace_lock_path
                else:
                    gate = self._content_cleanup_gate(item.root, path)
                with exclusive_file_lock(gate):
                    if path.name.endswith(".lock"):
                        with try_existing_exclusive_file_lock(path) as acquired:
                            if not acquired:
                                return _RetentionCleanupState.SKIPPED, 0, None
                            if item.expected_identity is not None:
                                try:
                                    current_identity = self._content_file_identity(path)
                                except FileNotFoundError:
                                    return (
                                        _RetentionCleanupState.DELETED,
                                        item.planned_bytes,
                                        None,
                                    )
                                if not self._retention_identity_matches(
                                    current_identity,
                                    item.expected_identity,
                                    lock_initialized=True,
                                ):
                                    return _RetentionCleanupState.SKIPPED, 0, None
                        # The stable namespace gate remains held after the OS
                        # handle closes, so unlink cannot split lock domains.
                        deleted, _size = self._delete_path(path)
                    elif item.root == "spool":
                        active_lock = path.with_name(f".{path.name}.active.lock")
                        if active_lock.exists():
                            with try_existing_exclusive_file_lock(
                                active_lock
                            ) as acquired:
                                if not acquired:
                                    return _RetentionCleanupState.SKIPPED, 0, None
                                if item.expected_identity is not None:
                                    try:
                                        current_identity = self._content_file_identity(
                                            path
                                        )
                                    except FileNotFoundError:
                                        return (
                                            _RetentionCleanupState.DELETED,
                                            item.planned_bytes,
                                            None,
                                        )
                                    if current_identity != item.expected_identity:
                                        return _RetentionCleanupState.SKIPPED, 0, None
                                deleted, _size = self._delete_path(path)
                            active_lock.unlink(missing_ok=True)
                        else:
                            if item.expected_identity is not None:
                                current_identity = self._content_file_identity(path)
                                if current_identity != item.expected_identity:
                                    return _RetentionCleanupState.SKIPPED, 0, None
                            deleted, _size = self._delete_path(path)
                    else:
                        if item.expected_identity is not None:
                            current_identity = self._content_file_identity(path)
                            if current_identity != item.expected_identity:
                                return _RetentionCleanupState.SKIPPED, 0, None
                        deleted, _size = self._delete_path(path)
                        self._prune_empty_content_shards(root, path.parent)
                if not deleted:
                    return _RetentionCleanupState.SKIPPED, 0, None
        except OSError as error:
            detail = _truncate_text(
                f"{path}: {type(error).__name__}: {error}",
                maximum=512,
            )
            return _RetentionCleanupState.FAILED, 0, detail
        return _RetentionCleanupState.DELETED, item.planned_bytes, None

    @staticmethod
    def _validated_retention_progress_outcome(
        item: _RetentionWorkItem,
        *,
        raw_state: object,
        raw_bytes: object,
        raw_detail: object,
    ) -> tuple[_RetentionCleanupState, dict[str, Any]]:
        try:
            state = _RetentionCleanupState(str(raw_state))
        except ValueError as error:
            raise IngestionPipelineError(
                "persisted retention cleanup progress is invalid"
            ) from error
        if (
            state not in _TERMINAL_RETENTION_CLEANUP_STATES
            or type(raw_bytes) is not int
            or raw_bytes < 0
            or raw_bytes > 2**63 - 1
            or (
                raw_detail is not None
                and (not isinstance(raw_detail, str) or len(raw_detail) > 512)
            )
        ):
            raise IngestionPipelineError(
                "persisted retention cleanup progress is invalid"
            )
        expected_bytes = (
            item.planned_bytes if state is _RetentionCleanupState.DELETED else 0
        )
        if raw_bytes != expected_bytes or (state is _RetentionCleanupState.FAILED) != (
            raw_detail is not None
        ):
            raise IngestionPipelineError(
                "persisted retention cleanup progress is inconsistent"
            )
        return state, {
            "state": state.value,
            "bytes": raw_bytes,
            "detail": raw_detail,
        }

    def _migrate_legacy_retention_progress(
        self,
        connection: sqlite3.Connection,
        *,
        audit_id: str,
        legacy_json: object,
        items_by_sequence: Mapping[int, _RetentionWorkItem],
    ) -> None:
        """Project one legacy aggregate checkpoint into incremental rows.

        Older builds rewrote one growing JSON object after every deletion.
        Migration is lazy because only pending operations need it, and atomic
        so a crash cannot leave a partly projected checkpoint. New cleanup
        never writes the aggregate column again.
        """

        try:
            value = json.loads(str(legacy_json))
        except (TypeError, ValueError) as error:
            raise IngestionPipelineError(
                "persisted retention cleanup progress is invalid"
            ) from error
        if not isinstance(value, dict):
            raise IngestionPipelineError(
                "persisted retention cleanup progress must be an object"
            )
        if not value:
            return
        migrated: list[tuple[int, str, int, str | None]] = []
        for raw_sequence, raw_outcome in value.items():
            try:
                sequence = parse_canonical_decimal_integer(
                    raw_sequence,
                    "persisted retention cleanup sequence",
                    minimum=0,
                    maximum=len(items_by_sequence) - 1,
                )
            except ValueError as error:
                raise IngestionPipelineError(
                    "persisted retention cleanup progress is invalid"
                ) from error
            if sequence not in items_by_sequence:
                raise IngestionPipelineError(
                    "persisted retention cleanup progress is invalid"
                )
            if not isinstance(raw_outcome, dict):
                raise IngestionPipelineError(
                    "persisted retention cleanup progress is invalid"
                )
            state, outcome = self._validated_retention_progress_outcome(
                items_by_sequence[sequence],
                raw_state=raw_outcome.get("state"),
                raw_bytes=raw_outcome.get("bytes"),
                raw_detail=raw_outcome.get("detail"),
            )
            migrated.append(
                (
                    sequence,
                    state.value,
                    int(outcome["bytes"]),
                    outcome["detail"],
                )
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            now = time.time_ns()
            for sequence, stored_state, deleted_bytes, detail in migrated:
                connection.execute(
                    """
                    INSERT INTO ingestion_retention_cleanup_progress (
                        audit_id, sequence, state, deleted_bytes,
                        detail, updated_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(audit_id, sequence) DO NOTHING
                    """,
                    (
                        audit_id,
                        sequence,
                        stored_state,
                        deleted_bytes,
                        detail,
                        now,
                    ),
                )
                stored = connection.execute(
                    """
                    SELECT state, deleted_bytes, detail
                    FROM ingestion_retention_cleanup_progress
                    WHERE audit_id = ? AND sequence = ?
                    """,
                    (audit_id, sequence),
                ).fetchone()
                if stored is None or (
                    str(stored["state"]),
                    int(stored["deleted_bytes"]),
                    stored["detail"],
                ) != (stored_state, deleted_bytes, detail):
                    raise IngestionPipelineError(
                        "persisted retention cleanup progress is inconsistent"
                    )
            connection.execute(
                """
                UPDATE ingestion_retention_audit
                SET cleanup_progress_json = '{}'
                WHERE audit_id = ? AND state = 'cleanup_pending'
                """,
                (audit_id,),
            )
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    @staticmethod
    def _retention_duration_ms(started_monotonic_ns: int) -> int:
        return max(0, (time.monotonic_ns() - started_monotonic_ns) // 1_000_000)

    @staticmethod
    def _retention_error_family(error: BaseException) -> str:
        if isinstance(error, sqlite3.Error):
            return "sqlite"
        if isinstance(error, OSError):
            return "filesystem"
        if isinstance(error, (TypeError, ValueError, ImportConflictError)):
            return "validation"
        if isinstance(error, IngestionPipelineError):
            return "pipeline"
        return "exception"

    def _retention_work_item_count(self, plan: _RetentionPlan) -> int:
        return len(
            self._deserialize_retention_work_items(self._serialize_retention_plan(plan))
        )

    @staticmethod
    def _emit_retention_truncations(
        context: _RetentionTelemetryContext,
        plan: _RetentionPlan,
    ) -> None:
        for truncation in plan.truncations:
            emit_operational_event(
                "retention.scan.truncated",
                run_id=context.run_id,
                source=truncation.source,
                limit=truncation.limit,
                observed_at_least=truncation.observed_at_least,
            )

    def _resume_retention_cleanup(
        self,
        scope: ImportScope,
        *,
        audit_id: str,
        telemetry: _RetentionTelemetryContext | None = None,
        resumed: bool = True,
    ) -> RetentionReport:
        if telemetry is None:
            telemetry = _RetentionTelemetryContext(
                run_id=f"run-{uuid4().hex}",
                started_monotonic_ns=time.monotonic_ns(),
            )
        telemetry.phase = "cleanup"
        telemetry.audit_id = audit_id
        telemetry.mutation_started = True

        def report_from_json(raw_report: object) -> RetentionReport:
            try:
                report_value = json.loads(str(raw_report))
            except (TypeError, ValueError) as error:
                raise IngestionPipelineError(
                    "persisted retention report is not valid JSON"
                ) from error
            if not isinstance(report_value, dict):
                raise IngestionPipelineError(
                    "persisted retention report must be an object"
                )
            return self._retention_report_from_mapping(scope, report_value)

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM ingestion_retention_audit
                WHERE audit_id = ? AND tenant_id = ? AND project_id = ?
                  AND workspace_id = ?
                """,
                (audit_id, *self._scope_predicate(scope)),
            ).fetchone()
            if row is None:
                raise IngestionPipelineError("retention operation journal is missing")
            provisional = report_from_json(row["report_json"])
            try:
                journal_state = _RetentionCleanupState(str(row["state"]))
            except ValueError as error:
                raise IngestionPipelineError(
                    "retention operation journal has an invalid state"
                ) from error
            if journal_state is _RetentionCleanupState.COMPLETED:
                emit_operational_event(
                    "retention.run.replayed",
                    run_id=telemetry.run_id,
                    audit_id=audit_id,
                    outcome="completed",
                )
                return provisional
            if (
                journal_state is not _RetentionCleanupState.CLEANUP_PENDING
                or row["plan_json"] is None
            ):
                raise IngestionPipelineError(
                    "retention operation journal has an invalid state"
                )
            items = self._deserialize_retention_work_items(str(row["plan_json"]))
            items_by_sequence = {item.sequence: item for item in items}
            self._migrate_legacy_retention_progress(
                connection,
                audit_id=audit_id,
                legacy_json=row["cleanup_progress_json"],
                items_by_sequence=items_by_sequence,
            )
            progress: dict[int, dict[str, Any]] = {}
            progress_states: dict[int, _RetentionCleanupState] = {}

            def merge_progress_rows(progress_rows: Iterable[sqlite3.Row]) -> None:
                for progress_row in progress_rows:
                    sequence = int(progress_row["sequence"])
                    item = items_by_sequence.get(sequence)
                    if item is None:
                        raise IngestionPipelineError(
                            "persisted retention cleanup progress is invalid"
                        )
                    state, outcome = self._validated_retention_progress_outcome(
                        item,
                        raw_state=progress_row["state"],
                        raw_bytes=progress_row["deleted_bytes"],
                        raw_detail=progress_row["detail"],
                    )
                    progress[sequence] = outcome
                    progress_states[sequence] = state

            merge_progress_rows(
                connection.execute(
                    """
                    SELECT sequence, state, deleted_bytes, detail
                    FROM ingestion_retention_cleanup_progress
                    WHERE audit_id = ? ORDER BY sequence
                    """,
                    (audit_id,),
                ).fetchall()
            )
            pending_items = [item for item in items if item.sequence not in progress]
            emit_operational_event(
                "retention.cleanup.started",
                run_id=telemetry.run_id,
                audit_id=audit_id,
                total_items=len(items),
                completed_items=len(progress),
                pending_items=len(pending_items),
                resumed=resumed or bool(progress),
            )
            for offset in range(
                0,
                len(pending_items),
                RETENTION_CLEANUP_FENCE_BATCH,
            ):
                batch = pending_items[offset : offset + RETENTION_CLEANUP_FENCE_BATCH]
                batch_started_monotonic_ns = time.monotonic_ns()
                # Canonical deletion and its exact outcome checkpoint share
                # one short publication fence. Releasing between bounded
                # batches lets waiting uploads publish without exposing the
                # publish-before-reference race or a delete-before-checkpoint
                # replay ambiguity.
                with exclusive_file_lock(self._maintenance_lock_path):
                    live_audit = connection.execute(
                        """
                        SELECT state, report_json
                        FROM ingestion_retention_audit
                        WHERE audit_id = ? AND tenant_id = ?
                          AND project_id = ? AND workspace_id = ?
                        """,
                        (audit_id, *self._scope_predicate(scope)),
                    ).fetchone()
                    if live_audit is None:
                        raise IngestionPipelineError(
                            "retention operation journal is missing"
                        )
                    try:
                        live_state = _RetentionCleanupState(str(live_audit["state"]))
                    except ValueError as error:
                        raise IngestionPipelineError(
                            "retention operation journal has an invalid state"
                        ) from error
                    if live_state is _RetentionCleanupState.COMPLETED:
                        emit_operational_event(
                            "retention.run.replayed",
                            run_id=telemetry.run_id,
                            audit_id=audit_id,
                            outcome="completed_during_resume",
                        )
                        return report_from_json(live_audit["report_json"])
                    if live_state is not _RetentionCleanupState.CLEANUP_PENDING:
                        raise IngestionPipelineError(
                            "retention operation journal has an invalid state"
                        )

                    placeholders = ",".join("?" for _item in batch)
                    merge_progress_rows(
                        connection.execute(
                            "SELECT sequence, state, deleted_bytes, detail "
                            "FROM ingestion_retention_cleanup_progress "
                            f"WHERE audit_id = ? AND sequence IN ({placeholders})",
                            (audit_id, *(item.sequence for item in batch)),
                        ).fetchall()
                    )
                    batch_pending = [
                        item for item in batch if item.sequence not in progress
                    ]
                    batch_outcomes: list[
                        tuple[
                            _RetentionWorkItem,
                            _RetentionCleanupState,
                            int,
                            str | None,
                        ]
                    ] = []
                    for item in batch_pending:
                        state, deleted_bytes, detail = (
                            self._process_retention_work_item(
                                item,
                                connection=connection,
                            )
                        )
                        batch_outcomes.append((item, state, deleted_bytes, detail))

                    if not batch_outcomes:
                        continue
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        transaction_state = connection.execute(
                            "SELECT state FROM ingestion_retention_audit "
                            "WHERE audit_id = ?",
                            (audit_id,),
                        ).fetchone()
                        if transaction_state is None:
                            raise IngestionPipelineError(
                                "retention operation journal is missing"
                            )
                        if (
                            str(transaction_state["state"])
                            != _RetentionCleanupState.CLEANUP_PENDING.value
                        ):
                            raise IngestionPipelineError(
                                "retention operation journal changed during cleanup"
                            )
                        checkpointed_rows: list[sqlite3.Row] = []
                        checkpointed_at = time.time_ns()
                        for item, state, deleted_bytes, detail in batch_outcomes:
                            connection.execute(
                                """
                                INSERT INTO ingestion_retention_cleanup_progress (
                                    audit_id, sequence, state, deleted_bytes,
                                    detail, updated_at_ns
                                ) VALUES (?, ?, ?, ?, ?, ?)
                                ON CONFLICT(audit_id, sequence) DO NOTHING
                                """,
                                (
                                    audit_id,
                                    item.sequence,
                                    state.value,
                                    deleted_bytes,
                                    detail,
                                    checkpointed_at,
                                ),
                            )
                            stored = connection.execute(
                                """
                                SELECT sequence, state, deleted_bytes, detail
                                FROM ingestion_retention_cleanup_progress
                                WHERE audit_id = ? AND sequence = ?
                                """,
                                (audit_id, item.sequence),
                            ).fetchone()
                            if stored is None:
                                raise IngestionPipelineError(
                                    "retention cleanup checkpoint was not persisted"
                                )
                            checkpointed_rows.append(stored)
                    except BaseException:
                        connection.rollback()
                        raise
                    else:
                        connection.commit()
                    merge_progress_rows(checkpointed_rows)
                    batch_states = [
                        progress_states[item.sequence]
                        for item in batch_pending
                        if item.sequence in progress_states
                    ]
                    emit_operational_event(
                        "retention.cleanup.batch_completed",
                        run_id=telemetry.run_id,
                        audit_id=audit_id,
                        batch_index=(offset // RETENTION_CLEANUP_FENCE_BATCH) + 1,
                        attempted_items=len(batch_pending),
                        checkpointed_items=len(checkpointed_rows),
                        deleted_items=sum(
                            state is _RetentionCleanupState.DELETED
                            for state in batch_states
                        ),
                        skipped_items=sum(
                            state is _RetentionCleanupState.SKIPPED
                            for state in batch_states
                        ),
                        failed_items=sum(
                            state is _RetentionCleanupState.FAILED
                            for state in batch_states
                        ),
                        deleted_bytes=sum(
                            int(progress[item.sequence]["bytes"])
                            for item in batch_pending
                            if item.sequence in progress
                            and progress_states[item.sequence]
                            is _RetentionCleanupState.DELETED
                        ),
                        remaining_items=len(items) - len(progress),
                        duration_ms=self._retention_duration_ms(
                            batch_started_monotonic_ns
                        ),
                    )

            ordered_outcomes = [progress[item.sequence] for item in items]
            failures = tuple(
                str(outcome["detail"])
                for sequence, outcome in zip(
                    (item.sequence for item in items),
                    ordered_outcomes,
                    strict=True,
                )
                if progress_states[sequence] is _RetentionCleanupState.FAILED
                and outcome["detail"] is not None
            )
            result = replace(
                provisional,
                deleted_files=sum(
                    state is _RetentionCleanupState.DELETED
                    for state in progress_states.values()
                ),
                deleted_bytes=sum(
                    int(outcome["bytes"])
                    for sequence, outcome in zip(
                        (item.sequence for item in items),
                        ordered_outcomes,
                        strict=True,
                    )
                    if progress_states[sequence] is _RetentionCleanupState.DELETED
                ),
                deletion_failures=sum(
                    state is _RetentionCleanupState.FAILED
                    for state in progress_states.values()
                ),
                failure_details=failures[:100],
            )
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE ingestion_retention_audit
                SET report_json = ?, state = 'completed'
                WHERE audit_id = ? AND state = 'cleanup_pending'
                """,
                (canonical_json(result.as_dict()), audit_id),
            ).rowcount
            if updated != 1:
                connection.rollback()
                completed = connection.execute(
                    """
                    SELECT state, report_json
                    FROM ingestion_retention_audit
                    WHERE audit_id = ? AND tenant_id = ?
                      AND project_id = ? AND workspace_id = ?
                    """,
                    (audit_id, *self._scope_predicate(scope)),
                ).fetchone()
                if (
                    completed is not None
                    and str(completed["state"])
                    == _RetentionCleanupState.COMPLETED.value
                ):
                    emit_operational_event(
                        "retention.run.replayed",
                        run_id=telemetry.run_id,
                        audit_id=audit_id,
                        outcome="completed_during_commit",
                    )
                    return report_from_json(completed["report_json"])
                raise IngestionPipelineError(
                    "retention operation journal changed before completion"
                )
            connection.commit()
        telemetry.phase = "completed"
        emit_operational_event(
            "retention.run.completed",
            run_id=telemetry.run_id,
            audit_id=audit_id,
            deleted_imports=result.deleted_imports,
            deleted_files=result.deleted_files,
            deleted_bytes=result.deleted_bytes,
            deletion_failures=result.deletion_failures,
            truncated=result.truncated,
            duration_ms=self._retention_duration_ms(telemetry.started_monotonic_ns),
        )
        return result

    def run_retention(
        self,
        scope: ImportScope,
        *,
        dry_run: bool = True,
        now_ns: int | None = None,
        actor: str = "system",
        operation_id: str | None = None,
    ) -> RetentionReport:
        """Inventory or execute one bounded, audited retention batch.

        Destructive callers may supply ``operation_id`` to make the complete
        database-and-filesystem operation exactly replayable. Reusing that
        identifier with the same actor, requested clock, scope, and policy
        resumes an interrupted cleanup or returns its stable final report;
        reusing it for any different request fails before mutation. Host scan
        progress is serialized separately so directory discovery does not
        occupy the upload/publication fence.
        """

        if type(dry_run) is not bool:
            raise ValueError("dry_run must be a boolean")
        if now_ns is not None and (type(now_ns) is not int or now_ns < 0):
            raise ValueError("now_ns must be a non-negative integer or None")
        retention_actor = _bounded_text(
            actor,
            "retention actor",
            MAX_RETENTION_ACTOR_LENGTH,
        )
        retention_operation_id = None
        if operation_id is not None:
            retention_operation_id = _bounded_identifier(
                operation_id,
                "retention operation_id",
                MAX_RETENTION_OPERATION_ID_LENGTH,
            )
        telemetry = _RetentionTelemetryContext(
            run_id=f"run-{uuid4().hex}",
            started_monotonic_ns=time.monotonic_ns(),
        )
        emit_operational_event(
            "retention.run.started",
            run_id=telemetry.run_id,
            mode="preview" if dry_run else "execute",
            policy_enabled=self.retention_policy.enabled,
            idempotent=retention_operation_id is not None,
            max_delete_batch=self.retention_policy.max_delete_batch,
            max_scan_entries=self.retention_policy.max_scan_entries,
        )
        try:
            return self._run_retention_operation(
                scope,
                dry_run=dry_run,
                now_ns=now_ns,
                actor=retention_actor,
                operation_id=retention_operation_id,
                telemetry=telemetry,
            )
        except BaseException as error:
            failure_fields: dict[str, bool | int | str] = {
                "run_id": telemetry.run_id,
                "phase": telemetry.phase,
                "error_family": self._retention_error_family(error),
                "mutation_started": telemetry.mutation_started,
            }
            if telemetry.audit_id is not None:
                failure_fields["audit_id"] = telemetry.audit_id
            emit_operational_event("retention.run.failed", **failure_fields)
            raise

    def _run_retention_operation(
        self,
        scope: ImportScope,
        *,
        dry_run: bool,
        now_ns: int | None,
        actor: str,
        operation_id: str | None,
        telemetry: _RetentionTelemetryContext,
    ) -> RetentionReport:
        # A preview is an advisory read, not a retention operation.  Keeping
        # this branch outside the destructive-operation lock lets operators
        # inspect the current database/filesystem projection while another
        # process applies a previously committed cleanup plan.  Each SQLite
        # inventory query is snapshot-safe and filesystem races already fail
        # conservatively in ``_build_retention_plan``; the combined view is
        # intentionally best-effort rather than a cross-store transaction.
        if dry_run:
            effective_now = self._now_ns() if now_ns is None else now_ns
            assert isinstance(effective_now, int)
            return self._run_retention_preview(
                scope,
                now_ns=effective_now,
                telemetry=telemetry,
            )
        with exclusive_file_lock(self._retention_operation_lock_path):
            # Resolve an exact replay before consulting a new wall clock or
            # walking any host root.  The persisted effective time and plan
            # are the authoritative continuation of that operation.
            telemetry.phase = "replay_lookup"
            if not dry_run and operation_id is not None:
                request_digest = self._retention_request_digest(
                    scope,
                    actor=actor,
                    operation_id=operation_id,
                    requested_now_ns=now_ns,
                )
                with self._connect() as connection:
                    existing = connection.execute(
                        """
                        SELECT * FROM ingestion_retention_audit
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND operation_id = ?
                        """,
                        (
                            *self._scope_predicate(scope),
                            operation_id,
                        ),
                    ).fetchone()
                if existing is not None:
                    if (
                        existing["actor"] != actor
                        or existing["request_digest"] != request_digest
                    ):
                        raise ImportConflictError(
                            "retention operation_id was already used for a "
                            "different request"
                        )
                    return self._resume_retention_cleanup(
                        scope,
                        audit_id=str(existing["audit_id"]),
                        telemetry=telemetry,
                        resumed=True,
                    )
            if not dry_run and operation_id is None:
                # An anonymous destructive call has no caller-supplied replay
                # key, but its durable cleanup journal is still authoritative.
                # Resume the oldest interrupted anonymous operation before
                # planning another batch so crashes cannot strand permanent
                # cleanup_pending rows or repeatedly delete around them.
                with self._connect() as connection:
                    interrupted = connection.execute(
                        """
                        SELECT audit_id FROM ingestion_retention_audit
                        WHERE tenant_id = ? AND project_id = ?
                          AND workspace_id = ? AND operation_id IS NULL
                          AND state = 'cleanup_pending'
                        ORDER BY created_at_ns, audit_id LIMIT 1
                        """,
                        self._scope_predicate(scope),
                    ).fetchone()
                if interrupted is not None:
                    telemetry.phase = "anonymous_replay"
                    return self._resume_retention_cleanup(
                        scope,
                        audit_id=str(interrupted["audit_id"]),
                        telemetry=telemetry,
                        resumed=True,
                    )
            if not dry_run and not self.retention_policy.enabled:
                raise IngestionPipelineError(
                    "destructive retention is disabled by policy"
                )
            effective_now = self._now_ns() if now_ns is None else now_ns
            assert isinstance(effective_now, int)
            telemetry.phase = "host_scan"
            host_scan = self._scan_host_cleanup(now_ns=effective_now)
            telemetry.phase = "advisory_plan"
            advisory_plan = self._build_retention_plan(
                scope,
                now_ns=effective_now,
                host_scan=host_scan,
            )
            return self._run_retention_under_fence(
                scope,
                dry_run=dry_run,
                now_ns=now_ns,
                actor=actor,
                operation_id=operation_id,
                host_scan=host_scan,
                effective_now_override=effective_now,
                precomputed_path_sizes=dict(advisory_plan.path_sizes),
                telemetry=telemetry,
            )

    def _run_retention_preview(
        self,
        scope: ImportScope,
        *,
        now_ns: int,
        telemetry: _RetentionTelemetryContext,
        host_scan: _HostRetentionScan | None = None,
    ) -> RetentionReport:
        """Return one non-mutating, best-effort retention observation."""

        telemetry.phase = "preview"
        plan = self._build_retention_plan(
            scope,
            now_ns=now_ns,
            host_scan=host_scan,
        )
        self._emit_retention_truncations(telemetry, plan)
        emit_operational_event(
            "retention.preview.completed",
            run_id=telemetry.run_id,
            eligible_imports=plan.report.eligible_imports,
            content_blobs=plan.report.content_blobs,
            revision_datasets=plan.report.revision_datasets,
            stale_partials=plan.report.stale_partials,
            work_items=self._retention_work_item_count(plan),
            truncated=plan.report.truncated,
            duration_ms=self._retention_duration_ms(telemetry.started_monotonic_ns),
        )
        telemetry.phase = "completed"
        return plan.report

    def _run_retention_under_fence(
        self,
        scope: ImportScope,
        *,
        dry_run: bool = True,
        now_ns: int | None = None,
        actor: str = "system",
        operation_id: str | None = None,
        host_scan: _HostRetentionScan | None = None,
        effective_now_override: int | None = None,
        precomputed_path_sizes: Mapping[Path, int] | None = None,
        telemetry: _RetentionTelemetryContext | None = None,
    ) -> RetentionReport:
        """Apply a validated scan and scoped plan under the publication fence."""

        if type(dry_run) is not bool:
            raise ValueError("dry_run must be a boolean")
        if now_ns is not None and (type(now_ns) is not int or now_ns < 0):
            raise ValueError("now_ns must be a non-negative integer or None")
        retention_actor = _bounded_text(
            actor,
            "retention actor",
            MAX_RETENTION_ACTOR_LENGTH,
        )
        retention_operation_id = (
            None
            if operation_id is None
            else _bounded_identifier(
                operation_id,
                "retention operation_id",
                MAX_RETENTION_OPERATION_ID_LENGTH,
            )
        )
        if telemetry is None:
            telemetry = _RetentionTelemetryContext(
                run_id=f"run-{uuid4().hex}",
                started_monotonic_ns=time.monotonic_ns(),
            )
        effective_now = (
            self._now_ns()
            if effective_now_override is None and now_ns is None
            else (
                effective_now_override if effective_now_override is not None else now_ns
            )
        )
        assert isinstance(effective_now, int)
        if dry_run:
            return self._run_retention_preview(
                scope,
                now_ns=effective_now,
                host_scan=host_scan,
                telemetry=telemetry,
            )
        if precomputed_path_sizes is None:
            telemetry.phase = "advisory_plan"
            advisory_plan = self._build_retention_plan(
                scope,
                now_ns=effective_now,
                host_scan=host_scan,
            )
            precomputed_path_sizes = dict(advisory_plan.path_sizes)
        request_digest: str | None = None
        if retention_operation_id is not None:
            telemetry.phase = "replay_lookup"
            request_digest = self._retention_request_digest(
                scope,
                actor=retention_actor,
                operation_id=retention_operation_id,
                requested_now_ns=now_ns,
            )
            with self._connect() as connection:
                existing = connection.execute(
                    """
                    SELECT * FROM ingestion_retention_audit
                    WHERE tenant_id = ? AND project_id = ?
                      AND workspace_id = ? AND operation_id = ?
                    """,
                    (
                        *self._scope_predicate(scope),
                        retention_operation_id,
                    ),
                ).fetchone()
            if existing is not None:
                if (
                    existing["actor"] != retention_actor
                    or existing["request_digest"] != request_digest
                ):
                    raise ImportConflictError(
                        "retention operation_id was already used for a "
                        "different request"
                    )
                return self._resume_retention_cleanup(
                    scope,
                    audit_id=str(existing["audit_id"]),
                    telemetry=telemetry,
                    resumed=True,
                )

        if not self.retention_policy.enabled:
            raise IngestionPipelineError("destructive retention is disabled by policy")
        telemetry.phase = "plan_commit"
        with exclusive_file_lock(self._maintenance_lock_path):
            plan = self._build_retention_plan(
                scope,
                now_ns=effective_now,
                host_scan=host_scan,
                precomputed_path_sizes=precomputed_path_sizes,
                measure_path_sizes=False,
            )
            audit_id = f"retention-{uuid4().hex}"
            plan_json = self._serialize_retention_plan(plan)
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                deleted_imports = 0
                for import_id in plan.import_ids:
                    deleted_imports += connection.execute(
                        """
                        DELETE FROM ingestion_imports
                        WHERE import_id = ? AND tenant_id = ?
                          AND project_id = ? AND workspace_id = ?
                          AND state IN (?, ?, ?)
                        """,
                        (
                            import_id,
                            *self._scope_predicate(scope),
                            ImportState.COMPLETED.value,
                            ImportState.FAILED.value,
                            ImportState.CANCELLED.value,
                        ),
                    ).rowcount
                for rowid in plan.receipt_rowids:
                    connection.execute(
                        "DELETE FROM ingestion_idempotency WHERE rowid = ?",
                        (rowid,),
                    )
                deleted_retention_audits = 0
                for expired_audit_id in plan.audit_ids:
                    deleted_retention_audits += connection.execute(
                        """
                        DELETE FROM ingestion_retention_audit
                        WHERE audit_id = ? AND tenant_id = ?
                          AND project_id = ? AND workspace_id = ?
                          AND state = 'completed'
                        """,
                        (
                            expired_audit_id,
                            *self._scope_predicate(scope),
                        ),
                    ).rowcount
                for root_name, cursor in plan.host_cursors:
                    connection.execute(
                        """
                        INSERT INTO ingestion_host_retention_cursor (
                            root_name, cursor, updated_at_ns
                        ) VALUES (?, ?, ?)
                        ON CONFLICT(root_name) DO UPDATE SET
                            cursor = excluded.cursor,
                            updated_at_ns = excluded.updated_at_ns
                        """,
                        (root_name, cursor, effective_now),
                    )
                provisional = replace(
                    plan.report,
                    executed=True,
                    deleted_imports=deleted_imports,
                    deleted_retention_audits=deleted_retention_audits,
                    audit_id=audit_id,
                )
                connection.execute(
                    """
                    INSERT INTO ingestion_retention_audit (
                        audit_id, tenant_id, project_id, workspace_id,
                        report_json, created_at_ns, actor, operation_id,
                        request_digest, effective_now_ns, plan_json,
                        cleanup_progress_json, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}',
                              'cleanup_pending')
                    """,
                    (
                        audit_id,
                        *self._scope_predicate(scope),
                        canonical_json(provisional.as_dict()),
                        effective_now,
                        retention_actor,
                        retention_operation_id,
                        request_digest,
                        effective_now,
                        plan_json,
                    ),
                )
                connection.commit()
                # Attribute any failure after the durable transaction to the
                # committed audit before either enclosing context can exit.
                telemetry.audit_id = audit_id
                telemetry.mutation_started = True
        self._emit_retention_truncations(telemetry, plan)
        emit_operational_event(
            "retention.plan.committed",
            run_id=telemetry.run_id,
            audit_id=audit_id,
            eligible_imports=plan.report.eligible_imports,
            work_items=len(self._deserialize_retention_work_items(plan_json)),
            truncated=plan.report.truncated,
        )
        return self._resume_retention_cleanup(
            scope,
            audit_id=audit_id,
            telemetry=telemetry,
            resumed=False,
        )

    def list_retention_audits(
        self,
        scope: ImportScope,
        *,
        limit: int = 100,
    ) -> tuple[RetentionAuditRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM ingestion_retention_audit
                WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
                ORDER BY created_at_ns DESC, audit_id DESC LIMIT ?
                """,
                (*self._scope_predicate(scope), limit),
            ).fetchall()
        return tuple(
            RetentionAuditRecord(
                audit_id=str(row["audit_id"]),
                scope=scope,
                created_at_ns=int(row["created_at_ns"]),
                report=json.loads(str(row["report_json"])),
                actor=(None if row["actor"] is None else str(row["actor"])),
                operation_id=(
                    None if row["operation_id"] is None else str(row["operation_id"])
                ),
                request_digest=(
                    None
                    if row["request_digest"] is None
                    else str(row["request_digest"])
                ),
                effective_now_ns=(
                    None
                    if row["effective_now_ns"] is None
                    else int(row["effective_now_ns"])
                ),
                state=str(row["state"]),
            )
            for row in rows
        )

    def release_artifact_pin(
        self,
        scope: ImportScope,
        *,
        artifact_kind: str,
        artifact_ref: str,
        owner_operation_id: str,
    ) -> bool:
        """Release one exact catalog ownership pin after coordinated deletion.

        This method never deletes the file itself. The coordinated retention
        pass may delete it while processing its still-eligible scoped queue
        row. Once no queue row derives the artifact, an explicit bounded
        host-reaper pass may later identify and delete it after the configured
        orphan grace period.
        """

        if artifact_kind not in {"blob", "dataset"}:
            raise ValueError("artifact_kind must be 'blob' or 'dataset'")
        _bounded_text(artifact_ref, "artifact_ref", 2_048)
        _bounded_text(owner_operation_id, "owner_operation_id", 512)
        if (
            "\\" in artifact_ref
            or Path(artifact_ref).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(artifact_ref).parts)
        ):
            raise ValueError("artifact_ref must be a safe relative POSIX path")
        with (
            exclusive_file_lock(self._maintenance_lock_path),
            self._connect() as connection,
        ):
            deleted = connection.execute(
                """
                DELETE FROM ingestion_artifact_pins
                WHERE artifact_kind = ? AND artifact_ref = ?
                  AND tenant_id = ? AND project_id = ?
                  AND workspace_id = ? AND owner_operation_id = ?
                """,
                (
                    artifact_kind,
                    artifact_ref,
                    *self._scope_predicate(scope),
                    owner_operation_id,
                ),
            ).rowcount
        return deleted == 1

    def get_import(
        self,
        scope: ImportScope,
        import_id: str,
    ) -> ImportDescriptor:
        _bounded_identifier(import_id, "import_id", MAX_IMPORT_ID_LENGTH)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM ingestion_imports
                WHERE import_id = ? AND tenant_id = ?
                  AND project_id = ? AND workspace_id = ?
                """,
                (import_id, *self._scope_predicate(scope)),
            ).fetchone()
        if row is None:
            raise ImportNotFoundError(import_id)
        return self._descriptor(row)

    def list_imports(
        self,
        scope: ImportScope,
        *,
        limit: int = 100,
        before_created_at_ns: int | None = None,
        before_import_id: str | None = None,
    ) -> tuple[ImportDescriptor, ...]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        query = """
            SELECT *
            FROM ingestion_imports
            WHERE tenant_id = ? AND project_id = ? AND workspace_id = ?
        """
        parameters: list[Any] = [*self._scope_predicate(scope)]
        if before_created_at_ns is not None:
            if not isinstance(before_created_at_ns, int) or isinstance(
                before_created_at_ns, bool
            ):
                raise ValueError("before_created_at_ns must be an integer or None")
            if before_import_id is None:
                raise ValueError(
                    "before_import_id is required with before_created_at_ns"
                )
            _bounded_identifier(
                before_import_id,
                "before_import_id",
                MAX_IMPORT_ID_LENGTH,
            )
            query += " AND (created_at_ns < ? OR (created_at_ns = ? AND import_id < ?))"
            parameters.extend(
                (
                    before_created_at_ns,
                    before_created_at_ns,
                    before_import_id,
                )
            )
        elif before_import_id is not None:
            raise ValueError("before_created_at_ns is required with before_import_id")
        query += " ORDER BY created_at_ns DESC, import_id DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(self._descriptor(row) for row in rows)

    def candidates(
        self,
        scope: ImportScope,
        import_id: str,
    ) -> tuple[PluginCandidate, ...]:
        self.get_import(scope, import_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM ingestion_candidates
                WHERE import_id = ?
                ORDER BY ordinal
                """,
                (import_id,),
            ).fetchall()
        return tuple(
            PluginCandidate(**json.loads(str(row["payload_json"]))) for row in rows
        )

    def events(
        self,
        scope: ImportScope,
        import_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 200,
    ) -> tuple[ImportEvent, ...]:
        self.get_import(scope, import_id)
        if (
            not isinstance(after_sequence, int)
            or isinstance(after_sequence, bool)
            or after_sequence < 0
        ):
            raise ValueError("after_sequence must be a non-negative integer")
        if not 1 <= limit <= MAX_IMPORT_EVENTS_PAGE:
            raise ValueError(f"limit must be between 1 and {MAX_IMPORT_EVENTS_PAGE}")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM ingestion_events
                WHERE import_id = ? AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (import_id, after_sequence, limit),
            ).fetchall()
        return tuple(self._event_descriptor(row) for row in rows)

    @staticmethod
    def _event_descriptor(row: sqlite3.Row) -> ImportEvent:
        event_type = str(row["event_type"])
        payload = json.loads(str(row["payload_json"]))
        message = str(row["message"])
        if event_type == "import_failed":
            raw_code = payload.get("error_code") if isinstance(payload, dict) else None
            code = _normalized_public_failure_code(
                raw_code if isinstance(raw_code, str) else None
            )
            message = PUBLIC_INGESTION_FAILURE_MESSAGES[code]
            payload = {"error_code": code}
        if not isinstance(payload, dict):
            raise IngestionPipelineError("stored import event payload is not an object")
        return ImportEvent(
            sequence=int(row["sequence"]),
            import_id=str(row["import_id"]),
            state=ImportState(str(row["state"])),
            event_type=event_type,
            message=message,
            payload=payload,
            created_at_ns=int(row["created_at_ns"]),
        )

    def select_plugin(
        self,
        scope: ImportScope,
        import_id: str,
        *,
        probe_set_hash: str,
        plugin_id: str,
        plugin_version: str,
        package_hash: str,
        idempotency_key: str,
        instance_id: str | None = None,
        registered_execution_identity: str | None = None,
    ) -> ImportDescriptor:
        for label, value, maximum in (
            ("probe_set_hash", probe_set_hash, 256),
            ("plugin_id", plugin_id, 256),
            ("plugin_version", plugin_version, 128),
            ("package_hash", package_hash, 256),
            (
                "idempotency_key",
                idempotency_key,
                MAX_IDEMPOTENCY_KEY_LENGTH,
            ),
        ):
            _bounded_text(value, label, maximum)
        if instance_id is not None:
            _bounded_identifier(instance_id, "instance_id", 256)
        if registered_execution_identity is not None:
            _bounded_identifier(
                registered_execution_identity,
                "registered_execution_identity",
                71,
            )
            if (
                len(registered_execution_identity) != 71
                or not registered_execution_identity.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in registered_execution_identity[7:]
                )
            ):
                raise ValueError("registered_execution_identity is invalid")
        if (instance_id is None) != (registered_execution_identity is None):
            raise ValueError(
                "instance_id and registered_execution_identity must be "
                "provided together"
            )
        request_material: dict[str, Any] = {
            "import_id": import_id,
            "probe_set_hash": probe_set_hash,
            "plugin_id": plugin_id,
            "plugin_version": plugin_version,
            "package_hash": package_hash,
        }
        if instance_id is not None:
            request_material["instance_id"] = instance_id
        if registered_execution_identity is not None:
            request_material["registered_execution_identity"] = (
                registered_execution_identity
            )
        request_digest = hashlib.sha256(
            canonical_json(request_material).encode("utf-8")
        ).hexdigest()
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT *
                FROM ingestion_imports
                WHERE import_id = ? AND tenant_id = ?
                  AND project_id = ? AND workspace_id = ?
                """,
                (import_id, *self._scope_predicate(scope)),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ImportNotFoundError(import_id)
            receipt = connection.execute(
                """
                SELECT request_digest, import_id
                FROM ingestion_idempotency
                WHERE tenant_id = ? AND project_id = ?
                  AND workspace_id = ? AND operation = ?
                  AND idempotency_key = ?
                """,
                (
                    *self._scope_predicate(scope),
                    "select_plugin",
                    idempotency_key,
                ),
            ).fetchone()
            if receipt is not None:
                if (
                    receipt["request_digest"] != request_digest
                    or receipt["import_id"] != import_id
                ):
                    connection.rollback()
                    raise ImportConflictError(
                        "idempotency key was already used for a different "
                        "plug-in selection request"
                    )
                connection.rollback()
                return self._descriptor(row)
            candidate_rows = connection.execute(
                """
                SELECT instance_id, registered_execution_identity
                FROM ingestion_candidates
                WHERE import_id = ? AND plugin_id = ?
                  AND plugin_version = ? AND package_hash = ?
                """,
                (
                    import_id,
                    plugin_id,
                    plugin_version,
                    package_hash,
                ),
            ).fetchall()
            matching_candidates = tuple(
                candidate
                for candidate in candidate_rows
                if (instance_id is None or candidate["instance_id"] == instance_id)
                and (
                    registered_execution_identity is None
                    or candidate["registered_execution_identity"]
                    == registered_execution_identity
                )
            )
            if len(matching_candidates) != 1:
                connection.rollback()
                raise ImportConflictError(
                    "selected plug-in coordinate is absent or ambiguous in "
                    "this probe set"
                )
            candidate = matching_candidates[0]
            if (
                row["selected_plugin_id"] == plugin_id
                and row["selected_plugin_version"] == plugin_version
                and row["selected_package_hash"] == package_hash
                and row["selected_execution_identity"]
                == candidate["registered_execution_identity"]
                and row["probe_set_hash"] == probe_set_hash
                and ImportState(str(row["state"]))
                in {
                    ImportState.READY,
                    ImportState.INGESTING,
                    ImportState.PUBLISHING,
                    ImportState.COMPLETED,
                    ImportState.FAILED,
                }
            ):
                connection.execute(
                    """
                    INSERT INTO ingestion_idempotency (
                        tenant_id, project_id, workspace_id, operation,
                        idempotency_key, request_digest, import_id,
                        created_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *self._scope_predicate(scope),
                        "select_plugin",
                        idempotency_key,
                        request_digest,
                        import_id,
                        now,
                    ),
                )
                connection.commit()
                return self._descriptor(row)
            if row["state"] != ImportState.AWAITING_SELECTION.value:
                connection.rollback()
                raise ImportConflictError(
                    "the import is not awaiting plug-in selection"
                )
            if row["probe_set_hash"] != probe_set_hash:
                connection.rollback()
                raise ImportConflictError("stale probe_set_hash")
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    selected_plugin_id = ?,
                    selected_plugin_version = ?,
                    selected_package_hash = ?,
                    selected_execution_identity = ?,
                    error_code = NULL, error_message = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (
                    ImportState.READY.value,
                    plugin_id,
                    plugin_version,
                    package_hash,
                    candidate["registered_execution_identity"],
                    now,
                    import_id,
                ),
            )
            self._append_event(
                connection,
                import_id,
                ImportState.READY,
                "plugin_selected",
                "Plug-in selection accepted; import is ready.",
                {
                    "plugin_id": plugin_id,
                    "plugin_version": plugin_version,
                    "idempotency_key": idempotency_key,
                },
                now=now,
            )
            connection.execute(
                """
                INSERT INTO ingestion_idempotency (
                    tenant_id, project_id, workspace_id, operation,
                    idempotency_key, request_digest, import_id,
                    created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *self._scope_predicate(scope),
                    "select_plugin",
                    idempotency_key,
                    request_digest,
                    import_id,
                    now,
                ),
            )
            updated_row = connection.execute(
                "SELECT * FROM ingestion_imports WHERE import_id = ?",
                (import_id,),
            ).fetchone()
            assert updated_row is not None
            connection.commit()
        self._wake.set()
        return self._descriptor(updated_row)

    def resume(
        self,
        scope: ImportScope,
        import_id: str,
    ) -> ImportDescriptor:
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT *
                FROM ingestion_imports
                WHERE import_id = ? AND tenant_id = ?
                  AND project_id = ? AND workspace_id = ?
                """,
                (import_id, *self._scope_predicate(scope)),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ImportNotFoundError(import_id)
            state = ImportState(str(row["state"]))
            if state in {
                ImportState.ADMITTING,
                ImportState.QUEUED,
                ImportState.PROBING,
                ImportState.READY,
                ImportState.INGESTING,
                ImportState.PUBLISHING,
                ImportState.AWAITING_SELECTION,
                ImportState.COMPLETED,
            }:
                connection.rollback()
                return self._descriptor(row)
            if state is ImportState.CANCELLED:
                connection.rollback()
                raise ImportConflictError("a cancelled import cannot be resumed")
            if int(row["attempt_count"]) >= self.limits.max_attempts:
                connection.rollback()
                raise ImportConflictError(
                    "the import exhausted its configured attempt limit"
                )
            next_state = (
                ImportState.PUBLISHING
                if row["publication_operation_id"] is not None
                else (
                    ImportState.ADMITTING
                    if not bool(row["catalog_fixture_admitted"])
                    else (
                        ImportState.READY
                        if row["selected_plugin_id"]
                        else ImportState.QUEUED
                    )
                )
            )
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    error_code = NULL, error_message = NULL,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (next_state.value, now, import_id),
            )
            self._append_event(
                connection,
                import_id,
                next_state,
                "import_resumed",
                "Import requeued from its last durable stage.",
                {},
                now=now,
            )
            updated_row = connection.execute(
                "SELECT * FROM ingestion_imports WHERE import_id = ?",
                (import_id,),
            ).fetchone()
            assert updated_row is not None
            connection.commit()
        self._wake.set()
        return self._descriptor(updated_row)

    def cancel(
        self,
        scope: ImportScope,
        import_id: str,
        *,
        expected_version: int,
    ) -> ImportDescriptor:
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
        ):
            raise ValueError("expected_version must be a positive integer")
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT *
                FROM ingestion_imports
                WHERE import_id = ? AND tenant_id = ?
                  AND project_id = ? AND workspace_id = ?
                """,
                (import_id, *self._scope_predicate(scope)),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ImportNotFoundError(import_id)
            state = ImportState(str(row["state"]))
            if state is ImportState.CANCELLED:
                connection.rollback()
                return self._descriptor(row)
            if int(row["version"]) != expected_version:
                connection.rollback()
                raise ImportConflictError("stale import version")
            if state.terminal:
                connection.rollback()
                raise ImportConflictError("a terminal import cannot be cancelled")
            if state in {
                ImportState.ADMITTING,
                ImportState.PROBING,
                ImportState.INGESTING,
                ImportState.PUBLISHING,
            }:
                connection.rollback()
                raise ImportConflictError(
                    "an in-progress import cannot be cancelled; retry after "
                    "the active stage reaches a durable boundary"
                )
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (ImportState.CANCELLED.value, now, import_id),
            )
            self._append_event(
                connection,
                import_id,
                ImportState.CANCELLED,
                "import_cancelled",
                "Import cancelled by the caller.",
                {},
                now=now,
            )
            updated_row = connection.execute(
                "SELECT * FROM ingestion_imports WHERE import_id = ?",
                (import_id,),
            ).fetchone()
            assert updated_row is not None
            connection.commit()
        return self._descriptor(updated_row)

    def wait(
        self,
        scope: ImportScope,
        import_id: str,
        *,
        timeout: float,
        stop_at_selection: bool = True,
    ) -> ImportDescriptor:
        if timeout < 0:
            raise ValueError("timeout must be non-negative")
        deadline = time.monotonic() + timeout
        while True:
            descriptor = self.get_import(scope, import_id)
            if descriptor.state.terminal or (
                stop_at_selection and descriptor.state is ImportState.AWAITING_SELECTION
            ):
                return descriptor
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"import {import_id} did not reach a stopping state")
            self._wake.wait(min(0.1, remaining))
            self._wake.clear()

    def _claim(self) -> sqlite3.Row | None:
        now = self._now_ns()
        lease_expires = now + self.limits.lease_seconds * 1_000_000_000
        lease_token = f"{self.worker_id}:{uuid4().hex}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._recover_expired_jobs_locked(connection, now=now)
            row = connection.execute(
                """
                SELECT *
                FROM ingestion_imports
                WHERE state IN (?, ?, ?, ?)
                  AND (
                    lease_expires_ns IS NULL
                    OR lease_expires_ns < ?
                  )
                ORDER BY created_at_ns, import_id
                LIMIT 1
                """,
                (
                    ImportState.ADMITTING.value,
                    ImportState.QUEUED.value,
                    ImportState.READY.value,
                    ImportState.PUBLISHING.value,
                    now,
                ),
            ).fetchone()
            if row is None:
                connection.rollback()
                return None
            processing_state = {
                ImportState.ADMITTING.value: ImportState.ADMITTING,
                ImportState.QUEUED.value: ImportState.PROBING,
                ImportState.READY.value: ImportState.INGESTING,
                ImportState.PUBLISHING.value: ImportState.PUBLISHING,
            }[str(row["state"])]
            updated = connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    lease_owner = ?, lease_expires_ns = ?,
                    updated_at_ns = ?
                WHERE import_id = ? AND state = ?
                  AND (
                    lease_expires_ns IS NULL
                    OR lease_expires_ns < ?
                  )
                """,
                (
                    processing_state.value,
                    lease_token,
                    lease_expires,
                    now,
                    row["import_id"],
                    row["state"],
                    now,
                ),
            ).rowcount
            if updated != 1:
                connection.rollback()
                return None
            self._append_event(
                connection,
                str(row["import_id"]),
                processing_state,
                {
                    ImportState.ADMITTING: "admission_started",
                    ImportState.PROBING: "probe_started",
                    ImportState.INGESTING: "ingestion_started",
                    ImportState.PUBLISHING: "publication_started",
                }[processing_state],
                {
                    ImportState.ADMITTING: (
                        "Staged fixture catalog admission started."
                    ),
                    ImportState.PROBING: "Allowlisted plug-in probing started.",
                    ImportState.INGESTING: "Selected plug-in ingestion started.",
                    ImportState.PUBLISHING: (
                        "Staged immutable revision publication started."
                    ),
                }[processing_state],
                {"worker_id": self.worker_id},
                now=now,
            )
            connection.commit()
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM ingestion_imports WHERE import_id = ?",
                (row["import_id"],),
            ).fetchone()

    @staticmethod
    def _worker_error_label(error: BaseException) -> str:
        error_code = (
            getattr(error, "sqlite_errorname", None)
            if isinstance(error, sqlite3.Error)
            else None
        )
        return _truncate_text(
            f"{type(error).__name__}"
            + (f" ({error_code})" if isinstance(error_code, str) else ""),
            maximum=512,
        )

    def _should_log_worker_error(self, consecutive: int, *, phase: str) -> bool:
        """Log a time-bounded geometric sample rather than flooding."""

        geometric = consecutive == 1 or consecutive & (consecutive - 1) == 0
        if not geometric:
            return False
        now = time.monotonic()
        with self._lock:
            previous = self._last_worker_log_at[phase]
            if now - previous < 5.0:
                return False
            self._last_worker_log_at[phase] = now
        return True

    def _record_worker_error(self, error: BaseException, *, phase: str) -> int:
        label = self._worker_error_label(error)
        with self._lock:
            if phase == "claim":
                self._total_claim_errors += 1
                self._consecutive_claim_errors += 1
                self._last_claim_error_at_ns = self._now_ns()
                self._last_claim_error = label
                consecutive = self._consecutive_claim_errors
            else:
                self._total_iteration_errors += 1
                self._consecutive_iteration_errors += 1
                self._last_iteration_error_at_ns = self._now_ns()
                self._last_iteration_error = label
                consecutive = self._consecutive_iteration_errors
        if self._should_log_worker_error(consecutive, phase=phase):
            emit_operational_event(
                "ingestion.worker.failure_sampled",
                phase=phase,
                error_family=self._worker_error_family(error),
                consecutive=consecutive,
            )
        return consecutive

    @staticmethod
    def _worker_error_family(error: BaseException) -> str:
        if isinstance(error, sqlite3.Error):
            return "sqlite"
        if isinstance(error, SystemExit):
            return "system_exit"
        if isinstance(error, Exception):
            return "exception"
        return "base_exception"

    def _worker_entrypoint(self) -> None:
        """Attribute fatal thread exits without exposing exception messages."""

        try:
            self._worker_loop()
        except BaseException as error:  # noqa: BLE001 - last-resort attribution.
            label = self._worker_error_label(error)
            with self._lock:
                self._unexpected_worker_exits += 1
                self._last_worker_exit_at_ns = self._now_ns()
                self._last_worker_exit = label
                unexpected_worker_exits = self._unexpected_worker_exits
            emit_operational_event(
                "ingestion.worker.exited",
                error_family=self._worker_error_family(error),
                unexpected_worker_exits=unexpected_worker_exits,
            )

    def _worker_error_backoff(self, consecutive: int) -> None:
        ceiling = min(
            5.0,
            max(0.01, self.limits.poll_interval_seconds)
            * (2 ** min(consecutive - 1, 8)),
        )
        delay = ceiling * (0.75 + random.random() * 0.5)
        self._stop.wait(delay)

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                row = self._claim()
            except (Exception, SystemExit) as error:  # noqa: BLE001
                consecutive = self._record_worker_error(error, phase="claim")
                self._worker_error_backoff(consecutive)
                continue
            with self._lock:
                self._consecutive_claim_errors = 0
            if row is None:
                self._wake.wait(self.limits.poll_interval_seconds)
                self._wake.clear()
                continue
            try:
                # Validate the claimed stage before the heartbeat consumes any
                # other row coordinate. This preserves precise worker-health
                # attribution for a malformed claim; _run_claimed_stage still
                # rechecks the state under the composition-policy guard.
                ImportState(str(row["state"]))
                with self._lease_heartbeat(row):
                    try:
                        self._run_claimed_stage(row)
                    except (Exception, SystemExit) as error:  # noqa: BLE001
                        # The error becomes a bounded durable failure record.
                        self._fail_claimed_import(row, error)
            except (Exception, SystemExit) as error:  # noqa: BLE001
                consecutive = self._record_worker_error(
                    error,
                    phase="iteration",
                )
                self._worker_error_backoff(consecutive)
            else:
                with self._lock:
                    self._consecutive_iteration_errors = 0
            finally:
                self._wake.set()

    def _run_claimed_stage(self, row: sqlite3.Row) -> None:
        """Dispatch one claim only under its immutable composition policy."""

        # This guard deliberately precedes every stage-specific method. In
        # particular, admission and publication may call an external catalog
        # and therefore must not run once a restarted worker has a different
        # provider-composition policy from the admitted import.
        self._require_composition_policy(row)
        state = ImportState(str(row["state"]))
        if state is ImportState.ADMITTING:
            self._run_admission(row)
        elif state is ImportState.PROBING:
            self._run_probe(row)
        elif state is ImportState.INGESTING:
            self._run_ingestion(row)
        elif state is ImportState.PUBLISHING:
            self._run_publication(row)
        else:  # pragma: no cover - _claim returns only active stage states
            raise IngestionPipelineError("claimed import stage is invalid")

    def _run_admission(self, row: sqlite3.Row) -> None:
        """Replay one durably staged fixture-catalog admission."""

        operation_id = row["admission_operation_id"]
        if not isinstance(operation_id, str) or not operation_id:
            raise IngestionPipelineError(
                "staged fixture admission is missing its operation ID"
            )
        metadata = json.loads(str(row["metadata_json"]))
        if not isinstance(metadata, dict):
            raise IngestionPipelineError("stored import metadata is invalid")
        scope = ImportScope(
            tenant_id=str(row["tenant_id"]),
            project_id=str(row["project_id"]),
            workspace_id=str(row["workspace_id"]),
        )
        call_context = self._publisher_call_context(
            operation_id=operation_id,
            attempt_number=int(row["attempt_count"]) + 1,
        )
        self._pin_catalog_artifact(
            row,
            artifact_kind=_RetentionArtifactKind.BLOB,
            artifact_ref=str(row["blob_ref"]),
            operation_id=operation_id,
        )
        attempt_number = call_context.attempt_number
        emit_operational_event(
            "ingestion.catalog_call.started",
            import_id=str(row["import_id"]),
            stage="admission",
            operation_id=operation_id,
            attempt=attempt_number,
            timeout_ms=max(
                1,
                (
                    call_context.deadline_monotonic_ns
                    - call_context.started_monotonic_ns
                    + 999_999
                )
                // 1_000_000,
            ),
        )
        publisher_values: dict[str, Any] = {
            "operation_id": operation_id,
            "fixture_id": str(row["fixture_id"]),
            "content_sha256": str(row["content_sha256"]),
            "byte_count": int(row["byte_count"]),
            "original_name": str(row["original_name"]),
            "content_type": str(row["content_type"]),
            "blob_ref": str(row["blob_ref"]),
            "node_hint": (
                str(row["node_hint"]) if row["node_hint"] is not None else None
            ),
            "metadata": metadata,
            "call_context": call_context,
        }
        if (
            self.limits.effective_publisher_execution_mode
            is PluginExecutionMode.PROCESS
        ):
            _run_catalog_publisher_child(
                self.publisher_process_bootstrap,
                stage="admission",
                scope=scope,
                values=publisher_values,
                timeout_seconds=(
                    self.limits.effective_publisher_execution_timeout_seconds
                ),
            )
        else:
            self.publisher.admit_fixture(scope, **publisher_values)
        call_context.raise_if_expired()
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT state, lease_owner, admission_operation_id
                FROM ingestion_imports
                WHERE import_id = ?
                """,
                (row["import_id"],),
            ).fetchone()
            if (
                current is None
                or current["state"] != ImportState.ADMITTING.value
                or current["lease_owner"] != row["lease_owner"]
                or current["admission_operation_id"] != operation_id
            ):
                connection.rollback()
                reason = (
                    "import_missing"
                    if current is None
                    else (
                        "state_changed"
                        if current["state"] != ImportState.ADMITTING.value
                        else (
                            "lease_lost"
                            if current["lease_owner"] != row["lease_owner"]
                            else "operation_changed"
                        )
                    )
                )
                emit_operational_event(
                    "ingestion.catalog_call.discarded",
                    import_id=str(row["import_id"]),
                    stage="admission",
                    operation_id=operation_id,
                    attempt=attempt_number,
                    duration_ms=max(
                        0,
                        (time.monotonic_ns() - call_context.started_monotonic_ns)
                        // 1_000_000,
                    ),
                    reason=reason,
                    remote_acknowledged=True,
                )
                return
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    catalog_fixture_admitted = 1,
                    error_code = NULL, error_message = NULL,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (
                    ImportState.QUEUED.value,
                    now,
                    row["import_id"],
                ),
            )
            connection.execute(
                """
                INSERT INTO ingestion_artifact_pins (
                    artifact_kind, artifact_ref,
                    tenant_id, project_id, workspace_id,
                    owner_operation_id, created_at_ns
                ) VALUES ('blob', ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    row["blob_ref"],
                    row["tenant_id"],
                    row["project_id"],
                    row["workspace_id"],
                    operation_id,
                    now,
                ),
            )
            self._append_event(
                connection,
                str(row["import_id"]),
                ImportState.QUEUED,
                "upload_admitted",
                "Fixture admitted to the catalog and queued for probing.",
                {
                    "operation_id": operation_id,
                    "fixture_id": str(row["fixture_id"]),
                },
                now=now,
            )
            connection.commit()
        emit_operational_event(
            "ingestion.catalog_call.completed",
            import_id=str(row["import_id"]),
            stage="admission",
            operation_id=operation_id,
            attempt=attempt_number,
            duration_ms=max(
                0,
                (time.monotonic_ns() - call_context.started_monotonic_ns) // 1_000_000,
            ),
            next_state="queued",
        )
        self._wake.set()

    def _blob_path(self, row: sqlite3.Row) -> Path:
        relative = Path(str(row["input_ref"]))
        fixture_id = str(row["fixture_id"])
        if (
            relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[0] != fixture_id
        ):
            raise IngestionPipelineError(
                "stored input reference does not belong to its fixture"
            )
        candidate = self._contained_path(
            self.fixture_root,
            relative,
            label="stored input reference",
        )
        if candidate.is_symlink() or not candidate.is_file():
            raise IngestionPipelineError("admitted upload blob is missing")
        if candidate.stat().st_size != int(row["byte_count"]):
            raise IngestionPipelineError("admitted upload byte count no longer matches")
        return candidate

    def _probe_candidates(
        self,
        input_path: Path,
        *,
        node_hint: str | None,
        metadata: dict[str, Any],
    ) -> tuple[PluginCandidate, ...]:
        if self.limits.plugin_execution_mode is PluginExecutionMode.INLINE:
            return _run_plugin_inline(
                lambda: self.registry.probe(
                    input_path,
                    node_hint=node_hint,
                    metadata=metadata,
                ),
                stage="probe",
            )
        payload = _run_plugin_child(
            _probe_plugin_child,
            (
                self.registry.process_bootstraps(),
                str(input_path),
                node_hint,
                metadata,
            ),
            timeout_seconds=self.limits.plugin_execution_timeout_seconds,
            stage="probe",
        )
        raw_candidates = payload.get("candidates")
        if (
            not isinstance(raw_candidates, list)
            or len(raw_candidates) > MAX_PLUGIN_CANDIDATES
        ):
            raise PluginExecutionProcessError(
                "plug-in probe child returned invalid candidate metadata"
            )
        candidates: list[PluginCandidate] = []
        identities: set[tuple[str, str, str, str, str]] = set()
        for index, value in enumerate(raw_candidates):
            if not isinstance(value, dict):
                raise PluginExecutionProcessError(
                    f"plug-in probe candidate {index} is not an object"
                )
            try:
                raw_plugin_id = value.get("plugin_id")
                raw_plugin_version = value.get("plugin_version")
                raw_package_hash = value.get("package_hash")
                raw_instance_id = value.get("instance_id")
                raw_execution_identity = value.get("registered_execution_identity")
                if not all(
                    isinstance(item, str)
                    for item in (
                        raw_plugin_id,
                        raw_plugin_version,
                        raw_package_hash,
                        raw_instance_id,
                        raw_execution_identity,
                    )
                ):
                    raise ValueError("identity fields are invalid")
                assert isinstance(raw_plugin_id, str)
                assert isinstance(raw_plugin_version, str)
                assert isinstance(raw_package_hash, str)
                assert isinstance(raw_instance_id, str)
                assert isinstance(raw_execution_identity, str)
                plugin_id = _bounded_identifier(
                    raw_plugin_id,
                    f"probe candidate {index} plugin_id",
                    256,
                )
                plugin_version = _bounded_identifier(
                    raw_plugin_version,
                    f"probe candidate {index} plugin_version",
                    128,
                )
                package_hash = _bounded_identifier(
                    raw_package_hash,
                    f"probe candidate {index} package_hash",
                    256,
                )
                instance_id = _bounded_identifier(
                    raw_instance_id,
                    f"probe candidate {index} instance_id",
                    256,
                )
                registered_execution_identity = _bounded_identifier(
                    raw_execution_identity,
                    f"probe candidate {index} registered_execution_identity",
                    71,
                )
                if (
                    len(registered_execution_identity) != 71
                    or not registered_execution_identity.startswith("sha256:")
                    or any(
                        character not in "0123456789abcdef"
                        for character in registered_execution_identity[7:]
                    )
                ):
                    raise ValueError("registered execution identity is invalid")
                confidence = value.get("confidence")
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not math.isfinite(float(confidence))
                    or not 0 <= float(confidence) <= 1
                ):
                    raise ValueError("confidence is invalid")
                raw_match_kind = value.get("match_kind")
                if not isinstance(raw_match_kind, str):
                    raise TypeError("match_kind is invalid")
                match_kind = ProbeMatchKind(raw_match_kind)
                if match_kind is ProbeMatchKind.NONE:
                    raise ValueError("NONE is not a candidate")
                reasons_value = value.get("reasons")
                if not isinstance(reasons_value, list) or not reasons_value:
                    raise ValueError("reasons are invalid")
                reasons = tuple(
                    _bounded_text(
                        reason,
                        f"probe candidate {index} reason",
                        MAX_PROBE_REASON_LENGTH,
                    )
                    for reason in reasons_value
                )
                detected_values: list[str | None] = []
                for field_name in (
                    "detected_platform",
                    "detected_software_version",
                ):
                    detected = value.get(field_name)
                    if detected is not None:
                        detected = _bounded_text(
                            detected,
                            f"probe candidate {index} {field_name}",
                            MAX_PROBE_DETECTED_TEXT_LENGTH,
                        )
                    detected_values.append(detected)
                probe_result = validate_probe_result(
                    ProbeResult(
                        confidence=float(confidence),
                        reasons=reasons,
                        detected_platform=detected_values[0],
                        detected_software_version=detected_values[1],
                        match_kind=match_kind,
                    )
                )
                registered = self.registry.get(
                    plugin_id,
                    plugin_version,
                    instance_id=instance_id,
                    registered_execution_identity=registered_execution_identity,
                )
                if (
                    registered.package_hash != package_hash
                    or registered.registered_execution_identity
                    != registered_execution_identity
                ):
                    raise ValueError("execution identity does not match registry")
            except (KeyError, TypeError, ValueError) as error:
                raise PluginExecutionProcessError(
                    f"plug-in probe candidate {index} is invalid: {error}"
                ) from error
            identity = (
                plugin_id,
                plugin_version,
                package_hash,
                instance_id,
                registered_execution_identity,
            )
            if identity in identities:
                raise PluginExecutionProcessError(
                    "plug-in probe child returned duplicate candidates"
                )
            identities.add(identity)
            candidates.append(
                PluginCandidate(
                    plugin_id=plugin_id,
                    plugin_version=plugin_version,
                    package_hash=package_hash,
                    instance_id=instance_id,
                    registered_execution_identity=registered_execution_identity,
                    confidence=float(probe_result.confidence),
                    match_kind=ProbeMatchKind(probe_result.match_kind).value,
                    reasons=probe_result.reasons,
                    detected_platform=probe_result.detected_platform,
                    detected_software_version=(probe_result.detected_software_version),
                )
            )
        return tuple(
            sorted(
                candidates,
                key=lambda item: (
                    -item.confidence,
                    item.plugin_id,
                    item.plugin_version,
                    item.package_hash,
                    item.registered_execution_identity,
                ),
            )
        )

    def _require_composition_policy(self, row: sqlite3.Row) -> None:
        stored_digest = row["composition_policy_digest"]
        if (
            not isinstance(stored_digest, str)
            or stored_digest != self.composition_policy.policy_digest
        ):
            raise IngestionPipelineError(
                "the import's immutable plug-in composition policy does not "
                "match this worker"
            )

    def _run_probe(self, row: sqlite3.Row) -> None:
        self._require_composition_policy(row)
        metadata = json.loads(str(row["metadata_json"]))
        if not isinstance(metadata, dict):
            raise IngestionPipelineError("stored import metadata is invalid")
        candidates = self._probe_candidates(
            self._blob_path(row),
            node_hint=(str(row["node_hint"]) if row["node_hint"] is not None else None),
            metadata=metadata,
        )
        payloads = [candidate.as_dict() for candidate in candidates]
        probe_set_hash = (
            "sha256:"
            + hashlib.sha256(canonical_json(payloads).encode("utf-8")).hexdigest()
        )
        preferred = row["preferred_plugin_id"]
        selected: PluginCandidate | None = None
        if preferred:
            preferred_matches = [
                candidate
                for candidate in candidates
                if candidate.plugin_id == preferred
            ]
            if len(preferred_matches) != 1:
                raise IngestionPipelineError(
                    "preferred plug-in did not produce one probe candidate"
                )
            selected = preferred_matches[0]
        elif bool(row["auto_select"]) and len(candidates) == 1:
            selected = candidates[0]

        state = (
            ImportState.READY
            if selected is not None
            else ImportState.AWAITING_SELECTION
        )
        if not candidates:
            raise IngestionPipelineError("no allowlisted plug-in matched the upload")
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT state, lease_owner FROM ingestion_imports WHERE import_id = ?",
                (row["import_id"],),
            ).fetchone()
            if (
                current is None
                or current["state"] != ImportState.PROBING.value
                or current["lease_owner"] != row["lease_owner"]
            ):
                connection.rollback()
                return
            connection.execute(
                "DELETE FROM ingestion_candidates WHERE import_id = ?",
                (row["import_id"],),
            )
            for ordinal, candidate in enumerate(candidates):
                connection.execute(
                    """
                    INSERT INTO ingestion_candidates (
                        import_id, ordinal, plugin_id, plugin_version,
                        package_hash, instance_id,
                        registered_execution_identity,
                        confidence, match_kind, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["import_id"],
                        ordinal,
                        candidate.plugin_id,
                        candidate.plugin_version,
                        candidate.package_hash,
                        candidate.instance_id,
                        candidate.registered_execution_identity,
                        candidate.confidence,
                        candidate.match_kind,
                        canonical_json(candidate.as_dict()),
                    ),
                )
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    probe_set_hash = ?,
                    selected_plugin_id = ?,
                    selected_plugin_version = ?,
                    selected_package_hash = ?,
                    selected_execution_identity = ?,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (
                    state.value,
                    probe_set_hash,
                    selected.plugin_id if selected else None,
                    selected.plugin_version if selected else None,
                    selected.package_hash if selected else None,
                    (selected.registered_execution_identity if selected else None),
                    now,
                    row["import_id"],
                ),
            )
            self._append_event(
                connection,
                str(row["import_id"]),
                state,
                ("plugin_auto_selected" if selected else "plugin_selection_required"),
                (
                    "The only matching plug-in was selected automatically."
                    if selected
                    else "Choose one candidate before ingestion can continue."
                ),
                {
                    "probe_set_hash": probe_set_hash,
                    "candidate_count": len(candidates),
                    "selected_plugin_id": (selected.plugin_id if selected else None),
                },
                now=now,
            )
            connection.commit()
        if selected is not None:
            self._wake.set()

    @staticmethod
    def _child_ingestion_metadata(
        payload: Mapping[str, Any],
        registered: RegisteredPlugin,
        *,
        capability_providers: CapabilityProviderRegistry,
        composition_policy: PluginCompositionPolicy,
        allow_inline_only: bool,
        expected_execution_plan_authority: PluginExecutionPlanAuthority,
    ) -> _StagedChildIngestion:
        try:
            raw_revision_id = payload.get("revision_id")
            raw_node_id = payload.get("node_id")
            if not isinstance(raw_revision_id, str) or not isinstance(raw_node_id, str):
                raise TypeError("revision or node identity is invalid")
            revision_id = _bounded_text(
                raw_revision_id,
                "child ingestion revision_id",
                1_024,
            )
            node_id = _bounded_text(
                raw_node_id,
                "child ingestion node_id",
                1_024,
            )
            dataset_sha256 = payload.get("dataset_sha256")
            if (
                not isinstance(dataset_sha256, str)
                or len(dataset_sha256) != 64
                or any(
                    character not in "0123456789abcdef" for character in dataset_sha256
                )
            ):
                raise ValueError("dataset_sha256 is invalid")
            counts: list[int] = []
            for field_name, allow_zero in (
                ("dataset_bytes", False),
                ("event_count", True),
                ("source_record_count", True),
                ("resource_count", True),
            ):
                value = payload.get(field_name)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < (0 if allow_zero else 1)
                    or value > 2**63 - 1
                ):
                    raise ValueError(f"{field_name} is invalid")
                counts.append(value)
            execution_plan = plugin_execution_plan_from_dict(
                payload.get("execution_plan")
            )
            if (
                execution_plan.node_id != node_id
                or execution_plan.basis_revision_id != revision_id
                or not _execution_plan_matches_composition(
                    execution_plan,
                    registered,
                    capability_providers=capability_providers,
                    composition_policy=composition_policy,
                    allow_inline_only=allow_inline_only,
                    expected_execution_plan_authority=(
                        expected_execution_plan_authority
                    ),
                )
            ):
                raise ValueError(
                    "execution plan does not match the staged revision basis"
                )
        except (TypeError, ValueError) as error:
            raise PluginExecutionProcessError(
                f"plug-in ingestion child returned invalid metadata: {error}"
            ) from error
        return _StagedChildIngestion(
            revision_id=revision_id,
            node_id=node_id,
            dataset_sha256=dataset_sha256,
            dataset_bytes=counts[0],
            event_count=counts[1],
            source_record_count=counts[2],
            resource_count=counts[3],
            execution_plan=execution_plan,
        )

    def _run_ingestion(self, row: sqlite3.Row) -> None:
        self._require_composition_policy(row)
        plugin_id = str(row["selected_plugin_id"] or "")
        plugin_version = str(row["selected_plugin_version"] or "")
        selected_execution_identity = str(row["selected_execution_identity"] or "")
        try:
            registered = self.registry.get(
                plugin_id,
                plugin_version,
                registered_execution_identity=selected_execution_identity,
            )
        except KeyError as error:
            raise IngestionPipelineError(
                "selected plug-in execution identity is no longer registered"
            ) from error
        selected_package_hash = str(row["selected_package_hash"] or "")
        if (
            selected_package_hash != registered.package_hash
            or selected_execution_identity != registered.registered_execution_identity
        ):
            raise IngestionPipelineError(
                "selected plug-in execution identity no longer matches the "
                "registered artifact, configuration, manifest, instance, or "
                "decoder identity"
            )
        upload_metadata = json.loads(str(row["metadata_json"]))
        if not isinstance(upload_metadata, dict):
            raise IngestionPipelineError("stored import metadata is invalid")
        node_hint = str(row["node_hint"]) if row["node_hint"] is not None else None
        input_path = self._blob_path(row)
        selected_composition_records = _selected_composition_records(
            registered,
            capability_providers=self.capability_providers,
            composition_policy=self.composition_policy,
        )
        expected_execution_plan_authority = _execution_plan_authority_for_mode(
            selected_composition_records,
            execution_mode=self.limits.plugin_execution_mode,
            allow_inline_only=self.allow_inline_only,
        )
        temporary = self.spool_root / f"{uuid4().hex}.dataset.child.partial"
        temporary_lock = temporary.with_name(f".{temporary.name}.active.lock")
        prepared_content: _PreparedContentFile | None = None
        operation_stack = ExitStack()
        try:
            operation_stack.enter_context(self._spool_active_file_lock(temporary_lock))
            if self.limits.plugin_execution_mode is PluginExecutionMode.PROCESS:
                auxiliary_selections = self.composition_policy.auxiliaries_for(
                    primary_instance_id=registered.instance_id,
                    primary_registered_execution_identity=(
                        registered.registered_execution_identity
                    ),
                )
                child_auxiliary_pins = _frozen_auxiliary_execution_pins(
                    self.capability_providers,
                    auxiliary_selections,
                )
                child_auxiliary_bootstraps = _frozen_auxiliary_process_bootstraps(
                    self.capability_providers,
                    auxiliary_selections,
                )
                child_auxiliary_bootstrap_digests = tuple(
                    _plugin_process_bootstrap_digest(value)
                    for value in child_auxiliary_bootstraps
                )
                process_bootstrap = registered.process_bootstrap
                primary_bootstrap_digest = registered.process_bootstrap_digest
                if primary_bootstrap_digest is None:
                    raise IngestionPipelineError(
                        "PROCESS ingestion lacks its primary bootstrap digest"
                    )
                PluginRegistry.revalidate_registered_identity(registered)
                payload = _run_plugin_child(
                    _ingest_plugin_child,
                    (
                        process_bootstrap,
                        primary_bootstrap_digest,
                        child_auxiliary_bootstrap_digests,
                        str(input_path),
                        node_hint,
                        upload_metadata,
                        str(temporary),
                        child_auxiliary_pins,
                        self.composition_policy,
                        child_auxiliary_bootstraps,
                    ),
                    timeout_seconds=(self.limits.plugin_execution_timeout_seconds),
                    stage="ingest",
                )
                staged = self._child_ingestion_metadata(
                    payload,
                    registered,
                    capability_providers=self.capability_providers,
                    composition_policy=self.composition_policy,
                    allow_inline_only=self.allow_inline_only,
                    expected_execution_plan_authority=(
                        expected_execution_plan_authority
                    ),
                )
            else:
                result, dataset_json, execution_plan = _run_plugin_inline(
                    lambda: _ingest_registered_plugin(
                        registered,
                        input_path,
                        capability_providers=self.capability_providers,
                        composition_policy=self.composition_policy,
                        allow_inline_only=self.allow_inline_only,
                        execution_mode=self.limits.plugin_execution_mode,
                        node_hint=node_hint,
                        # Authorization/catalog coordinates remain core-private.
                        # A plug-in receives caller-supplied parsing metadata.
                        metadata=upload_metadata,
                    ),
                    stage="ingest",
                )
                dataset_sha256 = hashlib.sha256(dataset_json).hexdigest()
                with temporary.open("xb") as stream:
                    stream.write(dataset_json)
                    stream.flush()
                    os.fsync(stream.fileno())
                staged = _StagedChildIngestion(
                    revision_id=result.revision_id,
                    node_id=result.node_id,
                    dataset_sha256=dataset_sha256,
                    dataset_bytes=len(dataset_json),
                    event_count=len(result.events),
                    source_record_count=len(result.source_records),
                    resource_count=len(result.dataset.get("resources", ())),
                    execution_plan=execution_plan,
                )
            self._validate_staged_timeline_binding(
                temporary,
                staged=staged,
                registered=registered,
            )
            if not self._renew_lease(
                str(row["import_id"]),
                ImportState.INGESTING,
                str(row["lease_owner"]),
            ):
                # Ownership expired or the state changed while the plug-in
                # ran. A stale worker must not install or publish a revision.
                return
            relative = (
                Path(staged.dataset_sha256[:2])
                / staged.dataset_sha256[2:4]
                / f"{staged.dataset_sha256}.json"
            )
            # Dataset hashing and a cross-filesystem copy fallback both scale
            # with plug-in output size. Stage them before serializing the
            # atomic publication/reference commit with retention.
            prepared_content = self._prepare_content_file(
                temporary,
                root=self.dataset_root,
                relative=relative,
                expected_sha256=staged.dataset_sha256,
                expected_bytes=staged.dataset_bytes,
            )
            if not _execution_plan_matches_composition(
                staged.execution_plan,
                registered,
                capability_providers=self.capability_providers,
                composition_policy=self.composition_policy,
                allow_inline_only=self.allow_inline_only,
                expected_execution_plan_authority=(expected_execution_plan_authority),
            ):
                error_type = (
                    PluginExecutionProcessError
                    if self.limits.plugin_execution_mode is PluginExecutionMode.PROCESS
                    else IngestionPipelineError
                )
                raise error_type(
                    "plug-in execution plan no longer matches the live registered "
                    "composition"
                )
            operation_stack.enter_context(
                exclusive_file_lock(self._maintenance_lock_path)
            )
            self._publish_prepared_content_file(prepared_content)
            operation_id = f"publication:{row['import_id']}"
            now = self._now_ns()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    """
                    SELECT state, lease_owner
                    FROM ingestion_imports
                    WHERE import_id = ?
                    """,
                    (row["import_id"],),
                ).fetchone()
                if (
                    current is None
                    or current["state"] != ImportState.INGESTING.value
                    or current["lease_owner"] != row["lease_owner"]
                ):
                    connection.rollback()
                    return
                connection.execute(
                    """
                    UPDATE ingestion_imports
                    SET state = ?, version = version + 1,
                        publication_operation_id = ?,
                        staged_source_revision_id = ?,
                        staged_node_id = ?,
                        staged_dataset_ref = ?,
                        staged_dataset_sha256 = ?,
                        staged_event_count = ?,
                        staged_source_record_count = ?,
                        staged_resource_count = ?,
                        staged_execution_plan_json = ?,
                        staged_execution_plan_digest = ?,
                        error_code = NULL, error_message = NULL,
                        lease_owner = NULL, lease_expires_ns = NULL,
                        updated_at_ns = ?
                    WHERE import_id = ?
                    """,
                    (
                        ImportState.PUBLISHING.value,
                        operation_id,
                        staged.revision_id,
                        staged.node_id,
                        relative.as_posix(),
                        staged.dataset_sha256,
                        staged.event_count,
                        staged.source_record_count,
                        staged.resource_count,
                        canonical_json(
                            plugin_execution_plan_dict(staged.execution_plan)
                        ),
                        staged.execution_plan.plan_digest,
                        now,
                        row["import_id"],
                    ),
                )
                self._append_event(
                    connection,
                    str(row["import_id"]),
                    ImportState.PUBLISHING,
                    "revision_staged",
                    ("Immutable analysis revision staged for catalog publication."),
                    {
                        "operation_id": operation_id,
                        "source_revision_id": staged.revision_id,
                        "node_id": staged.node_id,
                        "event_count": staged.event_count,
                        "source_record_count": staged.source_record_count,
                        "resource_count": staged.resource_count,
                        "dataset_sha256": staged.dataset_sha256,
                        "plugin_execution_plan_digest": (
                            staged.execution_plan.plan_digest
                        ),
                    },
                    now=now,
                )
                connection.commit()
            self._wake.set()
        finally:
            self._discard_prepared_content_file(prepared_content)
            temporary.unlink(missing_ok=True)
            operation_stack.close()

    def _run_publication(self, row: sqlite3.Row) -> None:
        """Publish one staged revision through an idempotent catalog receipt.

        The dataset and all publication arguments are durably staged before
        this method runs.  A crash after the catalog commit but before the
        queue commit therefore repeats the exact same operation identifier
        and payload instead of re-running the plug-in.
        """

        required_text = {
            "publication_operation_id": row["publication_operation_id"],
            "staged_source_revision_id": row["staged_source_revision_id"],
            "staged_node_id": row["staged_node_id"],
            "staged_dataset_ref": row["staged_dataset_ref"],
            "staged_dataset_sha256": row["staged_dataset_sha256"],
            "selected_plugin_id": row["selected_plugin_id"],
            "selected_plugin_version": row["selected_plugin_version"],
        }
        for label, value in required_text.items():
            if not isinstance(value, str) or not value:
                raise IngestionPipelineError(f"staged publication is missing {label}")
        required_counts = {
            "event_count": row["staged_event_count"],
            "source_record_count": row["staged_source_record_count"],
            "resource_count": row["staged_resource_count"],
        }
        for label, value in required_counts.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise IngestionPipelineError(f"staged publication has invalid {label}")
        plan_required = row["execution_plan_required"]
        if plan_required not in {
            _EXECUTION_PLAN_LEGACY_OPTIONAL,
            _EXECUTION_PLAN_REQUIRED,
        }:
            raise IngestionPipelineError(
                "staged publication has an invalid execution-plan contract"
            )
        raw_plan_json = row["staged_execution_plan_json"]
        raw_plan_digest = row["staged_execution_plan_digest"]
        plan_absent = raw_plan_json is None and raw_plan_digest is None
        if plan_absent:
            if plan_required == _EXECUTION_PLAN_REQUIRED:
                raise IngestionPipelineError(
                    "staged publication is missing its required execution plan"
                )
            execution_plan = None
        else:
            if (
                not isinstance(raw_plan_json, str)
                or not raw_plan_json
                or not isinstance(raw_plan_digest, str)
                or not raw_plan_digest
            ):
                raise IngestionPipelineError(
                    "staged publication has an incomplete execution plan"
                )
            try:
                execution_plan = plugin_execution_plan_from_dict(
                    json.loads(raw_plan_json)
                )
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise IngestionPipelineError(
                    "staged publication has an invalid execution plan"
                ) from error
            if (
                execution_plan.plan_digest != raw_plan_digest
                or execution_plan.node_id != required_text["staged_node_id"]
                or execution_plan.basis_revision_id
                != required_text["staged_source_revision_id"]
            ):
                raise IngestionPipelineError(
                    "staged publication execution plan does not match its revision"
                )
            try:
                primary_pin = primary_parser_execution_pin(execution_plan)
            except (TypeError, ValueError) as error:
                raise IngestionPipelineError(
                    "staged publication execution plan lacks one primary parser"
                ) from error
            if (
                primary_pin.plugin_id != required_text["selected_plugin_id"]
                or primary_pin.plugin_version
                != required_text["selected_plugin_version"]
                or primary_pin.artifact.package_hash != row["selected_package_hash"]
            ):
                raise IngestionPipelineError(
                    "staged publication primary parser does not match selection"
                )
        dataset_path = self._contained_path(
            self.dataset_root,
            Path(str(required_text["staged_dataset_ref"])),
            label="staged dataset reference",
        )
        dataset_plan_digest = self._verified_dataset_execution_plan_digest(
            dataset_path,
            expected_sha256=str(required_text["staged_dataset_sha256"]),
        )
        if (execution_plan is None and dataset_plan_digest is not None) or (
            execution_plan is not None
            and dataset_plan_digest != execution_plan.plan_digest
        ):
            raise IngestionPipelineError(
                "staged dataset execution-plan digest does not match publication"
            )
        scope = ImportScope(
            tenant_id=str(row["tenant_id"]),
            project_id=str(row["project_id"]),
            workspace_id=str(row["workspace_id"]),
        )
        publication_operation_id = str(required_text["publication_operation_id"])
        call_context = self._publisher_call_context(
            operation_id=publication_operation_id,
            attempt_number=int(row["attempt_count"]) + 1,
        )
        self._pin_catalog_artifact(
            row,
            artifact_kind=_RetentionArtifactKind.DATASET,
            artifact_ref=str(required_text["staged_dataset_ref"]),
            operation_id=publication_operation_id,
        )
        attempt_number = call_context.attempt_number
        emit_operational_event(
            "ingestion.catalog_call.started",
            import_id=str(row["import_id"]),
            stage="publication",
            operation_id=publication_operation_id,
            attempt=attempt_number,
            timeout_ms=max(
                1,
                (
                    call_context.deadline_monotonic_ns
                    - call_context.started_monotonic_ns
                    + 999_999
                )
                // 1_000_000,
            ),
        )
        publisher_values: dict[str, Any] = {
            "operation_id": publication_operation_id,
            "fixture_id": str(row["fixture_id"]),
            "source_revision_id": str(required_text["staged_source_revision_id"]),
            "node_id": str(required_text["staged_node_id"]),
            "plugin_id": str(required_text["selected_plugin_id"]),
            "plugin_version": str(required_text["selected_plugin_version"]),
            "dataset_ref": str(required_text["staged_dataset_ref"]),
            "dataset_sha256": str(required_text["staged_dataset_sha256"]),
            "event_count": int(required_counts["event_count"]),
            "source_record_count": int(required_counts["source_record_count"]),
            "resource_count": int(required_counts["resource_count"]),
            "call_context": call_context,
        }
        publisher_plan_support = _publisher_execution_plan_support(self.publisher)
        if (
            execution_plan is not None
            and publisher_plan_support is _PublisherExecutionPlanSupport.ABSENT
        ):
            raise IngestionPipelineError(
                "revision publisher does not support immutable execution plans"
            )
        if execution_plan is not None or (
            publisher_plan_support is _PublisherExecutionPlanSupport.EXPLICIT_KEYWORD
        ):
            publisher_values["execution_plan"] = execution_plan
        if (
            self.limits.effective_publisher_execution_mode
            is PluginExecutionMode.PROCESS
        ):
            catalog_revision_id = _run_catalog_publisher_child(
                self.publisher_process_bootstrap,
                stage="publication",
                scope=scope,
                values=publisher_values,
                timeout_seconds=(
                    self.limits.effective_publisher_execution_timeout_seconds
                ),
            )
        else:
            catalog_revision_id = self.publisher.publish_revision(
                scope,
                **publisher_values,
            )
        call_context.raise_if_expired()
        published_revision_id = catalog_revision_id or str(
            required_text["staged_source_revision_id"]
        )
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT state, lease_owner, publication_operation_id
                FROM ingestion_imports
                WHERE import_id = ?
                """,
                (row["import_id"],),
            ).fetchone()
            if (
                current is None
                or current["state"] != ImportState.PUBLISHING.value
                or current["lease_owner"] != row["lease_owner"]
                or current["publication_operation_id"]
                != required_text["publication_operation_id"]
            ):
                connection.rollback()
                reason = (
                    "import_missing"
                    if current is None
                    else (
                        "state_changed"
                        if current["state"] != ImportState.PUBLISHING.value
                        else (
                            "lease_lost"
                            if current["lease_owner"] != row["lease_owner"]
                            else "operation_changed"
                        )
                    )
                )
                emit_operational_event(
                    "ingestion.catalog_call.discarded",
                    import_id=str(row["import_id"]),
                    stage="publication",
                    operation_id=publication_operation_id,
                    attempt=attempt_number,
                    duration_ms=max(
                        0,
                        (time.monotonic_ns() - call_context.started_monotonic_ns)
                        // 1_000_000,
                    ),
                    reason=reason,
                    remote_acknowledged=True,
                )
                return
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    revision_id = ?, node_id = ?,
                    error_code = NULL, error_message = NULL,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (
                    ImportState.COMPLETED.value,
                    published_revision_id,
                    required_text["staged_node_id"],
                    now,
                    row["import_id"],
                ),
            )
            connection.execute(
                """
                INSERT INTO ingestion_artifact_pins (
                    artifact_kind, artifact_ref,
                    tenant_id, project_id, workspace_id,
                    owner_operation_id, created_at_ns
                ) VALUES ('dataset', ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    required_text["staged_dataset_ref"],
                    row["tenant_id"],
                    row["project_id"],
                    row["workspace_id"],
                    required_text["publication_operation_id"],
                    now,
                ),
            )
            self._append_event(
                connection,
                str(row["import_id"]),
                ImportState.COMPLETED,
                "revision_published",
                "Immutable analysis revision published.",
                {
                    "operation_id": required_text["publication_operation_id"],
                    "revision_id": published_revision_id,
                    "source_revision_id": required_text["staged_source_revision_id"],
                    "node_id": required_text["staged_node_id"],
                    **required_counts,
                    "dataset_sha256": required_text["staged_dataset_sha256"],
                    **(
                        {"plugin_execution_plan_digest": (execution_plan.plan_digest)}
                        if execution_plan is not None
                        else {}
                    ),
                },
                now=now,
            )
            connection.commit()
        emit_operational_event(
            "ingestion.catalog_call.completed",
            import_id=str(row["import_id"]),
            stage="publication",
            operation_id=publication_operation_id,
            attempt=attempt_number,
            duration_ms=max(
                0,
                (time.monotonic_ns() - call_context.started_monotonic_ns) // 1_000_000,
            ),
            next_state="completed",
            event_count=int(required_counts["event_count"]),
            source_record_count=int(required_counts["source_record_count"]),
            resource_count=int(required_counts["resource_count"]),
        )

    def _publisher_call_context(
        self,
        *,
        operation_id: str,
        attempt_number: int,
    ) -> PublisherCallContext:
        started = time.monotonic_ns()
        timeout_ns = max(
            1,
            int(
                self.limits.effective_publisher_execution_timeout_seconds
                * 1_000_000_000
            ),
        )
        return PublisherCallContext(
            operation_id=operation_id,
            attempt_number=attempt_number,
            started_monotonic_ns=started,
            deadline_monotonic_ns=started + timeout_ns,
        )

    def _pin_catalog_artifact(
        self,
        row: sqlite3.Row,
        *,
        artifact_kind: _RetentionArtifactKind,
        artifact_ref: str,
        operation_id: str,
    ) -> None:
        """Protect an outbox artifact before an ambiguous catalog call."""

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ingestion_artifact_pins (
                    artifact_kind, artifact_ref,
                    tenant_id, project_id, workspace_id,
                    owner_operation_id, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    artifact_kind.value,
                    artifact_ref,
                    row["tenant_id"],
                    row["project_id"],
                    row["workspace_id"],
                    operation_id,
                    self._now_ns(),
                ),
            )

    def _fail_claimed_import(
        self,
        row: sqlite3.Row,
        error: BaseException,
    ) -> None:
        code = _public_failure_code(error)
        message = PUBLIC_INGESTION_FAILURE_MESSAGES[code]
        exception_type, exception_message = _private_exception_fields(error)
        attempt_number = int(row["attempt_count"]) + 1
        stage = {
            ImportState.ADMITTING.value: "admission",
            ImportState.PROBING.value: "probe",
            ImportState.INGESTING.value: "ingestion",
            ImportState.PUBLISHING.value: "publication",
        }.get(str(row["state"]), "worker")
        now = self._now_ns()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT state, lease_owner FROM ingestion_imports WHERE import_id = ?",
                (row["import_id"],),
            ).fetchone()
            if (
                current is None
                or current["lease_owner"] != row["lease_owner"]
                or current["state"]
                not in {
                    ImportState.ADMITTING.value,
                    ImportState.PROBING.value,
                    ImportState.INGESTING.value,
                    ImportState.PUBLISHING.value,
                }
            ):
                connection.rollback()
                return
            self._insert_failure_diagnostic(
                connection,
                import_id=str(row["import_id"]),
                attempt_number=attempt_number,
                stage=stage,
                public_error_code=code,
                exception_type=exception_type,
                exception_message=exception_message,
                source_kind="attempt",
                source_id=str(attempt_number),
                created_at_ns=now,
            )
            connection.execute(
                """
                UPDATE ingestion_imports
                SET state = ?, version = version + 1,
                    attempt_count = attempt_count + 1,
                    error_code = ?, error_message = ?,
                    lease_owner = NULL, lease_expires_ns = NULL,
                    updated_at_ns = ?
                WHERE import_id = ?
                """,
                (
                    ImportState.FAILED.value,
                    code,
                    message,
                    now,
                    row["import_id"],
                ),
            )
            self._append_event(
                connection,
                str(row["import_id"]),
                ImportState.FAILED,
                "import_failed",
                message,
                {"error_code": code},
                now=now,
            )
            connection.commit()
        failure_fields: dict[str, Any] = {
            "import_id": str(row["import_id"]),
            "stage": stage,
            "attempt": attempt_number,
            "error_code": code,
            "retryable": attempt_number < self.limits.max_attempts,
            "ambiguous_external_outcome": (code == "catalog_execution_timeout"),
        }
        operation_column = {
            "admission": "admission_operation_id",
            "publication": "publication_operation_id",
        }.get(stage)
        if operation_column is not None and isinstance(
            row[operation_column],
            str,
        ):
            failure_fields["operation_id"] = str(row[operation_column])
        emit_operational_event(
            "ingestion.attempt.failed",
            **failure_fields,
        )

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        import_id: str,
        state: ImportState,
        event_type: str,
        message: str,
        payload: Mapping[str, Any],
        *,
        now: int,
    ) -> None:
        _bounded_identifier(event_type, "event_type")
        message = _bounded_text(
            message,
            "event message",
            MAX_EVENT_MESSAGE_LENGTH,
        )
        encoded = canonical_json(dict(payload))
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("import event payload exceeds 65536 bytes")
        connection.execute(
            """
            INSERT INTO ingestion_events (
                import_id, state, event_type, message,
                payload_json, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                state.value,
                event_type,
                message,
                encoded,
                now,
            ),
        )

    def _descriptor(self, row: sqlite3.Row) -> ImportDescriptor:
        state = ImportState(str(row["state"]))
        public_error_code = (
            _normalized_public_failure_code(
                str(row["error_code"]) if row["error_code"] is not None else None
            )
            if state is ImportState.FAILED
            else None
        )
        return ImportDescriptor(
            import_id=str(row["import_id"]),
            scope=ImportScope(
                tenant_id=str(row["tenant_id"]),
                project_id=str(row["project_id"]),
                workspace_id=str(row["workspace_id"]),
            ),
            fixture_id=str(row["fixture_id"]),
            state=state,
            version=int(row["version"]),
            original_name=str(row["original_name"]),
            content_type=str(row["content_type"]),
            node_hint=(str(row["node_hint"]) if row["node_hint"] is not None else None),
            metadata=json.loads(str(row["metadata_json"])),
            byte_count=int(row["byte_count"]),
            content_sha256=str(row["content_sha256"]),
            probe_set_hash=(
                str(row["probe_set_hash"])
                if row["probe_set_hash"] is not None
                else None
            ),
            plugin_composition_policy_digest=str(row["composition_policy_digest"]),
            selected_plugin_id=(
                str(row["selected_plugin_id"])
                if row["selected_plugin_id"] is not None
                else None
            ),
            selected_plugin_version=(
                str(row["selected_plugin_version"])
                if row["selected_plugin_version"] is not None
                else None
            ),
            revision_id=(
                str(row["revision_id"]) if row["revision_id"] is not None else None
            ),
            node_id=(str(row["node_id"]) if row["node_id"] is not None else None),
            attempt_count=int(row["attempt_count"]),
            max_attempts=self.limits.max_attempts,
            auto_select=bool(row["auto_select"]),
            error_code=public_error_code,
            error_message=(
                PUBLIC_INGESTION_FAILURE_MESSAGES[public_error_code]
                if public_error_code is not None
                else None
            ),
            created_at_ns=int(row["created_at_ns"]),
            updated_at_ns=int(row["updated_at_ns"]),
        )


def _import_metadata_json(value: Mapping[str, Any] | None) -> str:
    if value is not None and not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping or None")
    candidate = dict(value or {})
    validate_bounded_json_value(
        candidate,
        "import metadata",
        maximum_depth=12,
        maximum_container_items=1_024,
        maximum_units=8_192,
        maximum_atom_units=65_536,
        maximum_integer_bits=4_096,
    )
    encoded = canonical_json(candidate)
    if len(encoded.encode("utf-8")) > MAX_IMPORT_METADATA_BYTES:
        raise ValueError(
            f"import metadata exceeds {MAX_IMPORT_METADATA_BYTES} UTF-8 bytes"
        )
    return encoded


def validate_import_metadata(
    value: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return one detached, bounded plug-in-visible metadata object."""

    decoded = json.loads(_import_metadata_json(value))
    assert isinstance(decoded, dict)
    return decoded


def _path_for_containment_comparison(path: Path) -> str:
    r"""Normalize Windows device paths without changing the returned path.

    ``Path.resolve()`` may add the ``\\?\`` device prefix to only one side of
    a comparison when a concurrently-created target starts existing between
    resolutions.  The prefix changes spelling, not identity.  Strip it for
    the containment comparison, then apply the platform's normal case and
    separator normalization.
    """

    value = os.fspath(path)
    if os.name == "nt":
        windows_value = value.replace("/", "\\")
        folded = windows_value.casefold()
        if folded.startswith("\\\\?\\unc\\"):
            value = "\\\\" + windows_value[8:]
        elif folded.startswith("\\\\?\\"):
            value = windows_value[4:]
    return os.path.normcase(os.path.normpath(value))


def _fsync_directory(path: Path) -> None:
    """Best-effort durability barrier for a directory rename."""

    if os.name == "nt":
        # Windows does not expose a portable directory FlushFileBuffers
        # operation through Python.  File handles themselves are flushed.
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        os.fsync(descriptor)
    except OSError:
        # Some otherwise-supported local filesystems reject directory fsync.
        # Atomic rename still prevents partially-published file contents.
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bounded_text(value: str, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{label} must contain 1 to {maximum} characters and no NUL")
    return value


def _truncate_text(value: str, *, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    if maximum <= 3:
        return value[:maximum]
    return value[: maximum - 3] + "..."


def _normalized_public_failure_code(value: str | None) -> str:
    if value in PUBLIC_INGESTION_FAILURE_MESSAGES:
        assert value is not None
        return value
    return "worker_failure"


def _public_failure_code(error: BaseException) -> str:
    if isinstance(error, PluginExecutionTimeoutError):
        return "plugin_execution_timeout"
    if isinstance(error, CatalogExecutionTimeoutError):
        return "catalog_execution_timeout"
    if isinstance(error, CatalogExecutionProcessError):
        return "catalog_execution_failed"
    if isinstance(error, PluginExecutionProcessError):
        return "plugin_execution_failed"
    if isinstance(error, (IngestionError, IngestionPipelineError)):
        return "ingestion_rejected"
    return "worker_failure"


def _private_exception_message(error: BaseException) -> str:
    try:
        detail = str(error)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - formatting must never mask failure.
        detail = "<error text unavailable>"
    return _truncate_text(
        detail,
        maximum=MAX_PRIVATE_FAILURE_MESSAGE_LENGTH,
    )


def _private_exception_fields(error: BaseException) -> tuple[str, str]:
    private_type = getattr(error, "private_exception_type", None)
    private_message = getattr(error, "private_exception_message", None)
    if (
        isinstance(private_type, str)
        and private_type
        and isinstance(private_message, str)
    ):
        return (
            _truncate_text(
                private_type,
                maximum=MAX_PRIVATE_FAILURE_TYPE_LENGTH,
            ),
            _truncate_text(
                private_message,
                maximum=MAX_PRIVATE_FAILURE_MESSAGE_LENGTH,
            ),
        )

    selected = error
    seen: set[int] = set()
    while selected.__cause__ is not None and id(selected) not in seen:
        seen.add(id(selected))
        selected = selected.__cause__
    exception_type = f"{type(selected).__module__}.{type(selected).__qualname__}"
    return (
        _truncate_text(
            exception_type,
            maximum=MAX_PRIVATE_FAILURE_TYPE_LENGTH,
        ),
        _private_exception_message(selected),
    )


__all__ = [
    "CatalogExecutionProcessError",
    "CatalogExecutionTimeoutError",
    "DurableIngestionPipeline",
    "ImportConflictError",
    "ImportDescriptor",
    "ImportEvent",
    "ImportNotFoundError",
    "ImportQuotaExceededError",
    "ImportScope",
    "ImportState",
    "IngestionPipelineError",
    "IngestionStateRootPathError",
    "NullRevisionCatalogPublisher",
    "PipelineLimits",
    "PluginCandidate",
    "PluginExecutionMode",
    "PluginExecutionProcessError",
    "PluginExecutionTimeoutError",
    "PluginRegistry",
    "PublisherCallContext",
    "QueueHealthSnapshot",
    "RegisteredPlugin",
    "RetentionAuditRecord",
    "RetentionHostInventoryCoverage",
    "RetentionPolicy",
    "RetentionReport",
    "RevisionCatalogPublisher",
    "WorkerHealthSnapshot",
    "inspect_durable_queue",
    "validate_import_metadata",
    "validate_ingestion_state_root",
]
