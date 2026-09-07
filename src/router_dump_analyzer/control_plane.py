"""Durable composition root for catalogs, ingestion, and human review.

The individual stores in this package intentionally remain usable on their
own.  :class:`ControlPlane` wires them together at the boundaries where
cross-store invariants matter:

* an upload scope must name an existing tenant/project/workspace;
* immutable fixture and revision publications are registered atomically by
  their owning stores and carry content-addressed dataset references;
* every mutable review subject is resolved against an exact immutable
  revision before the annotation overlay accepts it;
* correlation reports contain only client-safe, revision-qualified
  observations and keep user assertions, plug-in facts, and conservative
  core corroboration distinct.

Device semantics stay outside this module.  Plug-ins create normalized
resources, events, source records, causal links, and opaque identifiers.  The
composition layer only verifies the core-normalized envelope and exact
identity references.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any, Self
from uuid import UUID

from .annotation_store import (
    MAX_ANNOTATION_SUBJECTS,
    MAX_CORRELATION_SUBJECTS,
    CorrelationReport,
    ManualCorrelationEdge,
    ManualEventCorrelation,
    ReviewAnnotation,
    ReviewAnnotationKind,
    ReviewOverlayError,
    ReviewOverlayStore,
    ReviewRetentionInventory,
    ReviewRetentionPolicy,
    ReviewRetentionResult,
    ReviewScope,
    ReviewSubject,
    ReviewSubjectKind,
    _review_retention_inventory_document,
    _review_retention_inventory_from_document,
    _review_retention_result_document,
    _review_retention_result_from_document,
    build_correlation_report,
    normalize_review_subjects,
)
from .annotation_store import (
    _review_retention_policy_document as _review_policy_document,
)
from .canonical import canonical_json, strict_canonical_json
from .capability_router import (
    CapabilityProviderRegistry,
    CapabilityRouteSelector,
    PlanBoundCapabilityRouter,
    RevisionSetCapabilityRouter,
)
from .consistency_materialization import (
    CONSISTENCY_MATERIALIZATION_COUNT_FIELDS,
    CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
    ConsistencyMaterializationError,
    ConsistencyMaterializationLimits,
    ConsistencyMaterializationStatus,
    _validate_materialized_artifact_ids,
    _validate_materialized_consistency_basis,
    _validate_materialized_consistency_diagnostic,
    _validate_materialized_consistency_finding,
    _validate_materialized_provider_projection,
    legacy_consistency_materialization_envelope,
    revision_consistency_selected_pins,
    validate_consistency_materialization_envelope,
)
from .control_plane_errors import (
    ControlPlaneError as ControlPlaneError,  # noqa: PLC0414 - compatibility export
)
from .control_plane_errors import (
    ControlPlaneScopeError as ControlPlaneScopeError,  # noqa: PLC0414 - compatibility export
)
from .control_plane_errors import (
    DatasetIntegrityError as DatasetIntegrityError,  # noqa: PLC0414 - compatibility export
)
from .control_plane_errors import (
    HiddenSubjectResolutionError as HiddenSubjectResolutionError,  # noqa: PLC0414 - compatibility export
)
from .control_plane_errors import (
    SubjectResolutionError as SubjectResolutionError,  # noqa: PLC0414 - compatibility export
)
from .corroboration import (
    CorroborationFact,
    EventIdentity,
    ExplicitCausalLink,
    ResolvedEventRef,
    SourceRecordIdentity,
    corroborate_events,
)
from .filesystem_lock import exclusive_file_lock
from .ingestion_contracts import (
    _DATASET_FORMAT as _DATASET_FORMAT,  # noqa: PLC0414 - compatibility export
)
from .ingestion_pipeline import (
    DurableIngestionPipeline,
    ImportScope,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
    RetentionHostInventoryCoverage,
    RetentionPolicy,
    RetentionReport,
    _registered_plugin_is_process_capable,
    _registered_plugin_is_trusted_inline_capable,
    _registered_plugins_require_inline_execution,
    _require_no_inline_only_plugin_compatibility,
    validate_ingestion_state_root,
)
from .normalized_data import (
    event_redaction_policy,
    project_consistency_findings_for_client,
    project_consistency_materialization_for_client,
    redact_event_for_client,
    resource_id,
)
from .plugin_api import (
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    EvidenceAnalysisFact,
    EvidenceAnalysisKind,
    EvidenceAnalysisRequest,
    PluginCapability,
)
from .plugin_composition import PluginCompositionPolicy
from .plugin_execution_plan import (
    PluginExecutionPin,
    PluginExecutionPlan,
    primary_parser_execution_pin,
    snapshot_plugin_execution_plan,
)
from .private_analysis import (
    DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES,
    MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES,
    MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES,
    PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA,
    PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND,
    EvidenceEnvelope,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeRange,
    PrivateAnalysisCapabilityArguments,
    PrivateAnalysisCapabilityIntent,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisPolicy,
    PrivateAnalysisRequest,
    evidence_locator_digest,
    evidence_payload_digest,
)
from .private_analysis_binding import (
    PrivateAnalysisEvidenceBindingError,
    bind_private_analysis_plugin_producer,
    bind_private_analysis_revision,
    verify_private_analysis_evidence_binding,
)
from .private_analysis_execution import (
    PrivateAnalysisExecutionCoordinator,
    PrivateAnalysisExecutionLimits,
    PrivateAnalysisRunnerRegistration,
)
from .private_analysis_promotion import (
    PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES,
    PrivateAnalysisProposalReviewService,
    SqliteProposalReviewStore,
)
from .private_analysis_revision_evidence import (
    PrivateAnalysisRevisionEvidenceCancelled,
    PrivateAnalysisRevisionEvidenceError,
    TrustedPrivateAnalysisRevision,
    build_private_analysis_revision_evidence_corpus,
    validate_private_analysis_timeline_metadata,
)
from .private_analysis_run_store import SqlitePrivateAnalysisRunStore
from .private_analysis_service import (
    PrivateAnalysisDeploymentCeilings,
    PrivateAnalysisService,
)
from .private_analysis_tool_service import (
    PrivateAnalysisAuthorizationDecision,
    PrivateAnalysisToolService,
    PrivateAnalysisWorkspacePolicySnapshot,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .relationship_projection_materialization import (
    RelationshipProjectionMaterializationError,
    RelationshipProjectionMaterializationLimits,
    RelationshipProjectionMaterializationStatus,
    validate_relationship_projection_storage_fragment,
)
from .session_catalog_publisher import (
    SessionCatalogPublisher as SessionCatalogPublisher,  # noqa: PLC0414 - compatibility export
)
from .session_store import (
    AnalysisRevisionDescriptor,
    AnalysisSession,
    CatalogArtifactRelease,
    CatalogRetentionInventory,
    CatalogRetentionPolicy,
    CatalogRetentionResult,
    FixtureDescriptor,
    IdempotencyConflict,
    RetentionSagaDescriptor,
    SessionStoreError,
    SqliteSessionStore,
    WorkspaceDescriptor,
    _catalog_artifact_release_from_document,
    _catalog_inventory_document,
    _catalog_inventory_from_document,
    _catalog_result_document,
    _catalog_result_from_document,
)
from .source_record_core import (
    project_source_record_for_log,
    source_record_event_uids,
)
from .value_core import MAX_JSON_SAFE_INTEGER, parse_canonical_decimal_integer

_DEFAULT_MAX_DATASET_BYTES = 2 * 1024 * 1024 * 1024
_DEFAULT_DATASET_CACHE_ENTRIES = 4
_MAX_REPORT_OBSERVATIONS = 10_000
_DEFAULT_MAX_REPORT_REVISIONS = 128
_DEFAULT_MAX_REPORT_DATASET_BYTES = 8 * 1024 * 1024 * 1024
_DEFAULT_MAX_REPORT_CORRELATION_EDGES = 20_000
_DEFAULT_MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES = 2_000_000
_DEFAULT_MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES = (
    DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
)
_CONSISTENCY_MATERIALIZATION_INGESTION_MODE = "core-ingestion-v3"
_MAX_RETENTION_RELEASE_ACTIONS = 10_000
_MAX_RETENTION_ACTOR_LENGTH = 256
_MAX_RETENTION_OPERATION_ID_LENGTH = 248
_RETENTION_SAGA_SCHEMA = "router_dump_analyzer.retention_saga.v1"
_RETENTION_PHASE_SCHEMA = "router_dump_analyzer.retention_phase.v1"
_PRIVATE_RUN_STORE_BINDING_SCHEMA = (
    "router_dump_analyzer.private_analysis.store_binding.v1"
)

_PRIVATE_ANALYSIS_KIND_BY_INTENT = {
    PrivateAnalysisCapabilityIntent.ROUTE_TRACE: EvidenceAnalysisKind.ROUTE_TRACE,
    PrivateAnalysisCapabilityIntent.TRACE_CORRELATION: (
        EvidenceAnalysisKind.TRACE_CORRELATION
    ),
    PrivateAnalysisCapabilityIntent.EVIDENCE_CORRELATION: (
        EvidenceAnalysisKind.EVIDENCE_CORRELATION
    ),
    PrivateAnalysisCapabilityIntent.EVIDENCE_INTERPRETATION: (
        EvidenceAnalysisKind.EVIDENCE_INTERPRETATION
    ),
}


def _private_analysis_plain_json(value: object) -> object:
    """Project an executor-validated frozen JSON value to plain containers."""

    if isinstance(value, Mapping):
        return {key: _private_analysis_plain_json(item) for key, item in value.items()}
    if type(value) in {tuple, list}:
        return [_private_analysis_plain_json(item) for item in value]
    return value


_PRIVATE_RUN_STORE_BINDING_NAME = ".private-analysis-run-store.binding.json"
_PRIVATE_RUN_STORE_BINDING_LOCK_NAME = ".private-analysis-run-store.binding.lock"
_MAX_PRIVATE_RUN_STORE_BINDING_BYTES = 1_024
_PROPOSAL_REVIEW_AUTHORITY_KEY_NAME = ".private-analysis-proposal-review.authority.key"
_PROPOSAL_REVIEW_AUTHORITY_KEY_LOCK_NAME = (
    ".private-analysis-proposal-review.authority.lock"
)


def _private_run_store_binding(path: Path) -> str | None:
    """Read one exact root-to-database binding without creating state."""

    try:
        try:
            path_status = path.stat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(path_status.st_mode) or (
            path_status.st_size > _MAX_PRIVATE_RUN_STORE_BINDING_BYTES
        ):
            raise ControlPlaneError("private-analysis run-store binding is invalid")
        wire = path.read_text(encoding="utf-8")
        document = json.loads(wire)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControlPlaneError(
            "private-analysis run-store binding is invalid"
        ) from error
    expected_fields = {"schema_version", "installation_id"}
    if (
        type(document) is not dict
        or set(document) != expected_fields
        or document.get("schema_version") != _PRIVATE_RUN_STORE_BINDING_SCHEMA
        or type(document.get("installation_id")) is not str
        or canonical_json(document) != wire
    ):
        raise ControlPlaneError("private-analysis run-store binding is invalid")
    return str(document["installation_id"])


def _write_private_run_store_binding(path: Path, installation_id: str) -> None:
    document = {
        "schema_version": _PRIVATE_RUN_STORE_BINDING_SCHEMA,
        "installation_id": installation_id,
    }
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical_json(document))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ControlPlaneError(
            "private-analysis run-store binding could not be persisted"
        ) from error


def _proposal_review_authority_key(path: Path) -> bytes | None:
    """Read one external proposal-review MAC key without creating state."""

    try:
        try:
            path_status = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(path_status.st_mode)
            or path_status.st_size != PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES
        ):
            raise ControlPlaneError(
                "private-analysis proposal-review authority key is invalid"
            )
        value = path.read_bytes()
    except OSError as error:
        raise ControlPlaneError(
            "private-analysis proposal-review authority key is invalid"
        ) from error
    if len(value) != PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES:
        raise ControlPlaneError(
            "private-analysis proposal-review authority key is invalid"
        )
    return value


def _write_proposal_review_authority_key(path: Path, value: bytes) -> None:
    if type(value) is not bytes or len(value) != PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES:
        raise ControlPlaneError(
            "private-analysis proposal-review authority key is invalid"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    binary_flag = getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags | binary_flag, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ControlPlaneError(
            "private-analysis proposal-review authority key could not be persisted"
        ) from error


class RetentionObservationMode(StrEnum):
    """Whether a retention response is advisory or transactionally ordered."""

    BEST_EFFORT_PREVIEW = "best_effort_preview"
    COORDINATED_EXECUTION = "coordinated_execution"


@dataclass(frozen=True, slots=True)
class ControlPlaneLimits:
    """Resource bounds applied while reopening serialized revisions."""

    max_dataset_bytes: int = _DEFAULT_MAX_DATASET_BYTES
    dataset_cache_entries: int = _DEFAULT_DATASET_CACHE_ENTRIES
    max_report_observations: int = _MAX_REPORT_OBSERVATIONS
    max_report_revisions: int = _DEFAULT_MAX_REPORT_REVISIONS
    max_report_dataset_bytes: int = _DEFAULT_MAX_REPORT_DATASET_BYTES
    max_report_correlation_edges: int = _DEFAULT_MAX_REPORT_CORRELATION_EDGES
    max_private_analysis_evidence_corpus_entries: int = (
        _DEFAULT_MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES
    )
    max_private_analysis_evidence_corpus_payload_bytes: int = (
        _DEFAULT_MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
    )
    max_subject_revisions: int = _DEFAULT_MAX_REPORT_REVISIONS
    max_subject_dataset_bytes: int = _DEFAULT_MAX_REPORT_DATASET_BYTES

    def __post_init__(self) -> None:
        if (
            type(self.max_subject_revisions) is not int
            or not 1 <= self.max_subject_revisions <= MAX_ANNOTATION_SUBJECTS
        ):
            raise ValueError("max_subject_revisions must be between 1 and 5000")
        if (
            type(self.max_subject_dataset_bytes) is not int
            or self.max_subject_dataset_bytes < 1
        ):
            raise ValueError("max_subject_dataset_bytes must be a positive integer")
        if type(self.max_dataset_bytes) is not int or self.max_dataset_bytes < 1:
            raise ValueError("max_dataset_bytes must be a positive integer")
        if (
            type(self.dataset_cache_entries) is not int
            or not 0 <= self.dataset_cache_entries <= 1_024
        ):
            raise ValueError("dataset_cache_entries must be between 0 and 1024")
        if (
            type(self.max_report_observations) is not int
            or not 1 <= self.max_report_observations <= _MAX_REPORT_OBSERVATIONS
        ):
            raise ValueError("max_report_observations must be between 1 and 10000")
        if (
            type(self.max_report_revisions) is not int
            or not 1 <= self.max_report_revisions <= 5_000
        ):
            raise ValueError("max_report_revisions must be between 1 and 5000")
        if (
            type(self.max_report_dataset_bytes) is not int
            or self.max_report_dataset_bytes < 1
        ):
            raise ValueError("max_report_dataset_bytes must be a positive integer")
        if (
            type(self.max_report_correlation_edges) is not int
            or not 1 <= self.max_report_correlation_edges <= 100_000
        ):
            raise ValueError(
                "max_report_correlation_edges must be between 1 and 100000"
            )
        if (
            type(self.max_private_analysis_evidence_corpus_entries) is not int
            or not 1
            <= self.max_private_analysis_evidence_corpus_entries
            <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES
        ):
            raise ValueError(
                "max_private_analysis_evidence_corpus_entries must be between "
                f"1 and {MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES}"
            )
        if (
            type(self.max_private_analysis_evidence_corpus_payload_bytes) is not int
            or not 1
            <= self.max_private_analysis_evidence_corpus_payload_bytes
            <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
        ):
            raise ValueError(
                "max_private_analysis_evidence_corpus_payload_bytes must be "
                "between 1 and "
                f"{MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES}"
            )


@dataclass(frozen=True, slots=True)
class RevisionConsistencyFindingsPage:
    """One detached, workspace-authorized page of durable findings."""

    revision_id: str
    materialization: Mapping[str, Any]
    items: tuple[Mapping[str, Any], ...]
    offset: int
    limit: int
    total_count: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if type(self.revision_id) is not str or not self.revision_id:
            raise ValueError("revision_id must be a non-empty string")
        if not isinstance(self.materialization, Mapping):
            raise TypeError("materialization must be a mapping")
        if type(self.items) is not tuple or any(
            not isinstance(item, Mapping) for item in self.items
        ):
            raise TypeError("items must be a tuple of mappings")
        if (
            type(self.offset) is not int
            or not 0 <= self.offset <= MAX_JSON_SAFE_INTEGER
        ):
            raise ValueError("offset must be a JSON-safe non-negative integer")
        if type(self.limit) is not int or not 1 <= self.limit <= 5_000:
            raise ValueError("limit must be between 1 and 5000")
        if (
            type(self.total_count) is not int
            or not 0 <= self.total_count <= MAX_JSON_SAFE_INTEGER
        ):
            raise ValueError("total_count must be a JSON-safe non-negative integer")
        if self.next_offset is not None and (
            type(self.next_offset) is not int
            or not 0 <= self.next_offset <= MAX_JSON_SAFE_INTEGER
            or self.next_offset <= self.offset
            or self.next_offset >= self.total_count
        ):
            raise ValueError("next_offset must identify a later page")


@dataclass(frozen=True, slots=True)
class _DatasetIndex:
    events: Mapping[str, Mapping[str, Any]]
    source_records: Mapping[str, Mapping[str, Any]]
    resources: frozenset[str]
    relationships: frozenset[str]
    findings: tuple[Mapping[str, Any], ...]
    consistency_materialization: Mapping[str, Any]
    timeline_start_ns: int
    timeline_end_ns: int


@dataclass(frozen=True, slots=True)
class _LoadedRevision:
    descriptor: AnalysisRevisionDescriptor
    dataset: Mapping[str, Any]
    index: _DatasetIndex


@dataclass(frozen=True, slots=True)
class ControlPlaneRetentionResult:
    """One workspace-scoped retention observation or maintenance result."""

    scope: ReviewScope
    executed: bool
    observation_mode: RetentionObservationMode
    ingestion: RetentionReport
    catalog: CatalogRetentionInventory | CatalogRetentionResult
    review: ReviewRetentionInventory | ReviewRetentionResult
    replayed_release_actions: int = 0
    replayed_artifact_releases: int = 0


def _catalog_policy_is_effective_for(
    requested: CatalogRetentionPolicy,
    effective: CatalogRetentionPolicy,
) -> bool:
    requested_document = requested.as_dict()
    effective_document = effective.as_dict()
    for field in (
        "enabled",
        "idempotency_before_ns",
        "snapshot_before_ns",
        "revision_before_ns",
        "fixture_before_ns",
        "preserve_latest_snapshot_per_session",
        "protected_fixture_ids",
        "protected_snapshot_ids",
        "maximum_candidates",
    ):
        if requested_document[field] != effective_document[field]:
            return False
    return effective.external_references_checked and set(
        requested.protected_revision_ids
    ).issubset(effective.protected_revision_ids)


def _retention_saga_request_document(
    catalog_policy: CatalogRetentionPolicy,
    review_policy: ReviewRetentionPolicy,
    ingestion_policy: RetentionPolicy,
) -> dict[str, Any]:
    return {
        "schema": _RETENTION_SAGA_SCHEMA,
        "catalog_policy": catalog_policy.as_dict(),
        "review_policy": _review_policy_document(review_policy),
        "ingestion_policy": asdict(ingestion_policy),
    }


def _review_phase_document(
    value: ReviewRetentionInventory | ReviewRetentionResult,
) -> dict[str, Any]:
    if isinstance(value, ReviewRetentionResult):
        inventory = value.inventory
        kind = "result"
        payload = _review_retention_result_document(value)
    else:
        inventory = value
        kind = "inventory"
        payload = {"inventory": _review_retention_inventory_document(value), "purged": []}
    return {
        "schema": _RETENTION_PHASE_SCHEMA,
        "kind": kind,
        "policy": _review_policy_document(inventory.policy),
        **payload,
    }


def _review_phase_from_document(
    scope: ReviewScope,
    value: Mapping[str, Any],
) -> ReviewRetentionInventory | ReviewRetentionResult:
    try:
        if set(value) != {"schema", "kind", "policy", "inventory", "purged"}:
            raise ValueError
        if value["schema"] != _RETENTION_PHASE_SCHEMA:
            raise ValueError
        kind = value["kind"]
        policy_value = value["policy"]
        if kind not in {"inventory", "result"} or not isinstance(policy_value, dict):
            raise ValueError
        policy = ReviewRetentionPolicy(**policy_value)
        if kind == "inventory":
            if value["purged"] != []:
                raise ValueError
            return _review_retention_inventory_from_document(
                value["inventory"], scope=scope, policy=policy
            )
        return _review_retention_result_from_document(
            {"inventory": value["inventory"], "purged": value["purged"]},
            scope=scope,
            policy=policy,
        )
    except (KeyError, TypeError, ValueError, ReviewOverlayError) as error:
        raise ControlPlaneError(
            "durable review retention phase result is invalid"
        ) from error


def _catalog_phase_document(
    value: CatalogRetentionInventory | CatalogRetentionResult,
) -> dict[str, Any]:
    if isinstance(value, CatalogRetentionResult):
        inventory = value.inventory
        kind = "result"
        payload = _catalog_result_document(value)
    else:
        inventory = value
        kind = "inventory"
        payload = {
            "inventory": _catalog_inventory_document(value),
            "purged": [],
            "artifact_releases": [],
        }
    return {
        "schema": _RETENTION_PHASE_SCHEMA,
        "kind": kind,
        "policy": inventory.policy.as_dict(),
        **payload,
    }


def _catalog_phase_from_document(
    scope: ReviewScope,
    value: Mapping[str, Any],
) -> CatalogRetentionInventory | CatalogRetentionResult:
    try:
        if set(value) != {
            "schema", "kind", "policy", "inventory", "purged", "artifact_releases"
        }:
            raise ValueError
        if value["schema"] != _RETENTION_PHASE_SCHEMA:
            raise ValueError
        kind = value["kind"]
        policy_value = value["policy"]
        if kind not in {"inventory", "result"} or not isinstance(policy_value, dict):
            raise ValueError
        policy = CatalogRetentionPolicy(**policy_value)
        if kind == "inventory":
            if value["purged"] != [] or value["artifact_releases"] != []:
                raise ValueError
            return _catalog_inventory_from_document(
                value["inventory"],
                tenant_id=scope.tenant_id,
                workspace_id=scope.workspace_id,
                policy=policy,
            )
        return _catalog_result_from_document(
            {
                "inventory": value["inventory"],
                "purged": value["purged"],
                "artifact_releases": value["artifact_releases"],
            },
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            policy=policy,
        )
    except (KeyError, TypeError, ValueError, SessionStoreError) as error:
        raise ControlPlaneError(
            "durable catalog retention phase result is invalid"
        ) from error


def _ingestion_phase_document(value: RetentionReport) -> dict[str, Any]:
    return {
        "schema": _RETENTION_PHASE_SCHEMA,
        "report": value.as_dict(),
    }


def _ingestion_phase_from_document(
    scope: ImportScope,
    value: Mapping[str, Any],
) -> RetentionReport:
    try:
        if set(value) != {"schema", "report"}:
            raise ValueError
        if value.get("schema") != _RETENTION_PHASE_SCHEMA:
            raise ValueError
        report = value["report"]
        report_fields = {
            "scope",
            "evaluated_at_ns",
            "executed",
            "policy_enabled",
            "host_storage_orphan_inventory",
            "eligible_imports",
            "candidate_events",
            "candidate_plugin_rows",
            "expired_idempotency_receipts",
            "expired_retention_audits",
            "fixture_views",
            "content_blobs",
            "revision_datasets",
            "stale_partials",
            "estimated_bytes",
            "deleted_imports",
            "deleted_retention_audits",
            "deleted_files",
            "deleted_bytes",
            "deletion_failures",
            "failure_details",
            "truncated",
            "audit_id",
        }
        legacy_report_fields = report_fields - {
            "expired_retention_audits",
            "deleted_retention_audits",
            "host_storage_orphan_inventory",
        }
        pre_coverage_report_fields = report_fields - {
            "host_storage_orphan_inventory",
        }
        if not isinstance(report, dict) or set(report) not in {
            frozenset(report_fields),
            frozenset(pre_coverage_report_fields),
            frozenset(legacy_report_fields),
        }:
            raise TypeError
        stored_scope = report["scope"]
        if not isinstance(stored_scope, dict) or stored_scope != {
            "tenant_id": scope.tenant_id,
            "project_id": scope.project_id,
            "workspace_id": scope.workspace_id,
        }:
            raise ValueError
        failure_details = report["failure_details"]
        if not isinstance(failure_details, list):
            raise TypeError
        integer_fields = (
            "eligible_imports",
            "candidate_events",
            "candidate_plugin_rows",
            "expired_idempotency_receipts",
            "expired_retention_audits",
            "fixture_views",
            "content_blobs",
            "revision_datasets",
            "stale_partials",
            "estimated_bytes",
            "deleted_imports",
            "deleted_retention_audits",
            "deleted_files",
            "deleted_bytes",
            "deletion_failures",
        )
        if any(type(report.get(field, 0)) is not int for field in integer_fields):
            raise ValueError
        integers = {field: report.get(field, 0) for field in integer_fields}
        if any(number < 0 for number in integers.values()):
            raise ValueError
        audit_id = report["audit_id"]
        if audit_id is not None and not isinstance(audit_id, str):
            raise ValueError
        evaluated_at_ns = parse_canonical_decimal_integer(
            report["evaluated_at_ns"],
            "retention report evaluated_at_ns",
            minimum=0,
            maximum=MAX_TIMESTAMP_NS,
        )
        if (
            type(report["executed"]) is not bool
            or type(report["policy_enabled"]) is not bool
            or type(report["truncated"]) is not bool
            or any(not isinstance(item, str) for item in failure_details)
        ):
            raise ValueError
        raw_host_inventory = report.get(
            "host_storage_orphan_inventory",
            RetentionHostInventoryCoverage.BOUNDED_HOST_SCAN.value,
        )
        if not isinstance(raw_host_inventory, str):
            raise TypeError
        host_inventory = RetentionHostInventoryCoverage(raw_host_inventory)
        return RetentionReport(
            scope=scope,
            evaluated_at_ns=evaluated_at_ns,
            executed=report["executed"],
            policy_enabled=report["policy_enabled"],
            host_storage_orphan_inventory=host_inventory,
            **integers,
            failure_details=tuple(str(item) for item in failure_details),
            truncated=report["truncated"],
            audit_id=audit_id,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ControlPlaneError(
            "durable ingestion retention phase result is invalid"
        ) from error


def _control_plane_retention_from_saga(
    scope: ReviewScope,
    saga: RetentionSagaDescriptor,
) -> ControlPlaneRetentionResult:
    if any(
        result is None
        for result in (
            saga.review_result,
            saga.catalog_result,
            saga.ingestion_result,
        )
    ):
        raise ControlPlaneError("retention saga is not complete")
    assert saga.review_result is not None
    assert saga.catalog_result is not None
    assert saga.ingestion_result is not None
    ingestion_scope = ImportScope(
        scope.tenant_id,
        scope.project_id,
        scope.workspace_id,
    )
    review = _review_phase_from_document(scope, saga.review_result)
    catalog = _catalog_phase_from_document(scope, saga.catalog_result)
    ingestion = _ingestion_phase_from_document(
        ingestion_scope,
        saga.ingestion_result,
    )
    return ControlPlaneRetentionResult(
        scope=scope,
        executed=(
            isinstance(review, ReviewRetentionResult)
            or isinstance(catalog, CatalogRetentionResult)
            or ingestion.executed
        ),
        observation_mode=RetentionObservationMode.COORDINATED_EXECUTION,
        ingestion=ingestion,
        catalog=catalog,
        review=review,
        replayed_release_actions=saga.replayed_release_actions,
        replayed_artifact_releases=saga.replayed_artifact_releases,
    )


def _retention_identity(value: object, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(
            f"{label} must contain 1 to {maximum} non-control characters "
            "without surrounding whitespace"
        )
    return value


def _exact_identifier(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DatasetIntegrityError(f"{label} must be a non-empty string")
    return value


def _non_negative_ns(value: object, *, label: str) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            label,
            minimum=0,
            maximum=MAX_TIMESTAMP_NS,
        )
    except ValueError as error:
        raise DatasetIntegrityError(
            f"{label} must be a non-negative signed 64-bit integer"
        ) from error


def _consistency_count(value: object, *, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_JSON_SAFE_INTEGER:
        raise DatasetIntegrityError(f"{label} must be a JSON-safe non-negative integer")
    return value


def _consistency_provider_projection(
    pin: PluginExecutionPin,
    plan: PluginExecutionPlan,
) -> dict[str, Any]:
    return {
        "member_id": plan.basis_revision_id,
        "node_id": plan.node_id,
        "basis_revision_id": plan.basis_revision_id,
        "plan_digest": plan.plan_digest,
        "instance_id": pin.instance_id,
        "plugin_id": pin.plugin_id,
        "plugin_version": pin.plugin_version,
        "registered_execution_identity": pin.registered_execution_identity,
        "configuration_digest": pin.configuration_digest,
        "schema_digest": pin.schema_digest,
        "package_hash": pin.artifact.package_hash,
        "capability": PluginCapability.CONSISTENCY_CHECK.value,
        "roles": list(pin.roles),
    }


def _verified_materialized_identity(
    record: Mapping[str, Any],
    *,
    identity_field: str,
    label: str,
) -> str:
    identifier = record.get(identity_field)
    if (
        type(identifier) is not str
        or len(identifier) != 71
        or not identifier.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in identifier[7:])
    ):
        raise DatasetIntegrityError(f"{label} has an invalid identifier")
    payload = dict(record)
    payload.pop(identity_field, None)
    try:
        canonical_payload = strict_canonical_json(payload)
    except (TypeError, ValueError) as error:
        raise DatasetIntegrityError(f"{label} is not canonical") from error
    expected = "sha256:" + hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    if identifier != expected:
        raise DatasetIntegrityError(f"{label} identifier does not match its record")
    return identifier


def _event_ns(value: object, *, label: str) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            label,
            minimum=MIN_TIMESTAMP_NS,
            maximum=MAX_TIMESTAMP_NS,
        )
    except ValueError as error:
        raise DatasetIntegrityError(
            f"{label} must be a canonical signed 64-bit integer"
        ) from error


def relationship_subject_id(value: Mapping[str, Any]) -> str:
    """Return the stable core identity used by relationship review subjects.

    A declared ``relationship_id``/``id`` wins.  Core-ingested relationship
    observations do not need to invent such a field, so their exact
    source/type/target tuple receives a type-preserving digest.  The core does
    not interpret any of those opaque values.
    """

    explicit = value.get("relationship_id") or value.get("id")
    if explicit is not None:
        return _exact_identifier(explicit, label="relationship identifier")
    for field in ("source", "target"):
        _exact_identifier(value.get(field), label=f"relationship {field}")
    relation_type = value.get("relation_type", value.get("type"))
    _exact_identifier(relation_type, label="relationship type")
    identity = {
        "source": value["source"],
        "relation_type": relation_type,
        "target": value["target"],
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return f"relationship:{digest}"


class ControlPlane:
    """Own one durable, single-host control-plane profile."""

    def __init__(
        self,
        root: str | Path,
        *,
        registry: PluginRegistry,
        pipeline_limits: PipelineLimits | None = None,
        retention_policy: RetentionPolicy | None = None,
        plugin_composition_policy: PluginCompositionPolicy | None = None,
        capability_providers: CapabilityProviderRegistry | None = None,
        limits: ControlPlaneLimits | None = None,
        private_analysis_runners: tuple[PrivateAnalysisRunnerRegistration, ...] = (),
        private_analysis_execution_limits: PrivateAnalysisExecutionLimits | None = None,
        private_analysis_ceilings: PrivateAnalysisDeploymentCeilings | None = None,
        allow_inline_only: bool = False,
    ) -> None:
        if type(registry) is not PluginRegistry:
            raise TypeError("registry must be an exact PluginRegistry")
        if type(allow_inline_only) is not bool:
            raise TypeError("allow_inline_only must be an exact boolean")
        if pipeline_limits is not None and type(pipeline_limits) is not PipelineLimits:
            raise TypeError("pipeline_limits must be PipelineLimits or None")
        authority_registry = registry._sealed_snapshot()
        authority_records = authority_registry.records()
        if allow_inline_only:
            for record in authority_records:
                PluginRegistry.revalidate_registered_identity(record)
                if not _registered_plugin_is_process_capable(
                    record
                ) and not _registered_plugin_is_trusted_inline_capable(record):
                    raise ValueError(
                        "trusted INLINE-only durable control plane requires "
                        "registered attested execution identities"
                    )
        else:
            authority_registry.require_executable_identities()
        authority_capability_providers: CapabilityProviderRegistry | None = None
        if capability_providers is not None:
            if type(capability_providers) is not CapabilityProviderRegistry:
                raise TypeError(
                    "capability_providers must be an exact "
                    "CapabilityProviderRegistry or None"
                )
            authority_capability_providers = capability_providers._sealed_snapshot()
            provider_records = authority_capability_providers.records()
            if not allow_inline_only:
                _require_no_inline_only_plugin_compatibility(
                    provider_records,
                    boundary=(
                        "durable control plane requires PROCESS-capable plug-in "
                        "providers"
                    ),
                )
            else:
                for record in provider_records:
                    PluginRegistry.revalidate_registered_identity(record)
                    if not _registered_plugin_is_process_capable(
                        record
                    ) and not _registered_plugin_is_trusted_inline_capable(record):
                        raise ValueError(
                            "trusted INLINE-only capability providers require "
                            "registered attested execution identities"
                        )
        else:
            provider_records = authority_records
        requires_inline_execution = _registered_plugins_require_inline_execution(
            (*authority_records, *provider_records)
        )
        effective_pipeline_limits = pipeline_limits or PipelineLimits(
            plugin_execution_mode=(
                PluginExecutionMode.INLINE
                if requires_inline_execution
                else PluginExecutionMode.PROCESS
            ),
            publisher_execution_mode=PluginExecutionMode.PROCESS,
        )
        if (
            requires_inline_execution
            and effective_pipeline_limits.plugin_execution_mode
            is not PluginExecutionMode.INLINE
        ):
            raise ValueError(
                "trusted INLINE-only durable control plane requires "
                "PipelineLimits(plugin_execution_mode='inline')"
            )
        if (
            allow_inline_only
            and effective_pipeline_limits.plugin_execution_mode
            is PluginExecutionMode.INLINE
            and effective_pipeline_limits.publisher_execution_mode is None
        ):
            effective_pipeline_limits = replace(
                effective_pipeline_limits,
                publisher_execution_mode=PluginExecutionMode.PROCESS,
            )
        # Validate the longest core-owned ingestion pathname before creating
        # SQLite files or directories, so an unsupported Windows state root
        # fails atomically instead of surfacing later as a worker failure.
        self.root: Path = validate_ingestion_state_root(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits: ControlPlaneLimits = limits or ControlPlaneLimits()
        self.allow_inline_only: bool = allow_inline_only
        self.requires_inline_execution: bool = requires_inline_execution
        self._lock = threading.RLock()
        self._closed = False
        self._started = False
        self._cache: OrderedDict[str, _LoadedRevision] = OrderedDict()
        self._retention_review_lock_path = self.root / ".review-catalog-retention.lock"
        self._private_run_store_binding_path = (
            self.root / _PRIVATE_RUN_STORE_BINDING_NAME
        )
        self._private_run_store_binding_lock_path = (
            self.root / _PRIVATE_RUN_STORE_BINDING_LOCK_NAME
        )
        self._proposal_review_authority_key_path = (
            self.root / _PROPOSAL_REVIEW_AUTHORITY_KEY_NAME
        )
        self._proposal_review_authority_key_lock_path = (
            self.root / _PROPOSAL_REVIEW_AUTHORITY_KEY_LOCK_NAME
        )
        self.sessions: SqliteSessionStore = SqliteSessionStore(
            self.root / "sessions.sqlite3"
        )
        annotations: ReviewOverlayStore | None = None
        private_analysis_runs: SqlitePrivateAnalysisRunStore | None = None
        private_analysis_execution: PrivateAnalysisExecutionCoordinator | None = None
        proposal_reviews: SqliteProposalReviewStore | None = None
        try:
            annotations = ReviewOverlayStore(self.root / "annotations.sqlite3")
            self.annotations: ReviewOverlayStore = annotations
            private_run_database = self.root / "private-analysis-runs.sqlite3"
            with exclusive_file_lock(self._private_run_store_binding_lock_path):
                expected_installation = _private_run_store_binding(
                    self._private_run_store_binding_path
                )
                try:
                    try:
                        database_status = private_run_database.stat()
                    except FileNotFoundError:
                        database_status = None
                except OSError as error:
                    raise ControlPlaneError(
                        "private-analysis run store could not be inspected"
                    ) from error
                if expected_installation is None and database_status is not None:
                    raise ControlPlaneError(
                        "private-analysis run-store binding is missing"
                    )
                if expected_installation is not None:
                    database_is_missing = database_status is None or (
                        not stat.S_ISREG(database_status.st_mode)
                        or database_status.st_size == 0
                    )
                    if database_is_missing:
                        raise ControlPlaneError(
                            "private-analysis run store is missing or truncated"
                        )
                private_analysis_runs = SqlitePrivateAnalysisRunStore(
                    private_run_database,
                    admission_validator=self._validate_private_analysis_request,
                    admission_fence=self._coordinated_review_catalog,
                )
                if expected_installation is None:
                    _write_private_run_store_binding(
                        self._private_run_store_binding_path,
                        private_analysis_runs.installation_id,
                    )
                elif private_analysis_runs.installation_id != expected_installation:
                    raise ControlPlaneError(
                        "private-analysis run store does not match its binding"
                    )
            self.private_analysis_runs: SqlitePrivateAnalysisRunStore = (
                private_analysis_runs
            )
            private_analysis_execution = PrivateAnalysisExecutionCoordinator(
                private_analysis_runs,
                registrations=private_analysis_runners,
                limits=private_analysis_execution_limits,
                core_tool_service_factory=(self._core_private_analysis_tool_service),
            )
            self.private_analysis_execution: PrivateAnalysisExecutionCoordinator = (
                private_analysis_execution
            )
            self.private_analysis: PrivateAnalysisService = PrivateAnalysisService(
                self.sessions,
                private_analysis_runs,
                private_analysis_execution,
                ceilings=private_analysis_ceilings,
            )
            proposal_review_database = (
                self.root / "private-analysis-proposal-reviews.sqlite3"
            )
            with exclusive_file_lock(self._proposal_review_authority_key_lock_path):
                try:
                    try:
                        proposal_review_database_status = (
                            proposal_review_database.lstat()
                        )
                    except FileNotFoundError:
                        proposal_review_database_status = None
                except OSError as error:
                    raise ControlPlaneError(
                        "private-analysis proposal-review store could not be inspected"
                    ) from error
                if proposal_review_database_status is not None and not stat.S_ISREG(
                    proposal_review_database_status.st_mode
                ):
                    raise ControlPlaneError(
                        "private-analysis proposal-review store is invalid"
                    )
                proposal_review_authority_key = _proposal_review_authority_key(
                    self._proposal_review_authority_key_path
                )
                if proposal_review_authority_key is None:
                    # Key creation is valid only for a brand-new store. Any
                    # pre-existing database may have lost rows independently
                    # of its key, so current contents cannot prove that
                    # minting replacement authority is safe.
                    if proposal_review_database_status is not None:
                        raise ControlPlaneError(
                            "private-analysis proposal-review authority key is missing"
                        )
                    proposal_review_authority_key = secrets.token_bytes(
                        PROPOSAL_REVIEW_AUTHORITY_KEY_BYTES
                    )
                    _write_proposal_review_authority_key(
                        self._proposal_review_authority_key_path,
                        proposal_review_authority_key,
                    )
                proposal_reviews = SqliteProposalReviewStore(
                    proposal_review_database,
                    authority_key=proposal_review_authority_key,
                )
            self.proposal_review_store: SqliteProposalReviewStore = proposal_reviews
            self.private_analysis_reviews: PrivateAnalysisProposalReviewService = (
                PrivateAnalysisProposalReviewService(
                    self.private_analysis,
                    proposal_reviews,
                    self,
                    admission_fence=self._coordinated_review_catalog,
                )
            )
            self.publisher: SessionCatalogPublisher = SessionCatalogPublisher(
                self.sessions
            )
            self.ingestion: DurableIngestionPipeline = DurableIngestionPipeline(
                self.root,
                registry=authority_registry,
                publisher=self.publisher,
                limits=effective_pipeline_limits,
                retention_policy=retention_policy,
                composition_policy=plugin_composition_policy,
                capability_providers=authority_capability_providers,
                allow_inline_only=allow_inline_only,
            )
            # Published execution plans and their exact provider directory
            # remain available to topology, route, and private-analysis
            # coordinators without exposing plug-in objects to callers.
            self.capability_providers: CapabilityProviderRegistry = (
                self.ingestion.capability_providers
            )
        except BaseException:
            if proposal_reviews is not None:
                proposal_reviews.close()
            if private_analysis_execution is not None:
                private_analysis_execution.close(timeout=0)
            if private_analysis_runs is not None:
                private_analysis_runs.close()
            if annotations is not None:
                annotations.close()
            self.sessions.close()
            raise

    def start(self) -> None:
        with self._lock:
            if self._closed:
                raise ControlPlaneError("control plane is closed")
            if self._started:
                return
            self.ingestion.start()
            self._started = True

    def close(self, *, timeout: float = 30.0) -> None:
        with self._lock:
            if self._closed:
                return
        # Keep the catalog and review stores alive until every ingestion
        # worker has stopped.  If a plug-in ignores shutdown long enough for
        # the timeout to expire, ``DurableIngestionPipeline.close`` raises and
        # a later call may retry without workers touching closed dependencies.
        self.private_analysis_execution.close(timeout=timeout)
        self.ingestion.close(timeout=timeout)
        with self._lock:
            if self._closed:
                return
            try:
                self.proposal_review_store.close()
            finally:
                try:
                    self.private_analysis_runs.close()
                finally:
                    try:
                        self.annotations.close()
                    finally:
                        self.sessions.close()
            self._closed = True
            self._cache.clear()
            self._started = False

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()

    def validate_scope(
        self,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
    ) -> WorkspaceDescriptor:
        """Resolve an authorization scope without trusting request metadata."""

        workspace = self.sessions.get_workspace(tenant_id, workspace_id)
        if workspace.project_id != project_id:
            raise ControlPlaneScopeError(
                "workspace does not belong to the requested project"
            )
        return workspace

    def _validate_private_analysis_request(
        self,
        request: PrivateAnalysisRequest,
    ) -> None:
        """Bind every requested revision to current durable catalog identity."""

        if type(request) is not PrivateAnalysisRequest:
            raise TypeError("request must be an exact PrivateAnalysisRequest")
        scope = request.scope
        workspace = self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        for binding in request.revisions:
            fixture = self.sessions.get_fixture(
                scope.tenant_id,
                binding.fixture_id,
            )
            revision = self.sessions.get_revision(
                scope.tenant_id,
                binding.revision_id,
            )
            expected_scope, expected_binding = bind_private_analysis_revision(
                workspace,
                fixture,
                revision,
            )
            if expected_scope != scope or expected_binding != binding:
                raise PrivateAnalysisEvidenceBindingError(
                    "private-analysis request revision binding has drifted"
                )

    def _core_private_analysis_tool_service(
        self,
        request: PrivateAnalysisRequest,
        runner_policy: PrivateAnalysisPolicy,
        cancellation_probe: Callable[[], bool],
    ) -> PrivateAnalysisToolService:
        """Freeze verified revision evidence before a local runner executes.

        The model receives only the closed query/read/analyze tool surface.
        Catalog, dataset, plug-in, filesystem, and mutation authority stay in
        this deployment-owned adapter, and each later read or analysis call
        revalidates its durable revision binding before releasing a payload.
        """

        self._validate_private_analysis_request(request)
        scope = request.scope
        workspace = self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        admitted_policy = self.sessions.get_workspace_disclosure_policy(
            workspace.tenant_id,
            workspace.workspace_id,
        )
        if admitted_policy.policy_digest != request.workspace_policy_digest:
            raise PrivateAnalysisEvidenceBindingError(
                "private-analysis workspace policy changed before evidence freezing"
            )
        plugin_evidence_class = (
            PrivateAnalysisEvidenceClass.PROPRIETARY
            if (
                admitted_policy.policy.mode
                is PrivateAnalysisDisclosureMode.FULL_FIDELITY
                and runner_policy.full_fidelity_workspace_data
            )
            else PrivateAnalysisEvidenceClass.CLIENT_SAFE
        )
        review_scope = ReviewScope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        trusted: list[TrustedPrivateAnalysisRevision] = []
        trusted_by_binding: dict[
            EvidenceRevisionBinding,
            TrustedPrivateAnalysisRevision,
        ] = {}
        for binding in request.revisions:
            if cancellation_probe():
                raise PrivateAnalysisRevisionEvidenceCancelled(
                    "private-analysis revision loading was cancelled"
                )
            fixture = self.sessions.get_fixture(
                scope.tenant_id,
                binding.fixture_id,
            )
            loaded = self._load_revision(
                review_scope,
                binding.revision_id,
                cancellation_probe=cancellation_probe,
            )
            expected_scope, expected_binding = bind_private_analysis_revision(
                workspace,
                fixture,
                loaded.descriptor,
            )
            if expected_scope != scope or expected_binding != binding:
                raise PrivateAnalysisEvidenceBindingError(
                    "private-analysis request revision binding has drifted"
                )
            supplied = TrustedPrivateAnalysisRevision(
                workspace=workspace,
                fixture=fixture,
                revision=loaded.descriptor,
                dataset=loaded.dataset,
            )
            trusted.append(supplied)
            trusted_by_binding[expected_binding] = supplied
        if cancellation_probe():
            raise PrivateAnalysisRevisionEvidenceCancelled(
                "private-analysis evidence freezing was cancelled"
            )
        corpus = build_private_analysis_revision_evidence_corpus(
            request,
            tuple(trusted),
            maximum_entries=(self.limits.max_private_analysis_evidence_corpus_entries),
            maximum_payload_bytes=(
                self.limits.max_private_analysis_evidence_corpus_payload_bytes
            ),
            plugin_evidence_class=plugin_evidence_class,
            cancellation_probe=cancellation_probe,
        )
        derived_references: dict[str, EvidenceReference] = {}
        derived_results: dict[
            str,
            tuple[EvidenceReference, dict[str, Any]],
        ] = {}
        derived_references_lock = threading.RLock()

        def authorize(
            selected: PrivateAnalysisRequest,
        ) -> PrivateAnalysisAuthorizationDecision:
            if selected != request:
                raise PrivateAnalysisEvidenceBindingError(
                    "private-analysis request changed after evidence freezing"
                )
            self._validate_private_analysis_request(selected)
            return PrivateAnalysisAuthorizationDecision.allow(selected)

        def resolve_policy(
            selected_scope: EvidenceScope,
        ) -> PrivateAnalysisWorkspacePolicySnapshot:
            if selected_scope != scope:
                raise ControlPlaneScopeError(
                    "private-analysis policy scope changed after admission"
                )
            current_workspace = self.validate_scope(
                selected_scope.tenant_id,
                selected_scope.project_id,
                selected_scope.workspace_id,
            )
            policy = self.sessions.get_workspace_disclosure_policy(
                current_workspace.tenant_id,
                current_workspace.workspace_id,
            )
            return PrivateAnalysisWorkspacePolicySnapshot(
                scope=selected_scope,
                policy_version=policy.version,
                policy=policy.policy,
                policy_digest=policy.policy_digest,
            )

        def analyze_evidence(
            selected: PrivateAnalysisRequest,
            arguments: PrivateAnalysisCapabilityArguments,
            parents: tuple[EvidenceEnvelope, ...],
            selected_cancellation_probe: Callable[[], bool] | None,
        ) -> tuple[EvidenceReference, dict[str, Any]]:
            """Invoke one exact plan-owned provider over disclosed evidence."""

            if selected != request:
                raise PrivateAnalysisEvidenceBindingError(
                    "private-analysis request changed before capability routing"
                )
            if type(arguments) is not PrivateAnalysisCapabilityArguments:
                raise TypeError(
                    "arguments must be an exact PrivateAnalysisCapabilityArguments"
                )
            if type(parents) is not tuple or not parents:
                raise TypeError("evidence analysis requires materialized parents")
            parent_digests = tuple(
                parent.reference.reference_digest for parent in parents
            )
            if parent_digests != arguments.parent_reference_digests:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis parents do not match the admitted arguments"
                )

            def checkpoint() -> None:
                if selected_cancellation_probe is None:
                    return
                cancelled = selected_cancellation_probe()
                if type(cancelled) is not bool:
                    raise PrivateAnalysisRevisionEvidenceCancelled(
                        "private-analysis cancellation state is invalid"
                    )
                if cancelled:
                    raise PrivateAnalysisRevisionEvidenceCancelled(
                        "private-analysis evidence analysis was cancelled"
                    )

            checkpoint()
            with derived_references_lock:
                cached = derived_results.get(arguments.arguments_digest)
                if cached is not None:
                    return cached[0], deepcopy(cached[1])

            targets = tuple(
                binding
                for binding in selected.revisions
                if binding.node_id == arguments.node_id
                and binding.revision_id == arguments.revision_id
            )
            if len(targets) != 1:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis target is not one exact request revision"
                )
            target = targets[0]
            supplied = trusted_by_binding.get(target)
            if supplied is None:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis target is not a trusted revision"
                )
            analysis_kind = _PRIVATE_ANALYSIS_KIND_BY_INTENT.get(arguments.intent)
            if analysis_kind is None:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis intent is unsupported"
                )
            facts = tuple(
                EvidenceAnalysisFact(
                    reference_digest=parent.reference.reference_digest,
                    evidence_kind=parent.reference.kind.value,
                    subject_kind=parent.reference.subject_kind,
                    node_id=parent.reference.revision.node_id,
                    revision_id=parent.reference.revision.revision_id,
                    payload_schema=parent.reference.payload_schema,
                    fact_provenance=parent.reference.fact_provenance.value,
                    time_basis=parent.reference.time_range.basis.value,
                    time_start_ns=parent.reference.time_range.start_ns,
                    time_end_ns=parent.reference.time_range.end_ns,
                    time_clock_domain=parent.reference.time_range.clock_domain,
                    payload=parent.payload,
                )
                for parent in parents
            )
            capability_request = EvidenceAnalysisRequest(
                invocation_id=arguments.arguments_digest,
                analysis_kind=analysis_kind,
                facts=facts,
                parameters=arguments.parameters,
                max_observations=arguments.max_observations,
            )
            route = self._capability_router_for_descriptor(
                supplied.revision,
                member_id=target.revision_id,
            ).resolve(
                CapabilityRouteSelector(
                    capability=PluginCapability.EVIDENCE_ANALYSIS,
                )
            )
            provider = route.provider
            execution_plan = supplied.revision.execution_plan
            if execution_plan is None:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis target has no executable plan"
                )
            if (
                provider.catalog_revision_id != target.revision_id
                or provider.node_id != target.node_id
                or provider.basis_revision_id != execution_plan.basis_revision_id
                or provider.plan_digest != target.execution_plan_digest
                or provider.capability is not PluginCapability.EVIDENCE_ANALYSIS
            ):
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis provider does not match the target revision"
                )
            try:
                invocation = route.analyze_evidence(capability_request)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except PrivateAnalysisEvidenceBindingError:
                raise
            except BaseException as error:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis capability invocation failed"
                ) from error
            if invocation.provider != provider:
                raise PrivateAnalysisEvidenceBindingError(
                    "evidence analysis provider changed during invocation"
                )
            checkpoint()

            observations = [
                {
                    "observation_id": observation.observation_id,
                    "category": observation.category,
                    "summary": observation.summary,
                    "cited_reference_digests": list(
                        observation.cited_reference_digests
                    ),
                    "quality": observation.quality.value,
                    "details": _private_analysis_plain_json(observation.details),
                }
                for observation in invocation.result.observations
            ]
            payload: dict[str, Any] = {
                "arguments_digest": arguments.arguments_digest,
                "intent": arguments.intent.value,
                "parent_reference_digests": list(arguments.parent_reference_digests),
                "observations": observations,
            }
            evidence_rank = {
                PrivateAnalysisEvidenceClass.PUBLIC_METADATA: 0,
                PrivateAnalysisEvidenceClass.CLIENT_SAFE: 1,
                PrivateAnalysisEvidenceClass.PROPRIETARY: 2,
                PrivateAnalysisEvidenceClass.NEVER_ASSISTANT: 3,
            }
            evidence_class = max(
                (parent.reference.evidence_class for parent in parents),
                key=evidence_rank.__getitem__,
            )
            producer = bind_private_analysis_plugin_producer(
                supplied.revision,
                plugin_instance_id=provider.pin.instance_id,
                capability=PluginCapability.EVIDENCE_ANALYSIS.value,
            )
            reference = EvidenceReference(
                scope=scope,
                revision=target,
                producer=producer,
                kind=EvidenceKind.PLUGIN_CAPABILITY_RESULT,
                subject_kind=(PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND),
                locator_digest=evidence_locator_digest(
                    PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND,
                    {"arguments_digest": arguments.arguments_digest},
                ),
                evidence_class=evidence_class,
                payload_schema=(PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA),
                fact_provenance=EvidenceFactProvenance.PLUGIN_ANALYZED,
                time_range=EvidenceTimeRange.unknown(),
                content_digest=evidence_payload_digest(
                    PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA,
                    payload,
                ),
            )
            with derived_references_lock:
                existing = derived_results.get(arguments.arguments_digest)
                if existing is not None:
                    if existing != (reference, payload):
                        raise PrivateAnalysisEvidenceBindingError(
                            "evidence analysis provider returned a non-deterministic "
                            "result"
                        )
                    return existing[0], deepcopy(existing[1])
                derived_references[reference.reference_digest] = reference
                derived_results[arguments.arguments_digest] = (
                    reference,
                    deepcopy(payload),
                )
            return reference, deepcopy(payload)

        def validate_references(
            references: tuple[EvidenceReference, ...],
        ) -> bool:
            with derived_references_lock:
                for reference in references:
                    derived = derived_references.get(reference.reference_digest)
                    if derived is None:
                        if not corpus.validate_reference(reference):
                            return False
                    elif derived != reference:
                        return False
            current_workspace = self.validate_scope(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
            )
            catalog: dict[
                EvidenceRevisionBinding,
                tuple[FixtureDescriptor, AnalysisRevisionDescriptor],
            ] = {}
            for reference in references:
                descriptors = catalog.get(reference.revision)
                if descriptors is None:
                    descriptors = (
                        self.sessions.get_fixture(
                            scope.tenant_id,
                            reference.revision.fixture_id,
                        ),
                        self.sessions.get_revision(
                            scope.tenant_id,
                            reference.revision.revision_id,
                        ),
                    )
                    catalog[reference.revision] = descriptors
                fixture, revision = descriptors
                verify_private_analysis_evidence_binding(
                    reference,
                    current_workspace,
                    fixture,
                    revision,
                )
            return True

        def validate_reference(reference: EvidenceReference) -> bool:
            return validate_references((reference,))

        return PrivateAnalysisToolService(
            request,
            runner_policy=runner_policy,
            authorize=authorize,
            resolve_policy=resolve_policy,
            query_references=None,
            query_reference_pages=corpus.query_references,
            resolve_reference=corpus.resolve_reference,
            validate_reference=validate_reference,
            materialize_payload=corpus.materialize_payload,
            validate_references=validate_references,
            analyze_evidence=analyze_evidence,
            cancellation_probe=cancellation_probe,
        )

    def scope(
        self,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
    ) -> ReviewScope:
        self.validate_scope(tenant_id, project_id, workspace_id)
        return ReviewScope(tenant_id, project_id, workspace_id)

    def import_scope(
        self,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
    ) -> ImportScope:
        self.validate_scope(tenant_id, project_id, workspace_id)
        return ImportScope(tenant_id, project_id, workspace_id)

    @contextmanager
    def _coordinated_review_catalog(self) -> Iterator[None]:
        """Serialize review/run references against catalog retention."""

        with self._lock, exclusive_file_lock(self._retention_review_lock_path):
            yield

    @staticmethod
    def _catalog_release(value: Mapping[str, Any]) -> CatalogArtifactRelease:
        try:
            return _catalog_artifact_release_from_document(value)
        except SessionStoreError as error:
            raise ControlPlaneError(
                "catalog retention journal contains an invalid artifact release"
            ) from error

    def _reconcile_retention_artifact_releases(
        self,
        scope: ReviewScope,
    ) -> tuple[int, int]:
        import_scope = ImportScope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        action_count = 0
        release_count = 0
        while action_count < _MAX_RETENTION_RELEASE_ACTIONS:
            pending = self.sessions.pending_artifact_release_audits(
                scope.tenant_id,
                scope.workspace_id,
                limit=min(1_000, _MAX_RETENTION_RELEASE_ACTIONS - action_count),
            )
            if not pending:
                return action_count, release_count
            for action in pending:
                releases = tuple(
                    self._catalog_release(value) for value in action.artifact_releases
                )
                for release in releases:
                    self.ingestion.release_artifact_pin(
                        import_scope,
                        artifact_kind=release.artifact_kind,
                        artifact_ref=release.artifact_ref,
                        owner_operation_id=release.owner_operation_id,
                    )
                self.sessions.acknowledge_artifact_releases(
                    scope.tenant_id,
                    scope.workspace_id,
                    action.operation_id,
                )
                action_count += 1
                release_count += len(releases)
        if self.sessions.pending_artifact_release_audits(
            scope.tenant_id,
            scope.workspace_id,
            limit=1,
        ):
            raise ControlPlaneError(
                "pending artifact releases exceed the maintenance safety bound"
            )
        return action_count, release_count

    def _catalog_retention_policy(
        self,
        scope: ReviewScope,
        policy: CatalogRetentionPolicy,
    ) -> CatalogRetentionPolicy:
        retained_review_revisions = self.annotations.referenced_revision_ids(scope)
        retained_run_revisions = self.private_analysis_runs.referenced_revision_ids(
            EvidenceScope(
                tenant_id=scope.tenant_id,
                project_id=scope.project_id,
                workspace_id=scope.workspace_id,
            )
        )
        retained_proposal_revisions = (
            self.proposal_review_store.pending_retention_references(scope).revision_ids
        )
        protected = tuple(
            sorted(
                {
                    *policy.protected_revision_ids,
                    *retained_review_revisions,
                    *retained_run_revisions,
                    *retained_proposal_revisions,
                }
            )
        )
        return replace(
            policy,
            external_references_checked=True,
            protected_revision_ids=protected,
        )

    def retention_inventory(
        self,
        scope: ReviewScope,
        *,
        catalog_policy: CatalogRetentionPolicy | None = None,
        review_policy: ReviewRetentionPolicy | None = None,
        now_ns: int | None = None,
    ) -> ControlPlaneRetentionResult:
        """Return one non-mutating, best-effort cross-store observation.

        Preview deliberately does not enter the review/catalog mutation fence.
        Each store supplies a safe read snapshot, but a concurrent maintenance
        saga may advance between those snapshots.  The result is therefore an
        advisory inventory, never an executable or atomic deletion plan.
        """

        self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        selected_catalog_policy = catalog_policy or CatalogRetentionPolicy()
        selected_review_policy = review_policy or ReviewRetentionPolicy()
        if type(selected_catalog_policy) is not CatalogRetentionPolicy:
            raise TypeError("catalog_policy must be an exact CatalogRetentionPolicy")
        if type(selected_review_policy) is not ReviewRetentionPolicy:
            raise TypeError("review_policy must be an exact ReviewRetentionPolicy")
        proposal_references = self.proposal_review_store.pending_retention_references(
            scope
        )
        review = self.annotations.inventory_retention(
            scope,
            selected_review_policy,
            protected_idempotency_keys=(proposal_references.overlay_idempotency_keys),
        )
        effective_catalog = self._catalog_retention_policy(
            scope,
            selected_catalog_policy,
        )
        catalog = self.sessions.inventory_retention(
            scope.tenant_id,
            scope.workspace_id,
            effective_catalog,
        )
        ingestion = self.ingestion.run_retention(
            ImportScope(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
            ),
            dry_run=True,
            now_ns=now_ns,
        )
        return ControlPlaneRetentionResult(
            scope=scope,
            executed=False,
            observation_mode=RetentionObservationMode.BEST_EFFORT_PREVIEW,
            ingestion=ingestion,
            catalog=catalog,
            review=review,
        )

    def run_retention(
        self,
        scope: ReviewScope,
        *,
        catalog_policy: CatalogRetentionPolicy,
        review_policy: ReviewRetentionPolicy,
        actor: str,
        operation_id: str,
        now_ns: int | None = None,
    ) -> ControlPlaneRetentionResult:
        """Run the ordered cross-store retention saga for one workspace.

        The catalog commits before ownership pins are released. A crash in
        that gap leaks reclaimable bytes but cannot delete referenced data;
        the catalog journal is replayed at the next maintenance operation.
        """

        if type(catalog_policy) is not CatalogRetentionPolicy:
            raise TypeError("catalog_policy must be an exact CatalogRetentionPolicy")
        if type(review_policy) is not ReviewRetentionPolicy:
            raise TypeError("review_policy must be an exact ReviewRetentionPolicy")
        actor = _retention_identity(
            actor,
            label="actor",
            maximum=_MAX_RETENTION_ACTOR_LENGTH,
        )
        operation_id = _retention_identity(
            operation_id,
            label="operation_id",
            maximum=_MAX_RETENTION_OPERATION_ID_LENGTH,
        )
        with self._coordinated_review_catalog():
            self.validate_scope(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
            )
            saga = self.sessions.begin_retention_saga(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
                operation_id,
                actor=actor,
                request=_retention_saga_request_document(
                    catalog_policy,
                    review_policy,
                    self.ingestion.retention_policy,
                ),
                requested_now_ns=now_ns,
            )
            if saga.complete:
                return _control_plane_retention_from_saga(scope, saga)

            prior_catalog = None
            if saga.catalog_result is None:
                prior_catalog = self.sessions.get_retention_audit(
                    scope.tenant_id,
                    scope.workspace_id,
                    f"{operation_id}:catalog",
                )
                if prior_catalog is not None:
                    try:
                        prior_effective_catalog = CatalogRetentionPolicy(
                            **dict(prior_catalog.policy)
                        )
                    except (TypeError, ValueError) as error:
                        raise ControlPlaneError(
                            "catalog retention receipt policy is invalid"
                        ) from error
                    if (
                        prior_catalog.actor != actor
                        or not _catalog_policy_is_effective_for(
                            catalog_policy,
                            prior_effective_catalog,
                        )
                    ):
                        raise IdempotencyConflict(
                            "catalog retention receipt conflicts with saga request"
                        )

            actions, releases = self._reconcile_retention_artifact_releases(scope)
            if actions or releases:
                saga = self.sessions.add_retention_saga_replay_counts(
                    scope.tenant_id,
                    scope.workspace_id,
                    operation_id,
                    release_actions=actions,
                    artifact_releases=releases,
                )

            review: ReviewRetentionInventory | ReviewRetentionResult
            if saga.review_result is None:
                proposal_references = (
                    self.proposal_review_store.pending_retention_references(scope)
                )
                if review_policy.enabled:
                    review = self.annotations.purge_retention(
                        scope,
                        review_policy,
                        actor=actor,
                        operation_id=f"{operation_id}:review",
                        protected_idempotency_keys=(
                            proposal_references.overlay_idempotency_keys
                        ),
                    )
                else:
                    review = self.annotations.inventory_retention(
                        scope,
                        review_policy,
                        protected_idempotency_keys=(
                            proposal_references.overlay_idempotency_keys
                        ),
                    )
                saga = self.sessions.record_retention_saga_phase(
                    scope.tenant_id,
                    scope.workspace_id,
                    operation_id,
                    "review",
                    _review_phase_document(review),
                )
            else:
                review = _review_phase_from_document(
                    scope,
                    saga.review_result,
                )

            catalog: CatalogRetentionInventory | CatalogRetentionResult
            if saga.catalog_result is None:
                if prior_catalog is not None:
                    try:
                        effective_catalog = CatalogRetentionPolicy(
                            **dict(prior_catalog.policy)
                        )
                    except (TypeError, ValueError) as error:
                        raise ControlPlaneError(
                            "catalog retention receipt policy is invalid"
                        ) from error
                else:
                    effective_catalog = self._catalog_retention_policy(
                        scope,
                        catalog_policy,
                    )
                if effective_catalog.enabled:
                    catalog = self.sessions.purge_retention(
                        scope.tenant_id,
                        scope.workspace_id,
                        effective_catalog,
                        actor=actor,
                        operation_id=f"{operation_id}:catalog",
                    )
                else:
                    catalog = self.sessions.inventory_retention(
                        scope.tenant_id,
                        scope.workspace_id,
                        effective_catalog,
                    )
                actions, releases = self._reconcile_retention_artifact_releases(scope)
                if actions or releases:
                    saga = self.sessions.add_retention_saga_replay_counts(
                        scope.tenant_id,
                        scope.workspace_id,
                        operation_id,
                        release_actions=actions,
                        artifact_releases=releases,
                    )
                saga = self.sessions.record_retention_saga_phase(
                    scope.tenant_id,
                    scope.workspace_id,
                    operation_id,
                    "catalog",
                    _catalog_phase_document(catalog),
                )
            else:
                catalog = _catalog_phase_from_document(
                    scope,
                    saga.catalog_result,
                )

            if isinstance(catalog, CatalogRetentionResult):
                for candidate in catalog.purged:
                    if candidate.category == "analysis_revision":
                        self._cache.pop(
                            f"{scope.tenant_id}\x1f{candidate.identifier}",
                            None,
                        )

            import_scope = ImportScope(
                scope.tenant_id,
                scope.project_id,
                scope.workspace_id,
            )
            if saga.ingestion_result is None:
                ingestion = self.ingestion.run_retention(
                    import_scope,
                    dry_run=not self.ingestion.retention_policy.enabled,
                    now_ns=saga.effective_now_ns,
                    actor=actor,
                    operation_id=f"{operation_id}:ingestion",
                )
                saga = self.sessions.record_retention_saga_phase(
                    scope.tenant_id,
                    scope.workspace_id,
                    operation_id,
                    "ingestion",
                    _ingestion_phase_document(ingestion),
                )
            else:
                ingestion = _ingestion_phase_from_document(
                    import_scope,
                    saga.ingestion_result,
                )
            saga = self.sessions.complete_retention_saga(
                scope.tenant_id,
                scope.workspace_id,
                operation_id,
            )
            return _control_plane_retention_from_saga(scope, saga)

    def _revision(
        self,
        scope: ReviewScope,
        revision_id: str,
    ) -> AnalysisRevisionDescriptor:
        self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        try:
            revision = self.sessions.get_revision(scope.tenant_id, revision_id)
        except KeyError as error:
            raise HiddenSubjectResolutionError(revision_id) from error
        if revision.workspace_id != scope.workspace_id:
            # Opaque identifiers outside the authorized workspace are hidden
            # exactly like absent records.
            raise HiddenSubjectResolutionError(revision_id)
        return revision

    @staticmethod
    def _dataset_path(root: Path, dataset_ref: object) -> Path:
        value = _exact_identifier(dataset_ref, label="dataset_ref")
        if "\\" in value:
            raise DatasetIntegrityError("dataset_ref must use POSIX separators")
        relative = PurePosixPath(value)
        if relative.is_absolute() or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise DatasetIntegrityError("dataset_ref must be a safe relative path")
        candidate = root.joinpath(*relative.parts).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError as error:
            raise DatasetIntegrityError(
                "dataset_ref escapes the revision store"
            ) from error
        return candidate

    @staticmethod
    def _mapping_list(
        dataset: Mapping[str, Any],
        field: str,
        *,
        construction_checkpoint: Callable[[], None] | None = None,
    ) -> list[Mapping[str, Any]]:
        value = dataset.get(field, [])
        if type(value) is not list:
            raise DatasetIntegrityError(f"dataset {field} must be an array of objects")
        for ordinal, item in enumerate(value):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            if not isinstance(item, Mapping):
                raise DatasetIntegrityError(
                    f"dataset {field} must be an array of objects"
                )
        return value

    @classmethod
    def _relationship_projection_index(
        cls,
        dataset: Mapping[str, Any],
        ingestion: Mapping[str, Any],
        *,
        execution_plan: PluginExecutionPlan | None,
        resources_by_id: Mapping[str, Mapping[str, Any]],
        construction_checkpoint: Callable[[], None] | None = None,
    ) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]:
        """Validate one revision-scoped projection without temporalizing it.

        Durable reload has no executable plug-in and deliberately does not
        reconstruct raw parser observations.  The storage validator therefore
        receives only independently checked plan, inventory, schema and base
        resource facts.  Projected edges are returned solely for revision
        subject indexing; callers must not append them to temporal
        ``relationships`` or ``relationship_intervals``.
        """

        fragment_fields = (
            "relationship_declarations",
            "relationship_projection_diagnostics",
            "relationship_projection_edges",
            "relationship_projection_materialization",
        )
        present = frozenset(field for field in fragment_fields if field in dataset)
        status_marker_present = (
            "relationship_projection_materialization_status" in ingestion
        )
        if not present and not status_marker_present:
            return (), {}
        if present != frozenset(fragment_fields) or not status_marker_present:
            raise DatasetIntegrityError(
                "dataset has partial relationship projection materialization metadata"
            )
        if execution_plan is None:
            raise DatasetIntegrityError(
                "relationship projection materialization lacks an execution plan"
            )

        limits = RelationshipProjectionMaterializationLimits()
        raw_declarations = dataset.get("relationship_declarations")
        raw_diagnostics = dataset.get("relationship_projection_diagnostics")
        raw_edges = dataset.get("relationship_projection_edges")
        raw_materialization = dataset.get("relationship_projection_materialization")
        if (
            any(
                type(value) is not list
                for value in (raw_declarations, raw_diagnostics, raw_edges)
            )
            or type(raw_materialization) is not dict
        ):
            raise DatasetIntegrityError(
                "relationship projection materialization has invalid containers"
            )
        assert type(raw_declarations) is list
        assert type(raw_diagnostics) is list
        assert type(raw_edges) is list
        assert type(raw_materialization) is dict
        if (
            len(raw_declarations) > limits.max_declarations
            or len(raw_diagnostics) > limits.max_diagnostics
            or len(raw_edges) > limits.max_declarations
        ):
            raise DatasetIntegrityError(
                "relationship projection materialization exceeds durable limits"
            )

        raw_status = raw_materialization.get("status")
        try:
            if type(raw_status) is not str:
                raise TypeError("status must be a string")
            status = RelationshipProjectionMaterializationStatus(raw_status)
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "relationship projection materialization status is invalid"
            ) from error
        if (
            ingestion.get("relationship_projection_materialization_status")
            != status.value
        ):
            raise DatasetIntegrityError(
                "ingestion relationship projection status does not match its materialization"
            )
        providers = raw_materialization.get("providers")
        if type(providers) is not list or len(providers) > limits.max_providers:
            raise DatasetIntegrityError("relationship projection providers are invalid")
        for provider in providers:
            if (
                not isinstance(provider, Mapping)
                or provider.get("catalog_revision_id")
                != execution_plan.basis_revision_id
                or provider.get("member_id") != execution_plan.basis_revision_id
                or provider.get("basis_revision_id") != execution_plan.basis_revision_id
                or provider.get("node_id") != execution_plan.node_id
                or provider.get("plan_digest") != execution_plan.plan_digest
                or provider.get("capability")
                != PluginCapability.RELATIONSHIP_PROJECTION.value
            ):
                raise DatasetIntegrityError(
                    "relationship projection provider is not bound to its revision"
                )

        inventory = dataset.get("inventory")
        members = inventory.get("members") if isinstance(inventory, Mapping) else None
        if type(members) is not list or len(members) > limits.max_artifact_ids:
            raise DatasetIntegrityError("relationship projection inventory is invalid")
        artifact_ids: set[UUID] = set()
        for member in members:
            artifact_text = member.get("artifact_id") if type(member) is dict else None
            try:
                artifact_id = UUID(artifact_text)
            except (AttributeError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "relationship projection inventory artifact is invalid"
                ) from error
            if str(artifact_id) != artifact_text or artifact_id in artifact_ids:
                raise DatasetIntegrityError(
                    "relationship projection inventory artifact is invalid"
                )
            artifact_ids.add(artifact_id)

        base_resource_ids: set[str] = set()
        resource_keys: dict[str, Mapping[str, Any]] = {}
        for identifier, resource in resources_by_id.items():
            key = resource.get("key")
            if not isinstance(key, Mapping):
                raise DatasetIntegrityError(
                    "relationship projection base resource lacks its typed key"
                )
            resource_keys[identifier] = key
            if resource.get("placeholder") is not True:
                base_resource_ids.add(identifier)
        if len(base_resource_ids) > limits.max_base_resources:
            raise DatasetIntegrityError(
                "relationship projection base resources exceed durable limits"
            )

        # Bind every projected opaque key to the independently indexed base
        # resource record.  A digest-valid claim must not be able to reuse a
        # real resource ID with a different typed key.
        for collection_name, values in (
            ("declaration", raw_declarations),
            ("resolved edge", raw_edges),
        ):
            for ordinal, value in enumerate(values):
                if ordinal % 256 == 0 and construction_checkpoint is not None:
                    construction_checkpoint()
                if not isinstance(value, Mapping):
                    raise DatasetIntegrityError(
                        f"relationship projection {collection_name} is invalid"
                    )
                for endpoint_name in ("source", "target"):
                    endpoint = value.get(endpoint_name)
                    if not isinstance(endpoint, Mapping):
                        raise DatasetIntegrityError(
                            f"relationship projection {collection_name} endpoint is invalid"
                        )
                    endpoint_identifier = endpoint.get("resource_id")
                    if (
                        type(endpoint_identifier) is not str
                        or endpoint_identifier not in resource_keys
                        or endpoint.get("typed_resource_key")
                        != resource_keys[endpoint_identifier]
                    ):
                        raise DatasetIntegrityError(
                            "relationship projection endpoint does not match its base resource"
                        )

        raw_relationship_types = dataset.get("relationship_descriptors")
        if (
            type(raw_relationship_types) is not list
            or len(raw_relationship_types) > 10_000
        ):
            raise DatasetIntegrityError(
                "relationship projection schema descriptors are invalid"
            )
        relationship_type_directions: dict[str, bool] = {}
        for descriptor in raw_relationship_types:
            if not isinstance(descriptor, Mapping):
                raise DatasetIntegrityError(
                    "relationship projection schema descriptors are invalid"
                )
            relation_type = descriptor.get("relation_type")
            directed = descriptor.get("directed")
            if (
                type(relation_type) is not str
                or not relation_type
                or len(relation_type) > 256
                or type(directed) is not bool
                or relation_type in relationship_type_directions
            ):
                raise DatasetIntegrityError(
                    "relationship projection schema descriptors are invalid"
                )
            relationship_type_directions[relation_type] = directed

        schema = dataset.get("schema")
        raw_perspectives = (
            schema.get("status_perspectives") if isinstance(schema, Mapping) else None
        )
        if type(raw_perspectives) is not list or len(raw_perspectives) > 10_000:
            raise DatasetIntegrityError(
                "relationship projection perspective schema is invalid"
            )
        perspective_ids: set[str] = set()
        for descriptor in raw_perspectives:
            perspective_id = (
                descriptor.get("perspective_id")
                if isinstance(descriptor, Mapping)
                else None
            )
            if (
                type(perspective_id) is not str
                or not perspective_id
                or len(perspective_id) > 128
                or perspective_id in perspective_ids
            ):
                raise DatasetIntegrityError(
                    "relationship projection perspective schema is invalid"
                )
            perspective_ids.add(perspective_id)

        if status is RelationshipProjectionMaterializationStatus.COMPLETE:
            basis = raw_materialization.get("basis")
            if not isinstance(basis, Mapping):
                raise DatasetIntegrityError(
                    "complete relationship projection lacks a basis"
                )
            try:
                canonical_projection_basis = _validate_materialized_consistency_basis(
                    basis,
                    artifact_ids=frozenset(artifact_ids),
                    limits=ConsistencyMaterializationLimits(),
                )
            except (ConsistencyMaterializationError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "relationship projection basis is not canonical"
                ) from error
            expected_basis_digest = (
                "sha256:"
                + hashlib.sha256(canonical_projection_basis.encode("utf-8")).hexdigest()
            )
        else:
            expected_basis_digest = None
        consistency_materialization = dataset.get("consistency_materialization")
        consistency_status: ConsistencyMaterializationStatus | None = None
        if isinstance(consistency_materialization, Mapping):
            raw_consistency_status = consistency_materialization.get("status")
            try:
                if type(raw_consistency_status) is not str:
                    raise TypeError("status must be a string")
                consistency_status = ConsistencyMaterializationStatus(
                    raw_consistency_status
                )
            except (TypeError, ValueError):
                pass
        if (
            status is RelationshipProjectionMaterializationStatus.COMPLETE
            and isinstance(consistency_materialization, Mapping)
            and consistency_status is ConsistencyMaterializationStatus.COMPLETE
            and consistency_materialization.get("basis_digest") != expected_basis_digest
        ):
            raise DatasetIntegrityError(
                "relationship projection and consistency bases disagree"
            )
        fragment = {field: dataset[field] for field in fragment_fields}
        try:
            detached = validate_relationship_projection_storage_fragment(
                fragment,
                plan=execution_plan,
                expected_basis_digest=expected_basis_digest,
                base_resource_ids=frozenset(base_resource_ids),
                relationship_type_directions=relationship_type_directions,
                perspective_ids=frozenset(perspective_ids),
                artifact_ids=frozenset(artifact_ids),
                limits=limits,
            )
        except (
            RelationshipProjectionMaterializationError,
            TypeError,
            ValueError,
        ) as error:
            raise DatasetIntegrityError(
                "relationship projection materialization is not canonical"
            ) from error

        generic_diagnostics = dataset.get("diagnostics")
        consistency_diagnostics = dataset.get("consistency_diagnostics", [])
        if (
            type(generic_diagnostics) is not list
            or type(consistency_diagnostics) is not list
        ):
            raise DatasetIntegrityError(
                "relationship projection diagnostics are not retained canonically"
            )
        expected_suffix = [*raw_diagnostics, *consistency_diagnostics]
        actual_suffix = (
            generic_diagnostics[-len(expected_suffix) :] if expected_suffix else []
        )
        try:
            diagnostics_match = strict_canonical_json(
                actual_suffix
            ) == strict_canonical_json(expected_suffix)
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "relationship projection diagnostics are not canonical"
            ) from error
        if len(generic_diagnostics) < len(expected_suffix) or not diagnostics_match:
            raise DatasetIntegrityError(
                "generic diagnostics do not retain the relationship projection suffix"
            )

        summary = dataset.get("summary")
        published_summary = (
            summary.get("relationship_projection")
            if isinstance(summary, Mapping)
            else None
        )
        expected_summary = {
            "status": status.value,
            "declaration_count": len(raw_declarations),
            "resolved_edge_count": len(raw_edges),
            "diagnostic_count": len(raw_diagnostics),
            "semantic_conflict_groups": raw_materialization.get(
                "semantic_conflict_groups"
            ),
        }
        if type(published_summary) is not dict or published_summary != expected_summary:
            raise DatasetIntegrityError(
                "dataset relationship projection summary does not match materialization"
            )
        return tuple(detached["relationship_projection_edges"]), deepcopy(
            dict(detached["relationship_projection_materialization"])
        )

    @classmethod
    def _consistency_index(
        cls,
        dataset: Mapping[str, Any],
        ingestion: Mapping[str, Any],
        *,
        plan_digest: object,
        execution_plan: PluginExecutionPlan | None,
        construction_checkpoint: Callable[[], None] | None = None,
    ) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]:
        storage_limits = ConsistencyMaterializationLimits()
        envelope_present = "consistency_materialization" in dataset
        envelope = dataset.get("consistency_materialization")
        requires_materialization = (
            ingestion.get("mode") == _CONSISTENCY_MATERIALIZATION_INGESTION_MODE
        )
        raw_findings = dataset.get("findings", [])
        if (
            (requires_materialization or envelope_present)
            and type(raw_findings) is list
            and len(raw_findings) > storage_limits.max_findings
        ):
            raise DatasetIntegrityError(
                "materialized consistency findings exceed the durable limit"
            )
        findings = tuple(
            cls._mapping_list(
                dataset,
                "findings",
                construction_checkpoint=construction_checkpoint,
            )
        )
        if requires_materialization or envelope_present:
            for required_array in (
                "findings",
                "consistency_diagnostics",
                "diagnostics",
            ):
                if (
                    required_array not in dataset
                    or type(dataset[required_array]) is not list
                ):
                    raise DatasetIntegrityError(
                        f"core-ingestion-v3 dataset requires {required_array}"
                    )
        if execution_plan is None:
            if plan_digest is not None:
                raise DatasetIntegrityError(
                    "dataset execution-plan digest lacks its exact execution plan"
                )
        elif type(plan_digest) is not str or execution_plan.plan_digest != plan_digest:
            raise DatasetIntegrityError(
                "dataset execution-plan digest does not match its execution plan"
            )
        if not envelope_present:
            inventory = dataset.get("inventory")
            carries_v3_marker = (
                requires_materialization
                or "consistency_materialization_status" in ingestion
                or "consistency_diagnostics" in dataset
                or (
                    isinstance(inventory, Mapping)
                    and inventory.get("mode")
                    == _CONSISTENCY_MATERIALIZATION_INGESTION_MODE
                )
            )
            if carries_v3_marker:
                raise DatasetIntegrityError(
                    "dataset has partial core-ingestion-v3 consistency metadata"
                )
            return findings, legacy_consistency_materialization_envelope(
                plan_digest=plan_digest if type(plan_digest) is str else None,
                finding_count=len(findings),
            )
        if not isinstance(envelope, Mapping):
            raise DatasetIntegrityError("consistency materialization must be an object")
        try:
            validate_consistency_materialization_envelope(envelope)
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "consistency materialization does not use its exact schema"
            ) from error
        if ingestion.get("mode") != _CONSISTENCY_MATERIALIZATION_INGESTION_MODE:
            raise DatasetIntegrityError(
                "consistency materialization requires core-ingestion-v3 metadata"
            )
        inventory = dataset.get("inventory")
        if (
            not isinstance(inventory, Mapping)
            or inventory.get("mode") != _CONSISTENCY_MATERIALIZATION_INGESTION_MODE
        ):
            raise DatasetIntegrityError(
                "consistency materialization requires core-ingestion-v3 inventory"
            )
        inventory_members = inventory.get("members")
        inventory_artifact_count = inventory.get("artifacts")
        if (
            type(inventory_members) is not list
            or type(inventory_artifact_count) is not int
            or inventory_artifact_count != len(inventory_members)
            or len(inventory_members) > storage_limits.max_artifact_ids
        ):
            raise DatasetIntegrityError(
                "consistency materialization inventory is invalid"
            )
        admitted_artifact_ids: set[UUID] = set()
        for member in inventory_members:
            artifact_text = member.get("artifact_id") if type(member) is dict else None
            try:
                artifact_id = UUID(artifact_text)
            except (AttributeError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "consistency materialization inventory artifact is invalid"
                ) from error
            if (
                str(artifact_id) != artifact_text
                or artifact_id in admitted_artifact_ids
            ):
                raise DatasetIntegrityError(
                    "consistency materialization inventory artifact is invalid"
                )
            admitted_artifact_ids.add(artifact_id)
        frozen_artifact_ids = _validate_materialized_artifact_ids(
            frozenset(admitted_artifact_ids),
            storage_limits,
        )
        if envelope.get("schema_version") != CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION:
            raise DatasetIntegrityError(
                "consistency materialization schema is unsupported"
            )
        status = envelope.get("status")
        if type(status) is not str or status not in {
            "complete",
            "not_applicable",
        }:
            raise DatasetIntegrityError("consistency materialization status is invalid")
        if ingestion.get("consistency_materialization_status") != status:
            raise DatasetIntegrityError(
                "ingestion consistency status does not match its materialization"
            )
        if type(plan_digest) is not str or envelope.get("plan_digest") != plan_digest:
            raise DatasetIntegrityError(
                "consistency materialization plan digest does not match ingestion"
            )
        assert execution_plan is not None
        try:
            selected_pins = revision_consistency_selected_pins(execution_plan)
        except (TypeError, ValueError, RuntimeError) as error:
            raise DatasetIntegrityError(
                "consistency provider selection is invalid"
            ) from error
        expected_providers = tuple(
            _consistency_provider_projection(pin, execution_plan)
            for pin in selected_pins
        )

        providers = envelope.get("providers")
        if type(providers) is not list:
            raise DatasetIntegrityError(
                "consistency materialization providers must be an array of objects"
            )
        if len(providers) > storage_limits.max_providers:
            raise DatasetIntegrityError(
                "consistency materialization providers exceed the durable limit"
            )
        if any(type(provider) is not dict for provider in providers):
            raise DatasetIntegrityError(
                "consistency materialization providers must be an array of objects"
            )
        provider_instance_ids: set[str] = set()
        for provider in providers:
            try:
                _validate_materialized_provider_projection(
                    provider,
                    "consistency materialization provider",
                )
            except (TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "consistency materialization provider is not canonical"
                ) from error
            instance_id = provider.get("instance_id")
            if type(instance_id) is not str or not instance_id:
                raise DatasetIntegrityError(
                    "consistency materialization provider lacks an instance identifier"
                )
            if instance_id in provider_instance_ids:
                raise DatasetIntegrityError(
                    "consistency materialization contains duplicate providers"
                )
            provider_instance_ids.add(instance_id)
            if (
                provider.get("plan_digest") != plan_digest
                or provider.get("capability")
                != PluginCapability.CONSISTENCY_CHECK.value
            ):
                raise DatasetIntegrityError(
                    "consistency materialization provider is not bound to its plan"
                )
        if tuple(dict(provider) for provider in providers) != expected_providers:
            raise DatasetIntegrityError(
                "consistency materialization providers do not match the exact plan"
            )
        provider_records = {
            strict_canonical_json(provider): provider for provider in expected_providers
        }
        raw_consistency_diagnostics = dataset.get("consistency_diagnostics")
        if (
            type(raw_consistency_diagnostics) is list
            and len(raw_consistency_diagnostics) > storage_limits.max_diagnostics
        ):
            raise DatasetIntegrityError(
                "materialized consistency diagnostics exceed the durable limit"
            )
        diagnostics = tuple(
            cls._mapping_list(
                dataset,
                "consistency_diagnostics",
                construction_checkpoint=construction_checkpoint,
            )
        )
        raw_generic_diagnostics = dataset.get("diagnostics")
        if type(raw_generic_diagnostics) is not list:
            raise DatasetIntegrityError("dataset diagnostics must be an array")
        generic_suffix = (
            raw_generic_diagnostics[-len(diagnostics) :] if diagnostics else []
        )
        if any(not isinstance(value, Mapping) for value in generic_suffix):
            raise DatasetIntegrityError(
                "generic diagnostics do not retain the consistency diagnostic suffix"
            )
        try:
            diagnostics_match = not diagnostics or strict_canonical_json(
                [dict(value) for value in generic_suffix]
            ) == strict_canonical_json([dict(value) for value in diagnostics])
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "generic diagnostics contain a non-canonical consistency suffix"
            ) from error
        if len(raw_generic_diagnostics) < len(diagnostics) or not diagnostics_match:
            raise DatasetIntegrityError(
                "generic diagnostics do not retain the consistency diagnostic suffix"
            )
        counts = {
            field: _consistency_count(
                envelope.get(field),
                label=f"consistency materialization {field}",
            )
            for field in CONSISTENCY_MATERIALIZATION_COUNT_FIELDS
        }
        if counts["provider_count"] != len(providers):
            raise DatasetIntegrityError(
                "consistency materialization provider count does not match providers"
            )
        if counts["finding_count"] != len(findings):
            raise DatasetIntegrityError(
                "consistency materialization finding count does not match findings"
            )
        if counts["diagnostic_count"] != len(diagnostics):
            raise DatasetIntegrityError(
                "consistency materialization diagnostic count does not match diagnostics"
            )
        if (
            counts["emitted_finding_count"]
            != counts["finding_count"] + counts["duplicate_findings_discarded"]
            or counts["emitted_diagnostic_count"]
            != counts["diagnostic_count"] + counts["duplicate_diagnostics_discarded"]
        ):
            raise DatasetIntegrityError(
                "consistency materialization emitted and duplicate counts disagree"
            )
        if (
            counts["emitted_finding_count"] > storage_limits.max_findings
            or counts["emitted_diagnostic_count"] > storage_limits.max_diagnostics
            or counts["world_reads"] > storage_limits.max_world_reads
        ):
            raise DatasetIntegrityError(
                "consistency materialization counts exceed durable limits"
            )

        finding_ids: set[str] = set()
        aggregate_resource_count = [0]
        aggregate_evidence_count = [0]
        consistency_summary = {"pass": 0, "fail": 0, "unknown": 0}
        previous_finding_id: str | None = None
        for ordinal, finding in enumerate(findings):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            try:
                _validate_materialized_consistency_finding(
                    finding,
                    artifact_ids=frozen_artifact_ids,
                    limits=storage_limits,
                    aggregate_resource_count=aggregate_resource_count,
                    aggregate_evidence_count=aggregate_evidence_count,
                )
            except (ConsistencyMaterializationError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "materialized consistency finding is not canonical"
                ) from error
            identifier = _verified_materialized_identity(
                finding,
                identity_field="finding_id",
                label="materialized consistency finding",
            )
            if identifier in finding_ids:
                raise DatasetIntegrityError(
                    "materialized consistency findings contain a duplicate identifier"
                )
            finding_ids.add(identifier)
            if previous_finding_id is not None and identifier <= previous_finding_id:
                raise DatasetIntegrityError(
                    "materialized consistency findings are not canonically ordered"
                )
            previous_finding_id = identifier
            if finding.get("execution_plan_digest") != plan_digest:
                raise DatasetIntegrityError(
                    "materialized consistency finding plan digest does not match ingestion"
                )
            result = finding.get("result")
            if result not in consistency_summary:
                raise DatasetIntegrityError(
                    "materialized consistency finding result is invalid"
                )
            consistency_summary[result] += 1
            producer = finding.get("producer")
            if (
                not isinstance(producer, Mapping)
                or strict_canonical_json(dict(producer)) not in provider_records
            ):
                raise DatasetIntegrityError(
                    "materialized consistency finding producer is not plan-selected"
                )

        diagnostic_ids: set[str] = set()
        previous_diagnostic_id: str | None = None
        for diagnostic in diagnostics:
            try:
                _validate_materialized_consistency_diagnostic(
                    diagnostic,
                    artifact_ids=frozen_artifact_ids,
                    limits=storage_limits,
                    aggregate_evidence_count=aggregate_evidence_count,
                )
            except (ConsistencyMaterializationError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "materialized consistency diagnostic is not canonical"
                ) from error
            identifier = _verified_materialized_identity(
                diagnostic,
                identity_field="diagnostic_id",
                label="materialized consistency diagnostic",
            )
            if identifier in diagnostic_ids:
                raise DatasetIntegrityError(
                    "materialized consistency diagnostics contain a duplicate identifier"
                )
            diagnostic_ids.add(identifier)
            if (
                previous_diagnostic_id is not None
                and identifier <= previous_diagnostic_id
            ):
                raise DatasetIntegrityError(
                    "materialized consistency diagnostics are not canonically ordered"
                )
            previous_diagnostic_id = identifier
            producer = diagnostic.get("producer")
            if (
                not isinstance(producer, Mapping)
                or strict_canonical_json(dict(producer)) not in provider_records
            ):
                raise DatasetIntegrityError(
                    "materialized consistency diagnostic producer is not plan-selected"
                )

        basis = envelope.get("basis")
        basis_digest = envelope.get("basis_digest")
        if status == "not_applicable":
            if (
                findings
                or diagnostics
                or providers
                or any(counts.values())
                or basis is not None
                or basis_digest is not None
            ):
                raise DatasetIntegrityError(
                    "not_applicable consistency materialization contains output"
                )
        else:
            if not providers:
                raise DatasetIntegrityError(
                    "complete consistency materialization lacks a provider"
                )
            if not isinstance(basis, Mapping):
                raise DatasetIntegrityError(
                    "complete consistency materialization lacks a basis"
                )
            try:
                canonical_basis = _validate_materialized_consistency_basis(
                    basis,
                    artifact_ids=frozen_artifact_ids,
                    limits=storage_limits,
                    aggregate_evidence_count=aggregate_evidence_count,
                )
            except (ConsistencyMaterializationError, TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "consistency materialization basis is not canonical"
                ) from error
            expected_basis_digest = (
                "sha256:"
                + hashlib.sha256(
                    strict_canonical_json(dict(basis)).encode("utf-8")
                ).hexdigest()
            )
            if basis_digest != expected_basis_digest:
                raise DatasetIntegrityError(
                    "consistency materialization basis digest does not match its basis"
                )
            if any(
                not isinstance(finding.get("basis"), Mapping)
                or strict_canonical_json(dict(finding["basis"])) != canonical_basis
                for finding in findings
            ):
                raise DatasetIntegrityError(
                    "materialized consistency finding basis does not match its envelope"
                )
        summary = dataset.get("summary")
        summary_consistency = (
            summary.get("consistency") if isinstance(summary, Mapping) else None
        )
        if (
            type(summary_consistency) is not dict
            or set(summary_consistency) != set(consistency_summary)
            or any(
                type(value) is not int or value < 0
                for value in summary_consistency.values()
            )
            or summary_consistency != consistency_summary
        ):
            raise DatasetIntegrityError(
                "dataset consistency summary does not match materialized findings"
            )
        published_projection = {
            "_ingestion": {
                "mode": _CONSISTENCY_MATERIALIZATION_INGESTION_MODE,
                "plugin_execution_plan_digest": plan_digest,
                "consistency_materialization_status": status,
            },
            "inventory": {"mode": _CONSISTENCY_MATERIALIZATION_INGESTION_MODE},
            "findings": [dict(value) for value in findings],
            "consistency_diagnostics": [dict(value) for value in diagnostics],
            "consistency_materialization": dict(envelope),
            "diagnostics": [dict(value) for value in diagnostics],
            "summary": {"consistency": summary_consistency},
        }
        serialized_bytes = 0
        encoder = json.JSONEncoder(
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        for chunk in encoder.iterencode(published_projection):
            serialized_bytes += len(chunk.encode("utf-8"))
            if serialized_bytes > storage_limits.max_serialized_bytes:
                raise DatasetIntegrityError(
                    "consistency materialization exceeds the durable byte limit"
                )
            if construction_checkpoint is not None:
                construction_checkpoint()
        return findings, deepcopy(dict(envelope))

    @classmethod
    def _index_dataset(
        cls,
        descriptor: AnalysisRevisionDescriptor,
        dataset: Mapping[str, Any],
        *,
        construction_checkpoint: Callable[[], None] | None = None,
    ) -> _DatasetIndex:
        if construction_checkpoint is not None:
            construction_checkpoint()
        ingestion = dataset.get("_ingestion")
        if not isinstance(ingestion, Mapping):
            raise DatasetIntegrityError("dataset lacks the core ingestion envelope")
        try:
            source_revision_id = _exact_identifier(
                descriptor.metadata.get("source_revision_id"),
                label="source_revision_id",
            )
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "catalog publication lacks a valid source revision"
            ) from error
        if ingestion.get("revision_id") != source_revision_id:
            raise DatasetIntegrityError(
                "dataset source revision does not match its catalog publication"
            )
        if ingestion.get("node_id", ingestion.get("node")) != descriptor.node_id:
            raise DatasetIntegrityError(
                "dataset node does not match its catalog publication"
            )
        try:
            execution_plan = (
                snapshot_plugin_execution_plan(descriptor.execution_plan)
                if descriptor.execution_plan is not None
                else None
            )
        except (TypeError, ValueError) as error:
            raise DatasetIntegrityError(
                "catalog revision has an invalid execution plan"
            ) from error
        catalog_plan_digest = descriptor.metadata.get("plugin_execution_plan_digest")
        dataset_plan_digest = ingestion.get("plugin_execution_plan_digest")
        if execution_plan is None:
            if catalog_plan_digest is not None or dataset_plan_digest is not None:
                raise DatasetIntegrityError(
                    "planless catalog revision disagrees with execution-plan metadata"
                )
        else:
            if (
                catalog_plan_digest != execution_plan.plan_digest
                or dataset_plan_digest != execution_plan.plan_digest
            ):
                raise DatasetIntegrityError(
                    "dataset execution-plan digest does not match its full catalog plan"
                )
            if execution_plan.basis_revision_id != source_revision_id:
                raise DatasetIntegrityError(
                    "execution-plan basis does not match the dataset source revision"
                )
            try:
                pin = primary_parser_execution_pin(execution_plan)
            except (TypeError, ValueError) as error:
                raise DatasetIntegrityError(
                    "catalog ingestion revision must contain one primary parser"
                ) from error
            if (
                descriptor.metadata.get("plugin_id") != pin.plugin_id
                or descriptor.metadata.get("plugin_version") != pin.plugin_version
            ):
                raise DatasetIntegrityError(
                    "catalog plug-in metadata does not match its full execution plan"
                )
        if execution_plan is None:
            # Legacy planless publications predate an explicit clock basis.
            timeline_start = _non_negative_ns(
                ingestion.get("timeline_start_ns", 0),
                label="timeline_start_ns",
            )
            timeline_end = _non_negative_ns(
                ingestion.get("timeline_end_ns", timeline_start),
                label="timeline_end_ns",
            )
            if timeline_end < timeline_start:
                raise DatasetIntegrityError("dataset timeline end precedes start")
        else:
            try:
                timeline_start, timeline_end, _basis, _clock_domain = (
                    validate_private_analysis_timeline_metadata(dataset)
                )
            except PrivateAnalysisRevisionEvidenceError as error:
                raise DatasetIntegrityError(
                    "dataset timeline metadata is invalid"
                ) from error

        events: dict[str, Mapping[str, Any]] = {}
        for ordinal, event in enumerate(
            cls._mapping_list(
                dataset,
                "events",
                construction_checkpoint=construction_checkpoint,
            )
        ):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            identifier = _exact_identifier(
                event.get("event_uid", event.get("event_id")),
                label="event identifier",
            )
            if identifier in events:
                raise DatasetIntegrityError(
                    f"dataset contains duplicate event identifier {identifier!r}"
                )
            events[identifier] = event

        source_records: dict[str, Mapping[str, Any]] = {}
        for ordinal, record in enumerate(
            cls._mapping_list(
                dataset,
                "source_records",
                construction_checkpoint=construction_checkpoint,
            )
        ):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            identifier = _exact_identifier(
                record.get("source_record_uid"),
                label="source-record identifier",
            )
            if identifier in source_records:
                raise DatasetIntegrityError(
                    "dataset contains duplicate source-record identifier "
                    f"{identifier!r}"
                )
            source_records[identifier] = record

        resources: set[str] = set()
        resources_by_id: dict[str, Mapping[str, Any]] = {}
        for ordinal, record in enumerate(
            cls._mapping_list(
                dataset,
                "resources",
                construction_checkpoint=construction_checkpoint,
            )
        ):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            identifier = resource_id(record)
            if identifier in resources:
                raise DatasetIntegrityError(
                    f"dataset contains duplicate resource identifier {identifier!r}"
                )
            resources.add(identifier)
            resources_by_id[identifier] = record

        for field, actual in (
            ("event_count", len(events)),
            ("source_record_count", len(source_records)),
            ("resource_count", len(resources)),
        ):
            expected = descriptor.metadata.get(field)
            if type(expected) is not int or expected != actual:
                raise DatasetIntegrityError(
                    f"dataset {field} does not match its catalog publication"
                )

        relationships: set[str] = set()
        for field in ("relationships", "relationship_intervals"):
            for ordinal, relationship in enumerate(
                cls._mapping_list(
                    dataset,
                    field,
                    construction_checkpoint=construction_checkpoint,
                )
            ):
                if ordinal % 256 == 0 and construction_checkpoint is not None:
                    construction_checkpoint()
                relationships.add(relationship_subject_id(relationship))
        findings, consistency_materialization = cls._consistency_index(
            dataset,
            ingestion,
            plan_digest=dataset_plan_digest,
            execution_plan=execution_plan,
            construction_checkpoint=construction_checkpoint,
        )
        projected_relationships, _relationship_projection_materialization = (
            cls._relationship_projection_index(
                dataset,
                ingestion,
                execution_plan=execution_plan,
                resources_by_id=resources_by_id,
                construction_checkpoint=construction_checkpoint,
            )
        )
        for relationship in projected_relationships:
            relationships.add(relationship_subject_id(relationship))
        if construction_checkpoint is not None:
            construction_checkpoint()
        return _DatasetIndex(
            events=events,
            source_records=source_records,
            resources=frozenset(resources),
            relationships=frozenset(relationships),
            findings=findings,
            consistency_materialization=consistency_materialization,
            timeline_start_ns=timeline_start,
            timeline_end_ns=timeline_end,
        )

    def _load_revision(
        self,
        scope: ReviewScope,
        revision_id: str,
        *,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> _LoadedRevision:
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")

        def checkpoint() -> None:
            if cancellation_probe is None:
                return
            cancelled = cancellation_probe()
            if type(cancelled) is not bool:
                raise ControlPlaneError(
                    "private-analysis cancellation probe returned an invalid value"
                )
            if cancelled:
                raise PrivateAnalysisRevisionEvidenceCancelled(
                    "private-analysis revision loading was cancelled"
                )

        checkpoint()
        descriptor = self._revision(scope, revision_id)
        cache_key = f"{scope.tenant_id}\x1f{revision_id}"
        with self._lock:
            if self._closed:
                raise ControlPlaneError("control plane is closed")
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache.move_to_end(cache_key)
                checkpoint()
                return cached

        metadata = descriptor.metadata
        if metadata.get("dataset_format") != _DATASET_FORMAT:
            raise DatasetIntegrityError("unsupported serialized dataset format")
        expected_digest = _exact_identifier(
            metadata.get("dataset_sha256"),
            label="dataset_sha256",
        )
        if expected_digest != descriptor.identity_digest:
            raise DatasetIntegrityError(
                "dataset digest disagrees with revision identity"
            )
        path = self._dataset_path(
            self.ingestion.dataset_root,
            metadata.get("dataset_ref"),
        )
        try:
            size = path.stat().st_size
        except OSError as error:
            raise DatasetIntegrityError("serialized dataset is unavailable") from error
        if size < 1 or size > self.limits.max_dataset_bytes:
            raise DatasetIntegrityError(
                "serialized dataset violates the configured byte limit"
            )
        try:
            serialized_buffer = bytearray()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    checkpoint()
                    serialized_buffer.extend(block)
                    digest.update(block)
                    if len(serialized_buffer) > self.limits.max_dataset_bytes:
                        raise DatasetIntegrityError(
                            "serialized dataset violates the configured byte limit"
                        )
        except OSError as error:
            raise DatasetIntegrityError("serialized dataset cannot be read") from error
        checkpoint()
        actual_digest = digest.hexdigest()
        if actual_digest != expected_digest:
            raise DatasetIntegrityError(
                "serialized dataset checksum does not match its publication"
            )

        def reject_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON constant {value}")

        try:
            # ``bytearray.decode`` creates only the required text object.  Do
            # not first copy a potentially multi-gigabyte dataset into an
            # additional immutable bytes object.
            decoded = serialized_buffer.decode("utf-8")
            del serialized_buffer
            checkpoint()
            parsed = json.loads(
                decoded,
                parse_constant=reject_constant,
            )
            del decoded
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise DatasetIntegrityError(
                "serialized dataset is not strict UTF-8 JSON"
            ) from error
        if not isinstance(parsed, dict):
            raise DatasetIntegrityError("serialized dataset must be a JSON object")
        checkpoint()
        index = self._index_dataset(
            descriptor,
            parsed,
            construction_checkpoint=checkpoint,
        )
        loaded = _LoadedRevision(descriptor, parsed, index)
        with self._lock:
            if self.limits.dataset_cache_entries:
                self._cache[cache_key] = loaded
                self._cache.move_to_end(cache_key)
                while len(self._cache) > self.limits.dataset_cache_entries:
                    self._cache.popitem(last=False)
        return loaded

    def load_revision_dataset(
        self,
        scope: ReviewScope,
        revision_id: str,
    ) -> dict[str, Any]:
        """Load and verify one catalog revision, returning a detached value."""

        return deepcopy(dict(self._load_revision(scope, revision_id).dataset))

    def list_revision_consistency_findings(
        self,
        scope: ReviewScope,
        revision_id: str,
        *,
        limit: int = 1_000,
        offset: int = 0,
    ) -> RevisionConsistencyFindingsPage:
        """Return one detached page from the revision's verified index."""

        if type(limit) is not int or not 1 <= limit <= 5_000:
            raise ValueError("limit must be between 1 and 5000")
        if type(offset) is not int or not 0 <= offset <= MAX_JSON_SAFE_INTEGER:
            raise ValueError(f"offset must be between 0 and {MAX_JSON_SAFE_INTEGER}")
        loaded = self._load_revision(scope, revision_id)
        total_count = len(loaded.index.findings)
        page_end = min(offset + limit, total_count)
        items = tuple(
            deepcopy(dict(item)) for item in loaded.index.findings[offset:page_end]
        )
        next_offset = page_end if page_end < total_count else None
        return RevisionConsistencyFindingsPage(
            revision_id=loaded.descriptor.revision_id,
            materialization=deepcopy(dict(loaded.index.consistency_materialization)),
            items=items,
            offset=offset,
            limit=limit,
            total_count=total_count,
            next_offset=next_offset,
        )

    def list_revision_consistency_findings_for_client(
        self,
        scope: ReviewScope,
        revision_id: str,
        *,
        limit: int = 1_000,
        offset: int = 0,
    ) -> RevisionConsistencyFindingsPage:
        """Return one verified page projected without copying the full dataset."""

        if type(limit) is not int or not 1 <= limit <= 5_000:
            raise ValueError("limit must be between 1 and 5000")
        if type(offset) is not int or not 0 <= offset <= MAX_JSON_SAFE_INTEGER:
            raise ValueError(f"offset must be between 0 and {MAX_JSON_SAFE_INTEGER}")
        loaded = self._load_revision(scope, revision_id)
        total_count = len(loaded.index.findings)
        page_end = min(offset + limit, total_count)
        projected = project_consistency_findings_for_client(
            loaded.dataset,
            loaded.index.findings[offset:page_end],
        )
        next_offset = page_end if page_end < total_count else None
        return RevisionConsistencyFindingsPage(
            revision_id=loaded.descriptor.revision_id,
            materialization=project_consistency_materialization_for_client(
                loaded.index.consistency_materialization,
            ),
            items=tuple(projected),
            offset=offset,
            limit=limit,
            total_count=total_count,
            next_offset=next_offset,
        )

    def capability_router_for_revision(
        self,
        scope: ReviewScope,
        revision_id: str,
        *,
        member_id: str | None = None,
    ) -> PlanBoundCapabilityRouter:
        """Bind one authorized immutable revision to its exact providers.

        The verified catalog execution plan is the sole dispatch authority.
        Planless/legacy plans and stale providers fail through the router's
        closed errors; no currently installed provider is used as fallback.
        """

        loaded = self._load_revision(scope, revision_id)
        return self._capability_router_for_descriptor(
            loaded.descriptor,
            member_id=(
                loaded.descriptor.revision_id if member_id is None else member_id
            ),
        )

    def _capability_router_for_descriptor(
        self,
        descriptor: AnalysisRevisionDescriptor,
        *,
        member_id: str,
    ) -> PlanBoundCapabilityRouter:
        """Bind a previously verified immutable descriptor without rereading it."""

        if type(descriptor) is not AnalysisRevisionDescriptor:
            raise TypeError("descriptor must be an AnalysisRevisionDescriptor")
        return PlanBoundCapabilityRouter(
            self.capability_providers,
            descriptor.execution_plan,
            catalog_revision_id=descriptor.revision_id,
            member_id=member_id,
            allow_inline_only=self.allow_inline_only,
        )

    def capability_router_for_revision_set(
        self,
        scope: ReviewScope,
        *,
        revision_ids: Iterable[str] = (),
        session_id: str | None = None,
        snapshot_id: str | None = None,
    ) -> RevisionSetCapabilityRouter:
        """Bind an explicit revision vector, session, or snapshot canonically.

        Session and snapshot member IDs remain part of routing identity. An
        explicit revision vector uses each revision ID as its member ID. Exactly
        one selector is required and at most 128 members are admitted.
        """

        supplied = tuple(islice(revision_ids, 129))
        if len(supplied) > 128:
            raise ValueError("a capability revision set requires 1 to 128 members")
        selector_count = sum(
            (
                bool(supplied),
                session_id is not None,
                snapshot_id is not None,
            )
        )
        if selector_count != 1:
            raise ValueError(
                "exactly one non-empty revision_ids, session_id, or snapshot_id "
                "selector is required"
            )
        self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        if supplied:
            if len(supplied) != len(set(supplied)):
                raise ValueError("revision_ids must not contain duplicates")
            members = tuple((revision_id, revision_id) for revision_id in supplied)
        elif session_id is not None:
            session = self.sessions.get_session(scope.tenant_id, session_id)
            if session.workspace_id != scope.workspace_id:
                raise KeyError(session_id)
            members = tuple(
                (member.member_id, member.revision_id) for member in session.members
            )
        else:
            assert snapshot_id is not None
            snapshot = self.sessions.get_snapshot(scope.tenant_id, snapshot_id)
            if snapshot.workspace_id != scope.workspace_id:
                raise KeyError(snapshot_id)
            members = tuple(
                (member.member_id, member.revision_id) for member in snapshot.members
            )
        if not 1 <= len(members) <= 128:
            raise ValueError("a capability revision set requires 1 to 128 members")
        return RevisionSetCapabilityRouter(
            self.capability_router_for_revision(
                scope,
                revision_id,
                member_id=member_id,
            )
            for member_id, revision_id in members
        )

    def resolve_catalog_revision(
        self,
        scope: ReviewScope,
        *,
        fixture_id: str,
        source_revision_id: str | None = None,
    ) -> AnalysisRevisionDescriptor:
        """Resolve the catalog identity produced for one pipeline fixture."""

        self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        matches = [
            revision
            for revision in self.sessions.list_revisions(
                scope.tenant_id,
                scope.workspace_id,
                fixture_id=fixture_id,
                source_revision_id=source_revision_id,
                limit=2,
            )
            if revision.fixture_id == fixture_id
        ]
        if len(matches) != 1:
            raise SubjectResolutionError(
                "fixture does not resolve to exactly one catalog revision"
            )
        return matches[0]

    def validate_subjects(
        self,
        scope: ReviewScope,
        subjects: Iterable[ReviewSubject],
        *,
        event_only: bool = False,
    ) -> tuple[ReviewSubject, ...]:
        """Resolve every exact subject before a mutable write is admitted."""

        materialized = normalize_review_subjects(
            subjects,
            maximum=MAX_CORRELATION_SUBJECTS if event_only else MAX_ANNOTATION_SUBJECTS,
            event_only=event_only,
        )
        subjects_by_revision: dict[str, list[ReviewSubject]] = {}
        for subject in materialized:
            subjects_by_revision.setdefault(subject.revision_id, []).append(subject)
        self._preflight_revision_reads(
            scope,
            tuple(subjects_by_revision),
            maximum_revisions=self.limits.max_subject_revisions,
            maximum_bytes=self.limits.max_subject_dataset_bytes,
            label="review subject",
        )
        # Retain only the existing bounded LRU, not every decoded revision.
        for revision_id, selected in subjects_by_revision.items():
            loaded = self._load_revision(scope, revision_id)
            for subject in selected:
                self._validate_loaded_subject(subject, loaded)
        return materialized

    @staticmethod
    def _validate_loaded_subject(
        subject: ReviewSubject, loaded: _LoadedRevision
    ) -> None:
        if subject.node_id is not None and subject.node_id != loaded.descriptor.node_id:
            raise SubjectResolutionError(
                "subject node does not match its exact revision"
            )
        subject_id = subject.subject_id
        if subject.kind is ReviewSubjectKind.EVENT:
            exists = subject_id in loaded.index.events
        elif subject.kind is ReviewSubjectKind.SOURCE_RECORD:
            exists = subject_id in loaded.index.source_records
        elif subject.kind is ReviewSubjectKind.RESOURCE:
            exists = subject_id in loaded.index.resources
        elif subject.kind is ReviewSubjectKind.RELATIONSHIP:
            exists = subject_id in loaded.index.relationships
        else:
            assert subject.kind is ReviewSubjectKind.TIME_RANGE
            assert subject.start_ns is not None and subject.end_ns is not None
            exists = (
                loaded.index.timeline_start_ns
                <= subject.start_ns
                <= subject.end_ns
                <= loaded.index.timeline_end_ns
            )
        if not exists:
            raise SubjectResolutionError(
                f"{subject.kind.value} subject does not exist in revision "
                f"{subject.revision_id!r}"
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
        with self._coordinated_review_catalog():
            resolved = self.validate_subjects(scope, subjects)
            return self.annotations.create_annotation(
                scope,
                kind=kind,
                subjects=resolved,
                author=author,
                title=title,
                body=body,
                tags=tags,
                annotation_id=annotation_id,
                idempotency_key=idempotency_key,
            )

    def get_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ReviewAnnotation:
        return self.annotations.get_annotation(
            scope,
            annotation_id,
            include_deleted=include_deleted,
        )

    def update_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        expected_version: int,
        actor: str,
        kind: ReviewAnnotationKind | None = None,
        subjects: Iterable[ReviewSubject] | None = None,
        title: str | None = None,
        body: str | None = None,
        tags: Iterable[str] | None = None,
    ) -> ReviewAnnotation:
        with self._coordinated_review_catalog():
            current = self.annotations.get_annotation(scope, annotation_id)
            resolved = (
                current.subjects
                if subjects is None
                else self.validate_subjects(scope, subjects)
            )
            return self.annotations.update_annotation(
                scope,
                annotation_id,
                expected_version=expected_version,
                actor=actor,
                kind=current.kind if kind is None else kind,
                subjects=resolved,
                title=current.title if title is None else title,
                body=current.body if body is None else body,
                tags=current.tags if tags is None else tags,
            )

    def delete_annotation(
        self,
        scope: ReviewScope,
        annotation_id: str,
        *,
        expected_version: int,
        actor: str,
    ) -> ReviewAnnotation:
        with self._coordinated_review_catalog():
            return self.annotations.delete_annotation(
                scope,
                annotation_id,
                expected_version=expected_version,
                actor=actor,
            )

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
        with self._coordinated_review_catalog():
            resolved = self.validate_subjects(scope, subjects, event_only=True)
            return self.annotations.create_correlation(
                scope,
                subjects=resolved,
                edges=edges,
                author=author,
                rationale=rationale,
                tags=tags,
                confidence=confidence,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )

    def get_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        include_deleted: bool = False,
    ) -> ManualEventCorrelation:
        return self.annotations.get_correlation(
            scope,
            correlation_id,
            include_deleted=include_deleted,
        )

    def update_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        expected_version: int,
        actor: str,
        subjects: Iterable[ReviewSubject] | None = None,
        edges: Iterable[ManualCorrelationEdge] | None = None,
        rationale: str | None = None,
        tags: Iterable[str] | None = None,
        confidence: float | None = None,
        replace_confidence: bool = False,
    ) -> ManualEventCorrelation:
        with self._coordinated_review_catalog():
            current = self.annotations.get_correlation(scope, correlation_id)
            resolved = (
                current.subjects
                if subjects is None
                else self.validate_subjects(scope, subjects, event_only=True)
            )
            return self.annotations.update_correlation(
                scope,
                correlation_id,
                expected_version=expected_version,
                actor=actor,
                subjects=resolved,
                edges=current.edges if edges is None else edges,
                rationale=current.rationale if rationale is None else rationale,
                tags=current.tags if tags is None else tags,
                confidence=(confidence if replace_confidence else current.confidence),
            )

    def delete_correlation(
        self,
        scope: ReviewScope,
        correlation_id: str,
        *,
        expected_version: int,
        actor: str,
    ) -> ManualEventCorrelation:
        with self._coordinated_review_catalog():
            return self.annotations.delete_correlation(
                scope,
                correlation_id,
                expected_version=expected_version,
                actor=actor,
            )

    @staticmethod
    def _selected_revision_ids(
        sessions: SqliteSessionStore,
        scope: ReviewScope,
        revision_ids: Iterable[str],
        session_id: str | None,
        snapshot_id: str | None,
        *,
        maximum: int,
    ) -> tuple[str, ...]:
        supplied = tuple(islice(revision_ids, maximum + 1))
        if len(supplied) > maximum:
            raise ControlPlaneError(
                "selected revisions exceed the report revision limit"
            )
        selected_forms = sum(
            (
                bool(supplied),
                session_id is not None,
                snapshot_id is not None,
            )
        )
        if selected_forms > 1:
            raise ValueError(
                "revision_ids, session_id, and snapshot_id are mutually exclusive"
            )
        if session_id is not None:
            session: AnalysisSession = sessions.get_session(
                scope.tenant_id,
                session_id,
            )
            if session.workspace_id != scope.workspace_id:
                raise KeyError(session_id)
            supplied = tuple(member.revision_id for member in session.members)
        elif snapshot_id is not None:
            snapshot = sessions.get_snapshot(
                scope.tenant_id,
                snapshot_id,
            )
            if snapshot.workspace_id != scope.workspace_id:
                raise KeyError(snapshot_id)
            supplied = tuple(member.revision_id for member in snapshot.members)
        if len(supplied) != len(set(supplied)):
            raise ValueError("revision_ids must not contain duplicates")
        return supplied

    @staticmethod
    def _event_time(event: Mapping[str, Any]) -> tuple[int | None, int | None]:
        raw = event.get("timestamp_ns")
        if raw is None:
            return None, None
        timestamp = _event_ns(raw, label="event timestamp_ns")
        raw_uncertainty = event.get("timestamp_uncertainty_ns")
        uncertainty = (
            0
            if raw_uncertainty is None
            else _event_ns(
                raw_uncertainty,
                label="event timestamp_uncertainty_ns",
            )
        )
        if uncertainty < 0:
            raise DatasetIntegrityError(
                "event timestamp_uncertainty_ns must be non-negative"
            )
        earliest = timestamp - uncertainty
        latest = timestamp + uncertainty
        if earliest < MIN_TIMESTAMP_NS or latest > MAX_TIMESTAMP_NS:
            raise DatasetIntegrityError(
                "event timestamp uncertainty interval exceeds signed 64-bit"
            )
        return earliest, latest

    @staticmethod
    def _event_clock_domain(event: Mapping[str, Any]) -> str | None:
        direct = event.get("clock_domain")
        if isinstance(direct, str) and direct:
            return direct
        evidence = event.get("evidence")
        if isinstance(evidence, Mapping):
            nested = evidence.get("clock_domain")
            if isinstance(nested, str) and nested:
                return nested
        return None

    @staticmethod
    def _causal_link_projection(
        revision_id: str,
        value: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        source = value.get("source_event_uid")
        target = value.get("target_event_uid")
        link_type = value.get("link_type")
        if not all(
            isinstance(item, str) and item for item in (source, target, link_type)
        ):
            return None
        target_revision = value.get("target_revision_id")
        if target_revision is not None and (
            not isinstance(target_revision, str) or not target_revision
        ):
            return None
        result: dict[str, Any] = {
            "revision_id": revision_id,
            "target_revision_id": target_revision or revision_id,
            "source_event_uid": source,
            "target_event_uid": target,
            "link_type": link_type,
        }
        for field in ("confidence", "provenance", "quality"):
            nested = value.get(field)
            if isinstance(nested, (str, int, float, bool)) or nested is None:
                result[field] = nested
        return result

    @staticmethod
    def _fact_projection(
        fact: CorroborationFact,
        *,
        correlation_id: str,
        edge_ordinal: int,
    ) -> dict[str, Any]:
        return {
            "fact_type": fact.reason_code.value,
            "result": fact.outcome.value,
            "correlation_id": correlation_id,
            "edge_ordinal": edge_ordinal,
            "left": {
                "revision_id": fact.left.partition_id,
                "event_uid": fact.left.event_id,
            },
            "right": {
                "revision_id": fact.right.partition_id,
                "event_uid": fact.right.event_id,
            },
            "temporal_relation": fact.temporal_relation.value,
            "shared_source_records": [
                {
                    "revision_id": item.source_id,
                    "source_record_uid": item.record_id,
                }
                for item in fact.shared_source_records
            ],
            "shared_resource_ids": list(fact.shared_resource_ids),
            "causal_link_ids": list(fact.causal_link_ids),
            "clock_alignment": {
                "left_clock_domain": fact.left_clock_domain,
                "right_clock_domain": fact.right_clock_domain,
                "comparable": (
                    fact.left_clock_domain is not None
                    and fact.left_clock_domain == fact.right_clock_domain
                ),
            },
            "evidence": list(fact.evidence),
            "provenance": list(fact.provenance),
        }

    def _preflight_revision_reads(
        self,
        scope: ReviewScope,
        revision_ids: tuple[str, ...],
        *,
        maximum_revisions: int,
        maximum_bytes: int,
        label: str,
    ) -> None:
        """Bound catalog-authorized dataset reads before decoding any payload."""
        if len(revision_ids) > maximum_revisions:
            raise ControlPlaneError(
                f"selected revisions exceed the {label} revision limit"
            )
        total_bytes = 0
        for revision_id in revision_ids:
            descriptor = self._revision(scope, revision_id)
            path = self._dataset_path(
                self.ingestion.dataset_root, descriptor.metadata.get("dataset_ref")
            )
            try:
                size = path.stat().st_size
            except OSError as error:
                raise DatasetIntegrityError(
                    "serialized revision dataset is unavailable"
                ) from error
            if size < 1 or size > self.limits.max_dataset_bytes:
                raise DatasetIntegrityError(
                    "serialized dataset violates the configured byte limit"
                )
            total_bytes += size
            if total_bytes > maximum_bytes:
                raise ControlPlaneError(
                    f"selected revision datasets exceed the {label} byte limit"
                )

    def build_report(
        self,
        scope: ReviewScope,
        *,
        revision_ids: Iterable[str] = (),
        session_id: str | None = None,
        snapshot_id: str | None = None,
    ) -> CorrelationReport:
        """Build a deterministic AI-friendly report from one revision set."""

        self.validate_scope(
            scope.tenant_id,
            scope.project_id,
            scope.workspace_id,
        )
        selected_ids = self._selected_revision_ids(
            self.sessions,
            scope,
            revision_ids,
            session_id,
            snapshot_id,
            maximum=self.limits.max_report_revisions,
        )
        if (session_id is not None or snapshot_id is not None) and not selected_ids:
            raise SubjectResolutionError(
                "the selected session or snapshot contains no revision members"
            )
        if not selected_ids:
            raise SubjectResolutionError(
                "correlation reports require explicit revision_ids, "
                "session_id, or snapshot_id"
            )
        self._preflight_revision_reads(
            scope,
            selected_ids,
            maximum_revisions=self.limits.max_report_revisions,
            maximum_bytes=self.limits.max_report_dataset_bytes,
            label="report",
        )
        loaded = {
            revision_id: self._load_revision(scope, revision_id)
            for revision_id in selected_ids
        }
        selected_set = set(loaded)

        overlay = self.annotations.snapshot_for_report(scope)
        annotations = tuple(
            annotation
            for annotation in overlay.annotations
            if {subject.revision_id for subject in annotation.subjects} <= selected_set
        )
        correlations = tuple(
            correlation
            for correlation in overlay.correlations
            if {subject.revision_id for subject in correlation.subjects} <= selected_set
        )
        correlation_edge_count = sum(
            len(correlation.edges) for correlation in correlations
        )
        if correlation_edge_count > self.limits.max_report_correlation_edges:
            raise ControlPlaneError(
                "manual correlation edges exceed the report edge limit"
            )

        event_subjects: set[tuple[str, str]] = set()
        source_subjects: set[tuple[str, str]] = set()
        review_records: tuple[
            ReviewAnnotation | ManualEventCorrelation,
            ...,
        ] = (*annotations, *correlations)
        for record in review_records:
            for subject in record.subjects:
                if subject.kind is ReviewSubjectKind.EVENT:
                    assert subject.subject_id is not None
                    event_subjects.add((subject.revision_id, subject.subject_id))
                elif subject.kind is ReviewSubjectKind.SOURCE_RECORD:
                    assert subject.subject_id is not None
                    source_subjects.add((subject.revision_id, subject.subject_id))
        if (
            len(event_subjects) + len(source_subjects)
            > self.limits.max_report_observations
        ):
            raise ControlPlaneError(
                "review selection exceeds the report observation limit"
            )

        source_by_event: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for revision_id, revision in loaded.items():
            for source_id, source in revision.index.source_records.items():
                for event_id in source_record_event_uids(dict(source)):
                    source_by_event.setdefault(
                        (revision_id, event_id),
                        [],
                    ).append((revision_id, source_id))
        for key in event_subjects:
            source_subjects.update(source_by_event.get(key, ()))
        if (
            len(event_subjects) + len(source_subjects)
            > self.limits.max_report_observations
        ):
            raise ControlPlaneError(
                "linked source records exceed the report observation limit"
            )

        event_projections: list[dict[str, Any]] = []
        source_projections: list[dict[str, Any]] = []
        resolved_events: dict[tuple[str, str], ResolvedEventRef] = {}
        selected_plugin_links: list[dict[str, Any]] = []
        unresolved_references: list[dict[str, Any]] = []
        selected_event_ids_by_revision: dict[str, set[str]] = {}
        for revision_id, event_id in event_subjects:
            selected_event_ids_by_revision.setdefault(revision_id, set()).add(event_id)
        source_revision_candidates: dict[str, list[str]] = {}
        for revision_id, revision in loaded.items():
            source_revision_id = revision.descriptor.metadata.get("source_revision_id")
            if isinstance(source_revision_id, str) and source_revision_id:
                source_revision_candidates.setdefault(
                    source_revision_id,
                    [],
                ).append(revision_id)

        def catalog_revision_id(value: str) -> str:
            if value in loaded:
                return value
            candidates = source_revision_candidates.get(value, ())
            return candidates[0] if len(candidates) == 1 else value

        for revision_id, revision in loaded.items():
            selected_events = selected_event_ids_by_revision.get(
                revision_id,
                set(),
            )
            causal_by_source: dict[str, list[ExplicitCausalLink]] = {}
            redaction_policy = event_redaction_policy(revision.dataset)
            raw_links = self._mapping_list(revision.dataset, "causal_links")
            for ordinal, raw_link in enumerate(raw_links):
                projection = self._causal_link_projection(
                    revision_id,
                    raw_link,
                )
                if projection is None:
                    raw_source = raw_link.get("source_event_uid")
                    if isinstance(raw_source, str) and raw_source in selected_events:
                        unresolved_references.append(
                            {
                                "kind": "plugin_causal_link",
                                "reason": "malformed_link",
                                "revision_id": revision_id,
                                "source_event_uid": raw_source,
                                "link_ordinal": ordinal,
                            }
                        )
                        if (
                            len(unresolved_references)
                            > self.limits.max_report_observations
                        ):
                            raise ControlPlaneError(
                                "unresolved causal references exceed the "
                                "report observation limit"
                            )
                    continue
                source_id = str(projection["source_event_uid"])
                target_id = str(projection["target_event_uid"])
                target_revision_id = catalog_revision_id(
                    str(projection["target_revision_id"])
                )
                projection["target_revision_id"] = target_revision_id
                target_events = selected_event_ids_by_revision.get(
                    target_revision_id,
                    set(),
                )
                if source_id in selected_events and target_id in target_events:
                    selected_plugin_links.append(projection)
                elif source_id in selected_events:
                    target_revision = loaded.get(target_revision_id)
                    if target_revision is None:
                        reason = "target_revision_not_selected"
                    elif target_id not in target_revision.index.events:
                        reason = "target_event_missing"
                    else:
                        reason = "target_event_not_selected"
                    unresolved_references.append(
                        {
                            "kind": "plugin_causal_link",
                            "reason": reason,
                            "revision_id": revision_id,
                            "source_event_uid": source_id,
                            "target_revision_id": target_revision_id,
                            "target_event_uid": target_id,
                            "link_type": projection["link_type"],
                            "link_ordinal": ordinal,
                        }
                    )
                if len(unresolved_references) > self.limits.max_report_observations:
                    raise ControlPlaneError(
                        "unresolved causal references exceed the report "
                        "observation limit"
                    )
                link_id = str(
                    raw_link.get("link_id")
                    or (
                        f"{revision_id}:causal-link:"
                        f"{hashlib.sha256(canonical_json(projection).encode('utf-8')).hexdigest()}"
                    )
                )
                causal_by_source.setdefault(source_id, []).append(
                    ExplicitCausalLink(
                        link_id=link_id,
                        target=EventIdentity(target_revision_id, target_id),
                    )
                )

            for event_id in selected_events:
                event = revision.index.events[event_id]
                projection = redact_event_for_client(
                    event,
                    revision.dataset,
                    policy=redaction_policy,
                )
                projection["revision_id"] = revision_id
                projection["node_id"] = revision.descriptor.node_id
                event_projections.append(projection)
                earliest, latest = self._event_time(event)
                subjects = event.get("subjects", ())
                resource_ids = tuple(
                    sorted(
                        {
                            str(item.get("resource_id"))
                            for item in subjects
                            if isinstance(item, Mapping) and item.get("resource_id")
                        }
                        | (
                            {str(event["resource_id"])}
                            if event.get("resource_id")
                            else set()
                        )
                    )
                )
                source_refs = tuple(
                    SourceRecordIdentity(source_revision, source_id)
                    for source_revision, source_id in sorted(
                        source_by_event.get((revision_id, event_id), ())
                    )
                )
                safe_evidence = projection.get("evidence")
                evidence = (
                    tuple(safe_evidence) if isinstance(safe_evidence, list) else ()
                )
                safe_provenance = projection.get("provenance")
                provenance = (
                    (safe_provenance,)
                    if isinstance(safe_provenance, (str, dict))
                    else ()
                )
                resolved_events[(revision_id, event_id)] = ResolvedEventRef(
                    identity=EventIdentity(revision_id, event_id),
                    source_records=source_refs,
                    canonical_resource_ids=resource_ids,
                    earliest_ns=earliest,
                    latest_ns=latest,
                    clock_domain=self._event_clock_domain(event),
                    causal_links=tuple(
                        sorted(
                            causal_by_source.get(event_id, ()),
                            key=lambda link: link.link_id,
                        )
                    ),
                    evidence=evidence,
                    provenance=provenance,
                )

        for revision_id, source_id in source_subjects:
            source = loaded[revision_id].index.source_records[source_id]
            projection = project_source_record_for_log(dict(source))
            projection["revision_id"] = revision_id
            projection["node_id"] = loaded[revision_id].descriptor.node_id
            source_projections.append(projection)

        facts: list[dict[str, Any]] = []
        warnings: list[str] = []
        for correlation in correlations:
            for edge_ordinal, edge in enumerate(correlation.edges):
                if not edge.directed:
                    warnings.append(
                        "Core corroboration skipped undirected manual edge "
                        f"{correlation.correlation_id}/{edge_ordinal}; "
                        "temporal direction was not asserted."
                    )
                    continue
                left_subject = correlation.subjects[edge.source_ordinal]
                right_subject = correlation.subjects[edge.target_ordinal]
                assert left_subject.subject_id is not None
                assert right_subject.subject_id is not None
                left = resolved_events[
                    (left_subject.revision_id, left_subject.subject_id)
                ]
                right = resolved_events[
                    (right_subject.revision_id, right_subject.subject_id)
                ]
                facts.extend(
                    self._fact_projection(
                        fact,
                        correlation_id=correlation.correlation_id,
                        edge_ordinal=edge_ordinal,
                    )
                    for fact in corroborate_events(left, right)
                )

        revision_vector = [
            {
                "revision_id": revision.descriptor.revision_id,
                "source_revision_id": revision.descriptor.metadata.get(
                    "source_revision_id"
                ),
                "node_id": revision.descriptor.node_id,
                "fixture_id": revision.descriptor.fixture_id,
                "identity_digest": revision.descriptor.identity_digest,
                "plugin_ids": list(revision.descriptor.plugin_ids),
                "plugin_execution_plan_digest": (
                    revision.descriptor.execution_plan_digest
                ),
                "published_at_ns": revision.descriptor.published_at_ns,
            }
            for revision in loaded.values()
        ]
        return build_correlation_report(
            scope,
            revision_vector=revision_vector,
            annotation_watermark=overlay.audit_watermark,
            annotations=annotations,
            manual_correlations=correlations,
            events=event_projections,
            source_records=source_projections,
            plugin_causal_links=selected_plugin_links,
            corroboration_facts=facts,
            unresolved_references=unresolved_references,
            warnings=warnings,
        )


def validate_revision_consistency_dataset(
    dataset: Mapping[str, Any],
    *,
    execution_plan: PluginExecutionPlan | None,
    construction_checkpoint: Callable[[], None] | None = None,
) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]:
    """Validate and detach one revision's durable consistency contract.

    Runtime and durable control-plane routes share this exact validator so a
    malformed materialization envelope can never be reinterpreted as legacy
    output at one transport boundary.
    """

    if not isinstance(dataset, Mapping):
        raise DatasetIntegrityError("dataset must be an object")
    ingestion = dataset.get("_ingestion")
    if not isinstance(ingestion, Mapping):
        raise DatasetIntegrityError("dataset lacks the core ingestion envelope")
    plan_digest = ingestion.get("plugin_execution_plan_digest")
    return ControlPlane._consistency_index(
        dataset,
        ingestion,
        plan_digest=plan_digest,
        execution_plan=execution_plan,
        construction_checkpoint=construction_checkpoint,
    )


__all__ = [
    "ControlPlane",
    "ControlPlaneError",
    "ControlPlaneLimits",
    "ControlPlaneScopeError",
    "DatasetIntegrityError",
    "RevisionConsistencyFindingsPage",
    "SessionCatalogPublisher",
    "SubjectResolutionError",
    "relationship_subject_id",
    "validate_revision_consistency_dataset",
]
