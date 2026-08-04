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
import threading
from collections import OrderedDict
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Self

from .annotation_store import (
    CorrelationReport,
    ManualCorrelationEdge,
    ManualEventCorrelation,
    ReviewAnnotation,
    ReviewAnnotationKind,
    ReviewOverlayStore,
    ReviewRetentionCandidate,
    ReviewRetentionInventory,
    ReviewRetentionPolicy,
    ReviewRetentionResult,
    ReviewScope,
    ReviewSubject,
    ReviewSubjectKind,
    build_correlation_report,
)
from .canonical import canonical_json
from .corroboration import (
    CorroborationFact,
    EventIdentity,
    ExplicitCausalLink,
    ResolvedEventRef,
    SourceRecordIdentity,
    corroborate_events,
)
from .filesystem_lock import exclusive_file_lock
from .ingestion_pipeline import (
    CatalogExecutionTimeoutError,
    DurableIngestionPipeline,
    ImportScope,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
    PublisherCallContext,
    RetentionHostInventoryCoverage,
    RetentionPolicy,
    RetentionReport,
    RevisionCatalogPublisher,
    validate_ingestion_state_root,
)
from .normalized_data import (
    event_redaction_policy,
    redact_event_for_client,
    resource_id,
)
from .plugin_api import MAX_TIMESTAMP_NS, MIN_TIMESTAMP_NS
from .plugin_execution_plan import (
    PluginExecutionPlan,
    snapshot_plugin_execution_plan,
)
from .session_store import (
    AnalysisRevisionDescriptor,
    AnalysisSession,
    CatalogArtifactRelease,
    CatalogRetentionCandidate,
    CatalogRetentionInventory,
    CatalogRetentionPolicy,
    CatalogRetentionResult,
    IdempotencyConflict,
    RetentionSagaDescriptor,
    SessionStoreDeadlineExceeded,
    SqliteSessionStore,
    WorkspaceDescriptor,
)
from .source_record_core import (
    project_source_record_for_log,
    source_record_event_uids,
)
from .value_core import parse_canonical_decimal_integer

_DEFAULT_MAX_DATASET_BYTES = 2 * 1024 * 1024 * 1024
_DEFAULT_DATASET_CACHE_ENTRIES = 4
_MAX_REPORT_OBSERVATIONS = 10_000
_DEFAULT_MAX_REPORT_REVISIONS = 128
_DEFAULT_MAX_REPORT_DATASET_BYTES = 8 * 1024 * 1024 * 1024
_DEFAULT_MAX_REPORT_CORRELATION_EDGES = 20_000
_DATASET_FORMAT = "router_dump_analyzer.canonical-json.v1"
_MAX_RETENTION_RELEASE_ACTIONS = 10_000
_MAX_RETENTION_ACTOR_LENGTH = 256
_MAX_RETENTION_OPERATION_ID_LENGTH = 248
_RETENTION_SAGA_SCHEMA = "router_dump_analyzer.retention_saga.v1"
_RETENTION_PHASE_SCHEMA = "router_dump_analyzer.retention_phase.v1"


class ControlPlaneError(RuntimeError):
    """Base error for cross-store composition failures."""


class ControlPlaneScopeError(ValueError, ControlPlaneError):
    """A project/workspace scope is not a valid catalog boundary."""


class DatasetIntegrityError(ControlPlaneError):
    """An immutable dataset no longer matches its catalog publication."""


class SubjectResolutionError(ValueError, ControlPlaneError):
    """A review subject does not exist in its exact immutable revision."""


class HiddenSubjectResolutionError(KeyError, SubjectResolutionError):
    """An absent or out-of-scope subject hidden as a lookup miss."""


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

    def __post_init__(self) -> None:
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


@dataclass(frozen=True, slots=True)
class _DatasetIndex:
    events: Mapping[str, Mapping[str, Any]]
    source_records: Mapping[str, Mapping[str, Any]]
    resources: frozenset[str]
    relationships: frozenset[str]
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


def _review_policy_document(policy: ReviewRetentionPolicy) -> dict[str, Any]:
    return {
        "enabled": policy.enabled,
        "tombstone_before_ns": policy.tombstone_before_ns,
        "idempotency_before_ns": policy.idempotency_before_ns,
        "audit_mode": policy.audit_mode.value,
        "audit_before_sequence": policy.audit_before_sequence,
        "maximum_candidates": policy.maximum_candidates,
    }


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


def _review_candidate_document(
    value: ReviewRetentionCandidate,
) -> dict[str, Any]:
    return {
        "category": value.category,
        "identifier": value.identifier,
        "retention_value": value.retention_value,
        "blockers": list(value.blockers),
    }


def _review_phase_document(
    value: ReviewRetentionInventory | ReviewRetentionResult,
) -> dict[str, Any]:
    inventory = value.inventory if isinstance(value, ReviewRetentionResult) else value
    return {
        "schema": _RETENTION_PHASE_SCHEMA,
        "kind": "result" if isinstance(value, ReviewRetentionResult) else "inventory",
        "policy": _review_policy_document(inventory.policy),
        "inventory": {
            "total_candidate_count": inventory.total_candidate_count,
            "candidates": [
                _review_candidate_document(candidate)
                for candidate in inventory.candidates
            ],
            "truncated": inventory.truncated,
        },
        "purged": (
            [_review_candidate_document(candidate) for candidate in value.purged]
            if isinstance(value, ReviewRetentionResult)
            else []
        ),
    }


def _review_phase_from_document(
    scope: ReviewScope,
    value: Mapping[str, Any],
) -> ReviewRetentionInventory | ReviewRetentionResult:
    try:
        if set(value) != {"schema", "kind", "policy", "inventory", "purged"}:
            raise ValueError
        if value.get("schema") != _RETENTION_PHASE_SCHEMA:
            raise ValueError
        kind = value["kind"]
        policy_value = value["policy"]
        inventory_value = value["inventory"]
        purged_value = value["purged"]
        if (
            kind not in {"inventory", "result"}
            or not isinstance(policy_value, dict)
            or not isinstance(inventory_value, dict)
            or not isinstance(purged_value, list)
            or set(inventory_value)
            != {"total_candidate_count", "candidates", "truncated"}
            or not isinstance(inventory_value.get("candidates"), list)
            or type(inventory_value.get("total_candidate_count")) is not int
            or inventory_value["total_candidate_count"] < 0
            or type(inventory_value.get("truncated")) is not bool
        ):
            raise ValueError
        policy = ReviewRetentionPolicy(**policy_value)

        def candidate(item: object) -> ReviewRetentionCandidate:
            if not isinstance(item, dict) or set(item) != {
                "category",
                "identifier",
                "retention_value",
                "blockers",
            }:
                raise TypeError
            blockers = item.get("blockers")
            if (
                not isinstance(item["category"], str)
                or not item["category"]
                or not isinstance(item["identifier"], str)
                or not item["identifier"]
                or type(item["retention_value"]) is not int
                or item["retention_value"] < 0
                or not isinstance(blockers, list)
                or any(not isinstance(blocker, str) for blocker in blockers)
            ):
                raise TypeError
            return ReviewRetentionCandidate(
                category=item["category"],
                identifier=item["identifier"],
                retention_value=item["retention_value"],
                blockers=tuple(blockers),
            )

        inventory = ReviewRetentionInventory(
            scope=scope,
            policy=policy,
            total_candidate_count=inventory_value["total_candidate_count"],
            candidates=tuple(candidate(item) for item in inventory_value["candidates"]),
            truncated=inventory_value["truncated"],
        )
        if kind == "inventory":
            if purged_value:
                raise ValueError
            return inventory
        purged = tuple(candidate(item) for item in purged_value)
        if any(
            item not in inventory.candidates or not item.eligible for item in purged
        ):
            raise ValueError
        return ReviewRetentionResult(
            inventory=inventory,
            purged=purged,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ControlPlaneError(
            "durable review retention phase result is invalid"
        ) from error


def _catalog_candidate_document(
    value: CatalogRetentionCandidate,
) -> dict[str, Any]:
    return {
        "category": value.category,
        "identifier": value.identifier,
        "retention_value": value.retention_value,
        "qualifier": value.qualifier,
        "blockers": list(value.blockers),
    }


def _catalog_phase_document(
    value: CatalogRetentionInventory | CatalogRetentionResult,
) -> dict[str, Any]:
    inventory = value.inventory if isinstance(value, CatalogRetentionResult) else value
    return {
        "schema": _RETENTION_PHASE_SCHEMA,
        "kind": "result" if isinstance(value, CatalogRetentionResult) else "inventory",
        "policy": inventory.policy.as_dict(),
        "inventory": {
            "total_candidate_count": inventory.total_candidate_count,
            "candidates": [
                _catalog_candidate_document(candidate)
                for candidate in inventory.candidates
            ],
            "truncated": inventory.truncated,
        },
        "purged": (
            [_catalog_candidate_document(candidate) for candidate in value.purged]
            if isinstance(value, CatalogRetentionResult)
            else []
        ),
        "artifact_releases": (
            [asdict(release) for release in value.artifact_releases]
            if isinstance(value, CatalogRetentionResult)
            else []
        ),
    }


def _catalog_phase_from_document(
    scope: ReviewScope,
    value: Mapping[str, Any],
) -> CatalogRetentionInventory | CatalogRetentionResult:
    try:
        if set(value) != {
            "schema",
            "kind",
            "policy",
            "inventory",
            "purged",
            "artifact_releases",
        }:
            raise ValueError
        if value.get("schema") != _RETENTION_PHASE_SCHEMA:
            raise ValueError
        kind = value["kind"]
        policy_value = value["policy"]
        inventory_value = value["inventory"]
        purged_value = value["purged"]
        releases_value = value["artifact_releases"]
        if (
            kind not in {"inventory", "result"}
            or not isinstance(policy_value, dict)
            or not isinstance(inventory_value, dict)
            or not isinstance(purged_value, list)
            or not isinstance(releases_value, list)
            or set(inventory_value)
            != {"total_candidate_count", "candidates", "truncated"}
            or not isinstance(inventory_value.get("candidates"), list)
            or type(inventory_value.get("total_candidate_count")) is not int
            or inventory_value["total_candidate_count"] < 0
            or type(inventory_value.get("truncated")) is not bool
        ):
            raise ValueError
        policy = CatalogRetentionPolicy(**policy_value)

        def candidate(item: object) -> CatalogRetentionCandidate:
            if not isinstance(item, dict) or set(item) != {
                "category",
                "identifier",
                "retention_value",
                "qualifier",
                "blockers",
            }:
                raise TypeError
            blockers = item.get("blockers")
            if (
                not isinstance(item["category"], str)
                or not item["category"]
                or not isinstance(item["identifier"], str)
                or not item["identifier"]
                or type(item["retention_value"]) is not int
                or item["retention_value"] < 0
                or not isinstance(blockers, list)
                or any(not isinstance(blocker, str) for blocker in blockers)
            ):
                raise TypeError
            qualifier = item.get("qualifier")
            if qualifier is not None and not isinstance(qualifier, str):
                raise ValueError
            return CatalogRetentionCandidate(
                category=item["category"],
                identifier=item["identifier"],
                retention_value=item["retention_value"],
                qualifier=qualifier,
                blockers=tuple(blockers),
            )

        inventory = CatalogRetentionInventory(
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            policy=policy,
            total_candidate_count=inventory_value["total_candidate_count"],
            candidates=tuple(candidate(item) for item in inventory_value["candidates"]),
            truncated=inventory_value["truncated"],
        )
        if kind == "inventory":
            if purged_value or releases_value:
                raise ValueError
            return inventory
        releases = []
        release_fields = {
            "artifact_kind",
            "artifact_ref",
            "owner_operation_id",
            "catalog_category",
            "catalog_identifier",
        }
        for item in releases_value:
            if (
                not isinstance(item, dict)
                or set(item) != release_fields
                or any(
                    not isinstance(item[field], str) or not item[field]
                    for field in release_fields
                )
            ):
                raise TypeError
            releases.append(CatalogArtifactRelease(**item))
        purged = tuple(candidate(item) for item in purged_value)
        if any(
            item not in inventory.candidates or not item.eligible for item in purged
        ):
            raise ValueError
        return CatalogRetentionResult(
            inventory=inventory,
            purged=purged,
            artifact_releases=tuple(releases),
        )
    except (KeyError, TypeError, ValueError) as error:
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


class SessionCatalogPublisher(RevisionCatalogPublisher):
    """Register pipeline publications in the durable session catalog."""

    def __init__(self, sessions: SqliteSessionStore) -> None:
        self.sessions = sessions

    def __getstate__(self) -> dict[str, str]:
        """Serialize only the durable locator for a bounded child call."""

        return {"database_path": self.sessions._process_reopen_path()}

    def __setstate__(self, state: Mapping[str, str]) -> None:
        database_path = state.get("database_path")
        if not isinstance(database_path, str) or not database_path:
            raise TypeError("catalog publisher process state is invalid")
        self.sessions = SqliteSessionStore(database_path)

    @staticmethod
    def _deadline(call_context: PublisherCallContext, operation_id: str) -> int:
        if call_context.operation_id != operation_id:
            raise ValueError("publisher context operation ID does not match")
        call_context.raise_if_expired()
        return call_context.deadline_monotonic_ns

    def _workspace(
        self,
        scope: ImportScope,
        *,
        deadline_ns: int,
    ) -> WorkspaceDescriptor:
        workspace = self.sessions.get_workspace(
            scope.tenant_id,
            scope.workspace_id,
            deadline_ns=deadline_ns,
        )
        if workspace.project_id != scope.project_id:
            raise ControlPlaneScopeError(
                "workspace does not belong to the requested project"
            )
        return workspace

    @staticmethod
    def catalog_revision_id(
        scope: ImportScope,
        *,
        fixture_id: str,
        source_revision_id: str,
        dataset_sha256: str,
    ) -> str:
        """Namespace a parser revision without changing its source identity."""

        identity = {
            "tenant_id": scope.tenant_id,
            "project_id": scope.project_id,
            "workspace_id": scope.workspace_id,
            "fixture_id": fixture_id,
            "source_revision_id": source_revision_id,
            "dataset_sha256": dataset_sha256,
        }
        digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
        return f"revision-{digest}"

    def admit_fixture(
        self,
        scope: ImportScope,
        *,
        operation_id: str,
        fixture_id: str,
        content_sha256: str,
        byte_count: int,
        original_name: str,
        content_type: str,
        blob_ref: str,
        node_hint: str | None,
        metadata: Mapping[str, Any],
        call_context: PublisherCallContext,
    ) -> None:
        deadline_ns = self._deadline(call_context, operation_id)
        try:
            self._workspace(scope, deadline_ns=deadline_ns)
            label = (
                original_name
                if len(original_name) <= 256
                else f"{original_name[:253]}..."
            )
            self.sessions.attach_fixture(
                scope.tenant_id,
                scope.workspace_id,
                fixture_id,
                label=label,
                content_digest=content_sha256,
                metadata={
                    "project_id": scope.project_id,
                    "admission_operation_id": operation_id,
                    "original_name": original_name,
                    "byte_count": byte_count,
                    "content_type": content_type,
                    "blob_ref": blob_ref,
                    "node_hint": node_hint,
                    "upload_metadata": dict(metadata),
                },
                idempotency_key=f"admission:{operation_id}",
                deadline_ns=deadline_ns,
            )
        except SessionStoreDeadlineExceeded as error:
            raise CatalogExecutionTimeoutError(
                "fixture catalog admission exceeded its deadline"
            ) from error

    def publish_revision(
        self,
        scope: ImportScope,
        *,
        operation_id: str,
        fixture_id: str,
        source_revision_id: str,
        node_id: str,
        plugin_id: str,
        plugin_version: str,
        dataset_ref: str,
        dataset_sha256: str,
        event_count: int,
        source_record_count: int,
        resource_count: int,
        execution_plan: PluginExecutionPlan | None,
        call_context: PublisherCallContext,
    ) -> str:
        deadline_ns = self._deadline(call_context, operation_id)
        try:
            if execution_plan is not None:
                try:
                    if type(execution_plan) is not PluginExecutionPlan:
                        raise TypeError
                    execution_plan = snapshot_plugin_execution_plan(
                        execution_plan
                    )
                except (TypeError, ValueError) as error:
                    raise DatasetIntegrityError(
                        "execution plan must use the core contract type"
                    ) from error
            self._workspace(scope, deadline_ns=deadline_ns)
            fixture = self.sessions.get_fixture(
                scope.tenant_id,
                fixture_id,
                deadline_ns=deadline_ns,
            )
            if fixture.workspace_id != scope.workspace_id:
                raise ControlPlaneScopeError(
                    "fixture does not belong to the requested workspace"
                )
            if execution_plan is not None and (
                execution_plan.node_id != node_id
                or execution_plan.basis_revision_id != source_revision_id
                or len(execution_plan.plugins) != 1
                or execution_plan.plugins[0].plugin_id != plugin_id
                or execution_plan.plugins[0].plugin_version != plugin_version
            ):
                raise DatasetIntegrityError(
                    "execution plan does not match the published revision basis"
                )
            catalog_revision_id = self.catalog_revision_id(
                scope,
                fixture_id=fixture_id,
                source_revision_id=source_revision_id,
                dataset_sha256=dataset_sha256,
            )
            metadata = {
                "project_id": scope.project_id,
                "publication_operation_id": operation_id,
                "source_revision_id": source_revision_id,
                "dataset_ref": dataset_ref,
                "dataset_sha256": dataset_sha256,
                "dataset_format": _DATASET_FORMAT,
                "plugin_id": plugin_id,
                "plugin_version": plugin_version,
                "event_count": event_count,
                "source_record_count": source_record_count,
                "resource_count": resource_count,
                **(
                    {
                        "plugin_execution_plan_digest": (
                            execution_plan.plan_digest
                        )
                    }
                    if execution_plan is not None
                    else {}
                ),
            }
            self.sessions.publish_revision(
                scope.tenant_id,
                scope.workspace_id,
                fixture_id,
                catalog_revision_id,
                node_id=node_id,
                identity_digest=dataset_sha256,
                plugin_ids=(plugin_id,),
                execution_plan=execution_plan,
                metadata=metadata,
                idempotency_key=f"publication:{operation_id}",
                deadline_ns=deadline_ns,
            )
        except SessionStoreDeadlineExceeded as error:
            raise CatalogExecutionTimeoutError(
                "revision catalog publication exceeded its deadline"
            ) from error
        call_context.raise_if_expired()
        return catalog_revision_id


class ControlPlane:
    """Own one durable, single-host control-plane profile."""

    def __init__(
        self,
        root: str | Path,
        *,
        registry: PluginRegistry,
        pipeline_limits: PipelineLimits | None = None,
        retention_policy: RetentionPolicy | None = None,
        limits: ControlPlaneLimits | None = None,
    ) -> None:
        registry.require_executable_identities()
        # Validate the longest core-owned ingestion pathname before creating
        # SQLite files or directories, so an unsupported Windows state root
        # fails atomically instead of surfacing later as a worker failure.
        self.root = validate_ingestion_state_root(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or ControlPlaneLimits()
        effective_pipeline_limits = pipeline_limits or PipelineLimits(
            plugin_execution_mode=PluginExecutionMode.PROCESS,
        )
        self._lock = threading.RLock()
        self._closed = False
        self._started = False
        self._cache: OrderedDict[str, _LoadedRevision] = OrderedDict()
        self._retention_review_lock_path = self.root / ".review-catalog-retention.lock"
        self.sessions = SqliteSessionStore(self.root / "sessions.sqlite3")
        annotations: ReviewOverlayStore | None = None
        try:
            annotations = ReviewOverlayStore(self.root / "annotations.sqlite3")
            self.annotations = annotations
            self.publisher = SessionCatalogPublisher(self.sessions)
            self.ingestion = DurableIngestionPipeline(
                self.root,
                registry=registry,
                publisher=self.publisher,
                limits=effective_pipeline_limits,
                retention_policy=retention_policy,
            )
        except BaseException:
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
        self.ingestion.close(timeout=timeout)
        with self._lock:
            if self._closed:
                return
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
        """Serialize cross-store reference changes on this single host."""

        with self._lock, exclusive_file_lock(self._retention_review_lock_path):
            yield

    @staticmethod
    def _catalog_release(value: Mapping[str, Any]) -> CatalogArtifactRelease:
        required = (
            "artifact_kind",
            "artifact_ref",
            "owner_operation_id",
            "catalog_category",
            "catalog_identifier",
        )
        if any(
            not isinstance(value.get(field), str) or not value[field]
            for field in required
        ):
            raise ControlPlaneError(
                "catalog retention journal contains an invalid artifact release"
            )
        return CatalogArtifactRelease(
            artifact_kind=str(value["artifact_kind"]),
            artifact_ref=str(value["artifact_ref"]),
            owner_operation_id=str(value["owner_operation_id"]),
            catalog_category=str(value["catalog_category"]),
            catalog_identifier=str(value["catalog_identifier"]),
        )

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
        protected = tuple(
            sorted(
                {
                    *policy.protected_revision_ids,
                    *retained_review_revisions,
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
        review = self.annotations.inventory_retention(
            scope,
            selected_review_policy,
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
                if review_policy.enabled:
                    review = self.annotations.purge_retention(
                        scope,
                        review_policy,
                        actor=actor,
                        operation_id=f"{operation_id}:review",
                    )
                else:
                    review = self.annotations.inventory_retention(
                        scope,
                        review_policy,
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
    ) -> list[Mapping[str, Any]]:
        value = dataset.get(field, [])
        if not isinstance(value, list) or any(
            not isinstance(item, Mapping) for item in value
        ):
            raise DatasetIntegrityError(f"dataset {field} must be an array of objects")
        return value

    @classmethod
    def _index_dataset(
        cls,
        descriptor: AnalysisRevisionDescriptor,
        dataset: Mapping[str, Any],
    ) -> _DatasetIndex:
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
        catalog_plan_digest = descriptor.metadata.get(
            "plugin_execution_plan_digest"
        )
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
                    "dataset execution-plan digest does not match its full "
                    "catalog plan"
                )
            if execution_plan.basis_revision_id != source_revision_id:
                raise DatasetIntegrityError(
                    "execution-plan basis does not match the dataset source revision"
                )
            if len(execution_plan.plugins) != 1:
                raise DatasetIntegrityError(
                    "catalog ingestion revision must contain one execution-plan pin"
                )
            pin = execution_plan.plugins[0]
            if (
                descriptor.metadata.get("plugin_id") != pin.plugin_id
                or descriptor.metadata.get("plugin_version")
                != pin.plugin_version
            ):
                raise DatasetIntegrityError(
                    "catalog plug-in metadata does not match its full execution plan"
                )
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

        events: dict[str, Mapping[str, Any]] = {}
        for event in cls._mapping_list(dataset, "events"):
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
        for record in cls._mapping_list(dataset, "source_records"):
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
        for record in cls._mapping_list(dataset, "resources"):
            identifier = resource_id(record)
            if identifier in resources:
                raise DatasetIntegrityError(
                    f"dataset contains duplicate resource identifier {identifier!r}"
                )
            resources.add(identifier)

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
            for relationship in cls._mapping_list(dataset, field):
                relationships.add(relationship_subject_id(relationship))
        return _DatasetIndex(
            events=events,
            source_records=source_records,
            resources=frozenset(resources),
            relationships=frozenset(relationships),
            timeline_start_ns=timeline_start,
            timeline_end_ns=timeline_end,
        )

    def _load_revision(self, scope: ReviewScope, revision_id: str) -> _LoadedRevision:
        descriptor = self._revision(scope, revision_id)
        cache_key = f"{scope.tenant_id}\x1f{revision_id}"
        with self._lock:
            if self._closed:
                raise ControlPlaneError("control plane is closed")
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._cache.move_to_end(cache_key)
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
            with path.open("rb") as stream:
                serialized = stream.read(self.limits.max_dataset_bytes + 1)
        except OSError as error:
            raise DatasetIntegrityError("serialized dataset cannot be read") from error
        if len(serialized) > self.limits.max_dataset_bytes:
            raise DatasetIntegrityError(
                "serialized dataset violates the configured byte limit"
            )
        actual_digest = hashlib.sha256(serialized).hexdigest()
        if actual_digest != expected_digest:
            raise DatasetIntegrityError(
                "serialized dataset checksum does not match its publication"
            )

        def reject_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON constant {value}")

        try:
            parsed = json.loads(
                serialized.decode("utf-8"),
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise DatasetIntegrityError(
                "serialized dataset is not strict UTF-8 JSON"
            ) from error
        if not isinstance(parsed, dict):
            raise DatasetIntegrityError("serialized dataset must be a JSON object")
        index = self._index_dataset(descriptor, parsed)
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
                limit=2,
            )
            if revision.fixture_id == fixture_id
            and (
                source_revision_id is None
                or revision.metadata.get("source_revision_id") == source_revision_id
            )
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
    ) -> tuple[ReviewSubject, ...]:
        """Resolve every exact subject before a mutable write is admitted."""

        materialized = tuple(subjects)
        loaded_by_revision: dict[str, _LoadedRevision] = {}
        for subject in materialized:
            if type(subject) is not ReviewSubject:
                raise SubjectResolutionError(
                    "subjects must contain exact ReviewSubject values"
                )
            loaded = loaded_by_revision.get(subject.revision_id)
            if loaded is None:
                loaded = self._load_revision(scope, subject.revision_id)
                loaded_by_revision[subject.revision_id] = loaded
            if (
                subject.node_id is not None
                and subject.node_id != loaded.descriptor.node_id
            ):
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
        return materialized

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
            resolved = self.validate_subjects(scope, subjects)
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
                else self.validate_subjects(scope, subjects)
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
    ) -> tuple[str, ...]:
        supplied = tuple(revision_ids)
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
    def _all_annotations(
        store: ReviewOverlayStore,
        scope: ReviewScope,
    ) -> tuple[ReviewAnnotation, ...]:
        first = store.list_annotations(scope, limit=5_000)
        if len(first) < 5_000:
            return first
        second = store.list_annotations(scope, limit=5_000, offset=5_000)
        if len(second) == 5_000 and store.list_annotations(
            scope,
            limit=1,
            offset=10_000,
        ):
            raise ControlPlaneError(
                "review annotations exceed the report collection limit"
            )
        return (*first, *second)

    @staticmethod
    def _all_correlations(
        store: ReviewOverlayStore,
        scope: ReviewScope,
    ) -> tuple[ManualEventCorrelation, ...]:
        first = store.list_correlations(scope, limit=5_000)
        if len(first) < 5_000:
            return first
        second = store.list_correlations(scope, limit=5_000, offset=5_000)
        if len(second) == 5_000 and store.list_correlations(
            scope,
            limit=1,
            offset=10_000,
        ):
            raise ControlPlaneError(
                "manual correlations exceed the report collection limit"
            )
        return (*first, *second)

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
        if len(selected_ids) > self.limits.max_report_revisions:
            raise ControlPlaneError(
                "selected revisions exceed the report revision limit"
            )
        total_dataset_bytes = 0
        for revision_id in selected_ids:
            descriptor = self._revision(scope, revision_id)
            dataset_path = self._dataset_path(
                self.ingestion.dataset_root,
                descriptor.metadata.get("dataset_ref"),
            )
            try:
                total_dataset_bytes += dataset_path.stat().st_size
            except OSError as error:
                raise DatasetIntegrityError(
                    "serialized revision dataset is unavailable"
                ) from error
            if total_dataset_bytes > self.limits.max_report_dataset_bytes:
                raise ControlPlaneError(
                    "selected revision datasets exceed the report byte limit"
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


__all__ = [
    "ControlPlane",
    "ControlPlaneError",
    "ControlPlaneLimits",
    "ControlPlaneScopeError",
    "DatasetIntegrityError",
    "SessionCatalogPublisher",
    "SubjectResolutionError",
    "relationship_subject_id",
]
