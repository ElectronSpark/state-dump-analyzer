"""Durable, tenant-scoped analysis session and revision catalog.

This module deliberately sits beside, rather than replacing, the runtime-v1
``RevisionStore`` contract.  A revision store serves one already-selected
revision set.  ``SqliteSessionStore`` owns the durable catalog from which those
sets are selected:

* fixtures and published revisions are immutable;
* workspaces collect fixtures and revisions;
* sessions are mutable selections protected by an optimistic integer version;
* revision-set snapshots copy the exact selected vector and never change.

The SQLite implementation is suitable for the local/single-host profile.  Its
API keeps tenant scope explicit so a server-backed implementation can enforce
the same boundary without trusting caller-supplied metadata.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Self
from uuid import uuid4

from .canonical import canonical_json, canonical_json_sha256, strict_canonical_json
from .contract_validation import validate_bounded_json_value
from .filesystem_lock import exclusive_file_lock
from .plugin_execution_plan import (
    PluginExecutionPlan,
    RevisionExecutionPlanRef,
    plugin_execution_plan_dict,
    plugin_execution_plan_digest,
    plugin_execution_plan_from_dict,
    plugin_execution_plan_plugin_ids,
    snapshot_plugin_execution_plan,
)
from .private_analysis import (
    WORKSPACE_DISCLOSURE_POLICY_VERSION,
    WorkspaceDisclosurePolicy,
    workspace_disclosure_policy_dict,
    workspace_disclosure_policy_digest,
    workspace_disclosure_policy_from_dict,
)
from .public_text import (
    contains_unsafe_identifier_text,
    contains_unsafe_invisible_text,
    has_visible_identity_anchor,
)
from .value_core import MAX_JSON_SAFE_INTEGER

_SCHEMA_VERSION = 2
_WORKSPACE_DISCLOSURE_ROOT_SCHEMA_VERSION = (
    "router_dump_analyzer.workspace_disclosure_policy_root.v1"
)
_WORKSPACE_DISCLOSURE_RECORD_SCHEMA_VERSION = (
    "router_dump_analyzer.workspace_disclosure_policy_record.v1"
)
_WORKSPACE_DISCLOSURE_RECEIPT_SCHEMA_VERSION = (
    "router_dump_analyzer.workspace_disclosure_policy_receipt.v1"
)
_MAX_ID_CHARACTERS = 256
_MAX_LABEL_CHARACTERS = 256
_MAX_ROLE_CHARACTERS = 128
_MAX_METADATA_BYTES = 256 * 1024
_MAX_DISCLOSURE_POLICY_BYTES = 4 * 1024
_MAX_DISCLOSURE_POLICY_REVISIONS = 100_000
_DEFAULT_PAGE_LIMIT = 1_000
_MAX_PAGE_LIMIT = 5_000
_MAX_SESSION_MEMBERS = 1_024
_MAX_RETENTION_CANDIDATES = 5_000
_MAX_RETENTION_PROTECTED_IDS = 5_000
_MAX_RETENTION_RESULT_BYTES = 8 * 1024 * 1024
_MAX_RETENTION_SAGA_REQUEST_BYTES = 1024 * 1024
_RETENTION_SAGA_PHASES = frozenset({"review", "catalog", "ingestion"})
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SessionStoreError(RuntimeError):
    """Base class for durable session catalog failures."""


class SessionStoreDeadlineExceeded(SessionStoreError):
    """A deadline-aware catalog operation exhausted its time budget."""


class SessionConflictError(SessionStoreError):
    """A requested identity or mutation conflicts with durable state."""


class StaleSessionVersion(SessionConflictError):
    """A mutable session changed after the caller read it."""


class StaleWorkspaceDisclosurePolicyVersion(SessionConflictError):
    """A workspace disclosure policy changed after the caller read it."""


class IdempotencyConflict(SessionConflictError):
    """An idempotency key was reused for a different request."""


class CatalogRetentionDisabledError(SessionStoreError):
    """A destructive catalog-retention request did not explicitly opt in."""


@dataclass(frozen=True, slots=True)
class ProjectDescriptor:
    tenant_id: str
    project_id: str
    label: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at_ns: int = 0


@dataclass(frozen=True, slots=True)
class WorkspaceDescriptor:
    tenant_id: str
    project_id: str
    workspace_id: str
    label: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at_ns: int = 0


@dataclass(frozen=True, slots=True)
class WorkspaceDisclosurePolicyRecord:
    """One immutable, workspace-bound disclosure-policy revision."""

    tenant_id: str
    project_id: str
    workspace_id: str
    version: int
    policy: WorkspaceDisclosurePolicy
    policy_digest: str
    actor_id: str
    created_at_ns: int
    explicit: bool = True


@dataclass(frozen=True, slots=True)
class _WorkspaceDisclosurePolicyState:
    """Validated current record plus its exact chain-end digest."""

    current: WorkspaceDisclosurePolicyRecord | None
    record_digest: str
    history: tuple[WorkspaceDisclosurePolicyRecord, ...]


@dataclass(frozen=True, slots=True)
class _LegacyWorkspaceDisclosurePolicyReceipt:
    record: WorkspaceDisclosurePolicyRecord
    idempotency_key: str
    request_digest: str
    commitment: str
    created_at_ns: int


@dataclass(frozen=True, slots=True)
class FixtureDescriptor:
    tenant_id: str
    workspace_id: str
    fixture_id: str
    label: str
    content_digest: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at_ns: int = 0


@dataclass(frozen=True, slots=True)
class AnalysisRevisionDescriptor:
    tenant_id: str
    workspace_id: str
    fixture_id: str
    revision_id: str
    node_id: str
    identity_digest: str
    plugin_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    published_at_ns: int = 0
    execution_plan: PluginExecutionPlan | None = None

    def __post_init__(self) -> None:
        if self.execution_plan is None:
            return
        if type(self.execution_plan) is not PluginExecutionPlan:
            raise TypeError("execution_plan must be PluginExecutionPlan or None")
        execution_plan = snapshot_plugin_execution_plan(self.execution_plan)
        object.__setattr__(self, "execution_plan", execution_plan)
        if execution_plan.node_id != self.node_id:
            raise ValueError("execution_plan node_id must match revision node_id")
        if self.plugin_ids != _execution_plan_plugin_ids(execution_plan):
            raise ValueError(
                "plugin_ids must match the execution_plan plug-in ID projection"
            )

    @property
    def execution_plan_digest(self) -> str | None:
        """Return the immutable plan identity without duplicating stored state."""

        if self.execution_plan is None:
            return None
        return plugin_execution_plan_digest(self.execution_plan)

    @property
    def execution_plan_ref(self) -> RevisionExecutionPlanRef | None:
        """Bind the persisted plan identity to this published revision."""

        if self.execution_plan is None:
            return None
        return RevisionExecutionPlanRef(
            node_id=self.node_id,
            revision_id=self.revision_id,
            plan_digest=plugin_execution_plan_digest(self.execution_plan),
        )


@dataclass(frozen=True, slots=True)
class SessionMemberDescriptor:
    member_id: str
    fixture_id: str
    revision_id: str
    node_id: str
    role: str = "member"


@dataclass(frozen=True, slots=True)
class AnalysisSession:
    tenant_id: str
    workspace_id: str
    session_id: str
    label: str
    version: int
    default_member_id: str | None
    members: tuple[SessionMemberDescriptor, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at_ns: int = 0
    updated_at_ns: int = 0


@dataclass(frozen=True, slots=True)
class RevisionSetSnapshot:
    tenant_id: str
    workspace_id: str
    session_id: str
    snapshot_id: str
    session_version: int
    digest: str
    default_member_id: str | None
    members: tuple[SessionMemberDescriptor, ...]
    created_at_ns: int


def _retention_cutoff(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_INTEGER:
        raise ValueError(f"{label} must be a non-negative SQLite-sized integer or None")
    return value


def _retention_protected_ids(
    value: object,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list or tuple of identifiers")
    if len(value) > _MAX_RETENTION_PROTECTED_IDS:
        raise ValueError(
            f"{label} supports at most {_MAX_RETENTION_PROTECTED_IDS} values"
        )
    identifiers = tuple(
        _bounded_identifier(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} must not contain duplicates")
    return identifiers


@dataclass(frozen=True, slots=True)
class CatalogRetentionPolicy:
    """Explicit, conservative policy for bounded catalog maintenance.

    Catalog entities are never eligible for physical deletion until the
    caller attests that references in stores outside this catalog were
    checked and supplies every externally protected opaque identifier.
    """

    enabled: bool = False
    idempotency_before_ns: int | None = None
    snapshot_before_ns: int | None = None
    revision_before_ns: int | None = None
    fixture_before_ns: int | None = None
    external_references_checked: bool = False
    preserve_latest_snapshot_per_session: bool = True
    protected_fixture_ids: tuple[str, ...] = ()
    protected_revision_ids: tuple[str, ...] = ()
    protected_snapshot_ids: tuple[str, ...] = ()
    maximum_candidates: int = 1_000

    def __post_init__(self) -> None:
        for label, value in (
            ("enabled", self.enabled),
            ("external_references_checked", self.external_references_checked),
            (
                "preserve_latest_snapshot_per_session",
                self.preserve_latest_snapshot_per_session,
            ),
        ):
            if type(value) is not bool:
                raise ValueError(f"{label} must be a boolean")
        for field_name in (
            "idempotency_before_ns",
            "snapshot_before_ns",
            "revision_before_ns",
            "fixture_before_ns",
        ):
            object.__setattr__(
                self,
                field_name,
                _retention_cutoff(getattr(self, field_name), field_name),
            )
        for field_name in (
            "protected_fixture_ids",
            "protected_revision_ids",
            "protected_snapshot_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _retention_protected_ids(getattr(self, field_name), field_name),
            )
        if (
            type(self.maximum_candidates) is not int
            or not 1 <= self.maximum_candidates <= _MAX_RETENTION_CANDIDATES
        ):
            raise ValueError(
                f"maximum_candidates must be between 1 and {_MAX_RETENTION_CANDIDATES}"
            )

    def as_dict(self) -> dict[str, Any]:
        """Return the one canonical JSON-safe policy projection."""

        return {
            "enabled": self.enabled,
            "idempotency_before_ns": self.idempotency_before_ns,
            "snapshot_before_ns": self.snapshot_before_ns,
            "revision_before_ns": self.revision_before_ns,
            "fixture_before_ns": self.fixture_before_ns,
            "external_references_checked": self.external_references_checked,
            "preserve_latest_snapshot_per_session": (
                self.preserve_latest_snapshot_per_session
            ),
            "protected_fixture_ids": list(self.protected_fixture_ids),
            "protected_revision_ids": list(self.protected_revision_ids),
            "protected_snapshot_ids": list(self.protected_snapshot_ids),
            "maximum_candidates": self.maximum_candidates,
        }


@dataclass(frozen=True, slots=True)
class CatalogRetentionCandidate:
    category: str
    identifier: str
    retention_value: int
    qualifier: str | None = None
    blockers: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return not self.blockers


@dataclass(frozen=True, slots=True)
class CatalogRetentionInventory:
    tenant_id: str
    workspace_id: str
    policy: CatalogRetentionPolicy
    total_candidate_count: int
    candidates: tuple[CatalogRetentionCandidate, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class CatalogArtifactRelease:
    artifact_kind: str
    artifact_ref: str
    owner_operation_id: str
    catalog_category: str
    catalog_identifier: str


@dataclass(frozen=True, slots=True)
class CatalogRetentionResult:
    inventory: CatalogRetentionInventory
    purged: tuple[CatalogRetentionCandidate, ...]
    artifact_releases: tuple[CatalogArtifactRelease, ...] = ()


@dataclass(frozen=True, slots=True)
class CatalogRetentionAuditEntry:
    sequence: int
    tenant_id: str
    workspace_id: str
    operation_id: str
    actor: str
    occurred_at_ns: int
    policy: Mapping[str, Any]
    candidate_count: int
    purged_count: int
    purged: tuple[Mapping[str, Any], ...]
    artifact_releases: tuple[Mapping[str, Any], ...]
    purged_sha256: str
    artifact_releases_acknowledged_at_ns: int | None = None
    result: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RetentionSagaDescriptor:
    """Durable coordinator state for one cross-store retention operation."""

    tenant_id: str
    project_id: str
    workspace_id: str
    operation_id: str
    actor: str
    request_sha256: str
    request: Mapping[str, Any]
    effective_now_ns: int
    review_result: Mapping[str, Any] | None
    catalog_result: Mapping[str, Any] | None
    ingestion_result: Mapping[str, Any] | None
    replayed_release_actions: int
    replayed_artifact_releases: int
    created_at_ns: int
    updated_at_ns: int
    completed_at_ns: int | None = None

    @property
    def complete(self) -> bool:
        return self.completed_at_ns is not None


def _bounded_identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ID_CHARACTERS
        or value != value.strip()
        or contains_unsafe_identifier_text(value)
        or not has_visible_identity_anchor(value)
    ):
        raise ValueError(
            f"{label} must contain 1 to {_MAX_ID_CHARACTERS} "
            "visible characters without surrounding whitespace"
        )
    return value


def _bounded_label(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_LABEL_CHARACTERS
        or value != value.strip()
        or contains_unsafe_invisible_text(value)
        or not has_visible_identity_anchor(value)
    ):
        raise ValueError(
            f"{label} must contain 1 to {_MAX_LABEL_CHARACTERS} "
            "visible characters without surrounding whitespace"
        )
    return value


def _bounded_role(value: object) -> str:
    role = _bounded_identifier(value, "member role")
    if len(role) > _MAX_ROLE_CHARACTERS:
        raise ValueError(
            f"member role must contain at most {_MAX_ROLE_CHARACTERS} characters"
        )
    return role


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 hexadecimal digest")
    return value


def _metadata_json(value: Mapping[str, Any] | None, label: str) -> str:
    candidate = dict(value or {})
    validate_bounded_json_value(
        candidate,
        label,
        maximum_depth=12,
        maximum_container_items=1_024,
        maximum_units=8_192,
        maximum_atom_units=65_536,
        maximum_integer_bits=4_096,
    )
    _validate_public_metadata_text(candidate, label)
    encoded = canonical_json(candidate)
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_METADATA_BYTES} encoded UTF-8 bytes")
    return encoded


def _workspace_disclosure_policy_json(
    policy: WorkspaceDisclosurePolicy,
) -> tuple[str, str]:
    if not isinstance(policy, WorkspaceDisclosurePolicy):
        raise TypeError("policy must be WorkspaceDisclosurePolicy")
    encoded = strict_canonical_json(workspace_disclosure_policy_dict(policy))
    if len(encoded.encode("utf-8")) > _MAX_DISCLOSURE_POLICY_BYTES:
        raise ValueError("workspace disclosure policy is too large")
    return encoded, workspace_disclosure_policy_digest(policy)


def _workspace_disclosure_policy_root_digest(
    *,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
    workspace_created_at_ns: int,
) -> str:
    """Return the immutable version-zero chain anchor for one workspace."""

    if type(workspace_created_at_ns) is not int or workspace_created_at_ns < 0:
        raise SessionStoreError("stored workspace disclosure policy root is invalid")
    document = {
        "schema_version": _WORKSPACE_DISCLOSURE_ROOT_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "project_id": project_id,
        "workspace_id": workspace_id,
        "workspace_created_at_ns": str(workspace_created_at_ns),
        "default_policy_digest": WorkspaceDisclosurePolicy.disabled().digest,
    }
    return sha256(strict_canonical_json(document).encode("utf-8")).hexdigest()


def _workspace_disclosure_policy_record_digest(
    record: WorkspaceDisclosurePolicyRecord,
    *,
    previous_record_digest: str,
    receipt_commitment: str | None,
) -> str:
    """Seal every security-relevant field and the predecessor chain link."""

    previous = _digest(previous_record_digest, "previous_record_digest")
    document = {
        "schema_version": _WORKSPACE_DISCLOSURE_RECORD_SCHEMA_VERSION,
        "tenant_id": record.tenant_id,
        "project_id": record.project_id,
        "workspace_id": record.workspace_id,
        "version": str(record.version),
        "policy": workspace_disclosure_policy_dict(record.policy),
        "policy_digest": record.policy_digest,
        "actor_id": record.actor_id,
        "created_at_ns": str(record.created_at_ns),
        "previous_record_digest": previous,
        "receipt_commitment": receipt_commitment,
    }
    return sha256(strict_canonical_json(document).encode("utf-8")).hexdigest()


def _workspace_disclosure_policy_receipt_commitment(
    *,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
    idempotency_key: str,
    request_digest: str,
    result_version: int,
    created_at_ns: int,
) -> str:
    """Commit one optional exact-result receipt into its revision seal."""

    key = _bounded_identifier(idempotency_key, "idempotency_key")
    request = _digest(request_digest, "request_digest")
    if (
        type(result_version) is not int
        or not 1 <= result_version <= _MAX_DISCLOSURE_POLICY_REVISIONS
        or type(created_at_ns) is not int
        or created_at_ns < 0
    ):
        raise ValueError("receipt coordinates are invalid")
    document = {
        "schema_version": _WORKSPACE_DISCLOSURE_RECEIPT_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "project_id": project_id,
        "workspace_id": workspace_id,
        "idempotency_key": key,
        "request_digest": request,
        "result_version": str(result_version),
        "created_at_ns": str(created_at_ns),
    }
    return sha256(strict_canonical_json(document).encode("utf-8")).hexdigest()


def _stored_workspace_disclosure_policy(
    policy_json: object,
    policy_digest: object,
) -> WorkspaceDisclosurePolicy:
    if (
        not isinstance(policy_json, str)
        or len(policy_json.encode("utf-8")) > _MAX_DISCLOSURE_POLICY_BYTES
        or not isinstance(policy_digest, str)
        or _DIGEST_PATTERN.fullmatch(policy_digest) is None
    ):
        raise SessionStoreError("stored workspace disclosure policy is invalid")
    try:
        loaded = json.loads(policy_json)
        if not isinstance(loaded, dict):
            raise TypeError
        policy = workspace_disclosure_policy_from_dict(loaded)
        canonical, digest = _workspace_disclosure_policy_json(policy)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SessionStoreError(
            "stored workspace disclosure policy is invalid"
        ) from error
    if canonical != policy_json or digest != policy_digest:
        raise SessionStoreError("stored workspace disclosure policy is invalid")
    return policy


def _validate_public_metadata_text(value: Any, label: str) -> None:
    """Reject invisible controls in catalog metadata returned by public APIs."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and contains_unsafe_invisible_text(key):
                raise ValueError(f"{label} contains an unsafe invisible key")
            _validate_public_metadata_text(item, label)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_public_metadata_text(item, label)
        return
    if isinstance(value, str) and contains_unsafe_invisible_text(
        value,
        allow_prose_whitespace=True,
    ):
        raise ValueError(f"{label} contains unsafe invisible text")


def validate_catalog_identifier(value: object, label: str) -> str:
    """Validate one caller-owned catalog identifier without touching storage."""

    return _bounded_identifier(value, label)


def validate_catalog_label(value: object, label: str) -> str:
    """Validate one caller-owned project, workspace, or session label."""

    return _bounded_label(value, label)


def validate_catalog_member_role(value: object) -> str:
    """Validate one caller-owned session-member role."""

    return _bounded_role(value)


def validate_catalog_metadata(
    value: Mapping[str, Any] | None,
    label: str,
) -> dict[str, Any]:
    """Return a detached, bounded catalog metadata object.

    HTTP and other adapters can use this exact validator before entering a
    store transaction.  Keeping it beside the store's own validation avoids
    a second, gradually diverging metadata contract at every adapter.
    """

    if value is not None and not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping or None")
    decoded = json.loads(_metadata_json(value, label))
    assert isinstance(decoded, dict)
    return decoded


def _bounded_retention_json(
    value: Mapping[str, Any],
    label: str,
    *,
    maximum_bytes: int,
) -> str:
    candidate = dict(value)
    validate_bounded_json_value(
        candidate,
        label,
        maximum_depth=16,
        maximum_container_items=50_000,
        maximum_units=500_000,
        maximum_atom_units=1_048_576,
        maximum_integer_bits=64,
    )
    encoded = canonical_json(candidate)
    if len(encoded.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} encoded UTF-8 bytes")
    return encoded


def _stored_bounded_retention_mapping(
    value: object,
    label: str,
    *,
    maximum_bytes: int,
) -> dict[str, Any]:
    """Load one canonical, bounded retention journal object fail-closed."""

    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum_bytes:
        raise SessionStoreError(f"stored {label} is invalid")
    try:
        loaded = json.loads(value)
        if not isinstance(loaded, dict):
            raise TypeError
        canonical = _bounded_retention_json(
            loaded,
            label,
            maximum_bytes=maximum_bytes,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SessionStoreError(f"stored {label} is invalid") from error
    if canonical != value:
        raise SessionStoreError(f"stored {label} is not canonical")
    return loaded


def _stored_catalog_retention_audit_sequence(value: object) -> int:
    """Validate one persisted/public catalog-audit coordinate fail-closed."""

    if type(value) is not int or not 0 <= value <= MAX_JSON_SAFE_INTEGER:
        raise SessionStoreError(
            "stored catalog retention audit sequence is outside the safe domain"
        )
    return value


def _plugin_ids(value: Sequence[str]) -> tuple[str, ...]:
    if len(value) > 128:
        raise ValueError("plugin_ids supports at most 128 identifiers")
    result = tuple(
        _bounded_identifier(item, f"plugin_ids[{index}]")
        for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise ValueError("plugin_ids must not contain duplicates")
    return result


def _execution_plan_plugin_ids(plan: PluginExecutionPlan) -> tuple[str, ...]:
    """Return ordered distinct producer identities represented by a plan."""

    return plugin_execution_plan_plugin_ids(plan)


def _stored_execution_plan(
    plan_json: object,
    plan_digest: object,
    plan_present: object,
    *,
    node_id: object,
) -> PluginExecutionPlan | None:
    """Load one canonical plan and independently verify its stored digest."""

    if type(plan_present) is not int or plan_present not in (0, 1):
        raise SessionStoreError("stored revision execution plan presence is invalid")
    if plan_present == 0:
        if plan_json is not None or plan_digest is not None:
            raise SessionStoreError("stored revision execution plan is invalid")
        return None
    if not isinstance(plan_json, str) or not isinstance(plan_digest, str):
        raise SessionStoreError("stored revision execution plan is invalid")
    try:
        document = json.loads(plan_json)
        plan = plugin_execution_plan_from_dict(document)
        canonical = canonical_json(plugin_execution_plan_dict(plan))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SessionStoreError("stored revision execution plan is invalid") from error
    if canonical != plan_json or plan.plan_digest != plan_digest:
        raise SessionStoreError("stored revision execution plan digest is invalid")
    if plan.node_id != node_id:
        raise SessionStoreError("stored revision execution plan node is invalid")
    return plan


def _json_mapping(value: str) -> dict[str, Any]:
    loaded = json.loads(value)
    if not isinstance(loaded, dict):
        raise SessionStoreError("stored metadata is not a JSON object")
    return loaded


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _page_bounds(limit: object, offset: object) -> tuple[int, int]:
    if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_PAGE_LIMIT}")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    return limit, offset


def _catalog_candidate_document(
    candidate: CatalogRetentionCandidate,
) -> dict[str, Any]:
    return {
        "category": candidate.category,
        "identifier": candidate.identifier,
        "retention_value": candidate.retention_value,
        "qualifier": candidate.qualifier,
        "blockers": list(candidate.blockers),
    }


def _catalog_result_document(
    result: CatalogRetentionResult,
) -> dict[str, Any]:
    return {
        "inventory": {
            "total_candidate_count": result.inventory.total_candidate_count,
            "candidates": [
                _catalog_candidate_document(candidate)
                for candidate in result.inventory.candidates
            ],
            "truncated": result.inventory.truncated,
        },
        "purged": [
            _catalog_candidate_document(candidate) for candidate in result.purged
        ],
        "artifact_releases": [asdict(release) for release in result.artifact_releases],
    }


def _catalog_candidate_from_document(
    value: object,
) -> CatalogRetentionCandidate:
    if not isinstance(value, dict) or set(value) != {
        "category",
        "identifier",
        "retention_value",
        "qualifier",
        "blockers",
    }:
        raise SessionStoreError("stored catalog retention result is invalid")
    try:
        category = _bounded_identifier(value["category"], "retention category")
        identifier = _bounded_identifier(value["identifier"], "retention identifier")
        qualifier_value = value["qualifier"]
        qualifier = (
            None
            if qualifier_value is None
            else _bounded_identifier(qualifier_value, "retention qualifier")
        )
        retention_value = value["retention_value"]
        blockers_value = value["blockers"]
        if (
            type(retention_value) is not int
            or not 0 <= retention_value <= _MAX_SQLITE_INTEGER
            or not isinstance(blockers_value, list)
            or len(blockers_value) > 16
        ):
            raise ValueError
        blockers = tuple(
            _bounded_identifier(item, "retention blocker") for item in blockers_value
        )
    except ValueError as error:
        raise SessionStoreError("stored catalog retention result is invalid") from error
    return CatalogRetentionCandidate(
        category=category,
        identifier=identifier,
        retention_value=retention_value,
        qualifier=qualifier,
        blockers=blockers,
    )


def _catalog_result_from_document(
    value: Mapping[str, Any],
    *,
    tenant_id: str,
    workspace_id: str,
    policy: CatalogRetentionPolicy,
) -> CatalogRetentionResult:
    if set(value) != {"inventory", "purged", "artifact_releases"}:
        raise SessionStoreError("stored catalog retention result is invalid")
    inventory_value = value["inventory"]
    purged_value = value["purged"]
    releases_value = value["artifact_releases"]
    if (
        not isinstance(inventory_value, dict)
        or set(inventory_value) != {"total_candidate_count", "candidates", "truncated"}
        or not isinstance(inventory_value["candidates"], list)
        or not isinstance(purged_value, list)
        or not isinstance(releases_value, list)
        or len(inventory_value["candidates"]) > _MAX_RETENTION_CANDIDATES
        or len(purged_value) > _MAX_RETENTION_CANDIDATES
        or len(releases_value) > _MAX_RETENTION_CANDIDATES
    ):
        raise SessionStoreError("stored catalog retention result is invalid")
    total = inventory_value["total_candidate_count"]
    truncated = inventory_value["truncated"]
    if type(total) is not int or total < 0 or type(truncated) is not bool:
        raise SessionStoreError("stored catalog retention result is invalid")
    candidates = tuple(
        _catalog_candidate_from_document(item) for item in inventory_value["candidates"]
    )
    purged = tuple(_catalog_candidate_from_document(item) for item in purged_value)
    if total < len(candidates) or any(
        candidate not in candidates or not candidate.eligible for candidate in purged
    ):
        raise SessionStoreError("stored catalog retention result is invalid")
    releases: list[CatalogArtifactRelease] = []
    release_fields = {
        "artifact_kind",
        "artifact_ref",
        "owner_operation_id",
        "catalog_category",
        "catalog_identifier",
    }
    for item in releases_value:
        if not isinstance(item, dict) or set(item) != release_fields:
            raise SessionStoreError("stored catalog retention result is invalid")
        if any(
            not isinstance(item[field], str) or not item[field]
            for field in release_fields
        ):
            raise SessionStoreError("stored catalog retention result is invalid")
        releases.append(CatalogArtifactRelease(**item))
    return CatalogRetentionResult(
        inventory=CatalogRetentionInventory(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy=policy,
            total_candidate_count=total,
            candidates=candidates,
            truncated=truncated,
        ),
        purged=purged,
        artifact_releases=tuple(releases),
    )


class SqliteSessionStore:
    """Thread-safe durable catalog for one local server profile."""

    def __init__(self, database_path: str | Path) -> None:
        raw_path = str(database_path)
        database_uri = False
        schema_lock_path: Path | None = None
        if raw_path != ":memory:":
            path = Path(database_path).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            raw_path = str(path)
            schema_lock_path = path.with_name(f".{path.name}.schema.lock")
        else:
            # A named shared-memory database preserves ordinary ``:memory:``
            # semantics while allowing a poisoned connection to be replaced
            # without discarding the catalog.  The replacement is opened
            # before the old connection is closed.
            raw_path = (
                "file:router-dump-analyzer-session-"
                f"{uuid4().hex}?mode=memory&cache=shared"
            )
            database_uri = True
        self._lock = threading.RLock()
        self._closed = False
        self._database_path = raw_path
        self._database_uri = database_uri
        self._connection = self._open_connection()
        if schema_lock_path is None:
            with self._lock:
                self._initialize_schema()
        else:
            # ``CREATE ... IF NOT EXISTS`` is safe across processes, but the
            # additive ``PRAGMA table_info``/``ALTER TABLE`` migrations are
            # a read-then-write sequence.  Serialize the whole bootstrap so
            # two workers opening one older catalog cannot both add a column.
            with exclusive_file_lock(schema_lock_path), self._lock:
                self._initialize_schema()

    def _process_reopen_path(self) -> str:
        """Return the durable path used by a disposable catalog worker."""

        with self._lock:
            if self._closed:
                raise RuntimeError("session store is closed")
            if self._database_uri:
                raise TypeError(
                    "an in-memory session store cannot cross a process boundary"
                )
            return self._database_path

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            isolation_level=None,
            check_same_thread=False,
            timeout=30.0,
            uri=self._database_uri,
        )
        try:
            self._configure_connection(connection)
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA journal_mode = WAL")

    def _initialize_schema(self) -> None:
        current_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if current_version not in {0, 1, _SCHEMA_VERSION}:
            raise SessionStoreError(
                f"unsupported session-store schema version {current_version}"
            )
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                created_at_ns INTEGER NOT NULL
            ) STRICT;

            CREATE TABLE IF NOT EXISTS projects (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                label TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, project_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workspaces (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                label TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                disclosure_policy_root_digest TEXT NOT NULL,
                disclosure_policy_tip_version INTEGER NOT NULL
                    CHECK (disclosure_policy_tip_version >= 0),
                disclosure_policy_tip_record_digest TEXT NOT NULL,
                PRIMARY KEY (tenant_id, workspace_id),
                FOREIGN KEY (tenant_id, project_id)
                    REFERENCES projects(tenant_id, project_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workspace_disclosure_policies (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                policy_json TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                PRIMARY KEY (tenant_id, workspace_id, version),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workspace_disclosure_policy_heads (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                current_version INTEGER NOT NULL CHECK (current_version > 0),
                current_policy_digest TEXT NOT NULL,
                updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
                PRIMARY KEY (tenant_id, workspace_id),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workspace_disclosure_policy_seals (
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version > 0),
                previous_record_digest TEXT NOT NULL,
                record_digest TEXT NOT NULL,
                receipt_commitment TEXT,
                PRIMARY KEY (tenant_id, workspace_id, version),
                FOREIGN KEY (tenant_id, workspace_id, version)
                    REFERENCES workspace_disclosure_policies(
                        tenant_id, workspace_id, version
                    ) ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workspace_disclosure_policy_receipts (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                result_version INTEGER NOT NULL CHECK (result_version > 0),
                result_record_digest TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                PRIMARY KEY (tenant_id, idempotency_key),
                UNIQUE (tenant_id, workspace_id, result_version),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (tenant_id, workspace_id, result_version)
                    REFERENCES workspace_disclosure_policies(
                        tenant_id, workspace_id, version
                    ) ON DELETE CASCADE
            ) STRICT;

            CREATE INDEX IF NOT EXISTS
                workspace_disclosure_policies_current_idx
            ON workspace_disclosure_policies(
                tenant_id, workspace_id, version DESC
            );

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_immutable
            BEFORE UPDATE ON workspace_disclosure_policies
            BEGIN
                SELECT RAISE(ABORT, 'workspace disclosure policy is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_no_direct_delete
            BEFORE DELETE ON workspace_disclosure_policies
            WHEN EXISTS (
                SELECT 1 FROM workspaces
                WHERE tenant_id = OLD.tenant_id
                  AND workspace_id = OLD.workspace_id
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy history is immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_head_no_direct_delete
            BEFORE DELETE ON workspace_disclosure_policy_heads
            WHEN EXISTS (
                SELECT 1 FROM workspaces
                WHERE tenant_id = OLD.tenant_id
                  AND workspace_id = OLD.workspace_id
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy head is immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_seal_immutable
            BEFORE UPDATE ON workspace_disclosure_policy_seals
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy seal is immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_seal_no_direct_delete
            BEFORE DELETE ON workspace_disclosure_policy_seals
            WHEN EXISTS (
                SELECT 1 FROM workspaces
                WHERE tenant_id = OLD.tenant_id
                  AND workspace_id = OLD.workspace_id
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy seals are immutable'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_receipt_immutable
            BEFORE UPDATE ON workspace_disclosure_policy_receipts
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy receipt is immutable'
                );
            END;

            CREATE TABLE IF NOT EXISTS fixtures (
                tenant_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                label TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, fixture_id),
                UNIQUE (tenant_id, fixture_id, workspace_id),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS analysis_revisions (
                tenant_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                plugin_ids_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                published_at_ns INTEGER NOT NULL,
                execution_plan_json TEXT,
                execution_plan_digest TEXT,
                execution_plan_present INTEGER NOT NULL DEFAULT 0
                    CHECK (execution_plan_present IN (0, 1)),
                PRIMARY KEY (tenant_id, revision_id),
                UNIQUE (tenant_id, revision_id, workspace_id),
                FOREIGN KEY (tenant_id, fixture_id, workspace_id)
                    REFERENCES fixtures(tenant_id, fixture_id, workspace_id)
                    ON DELETE RESTRICT
            ) STRICT;

            CREATE TABLE IF NOT EXISTS analysis_sessions (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                label TEXT NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 0),
                default_member_id TEXT,
                metadata_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                updated_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, session_id),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS session_members (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (tenant_id, session_id, member_id),
                FOREIGN KEY (tenant_id, session_id)
                    REFERENCES analysis_sessions(tenant_id, session_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (tenant_id, revision_id)
                    REFERENCES analysis_revisions(tenant_id, revision_id)
                    ON DELETE RESTRICT
            ) STRICT;

            CREATE TABLE IF NOT EXISTS revision_set_snapshots (
                tenant_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                session_version INTEGER NOT NULL,
                digest TEXT NOT NULL,
                default_member_id TEXT,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, snapshot_id),
                UNIQUE (tenant_id, session_id, session_version, digest),
                FOREIGN KEY (tenant_id, session_id)
                    REFERENCES analysis_sessions(tenant_id, session_id)
                    ON DELETE RESTRICT
            ) STRICT;

            CREATE TABLE IF NOT EXISTS revision_set_members (
                tenant_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (tenant_id, snapshot_id, member_id),
                FOREIGN KEY (tenant_id, snapshot_id)
                    REFERENCES revision_set_snapshots(tenant_id, snapshot_id)
                    ON DELETE RESTRICT,
                FOREIGN KEY (tenant_id, revision_id)
                    REFERENCES analysis_revisions(tenant_id, revision_id)
                    ON DELETE RESTRICT
            ) STRICT;

            CREATE TABLE IF NOT EXISTS idempotency_keys (
                tenant_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, operation, idempotency_key),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS catalog_retention_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at_ns INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
                purged_count INTEGER NOT NULL CHECK (purged_count >= 0),
                purged_json TEXT NOT NULL,
                artifact_releases_json TEXT NOT NULL,
                purged_sha256 TEXT NOT NULL,
                artifact_releases_acknowledged_at_ns INTEGER,
                result_json TEXT,
                UNIQUE (tenant_id, workspace_id, operation_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                    ON DELETE CASCADE
            ) STRICT;

            CREATE TABLE IF NOT EXISTS control_plane_retention_saga (
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                request_json TEXT NOT NULL,
                effective_now_ns INTEGER NOT NULL
                    CHECK (effective_now_ns >= 0),
                review_result_json TEXT,
                catalog_result_json TEXT,
                ingestion_result_json TEXT,
                replayed_release_actions INTEGER NOT NULL DEFAULT 0
                    CHECK (replayed_release_actions >= 0),
                replayed_artifact_releases INTEGER NOT NULL DEFAULT 0
                    CHECK (replayed_artifact_releases >= 0),
                created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
                updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
                completed_at_ns INTEGER,
                PRIMARY KEY (tenant_id, workspace_id, operation_id),
                FOREIGN KEY (tenant_id, workspace_id)
                    REFERENCES workspaces(tenant_id, workspace_id)
                    ON DELETE RESTRICT
            ) STRICT;

            CREATE INDEX IF NOT EXISTS workspace_project_index
                ON workspaces(tenant_id, project_id, workspace_id);
            CREATE INDEX IF NOT EXISTS fixture_workspace_index
                ON fixtures(tenant_id, workspace_id, fixture_id);
            CREATE INDEX IF NOT EXISTS revision_workspace_index
                ON analysis_revisions(
                    tenant_id, workspace_id, node_id, revision_id
                );
            CREATE INDEX IF NOT EXISTS session_workspace_index
                ON analysis_sessions(tenant_id, workspace_id, session_id);
            CREATE INDEX IF NOT EXISTS catalog_retention_audit_tenant_sequence
                ON catalog_retention_audit(
                    tenant_id, workspace_id, sequence
                );
            CREATE INDEX IF NOT EXISTS retention_saga_scope_updated
                ON control_plane_retention_saga(
                    tenant_id, workspace_id, updated_at_ns, operation_id
                );
            """
        )
        retention_audit_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(catalog_retention_audit)"
            ).fetchall()
        }
        if "artifact_releases_acknowledged_at_ns" not in retention_audit_columns:
            self._connection.execute(
                "ALTER TABLE catalog_retention_audit ADD COLUMN "
                "artifact_releases_acknowledged_at_ns INTEGER"
            )
        if "result_json" not in retention_audit_columns:
            self._connection.execute(
                "ALTER TABLE catalog_retention_audit ADD COLUMN result_json TEXT"
            )
        revision_columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(analysis_revisions)"
            ).fetchall()
        }
        if "execution_plan_json" not in revision_columns:
            self._connection.execute(
                "ALTER TABLE analysis_revisions ADD COLUMN execution_plan_json TEXT"
            )
        if "execution_plan_digest" not in revision_columns:
            self._connection.execute(
                "ALTER TABLE analysis_revisions ADD COLUMN execution_plan_digest TEXT"
            )
        if "execution_plan_present" not in revision_columns:
            self._connection.execute(
                "ALTER TABLE analysis_revisions ADD COLUMN "
                "execution_plan_present INTEGER NOT NULL DEFAULT 0 "
                "CHECK (execution_plan_present IN (0, 1))"
            )
        self._connection.execute(
            """
            UPDATE analysis_revisions
            SET execution_plan_present = 1
            WHERE execution_plan_present IS NOT 1
              AND (
                  execution_plan_json IS NOT NULL
                  OR execution_plan_digest IS NOT NULL
              )
            """
        )
        self._connection.executescript(
            """
            DROP TRIGGER IF EXISTS
                analysis_revision_execution_plan_no_downgrade;
            CREATE TRIGGER IF NOT EXISTS
                analysis_revision_execution_plan_insert_valid
            BEFORE INSERT ON analysis_revisions
            WHEN (
                NEW.execution_plan_present = 1
                AND (
                    NEW.execution_plan_json IS NULL
                    OR NEW.execution_plan_json = ''
                    OR NEW.execution_plan_digest IS NULL
                    OR NEW.execution_plan_digest = ''
                )
            ) OR (
                NEW.execution_plan_present = 0
                AND (
                    NEW.execution_plan_json IS NOT NULL
                    OR NEW.execution_plan_digest IS NOT NULL
                )
            )
            BEGIN
                SELECT RAISE(ABORT, 'revision execution-plan contract is invalid');
            END;

            CREATE TRIGGER IF NOT EXISTS
                analysis_revision_execution_plan_immutable
            BEFORE UPDATE OF
                execution_plan_present,
                execution_plan_json,
                execution_plan_digest
            ON analysis_revisions
            WHEN NEW.execution_plan_present IS NOT OLD.execution_plan_present
                 OR NEW.execution_plan_json IS NOT OLD.execution_plan_json
                 OR NEW.execution_plan_digest IS NOT OLD.execution_plan_digest
            BEGIN
                SELECT RAISE(ABORT, 'revision execution plan is immutable');
            END;
            """
        )
        if current_version < _SCHEMA_VERSION:
            self._migrate_workspace_disclosure_policy_integrity()
        self._install_workspace_disclosure_policy_integrity_triggers()

    def _migrate_workspace_disclosure_policy_integrity(self) -> None:
        """Anchor legacy policy rows and replace blob receipts atomically."""

        connection = self._connection
        cursor = connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "DROP TRIGGER IF EXISTS workspace_disclosure_policy_tip_guard"
            )
            columns = {
                row["name"]
                for row in cursor.execute("PRAGMA table_info(workspaces)")
            }
            if "disclosure_policy_root_digest" not in columns:
                cursor.execute(
                    "ALTER TABLE workspaces ADD COLUMN "
                    "disclosure_policy_root_digest TEXT"
                )
            if "disclosure_policy_tip_version" not in columns:
                cursor.execute(
                    "ALTER TABLE workspaces ADD COLUMN "
                    "disclosure_policy_tip_version INTEGER NOT NULL DEFAULT 0"
                )
            if "disclosure_policy_tip_record_digest" not in columns:
                cursor.execute(
                    "ALTER TABLE workspaces ADD COLUMN "
                    "disclosure_policy_tip_record_digest TEXT"
                )

            legacy_receipts: dict[
                tuple[str, str, int],
                _LegacyWorkspaceDisclosurePolicyReceipt,
            ] = {}
            legacy_receipt_rows = cursor.execute(
                """
                SELECT tenant_id, idempotency_key, request_digest,
                       response_json, created_at_ns
                FROM idempotency_keys
                WHERE operation = 'set_workspace_disclosure_policy'
                ORDER BY tenant_id, idempotency_key
                """
            ).fetchall()
            for receipt_row in legacy_receipt_rows:
                try:
                    payload = json.loads(receipt_row["response_json"])
                    if not isinstance(payload, Mapping):
                        raise TypeError
                    record = self._workspace_disclosure_policy_from_payload(payload)
                    tenant_id = _bounded_identifier(
                        receipt_row["tenant_id"], "tenant_id"
                    )
                    if tenant_id != record.tenant_id:
                        raise ValueError
                    idempotency_key = _bounded_identifier(
                        receipt_row["idempotency_key"], "idempotency_key"
                    )
                    stored_request_digest = _digest(
                        receipt_row["request_digest"], "request_digest"
                    )
                    legacy_request = {
                        "workspace_id": record.workspace_id,
                        "policy": workspace_disclosure_policy_dict(record.policy),
                        "actor_id": record.actor_id,
                        "expected_version": record.version - 1,
                    }
                    if stored_request_digest != canonical_json_sha256(
                        legacy_request
                    ):
                        raise ValueError
                    request_digest = canonical_json_sha256(
                        {
                            "tenant_id": record.tenant_id,
                            "project_id": record.project_id,
                            **legacy_request,
                        }
                    )
                    created_at_ns = receipt_row["created_at_ns"]
                    if type(created_at_ns) is not int or created_at_ns < 0:
                        raise TypeError
                    commitment = (
                        _workspace_disclosure_policy_receipt_commitment(
                            tenant_id=record.tenant_id,
                            project_id=record.project_id,
                            workspace_id=record.workspace_id,
                            idempotency_key=idempotency_key,
                            request_digest=request_digest,
                            result_version=record.version,
                            created_at_ns=created_at_ns,
                        )
                    )
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as error:
                    raise SessionStoreError(
                        "stored workspace disclosure policy receipt is invalid"
                    ) from error
                record_key = (
                    record.tenant_id,
                    record.workspace_id,
                    record.version,
                )
                if record_key in legacy_receipts:
                    raise SessionStoreError(
                        "stored workspace disclosure policy receipt is invalid"
                    )
                workspace_exists = cursor.execute(
                    """
                    SELECT 1 FROM workspaces
                    WHERE tenant_id = ? AND workspace_id = ?
                    """,
                    (record.tenant_id, record.workspace_id),
                ).fetchone()
                if workspace_exists is None:
                    cursor.execute(
                        """
                        DELETE FROM idempotency_keys
                        WHERE tenant_id = ?
                          AND operation = 'set_workspace_disclosure_policy'
                          AND idempotency_key = ?
                        """,
                        (record.tenant_id, idempotency_key),
                    )
                    continue
                legacy_receipts[record_key] = (
                    _LegacyWorkspaceDisclosurePolicyReceipt(
                        record=record,
                        idempotency_key=idempotency_key,
                        request_digest=request_digest,
                        commitment=commitment,
                        created_at_ns=created_at_ns,
                    )
                )
            workspaces = cursor.execute(
                """
                SELECT tenant_id, project_id, workspace_id, created_at_ns
                FROM workspaces
                ORDER BY tenant_id, workspace_id
                """
            ).fetchall()
            for workspace_row in workspaces:
                tenant_id = _bounded_identifier(
                    workspace_row["tenant_id"], "tenant_id"
                )
                project_id = _bounded_identifier(
                    workspace_row["project_id"], "project_id"
                )
                workspace_id = _bounded_identifier(
                    workspace_row["workspace_id"], "workspace_id"
                )
                workspace_created_at_ns = workspace_row["created_at_ns"]
                root_digest = _workspace_disclosure_policy_root_digest(
                    tenant_id=tenant_id,
                    project_id=project_id,
                    workspace_id=workspace_id,
                    workspace_created_at_ns=workspace_created_at_ns,
                )
                previous_digest = root_digest
                current_record: WorkspaceDisclosurePolicyRecord | None = None
                current_record_digest = root_digest
                history_rows = cursor.execute(
                    """
                    SELECT policy.*, workspaces.project_id
                    FROM workspace_disclosure_policies AS policy
                    JOIN workspaces
                      ON workspaces.tenant_id = policy.tenant_id
                     AND workspaces.workspace_id = policy.workspace_id
                    WHERE policy.tenant_id = ? AND policy.workspace_id = ?
                    ORDER BY policy.version
                    """,
                    (tenant_id, workspace_id),
                ).fetchall()
                for expected_version, history_row in enumerate(
                    history_rows,
                    start=1,
                ):
                    if expected_version > _MAX_DISCLOSURE_POLICY_REVISIONS:
                        raise SessionStoreError(
                            "stored workspace disclosure policy history is invalid"
                        )
                    record = self._workspace_disclosure_policy_row(history_row)
                    if (
                        record.tenant_id != tenant_id
                        or record.project_id != project_id
                        or record.workspace_id != workspace_id
                        or record.version != expected_version
                    ):
                        raise SessionStoreError(
                            "stored workspace disclosure policy history is invalid"
                        )
                    receipt = legacy_receipts.pop(
                        (tenant_id, workspace_id, expected_version),
                        None,
                    )
                    if receipt is not None and receipt.record != record:
                        raise SessionStoreError(
                            "stored workspace disclosure policy receipt is invalid"
                        )
                    receipt_commitment = (
                        None if receipt is None else receipt.commitment
                    )
                    record_digest = _workspace_disclosure_policy_record_digest(
                        record,
                        previous_record_digest=previous_digest,
                        receipt_commitment=receipt_commitment,
                    )
                    existing_seal = cursor.execute(
                        """
                        SELECT previous_record_digest, record_digest,
                               receipt_commitment
                        FROM workspace_disclosure_policy_seals
                        WHERE tenant_id = ? AND workspace_id = ? AND version = ?
                        """,
                        (tenant_id, workspace_id, expected_version),
                    ).fetchone()
                    if existing_seal is None:
                        cursor.execute(
                            """
                            INSERT INTO workspace_disclosure_policy_seals(
                                tenant_id, workspace_id, version,
                                previous_record_digest, record_digest,
                                receipt_commitment
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                tenant_id,
                                workspace_id,
                                expected_version,
                                previous_digest,
                                record_digest,
                                receipt_commitment,
                            ),
                        )
                    elif (
                        existing_seal["previous_record_digest"] != previous_digest
                        or existing_seal["record_digest"] != record_digest
                        or existing_seal["receipt_commitment"]
                        != receipt_commitment
                    ):
                        raise SessionStoreError(
                            "stored workspace disclosure policy seal is invalid"
                        )
                    if receipt is not None:
                        cursor.execute(
                            """
                            INSERT INTO workspace_disclosure_policy_receipts(
                                tenant_id, project_id, workspace_id,
                                idempotency_key, request_digest,
                                result_version, result_record_digest,
                                created_at_ns
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                record.tenant_id,
                                record.project_id,
                                record.workspace_id,
                                receipt.idempotency_key,
                                receipt.request_digest,
                                record.version,
                                record_digest,
                                receipt.created_at_ns,
                            ),
                        )
                        cursor.execute(
                            """
                            DELETE FROM idempotency_keys
                            WHERE tenant_id = ?
                              AND operation =
                                  'set_workspace_disclosure_policy'
                              AND idempotency_key = ?
                            """,
                            (record.tenant_id, receipt.idempotency_key),
                        )
                    previous_digest = record_digest
                    current_record_digest = record_digest
                    current_record = record

                head = cursor.execute(
                    """
                    SELECT * FROM workspace_disclosure_policy_heads
                    WHERE tenant_id = ? AND workspace_id = ?
                    """,
                    (tenant_id, workspace_id),
                ).fetchone()
                if current_record is None:
                    if head is not None:
                        raise SessionStoreError(
                            "stored workspace disclosure policy history is invalid"
                        )
                    tip_version = 0
                else:
                    if (
                        head is None
                        or head["current_version"] != current_record.version
                        or head["current_policy_digest"]
                        != current_record.policy_digest
                        or head["updated_at_ns"] != current_record.created_at_ns
                    ):
                        raise SessionStoreError(
                            "stored workspace disclosure policy head is invalid"
                        )
                    tip_version = current_record.version
                cursor.execute(
                    """
                    UPDATE workspaces
                    SET disclosure_policy_root_digest = ?,
                        disclosure_policy_tip_version = ?,
                        disclosure_policy_tip_record_digest = ?
                    WHERE tenant_id = ? AND workspace_id = ?
                    """,
                    (
                        root_digest,
                        tip_version,
                        current_record_digest,
                        tenant_id,
                        workspace_id,
                    ),
                )

            if legacy_receipts:
                raise SessionStoreError(
                    "stored workspace disclosure policy receipt is invalid"
                )
            if cursor.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise SessionStoreError(
                    "session-store schema migration violates foreign-key integrity"
                )
            cursor.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            cursor.close()

    def _install_workspace_disclosure_policy_integrity_triggers(self) -> None:
        self._connection.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_tip_guard
            BEFORE UPDATE OF
                disclosure_policy_root_digest,
                disclosure_policy_tip_version,
                disclosure_policy_tip_record_digest
            ON workspaces
            WHEN NEW.disclosure_policy_root_digest
                    IS NOT OLD.disclosure_policy_root_digest
                 OR NEW.disclosure_policy_tip_version
                    != OLD.disclosure_policy_tip_version + 1
                 OR NOT EXISTS (
                    SELECT 1
                    FROM workspace_disclosure_policy_seals AS seal
                    WHERE seal.tenant_id = NEW.tenant_id
                      AND seal.workspace_id = NEW.workspace_id
                      AND seal.version = NEW.disclosure_policy_tip_version
                      AND seal.previous_record_digest =
                          OLD.disclosure_policy_tip_record_digest
                      AND seal.record_digest =
                          NEW.disclosure_policy_tip_record_digest
                 )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy tip transition is invalid'
                );
            END;

            CREATE TRIGGER IF NOT EXISTS
                workspace_disclosure_policy_receipt_no_direct_delete
            BEFORE DELETE ON workspace_disclosure_policy_receipts
            WHEN EXISTS (
                SELECT 1 FROM workspaces
                WHERE tenant_id = OLD.tenant_id
                  AND workspace_id = OLD.workspace_id
            )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'workspace disclosure policy receipt is immutable'
                );
            END;
            """
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("session store is closed")

    def _recover_transaction_connection(
        self,
        connection: sqlite3.Connection,
    ) -> bool:
        """Roll back a failed transaction, replacing a poisoned connection.

        ``sqlite3.Connection.commit`` can fail after SQLite has opened a
        transaction.  Merely propagating that error leaves the shared
        connection wedged for every later caller.  Prefer rollback so an
        in-memory catalog retains the same connection; if rollback does not
        clear the transaction, open a replacement before retiring the old
        connection.  The return value tells the caller that closing its old
        cursor is no longer necessary.
        """

        rollback_completed = False
        try:
            connection.rollback()
        except sqlite3.Error:
            # Whether recovery is needed is determined by the connection's
            # state below.  A wrapper/proxy may report a rollback error even
            # though SQLite already ended the transaction.
            rollback_completed = False
        else:
            rollback_completed = True
        transaction_cleared = False
        if rollback_completed:
            try:
                transaction_cleared = not connection.in_transaction
            except sqlite3.Error:
                transaction_cleared = False
        if transaction_cleared:
            return False

        # Open the handle before retiring ``connection`` so a named
        # in-memory database remains alive.  Configure it only after closing
        # the poisoned writer, which may still hold SQLite's write lock.
        replacement = sqlite3.connect(
            self._database_path,
            isolation_level=None,
            check_same_thread=False,
            timeout=30.0,
            uri=self._database_uri,
        )
        with suppress(sqlite3.Error):
            connection.close()
            # The replacement is live; failure to close a poisoned handle
            # must not put it back into service or mask the original error.
        try:
            self._configure_connection(replacement)
        except BaseException:
            replacement.close()
            raise
        self._connection = replacement
        return True

    @staticmethod
    def _remaining_deadline_ns(deadline_ns: int | None) -> int | None:
        if deadline_ns is None:
            return None
        if type(deadline_ns) is not int or deadline_ns < 0:
            raise ValueError("deadline_ns must be a non-negative integer or None")
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            raise SessionStoreDeadlineExceeded(
                "session-store operation exceeded its deadline"
            )
        return remaining

    @contextmanager
    def _deadline_lock(self, deadline_ns: int | None) -> Iterator[None]:
        remaining_ns = self._remaining_deadline_ns(deadline_ns)
        if remaining_ns is None:
            acquired = self._lock.acquire()
        else:
            acquired = self._lock.acquire(timeout=remaining_ns / 1_000_000_000)
        if not acquired:
            raise SessionStoreDeadlineExceeded(
                "session-store lock acquisition exceeded its deadline"
            )
        try:
            self._remaining_deadline_ns(deadline_ns)
            yield
        finally:
            self._lock.release()

    def _apply_deadline_busy_timeout(
        self,
        connection: sqlite3.Connection,
        deadline_ns: int | None,
    ) -> None:
        remaining_ns = self._remaining_deadline_ns(deadline_ns)
        if remaining_ns is None:
            milliseconds = 30_000
        else:
            milliseconds = max(
                1,
                min(30_000, (remaining_ns + 999_999) // 1_000_000),
            )
        connection.execute(f"PRAGMA busy_timeout = {milliseconds}")

    @contextmanager
    def _transaction(
        self,
        *,
        deadline_ns: int | None = None,
    ) -> Iterator[sqlite3.Cursor]:
        with self._deadline_lock(deadline_ns):
            self._ensure_open()
            connection = self._connection
            self._apply_deadline_busy_timeout(connection, deadline_ns)
            cursor = connection.cursor()
            connection_replaced = False
            cursor.execute("BEGIN IMMEDIATE")
            self._remaining_deadline_ns(deadline_ns)
            try:
                yield cursor
            except BaseException:
                connection_replaced = self._recover_transaction_connection(connection)
                raise
            else:
                try:
                    self._remaining_deadline_ns(deadline_ns)
                    connection.commit()
                except BaseException:
                    connection_replaced = self._recover_transaction_connection(
                        connection
                    )
                    raise
            finally:
                if not connection_replaced:
                    cursor.close()
                if not self._closed:
                    with suppress(sqlite3.Error):
                        self._connection.execute("PRAGMA busy_timeout = 30000")

    @contextmanager
    def _read_cursor(
        self,
        *,
        deadline_ns: int | None = None,
    ) -> Iterator[sqlite3.Cursor]:
        with self._deadline_lock(deadline_ns):
            self._ensure_open()
            self._apply_deadline_busy_timeout(self._connection, deadline_ns)
            cursor = self._connection.cursor()
            try:
                yield cursor
            finally:
                cursor.close()
                if not self._closed:
                    with suppress(sqlite3.Error):
                        self._connection.execute("PRAGMA busy_timeout = 30000")

    @staticmethod
    def _ensure_tenant(cursor: sqlite3.Cursor, tenant_id: str) -> None:
        cursor.execute(
            """
            INSERT INTO tenants(tenant_id, created_at_ns)
            VALUES (?, ?)
            ON CONFLICT(tenant_id) DO NOTHING
            """,
            (tenant_id, time.time_ns()),
        )

    @staticmethod
    def _idempotent_response(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        operation: str,
        idempotency_key: str | None,
        request_digest: str,
    ) -> dict[str, Any] | None:
        if idempotency_key is None:
            return None
        key = _bounded_identifier(idempotency_key, "idempotency_key")
        row = cursor.execute(
            """
            SELECT request_digest, response_json
            FROM idempotency_keys
            WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?
            """,
            (tenant_id, operation, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise IdempotencyConflict(
                "idempotency key was already used for a different request"
            )
        response = json.loads(row["response_json"])
        if not isinstance(response, dict):
            raise SessionStoreError("stored idempotent response is invalid")
        return response

    @staticmethod
    def _record_idempotency(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        operation: str,
        idempotency_key: str | None,
        request_digest: str,
        response: Any,
    ) -> None:
        if idempotency_key is None:
            return
        cursor.execute(
            """
            INSERT INTO idempotency_keys(
                tenant_id, operation, idempotency_key, request_digest,
                response_json, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                operation,
                idempotency_key,
                request_digest,
                canonical_json(asdict(response)),
                time.time_ns(),
            ),
        )

    @staticmethod
    def _project_from_payload(payload: Mapping[str, Any]) -> ProjectDescriptor:
        return ProjectDescriptor(
            tenant_id=str(payload["tenant_id"]),
            project_id=str(payload["project_id"]),
            label=str(payload["label"]),
            metadata=dict(payload.get("metadata") or {}),
            created_at_ns=int(payload["created_at_ns"]),
        )

    @staticmethod
    def _workspace_from_payload(
        payload: Mapping[str, Any],
    ) -> WorkspaceDescriptor:
        return WorkspaceDescriptor(
            tenant_id=str(payload["tenant_id"]),
            project_id=str(payload["project_id"]),
            workspace_id=str(payload["workspace_id"]),
            label=str(payload["label"]),
            metadata=dict(payload.get("metadata") or {}),
            created_at_ns=int(payload["created_at_ns"]),
        )

    @staticmethod
    def _workspace_disclosure_policy_from_payload(
        payload: Mapping[str, Any],
    ) -> WorkspaceDisclosurePolicyRecord:
        raw_policy = payload.get("policy")
        if not isinstance(raw_policy, Mapping):
            raise SessionStoreError(
                "stored workspace disclosure policy response is invalid"
            )
        try:
            raw_version = payload["version"]
            raw_created_at_ns = payload["created_at_ns"]
            if type(raw_version) is not int or type(raw_created_at_ns) is not int:
                raise TypeError
            if set(raw_policy) == {"mode", "transports"}:
                raw_policy = {
                    "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                    "mode": raw_policy["mode"],
                    "transports": raw_policy["transports"],
                }
            policy = workspace_disclosure_policy_from_dict(raw_policy)
            record = WorkspaceDisclosurePolicyRecord(
                tenant_id=_bounded_identifier(payload.get("tenant_id"), "tenant_id"),
                project_id=_bounded_identifier(
                    payload.get("project_id"), "project_id"
                ),
                workspace_id=_bounded_identifier(
                    payload.get("workspace_id"), "workspace_id"
                ),
                version=raw_version,
                policy=policy,
                policy_digest=_digest(
                    payload.get("policy_digest"), "policy_digest"
                ),
                actor_id=_bounded_identifier(payload.get("actor_id"), "actor_id"),
                created_at_ns=raw_created_at_ns,
                explicit=payload.get("explicit") is True,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy response is invalid"
            ) from error
        if (
            type(record.version) is not int
            or record.version < 1
            or record.version > _MAX_SQLITE_INTEGER
            or type(record.created_at_ns) is not int
            or record.created_at_ns < 0
            or not record.explicit
            or record.policy_digest != policy.digest
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy response is invalid"
            )
        return record

    @classmethod
    def _workspace_disclosure_policy_receipt(
        cls,
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
        idempotency_key: str | None,
        request_digest: str,
        expected_version: int,
        policy: WorkspaceDisclosurePolicy,
        actor_id: str,
    ) -> WorkspaceDisclosurePolicyRecord | None:
        """Resolve an idempotent replay from its exact durable revision."""

        if idempotency_key is None:
            return None
        key = _bounded_identifier(idempotency_key, "idempotency_key")
        receipt = cursor.execute(
            """
            SELECT * FROM workspace_disclosure_policy_receipts
            WHERE tenant_id = ? AND idempotency_key = ?
            """,
            (tenant_id, key),
        ).fetchone()
        if receipt is None:
            return None
        try:
            stored_request_digest = _digest(
                receipt["request_digest"], "request_digest"
            )
            receipt_project_id = _bounded_identifier(
                receipt["project_id"], "project_id"
            )
            receipt_workspace_id = _bounded_identifier(
                receipt["workspace_id"], "workspace_id"
            )
            result_version = receipt["result_version"]
            result_record_digest = _digest(
                receipt["result_record_digest"], "result_record_digest"
            )
            created_at_ns = receipt["created_at_ns"]
            if (
                type(result_version) is not int
                or not 1 <= result_version <= _MAX_DISCLOSURE_POLICY_REVISIONS
                or type(created_at_ns) is not int
                or created_at_ns < 0
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy receipt is invalid"
            ) from error
        if stored_request_digest != request_digest:
            raise IdempotencyConflict(
                "idempotency key was already used for a different request"
            )
        if (
            receipt_project_id != project_id
            or receipt_workspace_id != workspace_id
            or result_version != expected_version + 1
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy receipt is invalid"
            )
        row = cursor.execute(
            """
            SELECT policy.*, workspaces.project_id,
                   seal.record_digest AS sealed_record_digest
            FROM workspace_disclosure_policies AS policy
            JOIN workspaces
              ON workspaces.tenant_id = policy.tenant_id
             AND workspaces.workspace_id = policy.workspace_id
            JOIN workspace_disclosure_policy_seals AS seal
              ON seal.tenant_id = policy.tenant_id
             AND seal.workspace_id = policy.workspace_id
             AND seal.version = policy.version
            WHERE policy.tenant_id = ? AND policy.workspace_id = ?
              AND policy.version = ?
            """,
            (tenant_id, workspace_id, result_version),
        ).fetchone()
        if row is None:
            raise SessionStoreError(
                "stored workspace disclosure policy receipt is invalid"
            )
        record = cls._workspace_disclosure_policy_row(row)
        try:
            sealed_record_digest = _digest(
                row["sealed_record_digest"], "sealed_record_digest"
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy receipt is invalid"
            ) from error
        if (
            record.tenant_id != tenant_id
            or record.project_id != project_id
            or record.workspace_id != workspace_id
            or record.version != result_version
            or record.policy != policy
            or record.actor_id != actor_id
            or sealed_record_digest != result_record_digest
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy receipt is invalid"
            )
        return record

    @staticmethod
    def _record_workspace_disclosure_policy_receipt(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
        idempotency_key: str | None,
        request_digest: str,
        result: WorkspaceDisclosurePolicyRecord,
        result_record_digest: str,
    ) -> None:
        if idempotency_key is None:
            return
        cursor.execute(
            """
            INSERT INTO workspace_disclosure_policy_receipts(
                tenant_id, project_id, workspace_id, idempotency_key,
                request_digest, result_version, result_record_digest,
                created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                project_id,
                workspace_id,
                _bounded_identifier(idempotency_key, "idempotency_key"),
                _digest(request_digest, "request_digest"),
                result.version,
                _digest(result_record_digest, "result_record_digest"),
                result.created_at_ns,
            ),
        )

    @staticmethod
    def _fixture_from_payload(payload: Mapping[str, Any]) -> FixtureDescriptor:
        return FixtureDescriptor(
            tenant_id=str(payload["tenant_id"]),
            workspace_id=str(payload["workspace_id"]),
            fixture_id=str(payload["fixture_id"]),
            label=str(payload["label"]),
            content_digest=str(payload["content_digest"]),
            metadata=dict(payload.get("metadata") or {}),
            created_at_ns=int(payload["created_at_ns"]),
        )

    @staticmethod
    def _revision_from_payload(
        payload: Mapping[str, Any],
    ) -> AnalysisRevisionDescriptor:
        raw_plan = payload.get("execution_plan")
        try:
            execution_plan = (
                None
                if raw_plan is None
                else plugin_execution_plan_from_dict(raw_plan)
            )
        except (TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored idempotent revision execution plan is invalid"
            ) from error
        node_id = str(payload["node_id"])
        if execution_plan is not None and execution_plan.node_id != node_id:
            raise SessionStoreError(
                "stored idempotent revision execution plan node is invalid"
            )
        return AnalysisRevisionDescriptor(
            tenant_id=str(payload["tenant_id"]),
            workspace_id=str(payload["workspace_id"]),
            fixture_id=str(payload["fixture_id"]),
            revision_id=str(payload["revision_id"]),
            node_id=node_id,
            identity_digest=str(payload["identity_digest"]),
            plugin_ids=tuple(str(item) for item in payload.get("plugin_ids", ())),
            metadata=dict(payload.get("metadata") or {}),
            published_at_ns=int(payload["published_at_ns"]),
            execution_plan=execution_plan,
        )

    @classmethod
    def _replayed_revision(
        cls,
        cursor: sqlite3.Cursor,
        payload: Mapping[str, Any],
        *,
        tenant_id: str,
        revision_id: str,
    ) -> AnalysisRevisionDescriptor:
        """Validate a receipt while returning the immutable durable revision."""

        receipt = cls._revision_from_payload(payload)
        row = cursor.execute(
            """
            SELECT * FROM analysis_revisions
            WHERE tenant_id = ? AND revision_id = ?
            """,
            (tenant_id, revision_id),
        ).fetchone()
        if row is None:
            raise SessionStoreError(
                "stored idempotent revision response has no durable revision"
            )
        durable = cls._revision_row(row)
        receipt_fields = (
            receipt.tenant_id,
            receipt.workspace_id,
            receipt.fixture_id,
            receipt.revision_id,
            receipt.node_id,
            receipt.identity_digest,
            receipt.plugin_ids,
            dict(receipt.metadata),
            receipt.published_at_ns,
        )
        durable_fields = (
            durable.tenant_id,
            durable.workspace_id,
            durable.fixture_id,
            durable.revision_id,
            durable.node_id,
            durable.identity_digest,
            durable.plugin_ids,
            dict(durable.metadata),
            durable.published_at_ns,
        )
        if receipt_fields != durable_fields or (
            payload.get("execution_plan") is not None
            and receipt.execution_plan != durable.execution_plan
        ):
            raise SessionStoreError(
                "stored idempotent revision response conflicts with durable revision"
            )
        return durable

    @staticmethod
    def _member_from_payload(
        payload: Mapping[str, Any],
    ) -> SessionMemberDescriptor:
        return SessionMemberDescriptor(
            member_id=str(payload["member_id"]),
            fixture_id=str(payload["fixture_id"]),
            revision_id=str(payload["revision_id"]),
            node_id=str(payload["node_id"]),
            role=str(payload.get("role") or "member"),
        )

    @classmethod
    def _session_from_payload(cls, payload: Mapping[str, Any]) -> AnalysisSession:
        members = payload.get("members") or ()
        if not isinstance(members, (list, tuple)):
            raise SessionStoreError("stored session members are invalid")
        return AnalysisSession(
            tenant_id=str(payload["tenant_id"]),
            workspace_id=str(payload["workspace_id"]),
            session_id=str(payload["session_id"]),
            label=str(payload["label"]),
            version=int(payload["version"]),
            default_member_id=(
                str(payload["default_member_id"])
                if payload.get("default_member_id") is not None
                else None
            ),
            members=tuple(cls._member_from_payload(item) for item in members),
            metadata=dict(payload.get("metadata") or {}),
            created_at_ns=int(payload["created_at_ns"]),
            updated_at_ns=int(payload["updated_at_ns"]),
        )

    @classmethod
    def _snapshot_from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> RevisionSetSnapshot:
        members = payload.get("members") or ()
        if not isinstance(members, (list, tuple)):
            raise SessionStoreError("stored snapshot members are invalid")
        return RevisionSetSnapshot(
            tenant_id=str(payload["tenant_id"]),
            workspace_id=str(payload["workspace_id"]),
            session_id=str(payload["session_id"]),
            snapshot_id=str(payload["snapshot_id"]),
            session_version=int(payload["session_version"]),
            digest=str(payload["digest"]),
            default_member_id=(
                str(payload["default_member_id"])
                if payload.get("default_member_id") is not None
                else None
            ),
            members=tuple(cls._member_from_payload(item) for item in members),
            created_at_ns=int(payload["created_at_ns"]),
        )

    def create_project(
        self,
        tenant_id: str,
        label: str,
        *,
        project_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> ProjectDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        project_label = _bounded_label(label, "project label")
        metadata_json = _metadata_json(metadata, "project metadata")
        request = {
            "project_id": project_id,
            "label": project_label,
            "metadata": json.loads(metadata_json),
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            self._ensure_tenant(cursor, tenant)
            prior = self._idempotent_response(
                cursor,
                tenant,
                "create_project",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._project_from_payload(prior)
            selected_id = _bounded_identifier(
                project_id or _new_id("project"),
                "project_id",
            )
            created_at_ns = time.time_ns()
            try:
                cursor.execute(
                    """
                    INSERT INTO projects(
                        tenant_id, project_id, label, metadata_json,
                        created_at_ns
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        selected_id,
                        project_label,
                        metadata_json,
                        created_at_ns,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    f"project already exists: {selected_id}"
                ) from error
            result = ProjectDescriptor(
                tenant_id=tenant,
                project_id=selected_id,
                label=project_label,
                metadata=json.loads(metadata_json),
                created_at_ns=created_at_ns,
            )
            self._record_idempotency(
                cursor,
                tenant,
                "create_project",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    def get_project(self, tenant_id: str, project_id: str) -> ProjectDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        selected_id = _bounded_identifier(project_id, "project_id")
        with self._read_cursor() as cursor:
            row = cursor.execute(
                """
                SELECT * FROM projects
                WHERE tenant_id = ? AND project_id = ?
                """,
                (tenant, selected_id),
            ).fetchone()
            if row is None:
                raise KeyError(selected_id)
            return self._project_row(row)

    def list_projects(
        self,
        tenant_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[ProjectDescriptor, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            rows = cursor.execute(
                """
                SELECT * FROM projects
                WHERE tenant_id = ?
                ORDER BY project_id
                LIMIT ? OFFSET ?
                """,
                (tenant, page_limit, page_offset),
            ).fetchall()
            return tuple(self._project_row(row) for row in rows)

    @staticmethod
    def _project_row(row: sqlite3.Row) -> ProjectDescriptor:
        return ProjectDescriptor(
            tenant_id=row["tenant_id"],
            project_id=row["project_id"],
            label=row["label"],
            metadata=_json_mapping(row["metadata_json"]),
            created_at_ns=row["created_at_ns"],
        )

    def create_workspace(
        self,
        tenant_id: str,
        project_id: str,
        label: str,
        *,
        workspace_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> WorkspaceDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        project = _bounded_identifier(project_id, "project_id")
        workspace_label = _bounded_label(label, "workspace label")
        metadata_json = _metadata_json(metadata, "workspace metadata")
        request = {
            "project_id": project,
            "workspace_id": workspace_id,
            "label": workspace_label,
            "metadata": json.loads(metadata_json),
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            self._require_project(cursor, tenant, project)
            prior = self._idempotent_response(
                cursor,
                tenant,
                "create_workspace",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._workspace_from_payload(prior)
            selected_id = _bounded_identifier(
                workspace_id or _new_id("workspace"),
                "workspace_id",
            )
            created_at_ns = time.time_ns()
            policy_root_digest = _workspace_disclosure_policy_root_digest(
                tenant_id=tenant,
                project_id=project,
                workspace_id=selected_id,
                workspace_created_at_ns=created_at_ns,
            )
            try:
                cursor.execute(
                    """
                    INSERT INTO workspaces(
                        tenant_id, workspace_id, project_id, label,
                        metadata_json, created_at_ns,
                        disclosure_policy_root_digest,
                        disclosure_policy_tip_version,
                        disclosure_policy_tip_record_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        tenant,
                        selected_id,
                        project,
                        workspace_label,
                        metadata_json,
                        created_at_ns,
                        policy_root_digest,
                        policy_root_digest,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    f"workspace already exists: {selected_id}"
                ) from error
            result = WorkspaceDescriptor(
                tenant_id=tenant,
                project_id=project,
                workspace_id=selected_id,
                label=workspace_label,
                metadata=json.loads(metadata_json),
                created_at_ns=created_at_ns,
            )
            self._record_idempotency(
                cursor,
                tenant,
                "create_workspace",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    @staticmethod
    def _require_project(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        project_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM projects
            WHERE tenant_id = ? AND project_id = ?
            """,
            (tenant_id, project_id),
        ).fetchone()
        if row is None:
            raise KeyError(project_id)
        return row

    @staticmethod
    def _require_workspace(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        workspace_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM workspaces
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            (tenant_id, workspace_id),
        ).fetchone()
        if row is None:
            raise KeyError(workspace_id)
        return row

    @staticmethod
    def _workspace_row(row: sqlite3.Row) -> WorkspaceDescriptor:
        return WorkspaceDescriptor(
            tenant_id=row["tenant_id"],
            project_id=row["project_id"],
            workspace_id=row["workspace_id"],
            label=row["label"],
            metadata=_json_mapping(row["metadata_json"]),
            created_at_ns=row["created_at_ns"],
        )

    def get_workspace(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        deadline_ns: int | None = None,
    ) -> WorkspaceDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        with self._read_cursor(deadline_ns=deadline_ns) as cursor:
            return self._workspace_row(
                self._require_workspace(cursor, tenant, workspace)
            )

    def list_workspaces(
        self,
        tenant_id: str,
        project_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[WorkspaceDescriptor, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        project = _bounded_identifier(project_id, "project_id")
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            self._require_project(cursor, tenant, project)
            rows = cursor.execute(
                """
                SELECT * FROM workspaces
                WHERE tenant_id = ? AND project_id = ?
                ORDER BY workspace_id
                LIMIT ? OFFSET ?
                """,
                (tenant, project, page_limit, page_offset),
            ).fetchall()
            return tuple(self._workspace_row(row) for row in rows)

    @staticmethod
    def _workspace_disclosure_policy_row(
        row: sqlite3.Row,
    ) -> WorkspaceDisclosurePolicyRecord:
        try:
            version = row["version"]
            created_at_ns = row["created_at_ns"]
            if (
                type(version) is not int
                or not 1 <= version <= _MAX_SQLITE_INTEGER
                or type(created_at_ns) is not int
                or created_at_ns < 0
            ):
                raise ValueError
            policy = _stored_workspace_disclosure_policy(
                row["policy_json"],
                row["policy_digest"],
            )
            return WorkspaceDisclosurePolicyRecord(
                tenant_id=_bounded_identifier(row["tenant_id"], "tenant_id"),
                project_id=_bounded_identifier(row["project_id"], "project_id"),
                workspace_id=_bounded_identifier(
                    row["workspace_id"], "workspace_id"
                ),
                version=version,
                policy=policy,
                policy_digest=_digest(row["policy_digest"], "policy_digest"),
                actor_id=_bounded_identifier(row["actor_id"], "actor_id"),
                created_at_ns=created_at_ns,
                explicit=True,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy record is invalid"
            ) from error

    @classmethod
    def _workspace_disclosure_policy_state(
        cls,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        workspace_id: str,
    ) -> _WorkspaceDisclosurePolicyState:
        """Validate the workspace-rooted tip, head, seals, and full history.

        The SQLite catalog/schema is the trusted single-host authority. These
        redundant values detect torn or independently corrupted state; no
        in-database construction can detect a privileged writer coherently
        replacing every anchor with one older, internally valid snapshot.
        """

        workspace_row = cursor.execute(
            """
            SELECT tenant_id, project_id, workspace_id, created_at_ns,
                   disclosure_policy_root_digest,
                   disclosure_policy_tip_version,
                   disclosure_policy_tip_record_digest
            FROM workspaces
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            (tenant_id, workspace_id),
        ).fetchone()
        if workspace_row is None:
            raise KeyError(workspace_id)
        try:
            project_id = _bounded_identifier(
                workspace_row["project_id"], "project_id"
            )
            stored_root_digest = _digest(
                workspace_row["disclosure_policy_root_digest"],
                "disclosure_policy_root_digest",
            )
            tip_record_digest = _digest(
                workspace_row["disclosure_policy_tip_record_digest"],
                "disclosure_policy_tip_record_digest",
            )
            tip_version = workspace_row["disclosure_policy_tip_version"]
            if (
                type(tip_version) is not int
                or not 0 <= tip_version <= _MAX_DISCLOSURE_POLICY_REVISIONS
            ):
                raise ValueError
            root_digest = _workspace_disclosure_policy_root_digest(
                tenant_id=tenant_id,
                project_id=project_id,
                workspace_id=workspace_id,
                workspace_created_at_ns=workspace_row["created_at_ns"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy root is invalid"
            ) from error
        if stored_root_digest != root_digest:
            raise SessionStoreError(
                "stored workspace disclosure policy root is invalid"
            )

        head = cursor.execute(
            """
            SELECT * FROM workspace_disclosure_policy_heads
            WHERE tenant_id = ? AND workspace_id = ?
            """,
            (tenant_id, workspace_id),
        ).fetchone()
        history_cursor = cursor.connection.execute(
            """
            SELECT policy.*, workspaces.project_id,
                   seal.previous_record_digest AS sealed_previous_record_digest,
                   seal.record_digest AS sealed_record_digest,
                   seal.receipt_commitment AS sealed_receipt_commitment,
                   receipt.project_id AS receipt_project_id,
                   receipt.workspace_id AS receipt_workspace_id,
                   receipt.idempotency_key AS receipt_idempotency_key,
                   receipt.request_digest AS receipt_request_digest,
                   receipt.result_version AS receipt_result_version,
                   receipt.result_record_digest AS receipt_result_record_digest,
                   receipt.created_at_ns AS receipt_created_at_ns
            FROM workspace_disclosure_policies AS policy
            JOIN workspaces
              ON workspaces.tenant_id = policy.tenant_id
             AND workspaces.workspace_id = policy.workspace_id
            LEFT JOIN workspace_disclosure_policy_seals AS seal
              ON seal.tenant_id = policy.tenant_id
             AND seal.workspace_id = policy.workspace_id
             AND seal.version = policy.version
            LEFT JOIN workspace_disclosure_policy_receipts AS receipt
              ON receipt.tenant_id = policy.tenant_id
             AND receipt.workspace_id = policy.workspace_id
             AND receipt.result_version = policy.version
            WHERE policy.tenant_id = ? AND policy.workspace_id = ?
            ORDER BY policy.version
            """,
            (tenant_id, workspace_id),
        )
        current_record: WorkspaceDisclosurePolicyRecord | None = None
        history_records: list[WorkspaceDisclosurePolicyRecord] = []
        history_count = 0
        previous_record_digest = root_digest
        try:
            for expected_version, row in enumerate(history_cursor, start=1):
                if expected_version > _MAX_DISCLOSURE_POLICY_REVISIONS:
                    raise SessionStoreError(
                        "stored workspace disclosure policy history is invalid"
                    )
                record = cls._workspace_disclosure_policy_row(row)
                if (
                    record.tenant_id != tenant_id
                    or record.project_id != project_id
                    or record.workspace_id != workspace_id
                    or record.version != expected_version
                ):
                    raise SessionStoreError(
                        "stored workspace disclosure policy history is invalid"
                    )
                try:
                    sealed_previous = _digest(
                        row["sealed_previous_record_digest"],
                        "sealed_previous_record_digest",
                    )
                    sealed_record = _digest(
                        row["sealed_record_digest"],
                        "sealed_record_digest",
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise SessionStoreError(
                        "stored workspace disclosure policy seal is invalid"
                    ) from error
                raw_receipt_commitment = row["sealed_receipt_commitment"]
                if raw_receipt_commitment is None:
                    receipt_commitment = None
                    if any(
                        row[field] is not None
                        for field in (
                            "receipt_project_id",
                            "receipt_workspace_id",
                            "receipt_idempotency_key",
                            "receipt_request_digest",
                            "receipt_result_version",
                            "receipt_result_record_digest",
                            "receipt_created_at_ns",
                        )
                    ):
                        raise SessionStoreError(
                            "stored workspace disclosure policy receipt is invalid"
                        )
                else:
                    try:
                        receipt_commitment = _digest(
                            raw_receipt_commitment,
                            "sealed_receipt_commitment",
                        )
                        receipt_project_id = _bounded_identifier(
                            row["receipt_project_id"], "project_id"
                        )
                        receipt_workspace_id = _bounded_identifier(
                            row["receipt_workspace_id"], "workspace_id"
                        )
                        receipt_idempotency_key = _bounded_identifier(
                            row["receipt_idempotency_key"], "idempotency_key"
                        )
                        receipt_request_digest = _digest(
                            row["receipt_request_digest"], "request_digest"
                        )
                        receipt_result_version = row["receipt_result_version"]
                        receipt_result_record_digest = _digest(
                            row["receipt_result_record_digest"],
                            "result_record_digest",
                        )
                        receipt_created_at_ns = row["receipt_created_at_ns"]
                        if (
                            type(receipt_result_version) is not int
                            or type(receipt_created_at_ns) is not int
                            or receipt_created_at_ns < 0
                        ):
                            raise TypeError
                        expected_receipt_commitment = (
                            _workspace_disclosure_policy_receipt_commitment(
                                tenant_id=tenant_id,
                                project_id=receipt_project_id,
                                workspace_id=receipt_workspace_id,
                                idempotency_key=receipt_idempotency_key,
                                request_digest=receipt_request_digest,
                                result_version=receipt_result_version,
                                created_at_ns=receipt_created_at_ns,
                            )
                        )
                    except (KeyError, TypeError, ValueError) as error:
                        raise SessionStoreError(
                            "stored workspace disclosure policy receipt is invalid"
                        ) from error
                    if (
                        receipt_project_id != project_id
                        or receipt_workspace_id != workspace_id
                        or receipt_result_version != record.version
                        or expected_receipt_commitment != receipt_commitment
                    ):
                        raise SessionStoreError(
                            "stored workspace disclosure policy receipt is invalid"
                        )
                expected_record_digest = (
                    _workspace_disclosure_policy_record_digest(
                        record,
                        previous_record_digest=previous_record_digest,
                        receipt_commitment=receipt_commitment,
                    )
                )
                if (
                    sealed_previous != previous_record_digest
                    or sealed_record != expected_record_digest
                ):
                    raise SessionStoreError(
                        "stored workspace disclosure policy seal is invalid"
                    )
                if (
                    receipt_commitment is not None
                    and receipt_result_record_digest != sealed_record
                ):
                    raise SessionStoreError(
                        "stored workspace disclosure policy receipt is invalid"
                    )
                history_count = expected_version
                current_record = record
                history_records.append(record)
                previous_record_digest = sealed_record
        finally:
            history_cursor.close()
        if (
            history_count != tip_version
            or previous_record_digest != tip_record_digest
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy tip is invalid"
            )
        if head is None:
            if history_count:
                raise SessionStoreError(
                    "stored workspace disclosure policy history is invalid"
                )
            return _WorkspaceDisclosurePolicyState(None, root_digest, ())
        try:
            current_version = head["current_version"]
            updated_at_ns = head["updated_at_ns"]
            current_digest = _digest(
                head["current_policy_digest"],
                "current_policy_digest",
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SessionStoreError(
                "stored workspace disclosure policy head is invalid"
            ) from error
        if (
            type(current_version) is not int
            or not 1 <= current_version <= _MAX_DISCLOSURE_POLICY_REVISIONS
            or type(updated_at_ns) is not int
            or updated_at_ns < 0
            or history_count != current_version
            or current_record is None
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy history is invalid"
            )
        if (
            current_record.policy_digest != current_digest
            or current_record.created_at_ns != updated_at_ns
        ):
            raise SessionStoreError(
                "stored workspace disclosure policy head is invalid"
            )
        return _WorkspaceDisclosurePolicyState(
            current_record,
            previous_record_digest,
            tuple(history_records),
        )

    def get_workspace_disclosure_policy(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        deadline_ns: int | None = None,
    ) -> WorkspaceDisclosurePolicyRecord:
        """Return the current policy or an explicit synthetic disabled revision 0."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        with self._read_cursor(deadline_ns=deadline_ns) as cursor:
            workspace_row = self._require_workspace(cursor, tenant, workspace)
            state = self._workspace_disclosure_policy_state(
                cursor,
                tenant,
                workspace,
            )
            current = state.current
            if current is not None:
                return current
            policy = WorkspaceDisclosurePolicy.disabled()
            return WorkspaceDisclosurePolicyRecord(
                tenant_id=tenant,
                project_id=_bounded_identifier(
                    workspace_row["project_id"], "project_id"
                ),
                workspace_id=workspace,
                version=0,
                policy=policy,
                policy_digest=policy.digest,
                actor_id="core-default",
                created_at_ns=0,
                explicit=False,
            )

    def list_workspace_disclosure_policy_history(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
        deadline_ns: int | None = None,
    ) -> tuple[WorkspaceDisclosurePolicyRecord, ...]:
        """Return append-only explicit policy revisions, newest first."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor(deadline_ns=deadline_ns) as cursor:
            self._require_workspace(cursor, tenant, workspace)
            state = self._workspace_disclosure_policy_state(
                cursor,
                tenant,
                workspace,
            )
            newest_first = tuple(reversed(state.history))
            return newest_first[page_offset : page_offset + page_limit]

    def set_workspace_disclosure_policy(
        self,
        tenant_id: str,
        workspace_id: str,
        policy: WorkspaceDisclosurePolicy,
        *,
        actor_id: str,
        expected_version: int,
        idempotency_key: str | None = None,
        deadline_ns: int | None = None,
    ) -> WorkspaceDisclosurePolicyRecord:
        """Append one policy revision using mandatory optimistic concurrency."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        actor = _bounded_identifier(actor_id, "actor_id")
        if (
            type(expected_version) is not int
            or not 0 <= expected_version <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError(
                "expected_version must be an integer between 0 and the SQLite maximum"
            )
        policy_json, policy_digest = _workspace_disclosure_policy_json(policy)
        with self._transaction(deadline_ns=deadline_ns) as cursor:
            workspace_row = self._require_workspace(cursor, tenant, workspace)
            project_id = _bounded_identifier(
                workspace_row["project_id"], "project_id"
            )
            request = {
                "tenant_id": tenant,
                "project_id": project_id,
                "workspace_id": workspace,
                "policy": workspace_disclosure_policy_dict(policy),
                "actor_id": actor,
                "expected_version": expected_version,
            }
            request_digest = canonical_json_sha256(request)
            state = self._workspace_disclosure_policy_state(
                cursor,
                tenant,
                workspace,
            )
            current = state.current
            prior = self._workspace_disclosure_policy_receipt(
                cursor,
                tenant_id=tenant,
                project_id=project_id,
                workspace_id=workspace,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_version=expected_version,
                policy=policy,
                actor_id=actor,
            )
            if prior is not None:
                return prior
            current_version = 0 if current is None else current.version
            if current_version != expected_version:
                raise StaleWorkspaceDisclosurePolicyVersion(
                    "workspace disclosure policy version conflict"
                )
            if current is not None and current.policy_digest == policy_digest:
                raise SessionConflictError(
                    "workspace disclosure policy is unchanged"
                )
            version = current_version + 1
            if version > _MAX_DISCLOSURE_POLICY_REVISIONS:
                raise SessionConflictError(
                    "workspace disclosure policy version is exhausted"
                )
            created_at_ns = time.time_ns()
            result = WorkspaceDisclosurePolicyRecord(
                tenant_id=tenant,
                project_id=project_id,
                workspace_id=workspace,
                version=version,
                policy=policy,
                policy_digest=policy_digest,
                actor_id=actor,
                created_at_ns=created_at_ns,
                explicit=True,
            )
            receipt_commitment = (
                None
                if idempotency_key is None
                else _workspace_disclosure_policy_receipt_commitment(
                    tenant_id=tenant,
                    project_id=project_id,
                    workspace_id=workspace,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    result_version=version,
                    created_at_ns=result.created_at_ns,
                )
            )
            record_digest = _workspace_disclosure_policy_record_digest(
                result,
                previous_record_digest=state.record_digest,
                receipt_commitment=receipt_commitment,
            )
            try:
                cursor.execute(
                    """
                    INSERT INTO workspace_disclosure_policies(
                        tenant_id, workspace_id, version, policy_json,
                        policy_digest, actor_id, created_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        workspace,
                        version,
                        policy_json,
                        policy_digest,
                        actor,
                        created_at_ns,
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO workspace_disclosure_policy_seals(
                        tenant_id, workspace_id, version,
                        previous_record_digest, record_digest,
                        receipt_commitment
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        workspace,
                        version,
                        state.record_digest,
                        record_digest,
                        receipt_commitment,
                    ),
                )
                if current is None:
                    cursor.execute(
                        """
                        INSERT INTO workspace_disclosure_policy_heads(
                            tenant_id, workspace_id, current_version,
                            current_policy_digest, updated_at_ns
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            tenant,
                            workspace,
                            version,
                            policy_digest,
                            created_at_ns,
                        ),
                    )
                else:
                    updated = cursor.execute(
                        """
                        UPDATE workspace_disclosure_policy_heads
                        SET current_version = ?, current_policy_digest = ?,
                            updated_at_ns = ?
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND current_version = ?
                          AND current_policy_digest = ?
                        """,
                        (
                            version,
                            policy_digest,
                            created_at_ns,
                            tenant,
                            workspace,
                            current.version,
                            current.policy_digest,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise SessionConflictError(
                            "workspace disclosure policy head changed concurrently"
                        )
                tip_updated = cursor.execute(
                    """
                    UPDATE workspaces
                    SET disclosure_policy_tip_version = ?,
                        disclosure_policy_tip_record_digest = ?
                    WHERE tenant_id = ? AND workspace_id = ?
                      AND disclosure_policy_root_digest = ?
                      AND disclosure_policy_tip_version = ?
                      AND disclosure_policy_tip_record_digest = ?
                    """,
                    (
                        version,
                        record_digest,
                        tenant,
                        workspace,
                        workspace_row["disclosure_policy_root_digest"],
                        current_version,
                        state.record_digest,
                    ),
                )
                if tip_updated.rowcount != 1:
                    raise SessionConflictError(
                        "workspace disclosure policy tip changed concurrently"
                    )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    "workspace disclosure policy conflicts with durable state"
                ) from error
            try:
                self._record_workspace_disclosure_policy_receipt(
                    cursor,
                    tenant_id=tenant,
                    project_id=project_id,
                    workspace_id=workspace,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    result=result,
                    result_record_digest=record_digest,
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    "workspace disclosure policy receipt conflicts with durable state"
                ) from error
            return result

    def attach_fixture(
        self,
        tenant_id: str,
        workspace_id: str,
        fixture_id: str,
        *,
        label: str,
        content_digest: str,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        deadline_ns: int | None = None,
    ) -> FixtureDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        fixture = _bounded_identifier(fixture_id, "fixture_id")
        fixture_label = _bounded_label(label, "fixture label")
        content = _digest(content_digest, "content_digest")
        metadata_json = _metadata_json(metadata, "fixture metadata")
        request = {
            "workspace_id": workspace,
            "fixture_id": fixture,
            "label": fixture_label,
            "content_digest": content,
            "metadata": json.loads(metadata_json),
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction(deadline_ns=deadline_ns) as cursor:
            self._require_workspace(cursor, tenant, workspace)
            prior = self._idempotent_response(
                cursor,
                tenant,
                "attach_fixture",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._fixture_from_payload(prior)
            created_at_ns = time.time_ns()
            try:
                cursor.execute(
                    """
                    INSERT INTO fixtures(
                        tenant_id, fixture_id, workspace_id, label,
                        content_digest, metadata_json, created_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        fixture,
                        workspace,
                        fixture_label,
                        content,
                        metadata_json,
                        created_at_ns,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    f"fixture already exists: {fixture}"
                ) from error
            result = FixtureDescriptor(
                tenant_id=tenant,
                workspace_id=workspace,
                fixture_id=fixture,
                label=fixture_label,
                content_digest=content,
                metadata=json.loads(metadata_json),
                created_at_ns=created_at_ns,
            )
            self._record_idempotency(
                cursor,
                tenant,
                "attach_fixture",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    def get_fixture(
        self,
        tenant_id: str,
        fixture_id: str,
        *,
        deadline_ns: int | None = None,
    ) -> FixtureDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        fixture = _bounded_identifier(fixture_id, "fixture_id")
        with self._read_cursor(deadline_ns=deadline_ns) as cursor:
            row = self._require_fixture(cursor, tenant, fixture)
            return self._fixture_row(row)

    def list_fixtures(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[FixtureDescriptor, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            rows = cursor.execute(
                """
                SELECT * FROM fixtures
                WHERE tenant_id = ? AND workspace_id = ?
                ORDER BY fixture_id
                LIMIT ? OFFSET ?
                """,
                (tenant, workspace, page_limit, page_offset),
            ).fetchall()
            return tuple(self._fixture_row(row) for row in rows)

    @staticmethod
    def _require_fixture(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        fixture_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM fixtures
            WHERE tenant_id = ? AND fixture_id = ?
            """,
            (tenant_id, fixture_id),
        ).fetchone()
        if row is None:
            raise KeyError(fixture_id)
        return row

    @staticmethod
    def _fixture_row(row: sqlite3.Row) -> FixtureDescriptor:
        return FixtureDescriptor(
            tenant_id=row["tenant_id"],
            workspace_id=row["workspace_id"],
            fixture_id=row["fixture_id"],
            label=row["label"],
            content_digest=row["content_digest"],
            metadata=_json_mapping(row["metadata_json"]),
            created_at_ns=row["created_at_ns"],
        )

    def publish_revision(
        self,
        tenant_id: str,
        workspace_id: str,
        fixture_id: str,
        revision_id: str,
        *,
        node_id: str,
        identity_digest: str,
        plugin_ids: Sequence[str] | None = None,
        execution_plan: PluginExecutionPlan | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        deadline_ns: int | None = None,
    ) -> AnalysisRevisionDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        fixture = _bounded_identifier(fixture_id, "fixture_id")
        revision = _bounded_identifier(revision_id, "revision_id")
        node = _bounded_identifier(node_id, "node_id")
        identity = _digest(identity_digest, "identity_digest")
        execution_plan_document: dict[str, Any] | None = None
        if execution_plan is not None:
            if type(execution_plan) is not PluginExecutionPlan:
                raise TypeError(
                    "execution_plan must be PluginExecutionPlan or None"
                )
            execution_plan = snapshot_plugin_execution_plan(execution_plan)
            execution_plan_document = plugin_execution_plan_dict(execution_plan)
        if execution_plan is not None and execution_plan.node_id != node:
            raise ValueError("execution_plan node_id must match revision node_id")
        derived_plugins = (
            _execution_plan_plugin_ids(execution_plan)
            if execution_plan is not None
            else ()
        )
        if plugin_ids is None:
            plugins = derived_plugins
        else:
            plugins = _plugin_ids(plugin_ids)
            if execution_plan is not None and plugins != derived_plugins:
                raise ValueError(
                    "plugin_ids must exactly match execution-plan plug-in IDs"
                )
        execution_plan_json = (
            canonical_json(execution_plan_document)
            if execution_plan_document is not None
            else None
        )
        execution_plan_digest = (
            execution_plan_document["plan_digest"]
            if execution_plan_document is not None
            else None
        )
        metadata_json = _metadata_json(metadata, "revision metadata")
        request: dict[str, Any] = {
            "workspace_id": workspace,
            "fixture_id": fixture,
            "revision_id": revision,
            "node_id": node,
            "identity_digest": identity,
            "plugin_ids": list(plugins),
            "metadata": json.loads(metadata_json),
        }
        if execution_plan_document is not None:
            request["execution_plan"] = execution_plan_document
        request_digest = canonical_json_sha256(request)
        with self._transaction(deadline_ns=deadline_ns) as cursor:
            self._require_workspace(cursor, tenant, workspace)
            fixture_row = self._require_fixture(cursor, tenant, fixture)
            if fixture_row["workspace_id"] != workspace:
                raise KeyError(fixture)
            prior = self._idempotent_response(
                cursor,
                tenant,
                "publish_revision",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._replayed_revision(
                    cursor,
                    prior,
                    tenant_id=tenant,
                    revision_id=revision,
                )
            published_at_ns = time.time_ns()
            try:
                cursor.execute(
                    """
                    INSERT INTO analysis_revisions(
                        tenant_id, revision_id, workspace_id, fixture_id,
                        node_id, identity_digest, plugin_ids_json,
                        metadata_json, published_at_ns, execution_plan_json,
                        execution_plan_digest, execution_plan_present
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        revision,
                        workspace,
                        fixture,
                        node,
                        identity,
                        canonical_json(list(plugins)),
                        metadata_json,
                        published_at_ns,
                        execution_plan_json,
                        execution_plan_digest,
                        int(execution_plan is not None),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    f"analysis revision already exists: {revision}"
                ) from error
            result = AnalysisRevisionDescriptor(
                tenant_id=tenant,
                workspace_id=workspace,
                fixture_id=fixture,
                revision_id=revision,
                node_id=node,
                identity_digest=identity,
                plugin_ids=plugins,
                metadata=json.loads(metadata_json),
                published_at_ns=published_at_ns,
                execution_plan=execution_plan,
            )
            self._record_idempotency(
                cursor,
                tenant,
                "publish_revision",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    @staticmethod
    def _require_revision(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        revision_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM analysis_revisions
            WHERE tenant_id = ? AND revision_id = ?
            """,
            (tenant_id, revision_id),
        ).fetchone()
        if row is None:
            raise KeyError(revision_id)
        return row

    @staticmethod
    def _revision_row(row: sqlite3.Row) -> AnalysisRevisionDescriptor:
        plugins = json.loads(row["plugin_ids_json"])
        if not isinstance(plugins, list):
            raise SessionStoreError("stored revision plugin IDs are invalid")
        execution_plan = _stored_execution_plan(
            row["execution_plan_json"],
            row["execution_plan_digest"],
            row["execution_plan_present"],
            node_id=row["node_id"],
        )
        expected_plugins = (
            _execution_plan_plugin_ids(execution_plan)
            if execution_plan is not None
            else None
        )
        parsed_plugins = _plugin_ids(plugins)
        if expected_plugins is not None and parsed_plugins != expected_plugins:
            raise SessionStoreError(
                "stored revision plug-in IDs do not match execution plan"
            )
        return AnalysisRevisionDescriptor(
            tenant_id=row["tenant_id"],
            workspace_id=row["workspace_id"],
            fixture_id=row["fixture_id"],
            revision_id=row["revision_id"],
            node_id=row["node_id"],
            identity_digest=row["identity_digest"],
            plugin_ids=parsed_plugins,
            metadata=_json_mapping(row["metadata_json"]),
            published_at_ns=row["published_at_ns"],
            execution_plan=execution_plan,
        )

    def get_revision(
        self,
        tenant_id: str,
        revision_id: str,
    ) -> AnalysisRevisionDescriptor:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        revision = _bounded_identifier(revision_id, "revision_id")
        with self._read_cursor() as cursor:
            return self._revision_row(self._require_revision(cursor, tenant, revision))

    def list_revisions(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        node_id: str | None = None,
        fixture_id: str | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[AnalysisRevisionDescriptor, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        node = _bounded_identifier(node_id, "node_id") if node_id is not None else None
        fixture = (
            _bounded_identifier(fixture_id, "fixture_id")
            if fixture_id is not None
            else None
        )
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            if node is None and fixture is None:
                rows = cursor.execute(
                    """
                    SELECT * FROM analysis_revisions
                    WHERE tenant_id = ? AND workspace_id = ?
                    ORDER BY node_id, revision_id
                    LIMIT ? OFFSET ?
                    """,
                    (tenant, workspace, page_limit, page_offset),
                ).fetchall()
            elif fixture is None:
                rows = cursor.execute(
                    """
                    SELECT * FROM analysis_revisions
                    WHERE tenant_id = ? AND workspace_id = ? AND node_id = ?
                    ORDER BY revision_id
                    LIMIT ? OFFSET ?
                    """,
                    (tenant, workspace, node, page_limit, page_offset),
                ).fetchall()
            elif node is None:
                rows = cursor.execute(
                    """
                    SELECT * FROM analysis_revisions
                    WHERE tenant_id = ? AND workspace_id = ?
                      AND fixture_id = ?
                    ORDER BY node_id, revision_id
                    LIMIT ? OFFSET ?
                    """,
                    (
                        tenant,
                        workspace,
                        fixture,
                        page_limit,
                        page_offset,
                    ),
                ).fetchall()
            else:
                rows = cursor.execute(
                    """
                    SELECT * FROM analysis_revisions
                    WHERE tenant_id = ? AND workspace_id = ?
                      AND node_id = ? AND fixture_id = ?
                    ORDER BY revision_id
                    LIMIT ? OFFSET ?
                    """,
                    (
                        tenant,
                        workspace,
                        node,
                        fixture,
                        page_limit,
                        page_offset,
                    ),
                ).fetchall()
            return tuple(self._revision_row(row) for row in rows)

    def create_session(
        self,
        tenant_id: str,
        workspace_id: str,
        label: str,
        *,
        session_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        session_label = _bounded_label(label, "session label")
        metadata_json = _metadata_json(metadata, "session metadata")
        request = {
            "workspace_id": workspace,
            "session_id": session_id,
            "label": session_label,
            "metadata": json.loads(metadata_json),
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            prior = self._idempotent_response(
                cursor,
                tenant,
                "create_session",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._session_from_payload(prior)
            selected_id = _bounded_identifier(
                session_id or _new_id("session"),
                "session_id",
            )
            now = time.time_ns()
            try:
                cursor.execute(
                    """
                    INSERT INTO analysis_sessions(
                        tenant_id, session_id, workspace_id, label, version,
                        default_member_id, metadata_json, created_at_ns,
                        updated_at_ns
                    ) VALUES (?, ?, ?, ?, 0, NULL, ?, ?, ?)
                    """,
                    (
                        tenant,
                        selected_id,
                        workspace,
                        session_label,
                        metadata_json,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    f"analysis session already exists: {selected_id}"
                ) from error
            result = self._session_from_database(cursor, tenant, selected_id)
            self._record_idempotency(
                cursor,
                tenant,
                "create_session",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    @staticmethod
    def _require_session(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        session_id: str,
    ) -> sqlite3.Row:
        row = cursor.execute(
            """
            SELECT * FROM analysis_sessions
            WHERE tenant_id = ? AND session_id = ?
            """,
            (tenant_id, session_id),
        ).fetchone()
        if row is None:
            raise KeyError(session_id)
        return row

    @classmethod
    def _session_from_database(
        cls,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        session_id: str,
    ) -> AnalysisSession:
        row = cls._require_session(cursor, tenant_id, session_id)
        member_rows = cursor.execute(
            """
            SELECT member_id, fixture_id, revision_id, node_id, role
            FROM session_members
            WHERE tenant_id = ? AND session_id = ?
            ORDER BY member_id
            """,
            (tenant_id, session_id),
        ).fetchall()
        members = tuple(
            SessionMemberDescriptor(
                member_id=item["member_id"],
                fixture_id=item["fixture_id"],
                revision_id=item["revision_id"],
                node_id=item["node_id"],
                role=item["role"],
            )
            for item in member_rows
        )
        default_member_id = row["default_member_id"]
        if default_member_id is not None and default_member_id not in {
            item.member_id for item in members
        }:
            raise SessionStoreError(
                "stored session default_member_id is not a current member"
            )
        return AnalysisSession(
            tenant_id=row["tenant_id"],
            workspace_id=row["workspace_id"],
            session_id=row["session_id"],
            label=row["label"],
            version=row["version"],
            default_member_id=default_member_id,
            members=members,
            metadata=_json_mapping(row["metadata_json"]),
            created_at_ns=row["created_at_ns"],
            updated_at_ns=row["updated_at_ns"],
        )

    def get_session(self, tenant_id: str, session_id: str) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        with self._read_cursor() as cursor:
            return self._session_from_database(cursor, tenant, session)

    def list_sessions(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[AnalysisSession, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            rows = cursor.execute(
                """
                SELECT session_id FROM analysis_sessions
                WHERE tenant_id = ? AND workspace_id = ?
                ORDER BY session_id
                LIMIT ? OFFSET ?
                """,
                (tenant, workspace, page_limit, page_offset),
            ).fetchall()
            return tuple(
                self._session_from_database(
                    cursor,
                    tenant,
                    row["session_id"],
                )
                for row in rows
            )

    def update_session(
        self,
        tenant_id: str,
        session_id: str,
        *,
        expected_version: int,
        label: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        replace_metadata: bool = False,
        idempotency_key: str | None = None,
    ) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        version = self._expected_version(expected_version)
        if label is None and not replace_metadata:
            raise ValueError("session update requires label or metadata")
        selected_label = (
            _bounded_label(label, "session label") if label is not None else None
        )
        if not isinstance(replace_metadata, bool):
            raise TypeError("replace_metadata must be a boolean")
        metadata_json = (
            _metadata_json(metadata, "session metadata") if replace_metadata else None
        )
        request = {
            "session_id": session,
            "expected_version": version,
            "label": selected_label,
            "replace_metadata": replace_metadata,
            "metadata": (
                json.loads(metadata_json) if metadata_json is not None else None
            ),
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            prior = self._idempotent_response(
                cursor,
                tenant,
                "update_session",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._session_from_payload(prior)
            current = self._require_session(cursor, tenant, session)
            if current["version"] != version:
                raise StaleSessionVersion(
                    f"expected session version {version}, found {current['version']}"
                )
            cursor.execute(
                """
                UPDATE analysis_sessions
                SET label = ?, metadata_json = ?,
                    version = version + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND session_id = ?
                """,
                (
                    selected_label or current["label"],
                    metadata_json or current["metadata_json"],
                    time.time_ns(),
                    tenant,
                    session,
                ),
            )
            result = self._session_from_database(cursor, tenant, session)
            self._record_idempotency(
                cursor,
                tenant,
                "update_session",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    def delete_session(
        self,
        tenant_id: str,
        session_id: str,
        *,
        expected_version: int,
        idempotency_key: str | None = None,
    ) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        version = self._expected_version(expected_version)
        request = {
            "session_id": session,
            "expected_version": version,
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            prior = self._idempotent_response(
                cursor,
                tenant,
                "delete_session",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._session_from_payload(prior)
            current = self._session_from_database(cursor, tenant, session)
            if current.version != version:
                raise StaleSessionVersion(
                    f"expected session version {version}, found {current.version}"
                )
            try:
                cursor.execute(
                    """
                    DELETE FROM analysis_sessions
                    WHERE tenant_id = ? AND session_id = ?
                    """,
                    (tenant, session),
                )
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    "a session with immutable snapshots cannot be deleted"
                ) from error
            self._record_idempotency(
                cursor,
                tenant,
                "delete_session",
                idempotency_key,
                request_digest,
                current,
            )
            return current

    @staticmethod
    def _expected_version(value: object) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("expected_version must be a non-negative integer")
        return value

    def put_member(
        self,
        tenant_id: str,
        session_id: str,
        member_id: str,
        *,
        fixture_id: str,
        revision_id: str,
        expected_version: int,
        role: str = "member",
        make_default: bool = False,
        idempotency_key: str | None = None,
    ) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        member = _bounded_identifier(member_id, "member_id")
        fixture = _bounded_identifier(fixture_id, "fixture_id")
        revision = _bounded_identifier(revision_id, "revision_id")
        selected_role = _bounded_role(role)
        version = self._expected_version(expected_version)
        if not isinstance(make_default, bool):
            raise TypeError("make_default must be a boolean")
        request = {
            "session_id": session,
            "member_id": member,
            "fixture_id": fixture,
            "revision_id": revision,
            "expected_version": version,
            "role": selected_role,
            "make_default": make_default,
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            prior = self._idempotent_response(
                cursor,
                tenant,
                "put_member",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._session_from_payload(prior)
            session_row = self._require_session(cursor, tenant, session)
            if session_row["version"] != version:
                raise StaleSessionVersion(
                    f"expected session version {version}, "
                    f"found {session_row['version']}"
                )
            revision_row = self._require_revision(cursor, tenant, revision)
            if (
                revision_row["workspace_id"] != session_row["workspace_id"]
                or revision_row["fixture_id"] != fixture
            ):
                raise KeyError(revision)
            existing = cursor.execute(
                """
                SELECT fixture_id, revision_id, node_id, role
                FROM session_members
                WHERE tenant_id = ? AND session_id = ? AND member_id = ?
                """,
                (tenant, session, member),
            ).fetchone()
            duplicate_revision = cursor.execute(
                """
                SELECT member_id
                FROM session_members
                WHERE tenant_id = ? AND session_id = ?
                  AND revision_id = ? AND member_id <> ?
                """,
                (tenant, session, revision, member),
            ).fetchone()
            if duplicate_revision is not None:
                raise SessionConflictError(
                    "a session may contain each immutable revision only once"
                )
            if existing is None:
                member_count = int(
                    cursor.execute(
                        """
                        SELECT COUNT(*)
                        FROM session_members
                        WHERE tenant_id = ? AND session_id = ?
                        """,
                        (tenant, session),
                    ).fetchone()[0]
                )
                if member_count >= _MAX_SESSION_MEMBERS:
                    raise SessionConflictError(
                        f"session member limit of {_MAX_SESSION_MEMBERS} was reached"
                    )
            same = (
                existing is not None
                and existing["fixture_id"] == fixture
                and existing["revision_id"] == revision
                and existing["node_id"] == revision_row["node_id"]
                and existing["role"] == selected_role
            )
            desired_default = (
                member
                if make_default or session_row["default_member_id"] is None
                else session_row["default_member_id"]
            )
            if same and desired_default == session_row["default_member_id"]:
                result = self._session_from_database(cursor, tenant, session)
            else:
                cursor.execute(
                    """
                    INSERT INTO session_members(
                        tenant_id, session_id, member_id, fixture_id,
                        revision_id, node_id, role
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, session_id, member_id)
                    DO UPDATE SET
                        fixture_id = excluded.fixture_id,
                        revision_id = excluded.revision_id,
                        node_id = excluded.node_id,
                        role = excluded.role
                    """,
                    (
                        tenant,
                        session,
                        member,
                        fixture,
                        revision,
                        revision_row["node_id"],
                        selected_role,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE analysis_sessions
                    SET version = version + 1,
                        default_member_id = ?,
                        updated_at_ns = ?
                    WHERE tenant_id = ? AND session_id = ?
                    """,
                    (desired_default, time.time_ns(), tenant, session),
                )
                result = self._session_from_database(cursor, tenant, session)
            self._record_idempotency(
                cursor,
                tenant,
                "put_member",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    def delete_member(
        self,
        tenant_id: str,
        session_id: str,
        member_id: str,
        *,
        expected_version: int,
        idempotency_key: str | None = None,
    ) -> AnalysisSession:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        member = _bounded_identifier(member_id, "member_id")
        version = self._expected_version(expected_version)
        request = {
            "session_id": session,
            "member_id": member,
            "expected_version": version,
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            prior = self._idempotent_response(
                cursor,
                tenant,
                "delete_member",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._session_from_payload(prior)
            session_row = self._require_session(cursor, tenant, session)
            if session_row["version"] != version:
                raise StaleSessionVersion(
                    f"expected session version {version}, "
                    f"found {session_row['version']}"
                )
            deleted = cursor.execute(
                """
                DELETE FROM session_members
                WHERE tenant_id = ? AND session_id = ? AND member_id = ?
                """,
                (tenant, session, member),
            ).rowcount
            if not deleted:
                raise KeyError(member)
            remaining = cursor.execute(
                """
                SELECT member_id FROM session_members
                WHERE tenant_id = ? AND session_id = ?
                ORDER BY member_id
                LIMIT 1
                """,
                (tenant, session),
            ).fetchone()
            default_member_id = session_row["default_member_id"]
            if default_member_id == member:
                default_member_id = (
                    remaining["member_id"] if remaining is not None else None
                )
            cursor.execute(
                """
                UPDATE analysis_sessions
                SET version = version + 1,
                    default_member_id = ?,
                    updated_at_ns = ?
                WHERE tenant_id = ? AND session_id = ?
                """,
                (default_member_id, time.time_ns(), tenant, session),
            )
            result = self._session_from_database(cursor, tenant, session)
            self._record_idempotency(
                cursor,
                tenant,
                "delete_member",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    def snapshot_session(
        self,
        tenant_id: str,
        session_id: str,
        *,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> RevisionSetSnapshot:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        session = _bounded_identifier(session_id, "session_id")
        version = (
            self._expected_version(expected_version)
            if expected_version is not None
            else None
        )
        request = {
            "session_id": session,
            "expected_version": version,
        }
        request_digest = canonical_json_sha256(request)
        with self._transaction() as cursor:
            prior = self._idempotent_response(
                cursor,
                tenant,
                "snapshot_session",
                idempotency_key,
                request_digest,
            )
            if prior is not None:
                return self._snapshot_from_payload(prior)
            selected = self._session_from_database(cursor, tenant, session)
            if version is not None and selected.version != version:
                raise StaleSessionVersion(
                    f"expected session version {version}, found {selected.version}"
                )
            vector = {
                "workspace_id": selected.workspace_id,
                "session_id": selected.session_id,
                "session_version": selected.version,
                "default_member_id": selected.default_member_id,
                "members": [
                    {
                        "member_id": item.member_id,
                        "fixture_id": item.fixture_id,
                        "revision_id": item.revision_id,
                        "node_id": item.node_id,
                        "role": item.role,
                    }
                    for item in selected.members
                ],
            }
            digest = canonical_json_sha256(vector)
            snapshot_id = f"revision-set-{digest[:32]}"
            existing = cursor.execute(
                """
                SELECT * FROM revision_set_snapshots
                WHERE tenant_id = ? AND session_id = ?
                    AND session_version = ? AND digest = ?
                """,
                (tenant, session, selected.version, digest),
            ).fetchone()
            if existing is None:
                created_at_ns = time.time_ns()
                cursor.execute(
                    """
                    INSERT INTO revision_set_snapshots(
                        tenant_id, snapshot_id, workspace_id, session_id,
                        session_version, digest, default_member_id,
                        created_at_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        snapshot_id,
                        selected.workspace_id,
                        session,
                        selected.version,
                        digest,
                        selected.default_member_id,
                        created_at_ns,
                    ),
                )
                for item in selected.members:
                    cursor.execute(
                        """
                        INSERT INTO revision_set_members(
                            tenant_id, snapshot_id, member_id, fixture_id,
                            revision_id, node_id, role
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tenant,
                            snapshot_id,
                            item.member_id,
                            item.fixture_id,
                            item.revision_id,
                            item.node_id,
                            item.role,
                        ),
                    )
            result = self._snapshot_from_database(
                cursor,
                tenant,
                snapshot_id,
            )
            self._record_idempotency(
                cursor,
                tenant,
                "snapshot_session",
                idempotency_key,
                request_digest,
                result,
            )
            return result

    @classmethod
    def _snapshot_from_database(
        cls,
        cursor: sqlite3.Cursor,
        tenant_id: str,
        snapshot_id: str,
    ) -> RevisionSetSnapshot:
        row = cursor.execute(
            """
            SELECT * FROM revision_set_snapshots
            WHERE tenant_id = ? AND snapshot_id = ?
            """,
            (tenant_id, snapshot_id),
        ).fetchone()
        if row is None:
            raise KeyError(snapshot_id)
        member_rows = cursor.execute(
            """
            SELECT member_id, fixture_id, revision_id, node_id, role
            FROM revision_set_members
            WHERE tenant_id = ? AND snapshot_id = ?
            ORDER BY member_id
            """,
            (tenant_id, snapshot_id),
        ).fetchall()
        return RevisionSetSnapshot(
            tenant_id=row["tenant_id"],
            workspace_id=row["workspace_id"],
            session_id=row["session_id"],
            snapshot_id=row["snapshot_id"],
            session_version=row["session_version"],
            digest=row["digest"],
            default_member_id=row["default_member_id"],
            members=tuple(
                SessionMemberDescriptor(
                    member_id=item["member_id"],
                    fixture_id=item["fixture_id"],
                    revision_id=item["revision_id"],
                    node_id=item["node_id"],
                    role=item["role"],
                )
                for item in member_rows
            ),
            created_at_ns=row["created_at_ns"],
        )

    def get_snapshot(
        self,
        tenant_id: str,
        snapshot_id: str,
    ) -> RevisionSetSnapshot:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        snapshot = _bounded_identifier(snapshot_id, "snapshot_id")
        with self._read_cursor() as cursor:
            return self._snapshot_from_database(cursor, tenant, snapshot)

    def list_snapshots(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        session_id: str | None = None,
        limit: int = _DEFAULT_PAGE_LIMIT,
        offset: int = 0,
    ) -> tuple[RevisionSetSnapshot, ...]:
        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        session = (
            _bounded_identifier(session_id, "session_id")
            if session_id is not None
            else None
        )
        page_limit, page_offset = _page_bounds(limit, offset)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            if session is None:
                rows = cursor.execute(
                    """
                    SELECT snapshot_id FROM revision_set_snapshots
                    WHERE tenant_id = ? AND workspace_id = ?
                    ORDER BY created_at_ns DESC, snapshot_id
                    LIMIT ? OFFSET ?
                    """,
                    (tenant, workspace, page_limit, page_offset),
                ).fetchall()
            else:
                session_row = self._require_session(
                    cursor,
                    tenant,
                    session,
                )
                if session_row["workspace_id"] != workspace:
                    raise KeyError(session)
                rows = cursor.execute(
                    """
                    SELECT snapshot_id FROM revision_set_snapshots
                    WHERE tenant_id = ? AND workspace_id = ?
                      AND session_id = ?
                    ORDER BY created_at_ns DESC, snapshot_id
                    LIMIT ? OFFSET ?
                    """,
                    (
                        tenant,
                        workspace,
                        session,
                        page_limit,
                        page_offset,
                    ),
                ).fetchall()
            return tuple(
                self._snapshot_from_database(
                    cursor,
                    tenant,
                    row["snapshot_id"],
                )
                for row in rows
            )

    @staticmethod
    def _retention_inventory_from_cursor(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        workspace_id: str,
        policy: CatalogRetentionPolicy,
    ) -> CatalogRetentionInventory:
        maximum = policy.maximum_candidates
        candidates: list[CatalogRetentionCandidate] = []
        total = 0

        def remaining() -> int:
            return maximum - len(candidates)

        def live_receipt_sql(entity_expression: str) -> tuple[str, tuple[Any, ...]]:
            cutoff_clause = ""
            parameters: tuple[Any, ...] = ()
            if policy.idempotency_before_ns is not None:
                cutoff_clause = " AND receipt.created_at_ns >= ?"
                parameters = (policy.idempotency_before_ns,)
            return (
                f"""
                EXISTS (
                    SELECT 1
                    FROM idempotency_keys AS receipt,
                         json_tree(receipt.response_json) AS value
                    WHERE receipt.tenant_id = item.tenant_id
                      AND value.type = 'text'
                      AND value.atom = {entity_expression}
                      {cutoff_clause}
                )
                """,
                parameters,
            )

        if policy.idempotency_before_ns is not None:
            cutoff = policy.idempotency_before_ns
            count_row = cursor.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM idempotency_keys
                WHERE tenant_id = ? AND created_at_ns < ?
                  AND json_extract(response_json, '$.workspace_id') = ?
                """,
                (tenant_id, cutoff, workspace_id),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                rows = cursor.execute(
                    """
                    SELECT operation, idempotency_key, created_at_ns
                    FROM idempotency_keys
                    WHERE tenant_id = ? AND created_at_ns < ?
                      AND json_extract(response_json, '$.workspace_id') = ?
                    ORDER BY created_at_ns, operation, idempotency_key
                    LIMIT ?
                    """,
                    (tenant_id, cutoff, workspace_id, remaining()),
                ).fetchall()
                candidates.extend(
                    CatalogRetentionCandidate(
                        category="catalog_idempotency",
                        identifier=row["idempotency_key"],
                        qualifier=row["operation"],
                        retention_value=int(row["created_at_ns"]),
                    )
                    for row in rows
                )

        if policy.snapshot_before_ns is not None:
            cutoff = policy.snapshot_before_ns
            count_row = cursor.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM revision_set_snapshots
                WHERE tenant_id = ? AND workspace_id = ?
                  AND created_at_ns < ?
                """,
                (tenant_id, workspace_id, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                receipt_sql, receipt_parameters = live_receipt_sql("item.snapshot_id")
                rows = cursor.execute(
                    f"""
                    SELECT item.snapshot_id, item.created_at_ns,
                           {receipt_sql} AS has_live_receipt,
                           NOT EXISTS (
                               SELECT 1
                               FROM revision_set_snapshots AS newer
                               WHERE newer.tenant_id = item.tenant_id
                                 AND newer.session_id = item.session_id
                                 AND (
                                     newer.created_at_ns > item.created_at_ns
                                     OR (
                                         newer.created_at_ns = item.created_at_ns
                                         AND newer.snapshot_id > item.snapshot_id
                                     )
                                 )
                           ) AS is_latest
                    FROM revision_set_snapshots AS item
                    WHERE item.tenant_id = ? AND item.workspace_id = ?
                      AND item.created_at_ns < ?
                    ORDER BY item.created_at_ns, item.snapshot_id
                    LIMIT ?
                    """,
                    (
                        *receipt_parameters,
                        tenant_id,
                        workspace_id,
                        cutoff,
                        remaining(),
                    ),
                ).fetchall()
                for row in rows:
                    blockers: list[str] = []
                    if not policy.external_references_checked:
                        blockers.append("external_references_not_checked")
                    if row["snapshot_id"] in policy.protected_snapshot_ids:
                        blockers.append("externally_protected")
                    if policy.preserve_latest_snapshot_per_session and row["is_latest"]:
                        blockers.append("latest_snapshot_for_session")
                    if row["has_live_receipt"]:
                        blockers.append("unexpired_idempotency_receipt")
                    candidates.append(
                        CatalogRetentionCandidate(
                            category="revision_set_snapshot",
                            identifier=row["snapshot_id"],
                            retention_value=int(row["created_at_ns"]),
                            blockers=tuple(blockers),
                        )
                    )

        if policy.revision_before_ns is not None:
            cutoff = policy.revision_before_ns
            count_row = cursor.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM analysis_revisions
                WHERE tenant_id = ? AND workspace_id = ?
                  AND published_at_ns < ?
                """,
                (tenant_id, workspace_id, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                receipt_sql, receipt_parameters = live_receipt_sql("item.revision_id")
                rows = cursor.execute(
                    f"""
                    SELECT item.revision_id, item.published_at_ns,
                           {receipt_sql} AS has_live_receipt,
                           EXISTS (
                               SELECT 1 FROM session_members AS member
                               WHERE member.tenant_id = item.tenant_id
                                 AND member.revision_id = item.revision_id
                           ) AS selected_by_session,
                           EXISTS (
                               SELECT 1 FROM revision_set_members AS member
                               WHERE member.tenant_id = item.tenant_id
                                 AND member.revision_id = item.revision_id
                           ) AS retained_by_snapshot
                    FROM analysis_revisions AS item
                    WHERE item.tenant_id = ? AND item.workspace_id = ?
                      AND item.published_at_ns < ?
                    ORDER BY item.published_at_ns, item.revision_id
                    LIMIT ?
                    """,
                    (
                        *receipt_parameters,
                        tenant_id,
                        workspace_id,
                        cutoff,
                        remaining(),
                    ),
                ).fetchall()
                for row in rows:
                    blockers = []
                    if not policy.external_references_checked:
                        blockers.append("external_references_not_checked")
                    if row["revision_id"] in policy.protected_revision_ids:
                        blockers.append("externally_protected")
                    if row["selected_by_session"]:
                        blockers.append("selected_by_session")
                    if row["retained_by_snapshot"]:
                        blockers.append("retained_by_snapshot")
                    if row["has_live_receipt"]:
                        blockers.append("unexpired_idempotency_receipt")
                    candidates.append(
                        CatalogRetentionCandidate(
                            category="analysis_revision",
                            identifier=row["revision_id"],
                            retention_value=int(row["published_at_ns"]),
                            blockers=tuple(blockers),
                        )
                    )

        if policy.fixture_before_ns is not None:
            cutoff = policy.fixture_before_ns
            count_row = cursor.execute(
                """
                SELECT COUNT(*) AS candidate_count
                FROM fixtures
                WHERE tenant_id = ? AND workspace_id = ?
                  AND created_at_ns < ?
                """,
                (tenant_id, workspace_id, cutoff),
            ).fetchone()
            total += int(count_row["candidate_count"])
            if remaining() > 0:
                receipt_sql, receipt_parameters = live_receipt_sql("item.fixture_id")
                rows = cursor.execute(
                    f"""
                    SELECT item.fixture_id, item.created_at_ns,
                           {receipt_sql} AS has_live_receipt,
                           EXISTS (
                               SELECT 1 FROM analysis_revisions AS revision
                               WHERE revision.tenant_id = item.tenant_id
                                 AND revision.fixture_id = item.fixture_id
                           ) AS retained_by_revision
                    FROM fixtures AS item
                    WHERE item.tenant_id = ? AND item.workspace_id = ?
                      AND item.created_at_ns < ?
                    ORDER BY item.created_at_ns, item.fixture_id
                    LIMIT ?
                    """,
                    (
                        *receipt_parameters,
                        tenant_id,
                        workspace_id,
                        cutoff,
                        remaining(),
                    ),
                ).fetchall()
                for row in rows:
                    blockers = []
                    if not policy.external_references_checked:
                        blockers.append("external_references_not_checked")
                    if row["fixture_id"] in policy.protected_fixture_ids:
                        blockers.append("externally_protected")
                    if row["retained_by_revision"]:
                        blockers.append("retained_by_revision")
                    if row["has_live_receipt"]:
                        blockers.append("unexpired_idempotency_receipt")
                    candidates.append(
                        CatalogRetentionCandidate(
                            category="fixture",
                            identifier=row["fixture_id"],
                            retention_value=int(row["created_at_ns"]),
                            blockers=tuple(blockers),
                        )
                    )

        return CatalogRetentionInventory(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            policy=policy,
            total_candidate_count=total,
            candidates=tuple(candidates),
            truncated=total > len(candidates),
        )

    def inventory_retention(
        self,
        tenant_id: str,
        workspace_id: str,
        policy: CatalogRetentionPolicy | None = None,
    ) -> CatalogRetentionInventory:
        """Return a bounded tenant-scoped dry run without deleting rows."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        if policy is None:
            policy = CatalogRetentionPolicy()
        if type(policy) is not CatalogRetentionPolicy:
            raise ValueError("policy must be an exact CatalogRetentionPolicy")
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            return self._retention_inventory_from_cursor(
                cursor,
                tenant,
                workspace,
                policy,
            )

    @staticmethod
    def _has_idempotency_reference(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        workspace_id: str,
        identifier: str,
    ) -> bool:
        return (
            cursor.execute(
                """
                SELECT 1
                FROM idempotency_keys AS receipt,
                     json_tree(receipt.response_json) AS value
                WHERE receipt.tenant_id = ?
                  AND json_extract(
                      receipt.response_json, '$.workspace_id'
                  ) = ?
                  AND value.type = 'text' AND value.atom = ?
                LIMIT 1
                """,
                (tenant_id, workspace_id, identifier),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _artifact_release_from_metadata(
        *,
        metadata_json: str,
        artifact_kind: str,
        reference_field: str,
        operation_field: str,
        catalog_category: str,
        catalog_identifier: str,
    ) -> CatalogArtifactRelease | None:
        metadata = _json_mapping(metadata_json)
        artifact_ref = metadata.get(reference_field)
        owner_operation_id = metadata.get(operation_field)
        if not (
            isinstance(artifact_ref, str)
            and artifact_ref
            and isinstance(owner_operation_id, str)
            and owner_operation_id
        ):
            return None
        return CatalogArtifactRelease(
            artifact_kind=artifact_kind,
            artifact_ref=artifact_ref,
            owner_operation_id=owner_operation_id,
            catalog_category=catalog_category,
            catalog_identifier=catalog_identifier,
        )

    def purge_retention(
        self,
        tenant_id: str,
        workspace_id: str,
        policy: CatalogRetentionPolicy,
        *,
        actor: str = "system",
        operation_id: str | None = None,
    ) -> CatalogRetentionResult:
        """Purge one bounded inventory under conservative dependency checks."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        if type(policy) is not CatalogRetentionPolicy:
            raise ValueError("policy must be an exact CatalogRetentionPolicy")
        if not policy.enabled:
            raise CatalogRetentionDisabledError(
                "catalog retention is disabled; dry-run with inventory_retention"
            )
        retention_actor = _bounded_label(actor, "retention actor")
        retention_operation_id = _bounded_identifier(
            operation_id or f"catalog-retention-{uuid4()}",
            "retention operation_id",
        )
        policy_document = policy.as_dict()
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            prior_row = cursor.execute(
                """
                SELECT * FROM catalog_retention_audit
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, retention_operation_id),
            ).fetchone()
            if prior_row is not None:
                prior = self._retention_audit_entry(
                    prior_row,
                    tenant,
                    workspace,
                )
                if (
                    prior.actor != retention_actor
                    or dict(prior.policy) != policy_document
                ):
                    raise SessionConflictError(
                        "retention operation_id was reused for a different request"
                    )
                if prior.result is None:
                    raise SessionConflictError(
                        "legacy retention action cannot be replayed"
                    )
                return _catalog_result_from_document(
                    prior.result,
                    tenant_id=tenant,
                    workspace_id=workspace,
                    policy=policy,
                )
            inventory = self._retention_inventory_from_cursor(
                cursor,
                tenant,
                workspace,
                policy,
            )
            purged: list[CatalogRetentionCandidate] = []
            artifact_releases: list[CatalogArtifactRelease] = []
            for candidate in inventory.candidates:
                if candidate.blockers:
                    continue
                if candidate.category == "catalog_idempotency":
                    assert policy.idempotency_before_ns is not None
                    assert candidate.qualifier is not None
                    deleted = cursor.execute(
                        """
                        DELETE FROM idempotency_keys
                        WHERE tenant_id = ? AND operation = ?
                          AND idempotency_key = ? AND created_at_ns < ?
                          AND json_extract(
                              response_json, '$.workspace_id'
                          ) = ?
                        """,
                        (
                            tenant,
                            candidate.qualifier,
                            candidate.identifier,
                            policy.idempotency_before_ns,
                            workspace,
                        ),
                    ).rowcount
                elif candidate.category == "revision_set_snapshot":
                    assert policy.snapshot_before_ns is not None
                    if self._has_idempotency_reference(
                        cursor,
                        tenant,
                        workspace,
                        candidate.identifier,
                    ):
                        continue
                    if policy.preserve_latest_snapshot_per_session:
                        is_latest = cursor.execute(
                            """
                            SELECT NOT EXISTS (
                                SELECT 1
                                FROM revision_set_snapshots AS newer
                                WHERE newer.tenant_id = current.tenant_id
                                  AND newer.session_id = current.session_id
                                  AND (
                                      newer.created_at_ns > current.created_at_ns
                                      OR (
                                          newer.created_at_ns = current.created_at_ns
                                          AND newer.snapshot_id > current.snapshot_id
                                      )
                                  )
                            ) AS is_latest
                            FROM revision_set_snapshots AS current
                            WHERE current.tenant_id = ?
                              AND current.workspace_id = ?
                              AND current.snapshot_id = ?
                            """,
                            (tenant, workspace, candidate.identifier),
                        ).fetchone()
                        if is_latest is None or is_latest["is_latest"]:
                            continue
                    cursor.execute(
                        """
                        DELETE FROM revision_set_members
                        WHERE tenant_id = ? AND snapshot_id = ?
                        """,
                        (tenant, candidate.identifier),
                    )
                    deleted = cursor.execute(
                        """
                        DELETE FROM revision_set_snapshots
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND snapshot_id = ?
                          AND created_at_ns < ?
                        """,
                        (
                            tenant,
                            workspace,
                            candidate.identifier,
                            policy.snapshot_before_ns,
                        ),
                    ).rowcount
                elif candidate.category == "analysis_revision":
                    assert policy.revision_before_ns is not None
                    if self._has_idempotency_reference(
                        cursor,
                        tenant,
                        workspace,
                        candidate.identifier,
                    ):
                        continue
                    referenced = cursor.execute(
                        """
                        SELECT
                            EXISTS (
                                SELECT 1 FROM session_members
                                WHERE tenant_id = ? AND revision_id = ?
                            ) OR EXISTS (
                                SELECT 1 FROM revision_set_members
                                WHERE tenant_id = ? AND revision_id = ?
                            ) AS is_referenced
                        """,
                        (
                            tenant,
                            candidate.identifier,
                            tenant,
                            candidate.identifier,
                        ),
                    ).fetchone()
                    if referenced["is_referenced"]:
                        continue
                    artifact_row = cursor.execute(
                        """
                        SELECT metadata_json FROM analysis_revisions
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND revision_id = ?
                        """,
                        (tenant, workspace, candidate.identifier),
                    ).fetchone()
                    deleted = cursor.execute(
                        """
                        DELETE FROM analysis_revisions
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND revision_id = ?
                          AND published_at_ns < ?
                        """,
                        (
                            tenant,
                            workspace,
                            candidate.identifier,
                            policy.revision_before_ns,
                        ),
                    ).rowcount
                    if deleted == 1 and artifact_row is not None:
                        release = self._artifact_release_from_metadata(
                            metadata_json=str(artifact_row["metadata_json"]),
                            artifact_kind="dataset",
                            reference_field="dataset_ref",
                            operation_field="publication_operation_id",
                            catalog_category=candidate.category,
                            catalog_identifier=candidate.identifier,
                        )
                        if release is not None:
                            artifact_releases.append(release)
                elif candidate.category == "fixture":
                    assert policy.fixture_before_ns is not None
                    if self._has_idempotency_reference(
                        cursor,
                        tenant,
                        workspace,
                        candidate.identifier,
                    ):
                        continue
                    retained = cursor.execute(
                        """
                        SELECT 1 FROM analysis_revisions
                        WHERE tenant_id = ? AND fixture_id = ? LIMIT 1
                        """,
                        (tenant, candidate.identifier),
                    ).fetchone()
                    if retained is not None:
                        continue
                    artifact_row = cursor.execute(
                        """
                        SELECT metadata_json FROM fixtures
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND fixture_id = ?
                        """,
                        (tenant, workspace, candidate.identifier),
                    ).fetchone()
                    deleted = cursor.execute(
                        """
                        DELETE FROM fixtures
                        WHERE tenant_id = ? AND workspace_id = ?
                          AND fixture_id = ?
                          AND created_at_ns < ?
                        """,
                        (
                            tenant,
                            workspace,
                            candidate.identifier,
                            policy.fixture_before_ns,
                        ),
                    ).rowcount
                    if deleted == 1 and artifact_row is not None:
                        release = self._artifact_release_from_metadata(
                            metadata_json=str(artifact_row["metadata_json"]),
                            artifact_kind="blob",
                            reference_field="blob_ref",
                            operation_field="admission_operation_id",
                            catalog_category=candidate.category,
                            catalog_identifier=candidate.identifier,
                        )
                        if release is not None:
                            artifact_releases.append(release)
                else:  # pragma: no cover - inventory categories are closed above
                    raise SessionStoreError(
                        f"unsupported retention category {candidate.category}"
                    )
                if deleted == 1:
                    purged.append(candidate)
            result = CatalogRetentionResult(
                inventory=inventory,
                purged=tuple(purged),
                artifact_releases=tuple(artifact_releases),
            )
            result_json = _bounded_retention_json(
                _catalog_result_document(result),
                "catalog retention result",
                maximum_bytes=_MAX_RETENTION_RESULT_BYTES,
            )
            purged_document = [
                {
                    "category": candidate.category,
                    "identifier": candidate.identifier,
                    "qualifier": candidate.qualifier,
                    "retention_value": candidate.retention_value,
                }
                for candidate in purged
            ]
            artifact_document = [asdict(release) for release in artifact_releases]
            digest_document = {
                "purged": purged_document,
                "artifact_releases": artifact_document,
            }
            digest = sha256(canonical_json(digest_document).encode("utf-8")).hexdigest()
            try:
                cursor.execute(
                    """
                    INSERT INTO catalog_retention_audit (
                        tenant_id, workspace_id, operation_id, actor,
                        occurred_at_ns, policy_json, candidate_count,
                        purged_count, purged_json, artifact_releases_json,
                        purged_sha256, result_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        workspace,
                        retention_operation_id,
                        retention_actor,
                        time.time_ns(),
                        canonical_json(policy_document),
                        inventory.total_candidate_count,
                        len(purged),
                        canonical_json(purged_document),
                        canonical_json(artifact_document),
                        digest,
                        result_json,
                    ),
                )
                _stored_catalog_retention_audit_sequence(cursor.lastrowid)
            except sqlite3.IntegrityError as error:
                raise SessionConflictError(
                    "retention operation_id was already used in this workspace"
                ) from error
            return result

    @staticmethod
    def _retention_audit_entry(
        row: sqlite3.Row,
        tenant: str,
        workspace: str,
    ) -> CatalogRetentionAuditEntry:
        policy_document = json.loads(row["policy_json"])
        purged_document = json.loads(row["purged_json"])
        artifact_document = json.loads(row["artifact_releases_json"])
        result_document = (
            _stored_bounded_retention_mapping(
                row["result_json"],
                "catalog retention result",
                maximum_bytes=_MAX_RETENTION_RESULT_BYTES,
            )
            if row["result_json"] is not None
            else None
        )
        if not (
            isinstance(policy_document, dict)
            and isinstance(purged_document, list)
            and all(isinstance(item, dict) for item in purged_document)
            and isinstance(artifact_document, list)
            and all(isinstance(item, dict) for item in artifact_document)
            and (result_document is None or isinstance(result_document, dict))
        ):
            raise SessionStoreError("stored catalog retention audit is invalid")
        entry = CatalogRetentionAuditEntry(
            sequence=_stored_catalog_retention_audit_sequence(row["sequence"]),
            tenant_id=tenant,
            workspace_id=workspace,
            operation_id=str(row["operation_id"]),
            actor=str(row["actor"]),
            occurred_at_ns=int(row["occurred_at_ns"]),
            policy=policy_document,
            candidate_count=int(row["candidate_count"]),
            purged_count=int(row["purged_count"]),
            purged=tuple(purged_document),
            artifact_releases=tuple(artifact_document),
            purged_sha256=str(row["purged_sha256"]),
            artifact_releases_acknowledged_at_ns=(
                int(row["artifact_releases_acknowledged_at_ns"])
                if row["artifact_releases_acknowledged_at_ns"] is not None
                else None
            ),
            result=result_document,
        )
        digest_document = {
            "purged": purged_document,
            "artifact_releases": artifact_document,
        }
        if (
            entry.purged_count != len(entry.purged)
            or sha256(canonical_json(digest_document).encode("utf-8")).hexdigest()
            != entry.purged_sha256
        ):
            raise SessionStoreError(
                "stored catalog retention audit digest or count is invalid"
            )
        return entry

    def list_retention_audit(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        after_sequence: int = 0,
        limit: int = _DEFAULT_PAGE_LIMIT,
    ) -> tuple[CatalogRetentionAuditEntry, ...]:
        """List bounded, workspace-scoped catalog retention actions."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence <= MAX_JSON_SAFE_INTEGER
        ):
            raise ValueError("after_sequence must be a non-negative JSON-safe integer")
        page_limit, _ = _page_bounds(limit, 0)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            rows = cursor.execute(
                """
                SELECT * FROM catalog_retention_audit
                WHERE tenant_id = ? AND workspace_id = ? AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (tenant, workspace, after_sequence, page_limit),
            ).fetchall()
        return tuple(
            self._retention_audit_entry(row, tenant, workspace) for row in rows
        )

    def get_retention_audit(
        self,
        tenant_id: str,
        workspace_id: str,
        operation_id: str,
    ) -> CatalogRetentionAuditEntry | None:
        """Return one exact catalog-retention action, if it exists."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            row = cursor.execute(
                """
                SELECT * FROM catalog_retention_audit
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
        if row is None:
            return None
        return self._retention_audit_entry(row, tenant, workspace)

    @staticmethod
    def _retention_saga_descriptor(
        row: sqlite3.Row,
    ) -> RetentionSagaDescriptor:
        try:
            request = _stored_bounded_retention_mapping(
                row["request_json"],
                "retention saga request",
                maximum_bytes=_MAX_RETENTION_SAGA_REQUEST_BYTES,
            )
            results = {
                phase: (
                    _stored_bounded_retention_mapping(
                        row[f"{phase}_result_json"],
                        f"retention saga {phase} result",
                        maximum_bytes=_MAX_RETENTION_RESULT_BYTES,
                    )
                    if row[f"{phase}_result_json"] is not None
                    else None
                )
                for phase in _RETENTION_SAGA_PHASES
            }
            tenant_id = _bounded_identifier(row["tenant_id"], "tenant_id")
            project_id = _bounded_identifier(row["project_id"], "project_id")
            workspace_id = _bounded_identifier(row["workspace_id"], "workspace_id")
            operation_id = _bounded_identifier(row["operation_id"], "operation_id")
            actor = _bounded_label(row["actor"], "retention actor")
        except (SessionStoreError, TypeError, ValueError) as error:
            raise SessionStoreError("stored retention saga is invalid") from error
        request_sha256 = str(row["request_sha256"])
        if (
            _DIGEST_PATTERN.fullmatch(request_sha256) is None
            or canonical_json_sha256(request) != request_sha256
        ):
            raise SessionStoreError("stored retention saga digest is invalid")
        integer_fields = {
            name: row[name]
            for name in (
                "effective_now_ns",
                "replayed_release_actions",
                "replayed_artifact_releases",
                "created_at_ns",
                "updated_at_ns",
            )
        }
        completed_at_ns = row["completed_at_ns"]
        if any(
            type(value) is not int or not 0 <= value <= _MAX_SQLITE_INTEGER
            for value in integer_fields.values()
        ) or (
            completed_at_ns is not None
            and (
                type(completed_at_ns) is not int
                or not 0 <= completed_at_ns <= _MAX_SQLITE_INTEGER
            )
        ):
            raise SessionStoreError("stored retention saga counters are invalid")
        if completed_at_ns is not None and any(
            result is None for result in results.values()
        ):
            raise SessionStoreError(
                "stored completed retention saga is missing a phase result"
            )
        return RetentionSagaDescriptor(
            tenant_id=tenant_id,
            project_id=project_id,
            workspace_id=workspace_id,
            operation_id=operation_id,
            actor=actor,
            request_sha256=request_sha256,
            request=request,
            effective_now_ns=integer_fields["effective_now_ns"],
            review_result=results["review"],
            catalog_result=results["catalog"],
            ingestion_result=results["ingestion"],
            replayed_release_actions=integer_fields["replayed_release_actions"],
            replayed_artifact_releases=integer_fields["replayed_artifact_releases"],
            created_at_ns=integer_fields["created_at_ns"],
            updated_at_ns=integer_fields["updated_at_ns"],
            completed_at_ns=completed_at_ns,
        )

    def begin_retention_saga(
        self,
        tenant_id: str,
        project_id: str,
        workspace_id: str,
        operation_id: str,
        *,
        actor: str,
        request: Mapping[str, Any],
        requested_now_ns: int | None = None,
    ) -> RetentionSagaDescriptor:
        """Create or exactly replay one durable retention coordinator row."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        project = _bounded_identifier(project_id, "project_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        retention_actor = _bounded_label(actor, "retention actor")
        request_json = _bounded_retention_json(
            request,
            "retention saga request",
            maximum_bytes=_MAX_RETENTION_SAGA_REQUEST_BYTES,
        )
        request_document = json.loads(request_json)
        request_sha256 = canonical_json_sha256(request_document)
        if requested_now_ns is not None and (
            type(requested_now_ns) is not int
            or not 0 <= requested_now_ns <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError(
                "requested_now_ns must be a SQLite-sized non-negative integer"
            )
        with self._transaction() as cursor:
            workspace_row = self._require_workspace(cursor, tenant, workspace)
            if str(workspace_row["project_id"]) != project:
                raise KeyError(workspace)
            prior_row = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            if prior_row is not None:
                prior = self._retention_saga_descriptor(prior_row)
                if (
                    prior.project_id != project
                    or prior.actor != retention_actor
                    or prior.request_sha256 != request_sha256
                    or dict(prior.request) != request_document
                    or (
                        requested_now_ns is not None
                        and prior.effective_now_ns != requested_now_ns
                    )
                ):
                    raise IdempotencyConflict(
                        "retention operation_id was reused for a different request"
                    )
                return prior
            now = time.time_ns()
            effective_now = now if requested_now_ns is None else requested_now_ns
            cursor.execute(
                """
                INSERT INTO control_plane_retention_saga (
                    tenant_id, project_id, workspace_id, operation_id,
                    actor, request_sha256, request_json, effective_now_ns,
                    created_at_ns, updated_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant,
                    project,
                    workspace,
                    operation,
                    retention_actor,
                    request_sha256,
                    request_json,
                    effective_now,
                    now,
                    now,
                ),
            )
            row = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            assert row is not None
            return self._retention_saga_descriptor(row)

    def record_retention_saga_phase(
        self,
        tenant_id: str,
        workspace_id: str,
        operation_id: str,
        phase: str,
        result: Mapping[str, Any],
    ) -> RetentionSagaDescriptor:
        """Durably checkpoint one exact completed saga phase."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        if phase not in _RETENTION_SAGA_PHASES:
            raise ValueError("unsupported retention saga phase")
        result_json = _bounded_retention_json(
            result,
            f"retention saga {phase} result",
            maximum_bytes=_MAX_RETENTION_RESULT_BYTES,
        )
        column = f"{phase}_result_json"
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            row = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            if row is None:
                raise KeyError(operation)
            prior_json = row[column]
            if prior_json is not None:
                if str(prior_json) != result_json:
                    raise SessionConflictError(
                        "retention saga phase result conflicts with durable state"
                    )
                return self._retention_saga_descriptor(row)
            if row["completed_at_ns"] is not None:
                raise SessionConflictError("completed retention saga is immutable")
            cursor.execute(
                f"""
                UPDATE control_plane_retention_saga
                SET {column} = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                  AND {column} IS NULL AND completed_at_ns IS NULL
                """,
                (result_json, time.time_ns(), tenant, workspace, operation),
            )
            updated = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            assert updated is not None
            return self._retention_saga_descriptor(updated)

    def add_retention_saga_replay_counts(
        self,
        tenant_id: str,
        workspace_id: str,
        operation_id: str,
        *,
        release_actions: int,
        artifact_releases: int,
    ) -> RetentionSagaDescriptor:
        """Add bounded reconciliation counts before final completion."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        for label, value in (
            ("release_actions", release_actions),
            ("artifact_releases", artifact_releases),
        ):
            if type(value) is not int or not 0 <= value <= _MAX_SQLITE_INTEGER:
                raise ValueError(f"{label} must be a non-negative integer")
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            row = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            if row is None:
                raise KeyError(operation)
            if row["completed_at_ns"] is not None:
                return self._retention_saga_descriptor(row)
            replayed_release_actions = int(row["replayed_release_actions"])
            replayed_artifact_releases = int(row["replayed_artifact_releases"])
            if (
                replayed_release_actions > _MAX_SQLITE_INTEGER - release_actions
                or replayed_artifact_releases > _MAX_SQLITE_INTEGER - artifact_releases
            ):
                raise SessionStoreError(
                    "retention saga replay counters exceed SQLite bounds"
                )
            cursor.execute(
                """
                UPDATE control_plane_retention_saga
                SET replayed_release_actions = ?,
                    replayed_artifact_releases = ?,
                    updated_at_ns = ?
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (
                    replayed_release_actions + release_actions,
                    replayed_artifact_releases + artifact_releases,
                    time.time_ns(),
                    tenant,
                    workspace,
                    operation,
                ),
            )
            updated = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            assert updated is not None
            return self._retention_saga_descriptor(updated)

    def complete_retention_saga(
        self,
        tenant_id: str,
        workspace_id: str,
        operation_id: str,
    ) -> RetentionSagaDescriptor:
        """Mark a saga complete only after all exact phase results exist."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            row = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            if row is None:
                raise KeyError(operation)
            descriptor = self._retention_saga_descriptor(row)
            if descriptor.complete:
                return descriptor
            if any(
                value is None
                for value in (
                    descriptor.review_result,
                    descriptor.catalog_result,
                    descriptor.ingestion_result,
                )
            ):
                raise SessionConflictError(
                    "retention saga cannot complete before every phase"
                )
            completed_at = time.time_ns()
            cursor.execute(
                """
                UPDATE control_plane_retention_saga
                SET completed_at_ns = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                  AND completed_at_ns IS NULL
                """,
                (completed_at, completed_at, tenant, workspace, operation),
            )
            updated = cursor.execute(
                """
                SELECT * FROM control_plane_retention_saga
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            assert updated is not None
            return self._retention_saga_descriptor(updated)

    def pending_artifact_release_audits(
        self,
        tenant_id: str,
        workspace_id: str,
        *,
        limit: int = _DEFAULT_PAGE_LIMIT,
    ) -> tuple[CatalogRetentionAuditEntry, ...]:
        """Return unacknowledged catalog releases for crash-safe replay."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        page_limit, _ = _page_bounds(limit, 0)
        with self._read_cursor() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            rows = cursor.execute(
                """
                    SELECT * FROM catalog_retention_audit
                    WHERE tenant_id = ? AND workspace_id = ?
                      AND artifact_releases_acknowledged_at_ns IS NULL
                      AND artifact_releases_json != '[]'
                    ORDER BY sequence LIMIT ?
                    """,
                (tenant, workspace, page_limit),
            ).fetchall()
        return tuple(
            self._retention_audit_entry(row, tenant, workspace) for row in rows
        )

    def acknowledge_artifact_releases(
        self,
        tenant_id: str,
        workspace_id: str,
        operation_id: str,
        *,
        acknowledged_at_ns: int | None = None,
    ) -> bool:
        """Acknowledge that every release in one audited action was replayed."""

        tenant = _bounded_identifier(tenant_id, "tenant_id")
        workspace = _bounded_identifier(workspace_id, "workspace_id")
        operation = _bounded_identifier(operation_id, "operation_id")
        occurred = time.time_ns() if acknowledged_at_ns is None else acknowledged_at_ns
        if type(occurred) is not int or not 0 <= occurred <= _MAX_SQLITE_INTEGER:
            raise ValueError("acknowledged_at_ns must be a SQLite-sized integer")
        with self._transaction() as cursor:
            self._require_workspace(cursor, tenant, workspace)
            row = cursor.execute(
                """
                SELECT artifact_releases_json,
                       artifact_releases_acknowledged_at_ns
                FROM catalog_retention_audit
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                """,
                (tenant, workspace, operation),
            ).fetchone()
            if row is None:
                raise KeyError(operation)
            if row["artifact_releases_acknowledged_at_ns"] is not None:
                return False
            releases = json.loads(str(row["artifact_releases_json"]))
            if not isinstance(releases, list) or not all(
                isinstance(item, dict) for item in releases
            ):
                raise SessionStoreError("stored catalog retention audit is invalid")
            cursor.execute(
                """
                UPDATE catalog_retention_audit
                SET artifact_releases_acknowledged_at_ns = ?
                WHERE tenant_id = ? AND workspace_id = ? AND operation_id = ?
                  AND artifact_releases_acknowledged_at_ns IS NULL
                """,
                (occurred, tenant, workspace, operation),
            )
            return cursor.rowcount == 1

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


__all__ = [
    "AnalysisRevisionDescriptor",
    "AnalysisSession",
    "CatalogArtifactRelease",
    "CatalogRetentionAuditEntry",
    "CatalogRetentionCandidate",
    "CatalogRetentionDisabledError",
    "CatalogRetentionInventory",
    "CatalogRetentionPolicy",
    "CatalogRetentionResult",
    "FixtureDescriptor",
    "IdempotencyConflict",
    "ProjectDescriptor",
    "RetentionSagaDescriptor",
    "RevisionSetSnapshot",
    "SessionConflictError",
    "SessionMemberDescriptor",
    "SessionStoreDeadlineExceeded",
    "SessionStoreError",
    "SqliteSessionStore",
    "StaleSessionVersion",
    "WorkspaceDescriptor",
    "validate_catalog_identifier",
    "validate_catalog_label",
    "validate_catalog_member_role",
    "validate_catalog_metadata",
]
