"""Core ingestion scope, errors and publication contracts, independent of the queue."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .plugin_execution_plan import PluginExecutionPlan

__all__ = [
    "CatalogExecutionTimeoutError",
    "CatalogPublisherProcessBootstrap",
    "ImportScope",
    "IngestionPipelineError",
    "PublisherCallContext",
    "RevisionCatalogPublisher",
]

MAX_SCOPE_ID_LENGTH = 128
_DATASET_FORMAT = "router_dump_analyzer.canonical-json.v1"


class IngestionPipelineError(RuntimeError):
    """Base class for durable pipeline failures."""


class CatalogExecutionTimeoutError(IngestionPipelineError):
    """A catalog call crossed its enforced deadline with an ambiguous outcome."""


@dataclass(frozen=True, slots=True)
class ImportScope:
    """Authorization scope resolved before repository access."""

    tenant_id: str
    project_id: str
    workspace_id: str

    def __post_init__(self) -> None:
        for label, value in (
            ("tenant_id", self.tenant_id),
            ("project_id", self.project_id),
            ("workspace_id", self.workspace_id),
        ):
            _bounded_identifier(value, label)


@dataclass(frozen=True, slots=True)
class PublisherCallContext:
    """Core-owned deadline and identity supplied to one catalog call.

    Process mode enforces this budget in the parent. Publishers should still
    use ``remaining_seconds`` for narrower RPC/lock deadlines, especially
    because a remote commit followed by timeout has an ambiguous outcome.
    """

    operation_id: str
    attempt_number: int
    started_monotonic_ns: int
    deadline_monotonic_ns: int

    def __post_init__(self) -> None:
        _bounded_identifier(self.operation_id, "operation_id", 256)
        if type(self.attempt_number) is not int or self.attempt_number < 1:
            raise ValueError("attempt_number must be a positive integer")
        for label, value in (
            ("started_monotonic_ns", self.started_monotonic_ns),
            ("deadline_monotonic_ns", self.deadline_monotonic_ns),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if self.deadline_monotonic_ns <= self.started_monotonic_ns:
            raise ValueError("publisher deadline must follow its start")

    @property
    def remaining_seconds(self) -> float:
        return max(
            0.0,
            (self.deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000,
        )

    def raise_if_expired(self) -> None:
        if time.monotonic_ns() >= self.deadline_monotonic_ns:
            raise CatalogExecutionTimeoutError(
                "catalog operation exceeded its cooperative deadline"
            )


@dataclass(frozen=True, slots=True)
class CatalogPublisherProcessBootstrap:
    """Inert constructor coordinates for one process-mode publisher."""

    loader_kind: str
    target: str | None = None
    constructor_args: tuple[str, ...] = ()
    schema_version: str = "router_dump_analyzer.catalog_process_bootstrap.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "router_dump_analyzer.catalog_process_bootstrap.v1":
            raise ValueError("catalog process bootstrap version is unsupported")
        if self.loader_kind not in {
            "core_null",
            "core_sqlite_session",
            "module_attribute",
            "class_constructor",
        }:
            raise ValueError("catalog process bootstrap loader kind is invalid")
        if self.target is not None:
            _normalized_explicit_bootstrap_target(
                self.target,
                "catalog_process_target",
            )
        if type(self.constructor_args) is not tuple or any(
            type(value) is not str for value in self.constructor_args
        ):
            raise TypeError("catalog process constructor arguments must be strings")
        if self.loader_kind in {"core_null", "core_sqlite_session"}:
            if self.target is not None:
                raise ValueError("core catalog process bootstrap cannot name a target")
        elif self.target is None:
            raise ValueError("custom catalog process bootstrap requires a target")
        expected_argument_count = 1 if self.loader_kind == "core_sqlite_session" else 0
        if len(self.constructor_args) != expected_argument_count:
            raise ValueError("catalog process constructor arguments are invalid")


class RevisionCatalogPublisher(Protocol):
    """Durable publication boundary supplied by the session catalog.

    Process mode serializes a core-owned inert bootstrap, never this live
    publisher object. A custom publisher must therefore be exposed through a
    module-level target or support no-argument class construction in the child.
    ``inline`` is reserved for trusted embeddings and cannot enforce
    cancellation.
    """

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
    ) -> None: ...

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
    ) -> str | None:
        """Publish and optionally return the catalog-visible revision ID."""
        ...


def _normalized_explicit_bootstrap_target(value: str, label: str) -> str:
    target = _bounded_identifier(value, label, 512)
    module_name, separator, attribute = target.partition(":")
    if (
        separator != ":"
        or not module_name
        or not attribute
        or ":" in attribute
        or target != target.strip()
    ):
        raise ValueError(f"{label} must use 'package.module:attribute' syntax")
    return target


def _bounded_identifier(
    value: str,
    label: str,
    maximum: int = MAX_SCOPE_ID_LENGTH,
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ValueError(
            f"{label} must be a non-empty bounded identifier without "
            "whitespace or control characters"
        )
    return value
