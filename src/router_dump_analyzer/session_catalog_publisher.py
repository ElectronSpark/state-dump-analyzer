"""Durable SQLite catalog adapter for the core publication protocol."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from .canonical import canonical_json
from .control_plane_errors import ControlPlaneScopeError, DatasetIntegrityError
from .ingestion_contracts import (
    _DATASET_FORMAT,
    CatalogExecutionTimeoutError,
    CatalogPublisherProcessBootstrap,
    ImportScope,
    PublisherCallContext,
    RevisionCatalogPublisher,
)
from .plugin_execution_plan import (
    PluginExecutionPlan,
    plugin_execution_plan_plugin_ids,
    primary_parser_execution_pin,
    snapshot_plugin_execution_plan,
)
from .session_store import (
    SessionStoreDeadlineExceeded,
    SqliteSessionStore,
    WorkspaceDescriptor,
)

__all__ = ["SessionCatalogPublisher"]

class SessionCatalogPublisher(RevisionCatalogPublisher):
    """Register pipeline publications in the durable session catalog."""

    def __init__(self, sessions: SqliteSessionStore) -> None:
        self.sessions: SqliteSessionStore = sessions

    def __getstate__(self) -> dict[str, str]:
        """Serialize only the durable locator for a bounded child call."""

        return {"database_path": self.sessions._process_reopen_path()}

    def __setstate__(self, state: Mapping[str, str]) -> None:
        database_path = state.get("database_path")
        if not isinstance(database_path, str) or not database_path:
            raise TypeError("catalog publisher process state is invalid")
        self.sessions = SqliteSessionStore(database_path)

    def process_bootstrap(self) -> CatalogPublisherProcessBootstrap:
        """Freeze only the durable SQLite locator for process reconstruction."""

        return CatalogPublisherProcessBootstrap(
            loader_kind="core_sqlite_session",
            constructor_args=(self.sessions._process_reopen_path(),),
        )

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
                    execution_plan = snapshot_plugin_execution_plan(execution_plan)
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
            if execution_plan is not None:
                try:
                    primary_pin = primary_parser_execution_pin(execution_plan)
                except (TypeError, ValueError) as error:
                    raise DatasetIntegrityError(
                        "execution plan must contain one primary parser"
                    ) from error
                if (
                    execution_plan.node_id != node_id
                    or execution_plan.basis_revision_id != source_revision_id
                    or primary_pin.plugin_id != plugin_id
                    or primary_pin.plugin_version != plugin_version
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
                    {"plugin_execution_plan_digest": (execution_plan.plan_digest)}
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
                plugin_ids=(
                    plugin_execution_plan_plugin_ids(execution_plan)
                    if execution_plan is not None
                    else (plugin_id,)
                ),
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
